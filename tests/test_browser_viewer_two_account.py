"""Disposable viewer-route tests: a Browser client_id is never proof of ownership.

Use an in-memory session pool and synthetic principals, not production OAuth
credentials, physical Browser workers or real sessions.
"""

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from commandcore_server.auth import READ_SCOPE, STANDARD_SCOPE
from commandcore_server.browser_viewer import install_browser_viewer
from commandcore_server.browser_worker_pool import OwnerBrowserWorkerPool
from commandcore_server.models import Principal


class FixturePool(OwnerBrowserWorkerPool):
    """Exercise the real HTTP owner guards with an isolated worker API stub."""

    def __init__(self):
        self.clients = {
            ("https://issuer-a.example/", "alice"): [
                {"client_id": "alice-browser", "session_id": "alice-private-session"}
            ],
            ("https://issuer-a.example/", "bob"): [
                {"client_id": "bob-browser", "session_id": "bob-private-session"}
            ],
            ("https://issuer-b.example/", "alice"): [],
        }
        self.actions = []

    def viewer_sessions(self, subject, issuer):
        self.actions.append(("list", issuer, subject))
        return list(self.clients.get((issuer, subject), []))

    async def viewer_frame(self, subject, issuer, client_id, args):
        self.actions.append(("frame", issuer, subject, client_id))
        return {"changed": True, "sequence": 1, "title": "Test page"}

    async def call(self, *, subject, issuer, client_id, name, args):
        self.actions.append(("handoff", issuer, subject, client_id, name))
        return {
            "handoff_url": "https://panel.example/browser/console/safe-token",
            "state": "awaiting_human",
        }


class FixtureAudit:
    def __init__(self):
        self.rows = []

    def add_audit(self, **kwargs):
        self.rows.append(kwargs)


@pytest.fixture
def viewer():
    app = FastAPI()
    pool = FixturePool()
    audit = FixtureAudit()

    async def principal(request: Request):
        return Principal(
            subject=request.headers.get("x-fixture-subject", "alice"),
            client_id="fixture-panel",
            auth_kind=request.headers.get("x-fixture-auth-kind", "oauth2-panel"),
            scopes=(
                (READ_SCOPE,)
                if request.headers.get("x-fixture-scope") == "read"
                else (STANDARD_SCOPE,)
            ),
            issuer=request.headers.get("x-fixture-issuer", "https://issuer-a.example/"),
        )

    def same_origin(request):
        return request.headers.get("origin") == "https://panel.example"

    install_browser_viewer(app, pool, principal, same_origin, audit)
    with TestClient(app, base_url="https://panel.example") as client:
        yield client, pool, audit


def test_list_is_partitioned_by_oauth_subject_and_issuer(viewer):
    client, pool, _ = viewer
    alice = client.get("/api/browser/sessions")
    bob = client.get("/api/browser/sessions", headers={"x-fixture-subject": "bob"})
    other_issuer = client.get(
        "/api/browser/sessions",
        headers={"x-fixture-issuer": "https://issuer-b.example/"},
    )
    assert alice.status_code == bob.status_code == other_issuer.status_code == 200
    assert [row["client_id"] for row in alice.json()["sessions"]] == ["alice-browser"]
    assert [row["client_id"] for row in bob.json()["sessions"]] == ["bob-browser"]
    assert other_issuer.json()["sessions"] == []
    assert alice.headers["cache-control"] == "no-store"
    assert "Authorization" in alice.headers["vary"]


@pytest.mark.parametrize(
    "foreign_client,headers",
    [
        ("alice-browser", {"x-fixture-subject": "bob"}),
        ("bob-browser", {}),
        ("alice-browser", {"x-fixture-issuer": "https://issuer-b.example/"}),
    ],
)
def test_foreign_frame_denied_before_worker_frame_call(viewer, foreign_client, headers):
    client, pool, _ = viewer
    result = client.get(
        "/api/browser/frame", params={"client_id": foreign_client}, headers=headers
    )
    assert result.status_code == 404
    assert not any(action[0] == "frame" for action in pool.actions)


@pytest.mark.parametrize(
    "foreign_client,headers",
    [
        ("alice-browser", {"x-fixture-subject": "bob"}),
        ("bob-browser", {}),
        ("alice-browser", {"x-fixture-issuer": "https://issuer-b.example/"}),
    ],
)
def test_foreign_handoff_denied_without_worker_action_or_audit(
    viewer, foreign_client, headers
):
    client, pool, audit = viewer
    result = client.post(
        "/api/browser/handoff",
        json={"client_id": foreign_client},
        headers={**headers, "origin": "https://panel.example"},
    )
    assert result.status_code == 404
    assert not any(action[0] == "handoff" for action in pool.actions)
    assert audit.rows == []


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"origin": "https://evil.example"},
    ],
)
def test_handoff_rejects_missing_or_foreign_origin(viewer, headers):
    client, pool, audit = viewer
    result = client.post(
        "/api/browser/handoff", json={"client_id": "alice-browser"}, headers=headers
    )
    assert result.status_code == 403
    assert not any(action[0] == "handoff" for action in pool.actions)
    assert audit.rows == []


def test_read_only_oauth_cannot_view_or_handoff(viewer):
    client, pool, audit = viewer
    headers = {"x-fixture-scope": "read"}
    assert client.get("/api/browser/sessions", headers=headers).status_code == 403
    assert (
        client.get(
            "/api/browser/frame", params={"client_id": "alice-browser"}, headers=headers
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/browser/handoff",
            json={"client_id": "alice-browser"},
            headers={**headers, "origin": "https://panel.example"},
        ).status_code
        == 403
    )
    assert pool.actions == []
    assert audit.rows == []


def test_owner_can_view_and_handoff_after_scope_and_origin_checks(viewer):
    client, pool, audit = viewer
    frame = client.get("/api/browser/frame", params={"client_id": "alice-browser"})
    assert frame.status_code == 200
    assert frame.json()["title"] == "Test page"
    response = client.post(
        "/api/browser/handoff",
        json={"client_id": "alice-browser"},
        headers={"origin": "https://panel.example"},
    )
    assert response.status_code == 200
    assert response.json()["handoff_path"] == "/browser/console/safe-token"
    assert len(audit.rows) == 1
    assert audit.rows[0]["user_id"] == "alice"
    assert [a[0] for a in pool.actions].count("handoff") == 1


@pytest.mark.parametrize(
    "headers",
    [
        {"x-fixture-auth-kind": "bootstrap-bearer"},
        {"x-fixture-auth-kind": "panel-cookie"},
        {"x-fixture-issuer": ""},
        {"x-fixture-subject": ""},
    ],
)
def test_non_oauth_and_missing_identity_cannot_access_viewer(viewer, headers):
    client, pool, audit = viewer
    assert client.get("/api/browser/sessions", headers=headers).status_code == 403
    assert (
        client.get(
            "/api/browser/frame", params={"client_id": "alice-browser"}, headers=headers
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/browser/handoff",
            json={"client_id": "alice-browser"},
            headers={**headers, "origin": "https://panel.example"},
        ).status_code
        == 403
    )
    assert pool.actions == []
    assert audit.rows == []


def test_closed_browser_session_cannot_be_reused_from_prior_listing(viewer):
    """A previously listed client ID is not a persistent ownership grant."""
    client, pool, audit = viewer
    initial = client.get("/api/browser/sessions")
    assert initial.status_code == 200
    assert initial.json()["sessions"][0]["client_id"] == "alice-browser"

    # Simulate a session closing between UI discovery and a later request.
    pool.clients[("https://issuer-a.example/", "alice")] = []
    assert (
        client.get(
            "/api/browser/frame", params={"client_id": "alice-browser"}
        ).status_code
        == 404
    )
    response = client.post(
        "/api/browser/handoff",
        json={"client_id": "alice-browser"},
        headers={"origin": "https://panel.example"},
    )
    assert response.status_code == 404
    assert not any(a[0] in {"frame", "handoff"} for a in pool.actions)
    assert audit.rows == []


def test_reassigned_client_id_never_inherits_previous_subject_access(viewer):
    """Client IDs can be reused, but subject and issuer still control access."""
    client, pool, audit = viewer
    pool.clients[("https://issuer-a.example/", "alice")] = []
    pool.clients[("https://issuer-a.example/", "bob")].append(
        {"client_id": "alice-browser", "session_id": "bob-new-session"}
    )

    assert client.get(
        "/api/browser/frame", params={"client_id": "alice-browser"}
    ).status_code == 404
    bob = client.get(
        "/api/browser/frame",
        params={"client_id": "alice-browser"},
        headers={"x-fixture-subject": "bob"},
    )
    assert bob.status_code == 200
    assert ("frame", "https://issuer-a.example/", "bob", "alice-browser") in pool.actions
    assert not any(
        a[0] == "frame" and a[2] == "alice" for a in pool.actions
    )
    assert audit.rows == []
