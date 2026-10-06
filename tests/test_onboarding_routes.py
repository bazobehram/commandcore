import base64
from pathlib import Path
from types import SimpleNamespace

import pytest
from commandcore_server.db import Database
from commandcore_server.enrollment import init_message
from commandcore_server.models import Principal
from commandcore_server.onboarding_routes import install_routes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient


@pytest.fixture
def panel(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    app = FastAPI()

    async def principal(request: Request):
        subject = request.headers.get("test-subject")
        if not subject:
            raise HTTPException(401, "authentication required")
        return Principal(
            subject,
            "test-panel",
            "oauth2-panel",
            ("commandcore:read", "commandcore:standard"),
        )

    class Agents:
        disconnected = []

        async def online_device_ids(self):
            return []

        async def disconnect_device(self, device_id):
            self.disconnected.append(device_id)

    agents = Agents()
    settings = SimpleNamespace(
        bootstrap_subject="registry",
        enrollment_ttl_seconds=600,
        public_base_url="https://panel.example",
        panel_oauth_client_id="",
    )
    service = install_routes(
        app,
        db,
        settings,
        principal,
        lambda r: r.headers.get("origin") in {None, "https://panel.example"},
        None,
        Path(__file__),
        agents,
    )
    client = TestClient(app, base_url="https://panel.example")
    return client, db, service, agents


def begin(client, ceiling="STANDARD"):
    key = Ed25519PrivateKey.generate()
    metadata = dict(
        display_name="disposable",
        hostname="disposable",
        platform="Linux",
        architecture="x86_64",
        agent_version="candidate",
        protocol_version="1",
        capabilities={"filesystem": True},
        local_ceiling=ceiling,
        public_key_b64=base64.b64encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode(),
    )
    response = client.post(
        "/api/enrollment/start",
        json={
            **metadata,
            "proof": base64.b64encode(key.sign(init_message(metadata))).decode(),
        },
    )
    assert response.status_code == 200
    item = response.json()
    assert response.headers["cache-control"] == "no-store"
    item["view_token"] = item["verification_uri"].split("#")[1]
    item["proof"] = base64.b64encode(
        key.sign(
            f"commandcore-enroll-claim-v1\n{item['id']}\n{item['poll_token']}".encode()
        )
    ).decode()
    return item


def operator(subject="operator"):
    return {"test-subject": subject, "origin": "https://panel.example"}


def approve(client, item):
    body = {"view_token": item["view_token"]}
    assert (
        client.post("/api/enrollment/review", headers=operator(), json=body).status_code
        == 200
    )
    body.update(code=item["verification_code"], approve=True, grant_to_me=True)
    assert (
        client.post(
            "/api/enrollment/decision", headers=operator(), json=body
        ).status_code
        == 200
    )
    response = client.post(
        "/api/enrollment/poll",
        json={"poll_token": item["poll_token"], "proof": item["proof"]},
    )
    assert response.status_code == 200
    return response.json()["device_id"]


def test_device_audit_is_manager_scoped_and_contains_no_arguments_or_credentials(panel):
    client, _, _, _ = panel
    device_id = approve(client, begin(client))
    path = "/api/managed-devices/" + device_id + "/audit"
    assert client.get(path).status_code == 401
    assert client.get(path, headers=operator("stranger")).status_code == 404
    response = client.get(path, headers=operator())
    assert (
        response.status_code == 200 and response.headers["cache-control"] == "no-store"
    )
    events = response.json()["events"]
    assert events and any(event["tool"] == "enrollment.consumed" for event in events)
    assert all(
        set(event) == {"timestamp", "tool", "status", "duration_ms", "risk_class"}
        for event in events
    )


def test_http_authentication_csrf_reviewer_isolation_and_input_limits(panel):
    client, _, _, _ = panel
    item = begin(client)
    body = {"view_token": item["view_token"]}
    assert client.post("/api/enrollment/review", json=body).status_code == 401
    assert (
        client.post(
            "/api/enrollment/review", headers={"test-subject": "operator"}, json=body
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/enrollment/review",
            headers={**operator(), "origin": "https://evil.example"},
            json=body,
        ).status_code
        == 403
    )
    assert (
        client.post("/api/enrollment/review", headers=operator(), json=body).status_code
        == 200
    )
    assert (
        client.get("/api/enrollment/pending", headers=operator("stranger")).json()[
            "enrollments"
        ]
        == []
    )
    assert (
        len(
            client.get("/api/enrollment/pending", headers=operator()).json()[
                "enrollments"
            ]
        )
        == 1
    )
    for _ in range(21):
        response = client.post(
            "/api/enrollment/decision",
            headers=operator(),
            json={**body, "code": "AAAA-AAAA", "approve": True},
        )
    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"
    assert (
        client.post(
            "/api/enrollment/poll", json={"poll_token": "short", "proof": "x"}
        ).status_code
        == 422
    )


def test_managers_cannot_access_others_or_raise_ceiling(panel):
    client, db, _, agents = panel
    device_id = approve(client, begin(client, "READ_ONLY"))
    path = "/api/managed-devices/" + device_id
    assert (
        client.get("/api/managed-devices", headers=operator("stranger")).json()[
            "devices"
        ]
        == []
    )
    assert (
        client.patch(
            path, headers=operator("stranger"), json={"display_name": "stolen"}
        ).status_code
        == 404
    )
    assert (
        client.put(
            path + "/grants",
            headers=operator(),
            json={"subject": "second", "profile": "STANDARD"},
        ).status_code
        == 403
    )
    assert (
        client.put(
            path + "/grants",
            headers=operator(),
            json={"subject": "second", "profile": "FULL_CONTROL"},
        ).status_code
        == 422
    )
    assert (
        client.put(
            path + "/grants",
            headers=operator(),
            json={"subject": "second", "profile": "READ_ONLY"},
        ).status_code
        == 200
    )
    assert (
        client.patch(
            path, headers=operator(), json={"display_name": "renamed"}
        ).status_code
        == 200
    )
    assert db.get_device(device_id)["display_name"] == "renamed"
    assert (
        client.delete(path + "/grants?subject=second", headers=operator()).status_code
        == 200
    )
    assert db.list_accessible_devices("second") == []
    assert client.post(path + "/revoke", headers=operator()).status_code == 200
    assert agents.disconnected == [device_id]
    assert db.get_device(device_id)["status"] == "revoked"
    assert (
        client.put(
            path + "/grants",
            headers=operator(),
            json={"subject": "second", "profile": "READ_ONLY"},
        ).status_code
        == 409
    )
