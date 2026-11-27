"""Activity metadata must not bypass the existing restricted-path policy."""

import json

import pytest
from commandcore_server.live_activity import LiveActivity
from commandcore_server.models import Principal


@pytest.mark.parametrize(
    ("tool", "key", "value"),
    [
        ("docker.inspect", "container", "service-password"),
        ("docker.inspect", "container_id", "token"),
        ("docker.run", "image", "registry.example/team/.env:latest"),
        ("docker.run", "image", "registry.example/team/app:credentials"),
        ("docker.run", "image", "https://alice:example-value@registry.example/app"),
        ("docker.run", "image", "registry.example/../app:latest"),
        ("services.manage", "service", "private-key"),
        ("services.manage", "action", "secrets"),
        ("package.install", "manager", "cookie"),
    ],
)
def test_sensitive_label_absent_from_active_and_completed_activity(tool, key, value):
    activity = LiveActivity()
    principal = Principal(
        subject="alice", issuer="https://idp.example", client_id="app"
    )
    operation = activity.begin(principal, tool, {key: value})
    assert value not in json.dumps(activity.active[operation]["detail"])
    activity.finish(operation)
    assert value not in json.dumps(activity.completed[operation]["detail"])


@pytest.mark.parametrize(
    ("tool", "key", "value"),
    [
        ("docker.inspect", "container", "commandcore-api"),
        ("docker.run", "image", "registry.example:5000/team/api:rc8"),
        ("docker.inspect", "container_id", "a" * 64),
        ("docker.run", "image", "registry.example/team/api@sha256:" + "a" * 64),
        ("services.manage", "service", "nginx.service"),
        ("services.manage", "action", "restart"),
        ("package.install", "manager", "apt"),
    ],
)
def test_ordinary_operational_labels_remain_visible(tool, key, value):
    activity = LiveActivity()
    principal = Principal(
        subject="alice", issuer="https://idp.example", client_id="app"
    )
    operation = activity.begin(principal, tool, {key: value})
    assert activity.active[operation]["detail"][key] == value
