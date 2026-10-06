from commandcore_server.security import audit_summary


def test_audit_summary_does_not_store_command_file_content_or_env_values():
    text = audit_summary(
        {
            "command": "curl -H 'Authorization: Bearer secret-123' https://example.invalid",
            "data": "private-file-content",
            "data_base64": "c2VjcmV0",
            "env": {"API_TOKEN": "super-secret", "NORMAL": "value"},
            "patches": [{"search": "password=old", "replace": "password=new"}],
            "path": "/tmp/example",
        }
    )
    for secret in (
        "secret-123",
        "private-file-content",
        "c2VjcmV0",
        "super-secret",
        "password=old",
        "password=new",
    ):
        assert secret not in text
    assert "/tmp/example" in text
    assert "sha256_16" in text
