from commandcore_server.db import Database


def _device(db: Database):
    return db.register_device(
        owner_id="owner",
        display_name="alpha",
        hostname="alpha-host",
        platform="Linux",
        architecture="x86_64",
        agent_version="0.2.0",
        agent_protocol_version="1",
        public_key_b64="AAAA",
        capabilities={"filesystem": True, "privileged_helper": False},
        auto_approve=True,
    )


def test_enrollment_token_can_be_canceled(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    item = db.create_enrollment_token("owner", 60)
    assert db.cancel_enrollment_token("owner", item["id"])
    assert db.consume_enrollment_token(item["token"]) is None
    listed = db.list_enrollment_tokens("owner")
    assert listed[0]["status"] == "canceled"


def test_device_metadata_update_normalizes_tags(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    d = _device(db)
    assert db.update_device_metadata(
        "owner",
        d["device_id"],
        display_name=" Build Box ",
        tags=["gpu", "gpu", " research ", ""],
    )
    item = db.get_device(d["device_id"])
    assert item["display_name"] == "Build Box"
    assert item["tags"] == ["gpu", "research"]


def test_overview_and_active_jobs(tmp_path):
    db = Database(str(tmp_path / "db.sqlite3"))
    d = _device(db)
    db.mark_online(
        d["device_id"],
        ip="127.0.0.1",
        agent_version="0.2.0",
        capabilities={},
        agent_protocol_version="1",
    )
    db.create_job("exec-1", "owner", d["device_id"], "shell.exec")
    overview = db.overview("owner")
    assert overview["devices"] == 1
    assert overview["online"] == 1
    assert overview["active_jobs"] == 1
    assert db.list_jobs("owner", active_only=True)[0]["execution_id"] == "exec-1"


def test_restart_marks_incomplete_jobs_interrupted(tmp_path):
    path = str(tmp_path / "db.sqlite3")
    db = Database(path)
    d = _device(db)
    db.create_job("exec-stale", "owner", d["device_id"], "shell.exec")
    assert db.list_jobs("owner", active_only=True)
    db2 = Database(path)
    assert db2.list_jobs("owner", active_only=True) == []
    row = next(x for x in db2.list_jobs("owner") if x["execution_id"] == "exec-stale")
    assert row["status"] == "interrupted"
    assert "restarted" in row["error"]


def test_v01_enrollment_schema_migrates_additively(tmp_path):
    import sqlite3

    path = str(tmp_path / "legacy.sqlite3")
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE enrollment_tokens (id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, owner_id TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL, used_at REAL)"
    )
    conn.commit()
    conn.close()
    db = Database(path)
    columns = {
        r["name"]
        for r in db.conn.execute("PRAGMA table_info(enrollment_tokens)").fetchall()
    }
    assert "canceled_at" in columns
    item = db.create_enrollment_token("owner", 60)
    assert db.cancel_enrollment_token("owner", item["id"])
