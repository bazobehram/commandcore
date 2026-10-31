"""Owner-scoped persistence for MCP task UI summaries.

The ledger stores task/call lifecycle metadata only. It does not store command
arguments, output, paths, screenshots, browser tokens or credentials. Principal
authorization remains in MCPHandler and ToolService.
"""

from __future__ import annotations

import contextlib
from datetime import UTC

from .tools import ToolError


# Durable UI task boundaries. No command arguments, output, paths, browser
# screenshots or credentials are stored here. Authorization stays in MCPHandler.
class UITaskLedger:
    def __init__(self, path=None):
        import os
        import sqlite3
        import threading

        # Native Windows server hosting is not a Browser persistence target.
        # Keep auxiliary summaries only in memory, never in an unprotected file.
        self._memory_db = None
        self._memory_lock = threading.RLock()
        if os.name != "posix" or path == ":memory:":
            self.path = None
            self._memory_db = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            self._initialize_file(path)
        self._initialize_schema()

    def _initialize_file(self, path):
        import os
        from pathlib import Path

        self.path = Path(
            path
            or os.environ.get("COMMANDCORE_UI_TASK_DB")
            or str(
                Path(
                    os.environ.get("COMMANDCORE_DB", "/data/commandcore.sqlite3")
                ).with_name("ui-tasks.sqlite3")
            )
        )
        if not self.path.is_absolute() or self.path.is_symlink():
            raise RuntimeError("UI task database requires a private absolute file")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(fd)
        except FileExistsError:
            if self.path.stat().st_mode & 0o077:
                raise RuntimeError("UI task database must be private")

    def _initialize_schema(self):
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS ui_tasks (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, conversation TEXT NOT NULL,
                    started REAL NOT NULL, ended REAL,
                    last_tool TEXT NOT NULL DEFAULT '', device TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS ui_tasks_owner ON ui_tasks(owner,conversation,started);
                CREATE TABLE IF NOT EXISTS ui_calls (
                    id TEXT PRIMARY KEY, task_id TEXT NOT NULL, started REAL NOT NULL,
                    ended REAL, status TEXT NOT NULL, tool TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ui_calls_task ON ui_calls(task_id,started);
            """)
            # A process restart cannot certify an outstanding remote call.
            db.execute(
                "UPDATE ui_calls SET ended=?,status='interrupted' WHERE ended IS NULL",
                (self.now(),),
            )

    def bind_activity(self, live):
        """Bind conversation tags to this private durable ledger at startup.

        Viewer references and activity traces remain ephemeral. Only the random
        HMAC secret survives, so persisted task identities survive a restart.
        Never replace the key of a broker already serving viewers or activity.
        """
        import os
        import secrets
        import stat

        if self._memory_db is not None or not hasattr(live, "_session_key"):
            return
        path = self.path.with_name(self.path.name + ".session-key")
        try:
            fd = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as handle:
                handle.write(secrets.token_bytes(32))
                handle.flush()
                os.fsync(handle.fileno())
        # A malicious FIFO must fail immediately instead of blocking startup.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o077
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
            ):
                raise RuntimeError(
                    "Conversation key requires a private owner-only regular file"
                )
            key = handle.read(33)
        if len(key) != 32:
            raise RuntimeError("Conversation key must contain exactly 32 bytes")
        if live._session_key != key:
            if any(
                getattr(live, name, None)
                for name in ("_viewers", "active", "completed")
            ):
                raise RuntimeError(
                    "Conversation key must be bound before serving activity"
                )
            live._session_key = key

    @staticmethod
    def now():
        import time

        return time.time()

    @contextlib.contextmanager
    def connect(self):
        import sqlite3
        from urllib.parse import quote

        with (
            self._memory_lock
            if self._memory_db is not None
            else contextlib.nullcontext()
        ):
            yield from self._connection_scope(sqlite3, quote)

    def _connection_scope(self, sqlite3, quote):
        db = (
            self._memory_db
            if self._memory_db is not None
            else sqlite3.connect(
                "file:" + quote(str(self.path), safe="/") + "?mode=rw",
                uri=True,
                timeout=2,
            )
        )
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            if self._memory_db is None:
                db.close()

    @staticmethod
    def owner(principal):
        import hashlib
        import json

        return hashlib.sha256(
            json.dumps(
                [principal.issuer, principal.subject, principal.client_id],
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    def start(self, owner, conversation):
        import uuid

        now = self.now()
        task = str(uuid.uuid4())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # Prior cards stop following later work in this same conversation.
            db.execute(
                "UPDATE ui_calls SET ended=?,status='interrupted' WHERE ended IS NULL AND task_id IN (SELECT id FROM ui_tasks WHERE owner=? AND conversation=? AND ended IS NULL)",
                (now, owner, conversation),
            )
            db.execute(
                "UPDATE ui_tasks SET ended=? WHERE owner=? AND conversation=? AND ended IS NULL",
                (now, owner, conversation),
            )
            db.execute(
                "INSERT INTO ui_tasks(id,owner,conversation,started) VALUES(?,?,?,?)",
                (task, owner, conversation, now),
            )
            cutoff = now - 7 * 86400
            db.execute(
                "DELETE FROM ui_calls WHERE task_id IN (SELECT id FROM ui_tasks WHERE started<?)",
                (cutoff,),
            )
            db.execute("DELETE FROM ui_tasks WHERE started<?", (cutoff,))
        return task

    def get(self, owner, conversation, task):
        if not isinstance(task, str) or len(task) != 36:
            raise ToolError(
                "invalid_task_view", "Task unavailable in this conversation"
            )
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM ui_tasks WHERE id=? AND owner=? AND conversation=?",
                (task, owner, conversation),
            ).fetchone()
            if row is None:
                raise ToolError(
                    "invalid_task_view", "Task unavailable in this conversation"
                )
            stats = db.execute(
                """SELECT count(*) total,
                sum(CASE WHEN ended IS NULL THEN 1 ELSE 0 END) running,
                sum(CASE WHEN ended IS NOT NULL AND status NOT IN ('ok','completed','started','returned') THEN 1 ELSE 0 END) failed
                FROM ui_calls WHERE task_id=?""",
                (task,),
            ).fetchone()
            last = db.execute(
                "SELECT status,tool FROM ui_calls WHERE task_id=? ORDER BY started DESC LIMIT 1",
                (task,),
            ).fetchone()
        return dict(row) | {
            "total": stats["total"],
            "running": stats["running"] or 0,
            "failed": stats["failed"] or 0,
            "last_status": last["status"] if last else "ready",
            "last_tool": last["tool"] if last else "",
        }

    @staticmethod
    def public(row):
        return {
            key: row[key]
            for key in [
                "id",
                "started",
                "ended",
                "total",
                "running",
                "failed",
                "last_status",
                "last_tool",
                "device",
            ]
        }

    def begin_call(self, owner, conversation, tool):
        import uuid

        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            task = db.execute(
                "SELECT id FROM ui_tasks WHERE owner=? AND conversation=? AND ended IS NULL ORDER BY started DESC LIMIT 1",
                (owner, conversation),
            ).fetchone()
            if not task:
                return None
            call = str(uuid.uuid4())
            db.execute(
                "INSERT INTO ui_calls(id,task_id,started,status,tool) VALUES(?,?,?,?,?)",
                (call, task["id"], self.now(), "running", tool),
            )
            db.execute("UPDATE ui_tasks SET last_tool=? WHERE id=?", (tool, task["id"]))
        return call

    def end_call(self, call, status, device=""):
        if not call:
            return
        with self.connect() as db:
            db.execute(
                "UPDATE ui_calls SET ended=?,status=? WHERE id=? AND ended IS NULL",
                (self.now(), str(status)[:40], call),
            )
            if isinstance(device, str) and device:
                db.execute(
                    "UPDATE ui_tasks SET device=? WHERE id=(SELECT task_id FROM ui_calls WHERE id=?)",
                    (device[:100], call),
                )

    def history(self, owner, conversation, task):
        # Recheck ownership in the query; never expose another task's calls.
        from datetime import datetime

        with self.connect() as db:
            rows = db.execute(
                """SELECT c.id,c.started,c.ended,c.status,c.tool
                FROM ui_calls c JOIN ui_tasks t ON t.id=c.task_id
                WHERE t.id=? AND t.owner=? AND t.conversation=?
                ORDER BY c.started DESC LIMIT 50""",
                (task, owner, conversation),
            ).fetchall()

        def iso(value):
            return (
                datetime.fromtimestamp(value, UTC).isoformat()
                if value is not None
                else None
            )

        return [
            {
                "id": "saved-call-" + r["id"],
                "tool": r["tool"],
                "status": r["status"],
                "device": "Not retained",
                "started_at": iso(r["started"]),
                "finished_at": iso(r["ended"]),
                "duration_ms": round(max(0, (r["ended"] - r["started"]) * 1000))
                if r["ended"] is not None
                else None,
                "history_summary": True,
                "detail": {
                    "category": "Saved summary",
                    "note": "Saved call summary. Device, command and file details are no longer available. Duration includes call tracking overhead.",
                },
            }
            for r in rows
        ]

    def finish(self, owner, conversation, task):
        row = self.get(owner, conversation, task)
        if row["running"]:
            raise ToolError(
                "task_still_running",
                "Wait for outstanding calls before finishing the task",
            )
        with self.connect() as db:
            db.execute(
                "UPDATE ui_tasks SET ended=COALESCE(ended,?) WHERE id=?",
                (self.now(), task),
            )
        return self.public(self.get(owner, conversation, task))
