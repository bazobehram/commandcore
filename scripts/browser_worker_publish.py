#!/usr/bin/env python3
"""Publish only immutable owner bindings and routes, not the private registry."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import stat
import tempfile
import time
from contextlib import closing
from pathlib import Path

from browser_worker_lifecycle import exclusive_state
from commandcore_server.browser_worker_orchestrator import WorkerQuarantined

_WORKER = re.compile(r"w-[0-9a-f]{18}\Z")


def _read_binding(path: Path, worker: str, uid: int, gid: int | None) -> str:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != uid
        or path.resolve() != path
        or (stat.S_IMODE(info.st_mode) != (0o600 if gid is None else 0o640))
        or (gid is not None and info.st_gid != gid)
    ):
        raise WorkerQuarantined("unsafe owner binding publication source")
    with closing(
        sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)
    ) as db:
        rows = db.execute(
            "SELECT singleton, worker_id, owner_mac FROM worker_binding"
        ).fetchall()
    if (
        len(rows) != 1
        or rows[0][0] != 1
        or rows[0][1] != worker
        or not isinstance(rows[0][2], str)
        or not re.fullmatch(r"[0-9a-f]{64}", rows[0][2])
    ):
        raise WorkerQuarantined("unclaimed or invalid owner binding")
    return rows[0][2]


def _publish_binding(path: Path, worker: str, mac: str, uid: int, gid: int) -> None:
    if path.exists() or path.is_symlink():
        if _read_binding(path, worker, uid, gid) != mac:
            raise WorkerQuarantined("immutable published owner binding differs")
        return
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".binding-")
    os.close(fd)
    temporary = Path(tmp)
    try:
        with closing(sqlite3.connect(str(temporary))) as db, db:
            db.execute(
                "CREATE TABLE worker_binding (singleton INTEGER PRIMARY KEY CHECK(singleton=1), worker_id TEXT NOT NULL, owner_mac TEXT, claimed_at TEXT)"
            )
            db.execute(
                "INSERT INTO worker_binding VALUES (1, ?, ?, NULL)", (worker, mac)
            )
        os.chown(temporary, uid, gid)
        os.chmod(temporary, 0o640)
        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        # Never replace a previously published owner ledger.
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _manifest(root: Path, rows: list[dict], uid: int, gid: int) -> None:
    fd, tmp = tempfile.mkstemp(dir=root, prefix=".routes-")
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), 0o640)
            json.dump({"workers": rows}, stream, separators=(",", ":"), sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, root / "browser-workers.json")
        directory = os.open(root, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(tmp).unlink(missing_ok=True)


def publish_once(state: Path, root: Path, *, uid: int, gid: int) -> int:
    if uid <= 0 or gid <= 0 or not root.is_absolute() or root.resolve() != root:
        raise WorkerQuarantined("invalid public Browser publication configuration")
    info = root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o750
        or (info.st_uid, info.st_gid) != (uid, gid)
        or root.parent.stat().st_mode & 0o022
        or not state.is_absolute()
        or state.resolve() != state
        or state == root
        or root.is_relative_to(state)
        or state.is_relative_to(root)
    ):
        raise WorkerQuarantined("unsafe public Browser publication directory")
    try:
        with exclusive_state(state) as entries:
            rows = []
            seen = set()
            for entry in entries:
                if entry["state"] != "active":
                    continue
                worker = entry["worker_id"]
                if (
                    not _WORKER.fullmatch(worker)
                    or worker in seen
                    or not entry.get("relay")
                ):
                    raise WorkerQuarantined("invalid public relay worker")
                seen.add(worker)
                source = state / worker / "owner.sqlite3"
                if entry["route"]["binding_path"] != str(source):
                    raise WorkerQuarantined("unexpected private owner binding path")
                mac = _read_binding(source, worker, uid, None)
                target = root / (worker + ".sqlite3")
                _publish_binding(target, worker, mac, uid, gid)
                # Derive every endpoint from the immutable registry worker ID.
                rows.append(
                    {
                        "worker_id": worker,
                        "binding_path": str(target),
                        "steel_url": f"http://ccctl-{worker}:3000",
                        "cdp_url": f"ws://ccctl-{worker}:3000",
                        "egress_proxy_url": "http://browser-boundary:8080",
                        "egress_policy_url": f"http://ccctl-{worker}:8080",
                    }
                )
            _manifest(root, rows, uid, gid)
            return len(rows)
    except (
        WorkerQuarantined,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        sqlite3.Error,
    ):
        _manifest(root, [], uid, gid)
        raise WorkerQuarantined("public Browser publication withheld") from None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--publication-dir", type=Path, required=True)
    parser.add_argument("--operator-uid", type=int, required=True)
    parser.add_argument("--publication-gid", type=int, required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    try:
        while True:
            publish_once(
                args.state_dir,
                args.publication_dir,
                uid=args.operator_uid,
                gid=args.publication_gid,
            )
            if args.once:
                break
            time.sleep(2)
    except (WorkerQuarantined, OSError, ValueError):
        parser.exit(2, "Browser publication unavailable\n")


if __name__ == "__main__":
    main()
