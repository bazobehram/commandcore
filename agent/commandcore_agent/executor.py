from __future__ import annotations

import asyncio
import base64
import json
import os
import platform
import re
import shutil
import signal
import socket
import stat as statmod
import tempfile
import time
import uuid
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

import psutil

from .permissions import is_allowed
from . import desktop_backend
from .helper_client import HelperClient
from .local_policy import PROFILE_RANK, load_local_policy, normalize_profile
from . import __version__
from .runtime_health import default_health_path
from .state import default_state_path
from .update_lifecycle import (
    activate_staged,
    fetch_manifest,
    rollback_last_update,
    rollout_status,
    select_artifact,
    stage_artifact,
    verify_manifest,
)

OutputFn = Callable[[str, str], Awaitable[None]]


@dataclass
class ManagedProcess:
    process_id: str
    process: asyncio.subprocess.Process
    command: str
    started_at: float
    cwd: str | None
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    max_capture: int = 4 * 1024 * 1024

    def append(self, stream: str, data: bytes) -> None:
        target = self.stderr if stream == "stderr" else self.stdout
        remaining = self.max_capture - len(target)
        if remaining > 0:
            target.extend(data[:remaining])


class Executor:
    def __init__(
        self,
        max_transfer_bytes: int = 10 * 1024 * 1024,
        helper_client: HelperClient | None = None,
        delegate_full_control: bool = True,
        enforce_local_ceiling: bool = True,
    ):
        self.managed: dict[str, ManagedProcess] = {}
        self.running_jobs: dict[str, asyncio.subprocess.Process] = {}
        self.max_transfer_bytes = max_transfer_bytes
        self.helper_client = helper_client or HelperClient()
        self.delegate_full_control = delegate_full_control
        self.enforce_local_ceiling = enforce_local_ceiling

    async def _terminate_tree(
        self, proc: asyncio.subprocess.Process, force: bool = False
    ) -> None:
        if proc.returncode is not None:
            return
        if os.name != "nt":
            try:
                os.killpg(proc.pid, signal.SIGKILL if force else signal.SIGTERM)
            except ProcessLookupError:
                pass
        else:
            try:
                parent = psutil.Process(proc.pid)
                children = parent.children(recursive=True)
                for child in children:
                    child.kill() if force else child.terminate()
                parent.kill() if force else parent.terminate()
            except psutil.Error:
                proc.kill() if force else proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=3)
        except asyncio.TimeoutError:
            if not force:
                await self._terminate_tree(proc, force=True)

    async def cancel(self, execution_id: str) -> None:
        if self.delegate_full_control:
            try:
                await self.helper_client.cancel(execution_id)
            except Exception:
                pass
        proc = self.running_jobs.get(execution_id)
        if proc and proc.returncode is None:
            await self._terminate_tree(proc, force=False)

    async def cancel_all(self) -> None:
        """End commands and managed processes when authorization ends."""
        jobs = list(self.running_jobs)
        processes = [m.process for m in self.managed.values()]
        await asyncio.gather(
            *(self.cancel(execution_id) for execution_id in jobs),
            *(self._terminate_tree(proc) for proc in processes),
            return_exceptions=True,
        )

    async def cancel_requests(self) -> None:
        """Cancel foreground requests while preserving explicitly started jobs."""
        await asyncio.gather(
            *(self.cancel(eid) for eid in list(self.running_jobs)),
            return_exceptions=True,
        )

    async def execute(
        self,
        execution_id: str,
        profile: str,
        tool: str,
        args: dict[str, Any],
        output: OutputFn,
    ) -> dict[str, Any]:
        profile = normalize_profile(profile, "READ_ONLY")
        if self.enforce_local_ceiling:
            configured_max = normalize_profile(
                str(
                    load_local_policy().get(
                        "configured_max_permission_profile", "STANDARD"
                    )
                ),
                "STANDARD",
            )
            if PROFILE_RANK[profile] > PROFILE_RANK[configured_max]:
                return {
                    "status": "error",
                    "error": f"local_permission_ceiling:{configured_max}",
                }
        if not is_allowed(profile, tool):
            return {
                "status": "error",
                "error": f"permission_denied: {tool} under {profile}",
            }
        session_tools = {
            "desktop.windows",
            "screen.capture",
            "mouse.click",
            "keyboard.type",
            "keyboard.keypress",
            "clipboard.read",
            "clipboard.write",
        }
        if (
            profile == "FULL_CONTROL"
            and self.delegate_full_control
            and tool not in session_tools
        ):
            probe = await self.helper_client.probe()
            if (
                not probe.get("available")
                or probe.get("max_permission_profile") != "FULL_CONTROL"
            ):
                return {
                    "status": "error",
                    "error": "privileged_helper_unavailable_or_not_authorized",
                }
            return await self.helper_client.execute(execution_id, tool, args, output)
        handler = getattr(self, "_" + tool.replace(".", "_"), None)
        if handler is None:
            return {"status": "error", "error": f"unsupported_tool: {tool}"}
        try:
            result = await handler(execution_id, args, output)
            if (
                isinstance(result, dict)
                and "status" in result
                and result["status"] in {"error", "timeout"}
            ):
                return result
            return {
                "status": "ok",
                "result": result if isinstance(result, dict) else {"value": result},
            }
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}

    async def _run_argv(
        self,
        execution_id: str,
        argv: list[str],
        output: OutputFn,
        timeout: float = 3600.0,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=(os.name != "nt"),
        )
        self.running_jobs[execution_id] = proc

        async def pump(stream: asyncio.StreamReader | None, name: str) -> None:
            if not stream:
                return
            while True:
                chunk = await stream.read(8192)
                if not chunk:
                    break
                await output(name, chunk.decode("utf-8", errors="replace"))

        p1 = asyncio.create_task(pump(proc.stdout, "stdout"))
        p2 = asyncio.create_task(pump(proc.stderr, "stderr"))
        try:
            try:
                await asyncio.wait_for(proc.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                await self._terminate_tree(proc, force=False)
                await asyncio.gather(p1, p2, return_exceptions=True)
                return {
                    "status": "timeout",
                    "exit_code": proc.returncode,
                    "error": "command timeout",
                }
            except asyncio.CancelledError:
                await self._terminate_tree(proc, force=False)
                await asyncio.gather(p1, p2, return_exceptions=True)
                raise
            await asyncio.gather(p1, p2)
            return {"exit_code": proc.returncode, "pid": proc.pid, "argv": argv}
        finally:
            self.running_jobs.pop(execution_id, None)

    def _update_config(self) -> tuple[str, Path, Path, Path, str]:
        policy = load_local_policy()
        public_key = str(
            policy.get("update_public_key_b64")
            or os.getenv("COMMANDCORE_UPDATE_PUBLIC_KEY_B64", "")
        ).strip()
        if not public_key:
            raise RuntimeError("trusted_update_public_key_not_configured")
        install_root = Path(
            os.getenv("COMMANDCORE_AGENT_INSTALL_ROOT", "/opt/commandcore-agent")
        ).resolve()
        stage_root = Path(
            os.getenv("COMMANDCORE_UPDATE_STAGE_DIR", "/var/lib/commandcore/updates")
        ).resolve()
        health_file = Path(
            os.getenv(
                "COMMANDCORE_AGENT_HEALTH_FILE",
                str(default_health_path(default_state_path())),
            )
        ).resolve()
        service_name = (
            os.getenv("COMMANDCORE_AGENT_SERVICE", "commandcore-agent").strip()
            or "commandcore-agent"
        )
        return public_key, install_root, stage_root, health_file, service_name

    async def _agent_update_status(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        policy = load_local_policy()
        install_root = Path(
            os.getenv("COMMANDCORE_AGENT_INSTALL_ROOT", "/opt/commandcore-agent")
        ).resolve()
        result = rollout_status(install_root)
        return {
            "current_version": __version__,
            "implementation": "python",
            "rollout": result,
            "trusted_release_key_configured": bool(
                str(
                    policy.get("update_public_key_b64")
                    or os.getenv("COMMANDCORE_UPDATE_PUBLIC_KEY_B64", "")
                ).strip()
            ),
        }

    async def _agent_update_stage(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        public_key, _install_root, stage_root, _health_file, _service_name = (
            self._update_config()
        )
        manifest_url = str(args.get("manifest_url", "")).strip()
        if not manifest_url:
            raise ValueError("manifest_url_required")
        parsed = urlsplit(manifest_url)
        origin = (
            f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
            if parsed.scheme and parsed.netloc
            else ""
        )
        policy = load_local_policy()
        allowed_origins = {
            str(x).rstrip("/").lower()
            for x in policy.get("update_manifest_origins", [])
        }
        env_origin = (
            os.getenv("COMMANDCORE_UPDATE_MANIFEST_ORIGIN", "")
            .strip()
            .rstrip("/")
            .lower()
        )
        if env_origin:
            allowed_origins.add(env_origin)
        if not allowed_origins:
            raise RuntimeError("trusted_update_manifest_origin_not_configured")
        if parsed.scheme.lower() != "https" or origin.lower() not in allowed_origins:
            raise PermissionError("update_manifest_origin_not_allowed")
        manifest = await asyncio.to_thread(
            fetch_manifest, manifest_url, allow_insecure_http=False
        )
        await asyncio.to_thread(verify_manifest, manifest, public_key)
        artifact = select_artifact(manifest)
        staged = await asyncio.to_thread(
            stage_artifact,
            manifest,
            artifact,
            root=stage_root,
            allow_insecure_http=False,
            current_version=__version__,
        )
        return staged

    async def _agent_update_activate(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        public_key, install_root, stage_root, health_file, service_name = (
            self._update_config()
        )
        raw = str(args.get("stage_metadata_path", "")).strip()
        if not raw:
            raise ValueError("stage_metadata_path_required")
        metadata_path = Path(raw).resolve()
        try:
            metadata_path.relative_to(stage_root)
        except ValueError as exc:
            raise ValueError("stage_metadata_path_outside_configured_root") from exc
        if metadata_path.name != "stage.json":
            raise ValueError("stage_metadata_path_must_be_stage_json")
        timeout = max(5.0, min(float(args.get("health_timeout_seconds", 60.0)), 300.0))
        result = await asyncio.to_thread(
            activate_staged,
            metadata_path,
            public_key,
            install_root=install_root,
            health_file=health_file,
            service_name=service_name,
            health_timeout=timeout,
        )
        return result

    async def _agent_update_rollback(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        _public_key, install_root, _stage_root, health_file, service_name = (
            self._update_config()
        )
        timeout = max(5.0, min(float(args.get("health_timeout_seconds", 60.0)), 300.0))
        result = await asyncio.to_thread(
            rollback_last_update,
            install_root=install_root,
            health_file=health_file,
            service_name=service_name,
            health_timeout=timeout,
        )
        return result

    async def _desktop_windows(self, execution_id, args, output):
        return await desktop_backend.windows_list()

    async def _screen_capture(self, execution_id, args, output):
        return await desktop_backend.screenshot()

    async def _mouse_click(self, execution_id, args, output):
        return await desktop_backend.mouse_click(
            int(args["x"]),
            int(args["y"]),
            str(args.get("button", "left")),
            bool(args.get("double", False)),
        )

    async def _keyboard_type(self, execution_id, args, output):
        return await desktop_backend.type_text(str(args["text"]))

    async def _keyboard_keypress(self, execution_id, args, output):
        return await desktop_backend.keypress([str(x) for x in args["keys"]])

    async def _clipboard_read(self, execution_id, args, output):
        return await desktop_backend.clipboard_read()

    async def _clipboard_write(self, execution_id, args, output):
        return await desktop_backend.clipboard_write(str(args["text"]))

    async def _shell_exec(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        command = str(args["command"])
        cwd = args.get("cwd") or None
        env = os.environ.copy()
        if isinstance(args.get("env"), dict):
            env.update({str(k): str(v) for k, v in args["env"].items()})
        timeout = max(0.1, min(float(args.get("timeout_ms", 30000)) / 1000.0, 3600.0))
        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=(os.name != "nt"),
        )
        self.running_jobs[execution_id] = proc

        async def pump(stream: asyncio.StreamReader | None, name: str) -> None:
            if not stream:
                return
            while True:
                chunk = await stream.read(8192)
                if not chunk:
                    break
                await output(name, chunk.decode("utf-8", errors="replace"))

        p1 = asyncio.create_task(pump(proc.stdout, "stdout"))
        p2 = asyncio.create_task(pump(proc.stderr, "stderr"))
        try:
            try:
                await asyncio.wait_for(proc.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                await self._terminate_tree(proc, force=False)
                await asyncio.gather(p1, p2, return_exceptions=True)
                return {
                    "status": "timeout",
                    "exit_code": proc.returncode,
                    "error": "command timeout",
                }
            except asyncio.CancelledError:
                await self._terminate_tree(proc, force=False)
                await asyncio.gather(p1, p2, return_exceptions=True)
                raise
            await asyncio.gather(p1, p2)
            return {"exit_code": proc.returncode, "pid": proc.pid}
        finally:
            self.running_jobs.pop(execution_id, None)

    async def _process_start(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        command = str(args["command"])
        cwd = args.get("cwd") or None
        env = os.environ.copy()
        if isinstance(args.get("env"), dict):
            env.update({str(k): str(v) for k, v in args["env"].items()})
        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=(os.name != "nt"),
        )
        process_id = str(uuid.uuid4())
        managed = ManagedProcess(process_id, proc, command, time.time(), cwd)
        self.managed[process_id] = managed

        async def pump(stream: asyncio.StreamReader | None, name: str) -> None:
            if not stream:
                return
            while True:
                chunk = await stream.read(8192)
                if not chunk:
                    break
                managed.append(name, chunk)

        asyncio.create_task(pump(proc.stdout, "stdout"))
        asyncio.create_task(pump(proc.stderr, "stderr"))
        return {
            "process_id": process_id,
            "pid": proc.pid,
            "command": command,
            "started_at": managed.started_at,
        }

    async def _process_list(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        limit = max(1, min(int(args.get("limit", 500)), 2000))
        needle = str(args.get("filter", "")).lower()
        rows: list[dict[str, Any]] = []
        for p in psutil.process_iter(
            [
                "pid",
                "ppid",
                "name",
                "username",
                "status",
                "cmdline",
                "create_time",
                "cpu_percent",
                "memory_info",
            ]
        ):
            try:
                i = p.info
                cmdline = " ".join(i.get("cmdline") or [])
                hay = f"{i.get('name', '')} {cmdline}".lower()
                if needle and needle not in hay:
                    continue
                mem = i.get("memory_info")
                rows.append(
                    {
                        "pid": i.get("pid"),
                        "ppid": i.get("ppid"),
                        "name": i.get("name"),
                        "username": i.get("username"),
                        "status": i.get("status"),
                        "cmdline": cmdline,
                        "create_time": i.get("create_time"),
                        "cpu_percent": i.get("cpu_percent"),
                        "rss": getattr(mem, "rss", None) if mem else None,
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if len(rows) >= limit:
                break
        return {"processes": rows}

    async def _process_status(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        process_id = args.get("process_id")
        if process_id:
            m = self.managed.get(str(process_id))
            if not m:
                return {"found": False, "process_id": process_id}
            return {
                "found": True,
                "managed": True,
                "process_id": m.process_id,
                "pid": m.process.pid,
                "running": m.process.returncode is None,
                "exit_code": m.process.returncode,
                "command": m.command,
                "started_at": m.started_at,
            }
        pid = int(args.get("pid", 0))
        if pid <= 0:
            raise ValueError("process_id or pid required")
        try:
            p = psutil.Process(pid)
            return {
                "found": True,
                "managed": False,
                "pid": pid,
                "status": p.status(),
                "name": p.name(),
                "cmdline": p.cmdline(),
                "create_time": p.create_time(),
                "username": p.username(),
            }
        except psutil.NoSuchProcess:
            return {"found": False, "pid": pid}

    async def _process_output(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        process_id = str(args["process_id"])
        m = self.managed.get(process_id)
        if not m:
            return {
                "available": False,
                "reason": "output_unavailable_for_external_or_unknown_process",
                "process_id": process_id,
            }
        offset = max(0, int(args.get("offset", 0)))
        limit = max(1, min(int(args.get("limit", 65536)), 1048576))
        out = bytes(m.stdout)[offset : offset + limit]
        err = bytes(m.stderr)[offset : offset + limit]
        return {
            "available": True,
            "process_id": process_id,
            "pid": m.process.pid,
            "stdout": out.decode("utf-8", errors="replace"),
            "stderr": err.decode("utf-8", errors="replace"),
            "next_offset": offset + max(len(out), len(err)),
            "running": m.process.returncode is None,
            "exit_code": m.process.returncode,
        }

    async def _process_stop(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        force = bool(args.get("force", False))
        process_id = args.get("process_id")
        if process_id:
            m = self.managed.get(str(process_id))
            if not m:
                return {"stopped": False, "reason": "not_found"}
            if m.process.returncode is not None:
                return {
                    "stopped": True,
                    "already_exited": True,
                    "exit_code": m.process.returncode,
                }
            await self._terminate_tree(m.process, force=force)
            return {
                "stopped": True,
                "pid": m.process.pid,
                "exit_code": m.process.returncode,
            }
        pid = int(args.get("pid", 0))
        if pid <= 0:
            raise ValueError("process_id or pid required")
        p = psutil.Process(pid)
        p.kill() if force else p.terminate()
        try:
            p.wait(timeout=5)
        except psutil.TimeoutExpired:
            p.kill()
        return {"stopped": True, "pid": pid}

    async def _fs_list(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        path = Path(str(args["path"])).expanduser()
        limit = max(1, min(int(args.get("limit", 1000)), 5000))
        entries = []
        with os.scandir(path) as it:
            for entry in it:
                try:
                    st = entry.stat(follow_symlinks=False)
                    entries.append(
                        {
                            "name": entry.name,
                            "path": entry.path,
                            "is_dir": entry.is_dir(follow_symlinks=False),
                            "is_file": entry.is_file(follow_symlinks=False),
                            "is_symlink": entry.is_symlink(),
                            "size": st.st_size,
                            "mtime": st.st_mtime,
                        }
                    )
                except OSError as exc:
                    entries.append(
                        {"name": entry.name, "path": entry.path, "error": str(exc)}
                    )
                if len(entries) >= limit:
                    break
        return {
            "path": str(path),
            "entries": entries,
            "truncated": len(entries) >= limit,
        }

    async def _fs_stat(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        p = Path(str(args["path"])).expanduser()
        st = p.lstat()
        return {
            "path": str(p),
            "exists": True,
            "size": st.st_size,
            "mode": statmod.filemode(st.st_mode),
            "mtime": st.st_mtime,
            "ctime": st.st_ctime,
            "is_file": p.is_file(),
            "is_dir": p.is_dir(),
            "is_symlink": p.is_symlink(),
        }

    async def _fs_read(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        p = Path(str(args["path"])).expanduser()
        offset = max(0, int(args.get("offset", 0)))
        length = max(1, min(int(args.get("length", 65536)), 1048576))
        with p.open("rb") as f:
            f.seek(offset)
            data = f.read(length)
        encoding = args.get("encoding", "text")
        payload = (
            base64.b64encode(data).decode()
            if encoding == "base64"
            else data.decode("utf-8", errors="replace")
        )
        return {
            "path": str(p),
            "offset": offset,
            "bytes": len(data),
            "next_offset": offset + len(data),
            "encoding": encoding,
            "data": payload,
            "eof": len(data) < length,
        }

    async def _fs_write(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        p = Path(str(args["path"])).expanduser()
        if args.get("create_parents", True):
            p.parent.mkdir(parents=True, exist_ok=True)
        data_s = str(args["data"])
        data = (
            base64.b64decode(data_s, validate=True)
            if args.get("encoding") == "base64"
            else data_s.encode("utf-8")
        )
        mode = "ab" if args.get("mode") == "append" else "wb"
        with p.open(mode) as f:
            f.write(data)
        return {
            "path": str(p),
            "bytes_written": len(data),
            "mode": args.get("mode", "rewrite"),
        }

    async def _fs_patch(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        p = Path(str(args["path"])).expanduser()
        follow_symlinks = bool(args.get("follow_symlinks", False))
        if p.is_symlink():
            if not follow_symlinks:
                raise ValueError(
                    "fs.patch refuses symlinks unless follow_symlinks=true"
                )
            p = p.resolve(strict=True)
        original = p.stat()
        if not statmod.S_ISREG(original.st_mode):
            raise ValueError("fs.patch requires a regular file")
        text = p.read_text(encoding="utf-8")
        count = 0
        for patch in args.get("patches", []):
            search = str(patch["search"])
            replace = str(patch["replace"])
            occurrences = text.count(search)
            if occurrences == 0:
                raise ValueError("patch search block not found")
            if occurrences > 1 and not patch.get("replace_all"):
                raise ValueError(
                    "patch search block is ambiguous; set replace_all=true"
                )
            if patch.get("replace_all"):
                text = text.replace(search, replace)
                count += occurrences
            else:
                text = text.replace(search, replace, 1)
                count += 1
        fd, temp_name = tempfile.mkstemp(prefix=f".{p.name}.commandcore-", dir=p.parent)
        tmp = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, statmod.S_IMODE(original.st_mode))
            if hasattr(os, "chown"):
                try:
                    os.chown(tmp, original.st_uid, original.st_gid)
                except PermissionError:
                    pass
            os.replace(tmp, p)
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
        return {"path": str(p), "replacements": count, "atomic": True}

    async def _fs_search(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        root = Path(str(args["root"])).expanduser()
        query = str(args["query"])
        content = bool(args.get("content", False))
        use_regex = bool(args.get("regex", False))
        max_results = max(1, min(int(args.get("max_results", 100)), 1000))
        matcher = re.compile(query) if use_regex else None
        results: list[dict[str, Any]] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if not Path(dirpath, d).is_symlink()]
            for name in filenames:
                p = Path(dirpath) / name
                matched_name = (
                    bool(matcher.search(name))
                    if matcher
                    else query.lower() in name.lower()
                )
                if matched_name:
                    results.append({"path": str(p), "match": "name"})
                if content and len(results) < max_results:
                    try:
                        if p.stat().st_size <= 4 * 1024 * 1024:
                            text = p.read_text(encoding="utf-8", errors="ignore")
                            found = (
                                bool(matcher.search(text))
                                if matcher
                                else query.lower() in text.lower()
                            )
                            if found:
                                results.append({"path": str(p), "match": "content"})
                    except (OSError, UnicodeError):
                        pass
                if len(results) >= max_results:
                    return {"results": results, "truncated": True}
        return {"results": results, "truncated": False}

    async def _fs_copy(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        src = Path(str(args["source"])).expanduser()
        dst = Path(str(args["destination"])).expanduser()
        overwrite = bool(args.get("overwrite", False))
        if dst.exists() and not overwrite:
            raise FileExistsError(str(dst))
        if src.is_dir():
            if dst.exists() and overwrite:
                shutil.rmtree(dst)
            shutil.copytree(src, dst, symlinks=True)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst, follow_symlinks=False)
        return {"source": str(src), "destination": str(dst)}

    async def _fs_move(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        src = Path(str(args["source"])).expanduser()
        dst = Path(str(args["destination"])).expanduser()
        if dst.exists() and not args.get("overwrite", False):
            raise FileExistsError(str(dst))
        if dst.exists() and args.get("overwrite", False):
            shutil.rmtree(dst) if dst.is_dir() else dst.unlink()
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        return {"source": str(src), "destination": str(dst)}

    async def _fs_delete(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        p = Path(str(args["path"])).expanduser()
        if p.is_dir() and not p.is_symlink():
            if not args.get("recursive", False):
                p.rmdir()
            else:
                shutil.rmtree(p)
        else:
            p.unlink()
        return {"deleted": True, "path": str(p)}

    async def _system_info(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage(Path.home().anchor or "/")
        return {
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python": platform.python_version(),
            "cpu_logical": psutil.cpu_count(),
            "cpu_physical": psutil.cpu_count(logical=False),
            "memory_total": vm.total,
            "disk_total": disk.total,
            "boot_time": psutil.boot_time(),
        }

    async def _system_metrics(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk = psutil.disk_usage(Path.home().anchor or "/")
        try:
            load = os.getloadavg()
        except (AttributeError, OSError):
            load = None
        return {
            "cpu_percent": psutil.cpu_percent(interval=0.15),
            "memory": {
                "total": vm.total,
                "available": vm.available,
                "percent": vm.percent,
            },
            "swap": {"total": swap.total, "used": swap.used, "percent": swap.percent},
            "disk": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": disk.percent,
            },
            "loadavg": load,
        }

    async def _transfer_upload(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        data = base64.b64decode(str(args["data_base64"]), validate=True)
        if len(data) > self.max_transfer_bytes:
            raise ValueError("transfer exceeds configured maximum")
        p = Path(str(args["path"])).expanduser()
        if p.exists() and not args.get("overwrite", False):
            raise FileExistsError(str(p))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return {"path": str(p), "bytes_written": len(data)}

    async def _transfer_download(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        p = Path(str(args["path"])).expanduser()
        size = p.stat().st_size
        if size > self.max_transfer_bytes:
            raise ValueError("transfer exceeds configured maximum")
        data = p.read_bytes()
        return {
            "path": str(p),
            "bytes": len(data),
            "data_base64": base64.b64encode(data).decode(),
        }

    async def _capture_argv(
        self,
        argv: list[str],
        *,
        cwd: str | None = None,
        timeout: float = 30.0,
        max_bytes: int = 1024 * 1024,
    ) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=(os.name != "nt"),
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            await self._terminate_tree(proc, force=False)
            raise TimeoutError(f"command timeout after {timeout}s")
        return (
            int(proc.returncode or 0),
            stdout_b[:max_bytes].decode("utf-8", errors="replace"),
            stderr_b[:max_bytes].decode("utf-8", errors="replace"),
        )

    @staticmethod
    def _tool_binary(name: str) -> str:
        binary = shutil.which(name)
        if not binary:
            raise RuntimeError(f"{name} is not installed")
        return binary

    async def _git_status(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        git = self._tool_binary("git")
        repo = str(Path(str(args["repo"])).expanduser())
        code, stdout, stderr = await self._capture_argv(
            [
                git,
                "-c",
                f"safe.directory={repo}",
                "-C",
                repo,
                "status",
                "--porcelain=v2",
                "--branch",
            ],
            cwd=None,
            timeout=30,
        )
        if code != 0:
            raise RuntimeError(stderr.strip() or f"git status exited {code}")
        return {
            "repo": repo,
            "porcelain_v2": stdout,
            "clean": not any(
                line and not line.startswith("#") for line in stdout.splitlines()
            ),
        }

    async def _git_diff(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        git = self._tool_binary("git")
        repo = str(Path(str(args["repo"])).expanduser())
        argv = [
            git,
            "-c",
            f"safe.directory={repo}",
            "-C",
            repo,
            "diff",
            "--no-ext-diff",
            "--no-color",
        ]
        if bool(args.get("staged", False)):
            argv.append("--cached")
        paths = args.get("paths") or []
        if paths:
            argv.append("--")
            argv.extend(str(x) for x in paths)
        max_bytes = max(1024, min(int(args.get("max_bytes", 262144)), 1048576))
        code, stdout, stderr = await self._capture_argv(
            argv, timeout=60, max_bytes=max_bytes
        )
        if code != 0:
            raise RuntimeError(stderr.strip() or f"git diff exited {code}")
        return {
            "repo": repo,
            "diff": stdout,
            "truncated": len(stdout.encode("utf-8")) >= max_bytes,
        }

    async def _git_log(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        git = self._tool_binary("git")
        repo = str(Path(str(args["repo"])).expanduser())
        limit = max(1, min(int(args.get("limit", 20)), 200))
        sep = "\x1f"
        fmt = f"%H{sep}%h{sep}%an{sep}%ae{sep}%aI{sep}%s"
        code, stdout, stderr = await self._capture_argv(
            [
                git,
                "-c",
                f"safe.directory={repo}",
                "-C",
                repo,
                "log",
                f"-{limit}",
                f"--pretty=format:{fmt}",
            ],
            timeout=30,
        )
        if code != 0:
            raise RuntimeError(stderr.strip() or f"git log exited {code}")
        commits = []
        for line in stdout.splitlines():
            parts = line.split(sep, 5)
            if len(parts) == 6:
                commits.append(
                    {
                        "sha": parts[0],
                        "short_sha": parts[1],
                        "author": parts[2],
                        "email": parts[3],
                        "date": parts[4],
                        "subject": parts[5],
                    }
                )
        return {"repo": repo, "commits": commits}

    async def _git_run(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        git = self._tool_binary("git")
        repo = str(Path(str(args["repo"])).expanduser())
        raw_args = args.get("args")
        if not isinstance(raw_args, list) or not raw_args:
            raise ValueError("args must be a non-empty array")
        clean = [str(x) for x in raw_args]
        if any("\x00" in x for x in clean):
            raise ValueError("git arguments may not contain NUL")
        timeout = max(0.1, min(float(args.get("timeout_ms", 120000)) / 1000.0, 600.0))
        result = await self._run_argv(
            execution_id,
            [git, "-c", f"safe.directory={repo}", "-C", repo, *clean],
            output,
            timeout=timeout,
        )
        result.update({"repo": repo, "git_args": clean})
        return result

    @staticmethod
    def _validate_docker_ref(value: object, field: str) -> str:
        text = str(value).strip()
        if not text or text.startswith("-") or "\x00" in text:
            raise ValueError(f"invalid {field}")
        return text

    async def _docker_ps(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        docker = self._tool_binary("docker")
        argv = [docker, "ps"]
        if bool(args.get("all", False)):
            argv.append("--all")
        argv += ["--format", "{{json .}}"]
        code, stdout, stderr = await self._capture_argv(argv, timeout=30)
        if code != 0:
            raise RuntimeError(stderr.strip() or f"docker ps exited {code}")
        rows = []
        for line in stdout.splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"raw": line})
        return {"containers": rows}

    async def _docker_inspect(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        docker = self._tool_binary("docker")
        obj = self._validate_docker_ref(args.get("object"), "object")
        code, stdout, stderr = await self._capture_argv(
            [docker, "inspect", "--", obj], timeout=30
        )
        if code != 0:
            raise RuntimeError(stderr.strip() or f"docker inspect exited {code}")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            payload = {"raw": stdout}
        return {"object": obj, "inspect": payload}

    async def _docker_logs(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        docker = self._tool_binary("docker")
        container = self._validate_docker_ref(args.get("container"), "container")
        tail = max(1, min(int(args.get("tail", 200)), 10000))
        argv = [docker, "logs", "--tail", str(tail)]
        if bool(args.get("timestamps", False)):
            argv.append("--timestamps")
        argv += ["--", container]
        code, stdout, stderr = await self._capture_argv(
            argv, timeout=30, max_bytes=1024 * 1024
        )
        # Docker writes ordinary logs to stdout/stderr depending on the container stream.
        if code != 0:
            raise RuntimeError(stderr.strip() or f"docker logs exited {code}")
        return {
            "container": container,
            "stdout": stdout,
            "stderr": stderr,
            "tail": tail,
        }

    async def _docker_exec(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        docker = self._tool_binary("docker")
        container = self._validate_docker_ref(args.get("container"), "container")
        raw = args.get("argv")
        if not isinstance(raw, list) or not raw:
            raise ValueError("argv must be a non-empty array")
        argv = [str(x) for x in raw]
        if any("\x00" in x for x in argv):
            raise ValueError("argv may not contain NUL")
        timeout = max(0.1, min(float(args.get("timeout_ms", 120000)) / 1000.0, 600.0))
        result = await self._run_argv(
            execution_id,
            [docker, "exec", "--", container, *argv],
            output,
            timeout=timeout,
        )
        result.update({"container": container, "container_argv": argv})
        return result

    async def _docker_run(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        docker = self._tool_binary("docker")
        image = self._validate_docker_ref(args.get("image"), "image")
        raw = args.get("args") or []
        if not isinstance(raw, list):
            raise ValueError("args must be an array")
        run_args = [str(x) for x in raw]
        if any("\x00" in x for x in run_args):
            raise ValueError("args may not contain NUL")
        argv = [docker, "run"]
        if bool(args.get("remove", True)):
            argv.append("--rm")
        argv += ["--", image, *run_args]
        timeout = max(0.1, min(float(args.get("timeout_ms", 3600000)) / 1000.0, 3600.0))
        result = await self._run_argv(execution_id, argv, output, timeout=timeout)
        result.update({"image": image})
        return result

    async def _services_manage(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        service = str(args.get("service", "")).strip()
        action = str(args.get("action", "status")).strip().lower()
        allowed_actions = {
            "status",
            "start",
            "stop",
            "restart",
            "reload",
            "enable",
            "disable",
        }
        if not service or "\x00" in service:
            raise ValueError("service is required")
        if service.startswith("-"):
            raise ValueError("service name may not begin with an option prefix")
        if action not in allowed_actions:
            raise ValueError(f"unsupported service action: {action}")
        if platform.system() != "Linux":
            raise RuntimeError("services.manage is currently implemented for Linux")
        systemctl = shutil.which("systemctl")
        if not systemctl:
            raise RuntimeError("systemctl not available")
        argv = [systemctl, action, service]
        timeout = max(0.1, min(float(args.get("timeout_ms", 120000)) / 1000.0, 600.0))
        result = await self._run_argv(execution_id, argv, output, timeout=timeout)
        result["service"] = service
        result["action"] = action
        return result

    async def _package_install(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        if platform.system() != "Linux":
            raise RuntimeError("package.install is currently implemented for Linux")
        packages = args.get("packages")
        if isinstance(packages, str):
            packages = [packages]
        if not isinstance(packages, list) or not packages:
            raise ValueError("packages must be a non-empty array")
        clean: list[str] = []
        for package in packages:
            value = str(package).strip()
            if not value or value.startswith("-") or "\x00" in value:
                raise ValueError(f"invalid package name: {value!r}")
            clean.append(value)
        requested = str(args.get("manager", "auto")).lower()
        update = bool(args.get("update", False))
        timeout = max(1.0, min(float(args.get("timeout_ms", 3600000)) / 1000.0, 3600.0))
        candidates = (
            [requested]
            if requested != "auto"
            else ["apt-get", "dnf", "yum", "zypper", "pacman", "apk"]
        )
        manager = next((name for name in candidates if shutil.which(name)), None)
        if not manager:
            raise RuntimeError("no supported package manager found")
        binary = shutil.which(manager) or manager
        if manager == "apt-get":
            env = os.environ.copy()
            env["DEBIAN_FRONTEND"] = "noninteractive"
            if update:
                first = await self._run_argv(
                    execution_id,
                    [binary, "update"],
                    output,
                    timeout=min(timeout, 1800.0),
                    env=env,
                )
                if first.get("exit_code") != 0:
                    return {**first, "manager": manager, "phase": "update"}
            result = await self._run_argv(
                execution_id,
                [binary, "install", "-y", *clean],
                output,
                timeout=timeout,
                env=env,
            )
        elif manager in {"dnf", "yum"}:
            result = await self._run_argv(
                execution_id, [binary, "install", "-y", *clean], output, timeout=timeout
            )
        elif manager == "zypper":
            result = await self._run_argv(
                execution_id,
                [binary, "--non-interactive", "install", *clean],
                output,
                timeout=timeout,
            )
        elif manager == "pacman":
            result = await self._run_argv(
                execution_id,
                [binary, "--noconfirm", "-S", *clean],
                output,
                timeout=timeout,
            )
        elif manager == "apk":
            result = await self._run_argv(
                execution_id, [binary, "add", *clean], output, timeout=timeout
            )
        else:
            raise RuntimeError(f"unsupported package manager: {manager}")
        result["manager"] = manager
        result["packages"] = clean
        return result

    async def _system_reboot(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        if platform.system() != "Linux":
            raise RuntimeError("system.reboot is currently implemented for Linux")
        if not bool(args.get("confirm", False)):
            raise ValueError("confirm=true is required")
        if bool(args.get("dry_run", False)):
            return {"scheduled": False, "dry_run": True, "action": "reboot"}
        systemctl = shutil.which("systemctl")
        if not systemctl:
            raise RuntimeError("systemctl not available")
        delay = max(0, min(int(args.get("delay_seconds", 0)), 3600))
        if delay:
            shutdown = shutil.which("shutdown")
            if not shutdown:
                raise RuntimeError("shutdown utility not available for delayed reboot")
            minutes = max(1, (delay + 59) // 60)
            result = await self._run_argv(
                execution_id, [shutdown, "-r", f"+{minutes}"], output, timeout=15.0
            )
            return {
                **result,
                "scheduled": result.get("exit_code") == 0,
                "delay_seconds": delay,
                "action": "reboot",
            }
        result = await self._run_argv(
            execution_id, [systemctl, "reboot"], output, timeout=15.0
        )
        return {**result, "scheduled": result.get("exit_code") == 0, "action": "reboot"}

    async def _system_shutdown(
        self, execution_id: str, args: dict[str, Any], output: OutputFn
    ) -> dict[str, Any]:
        if platform.system() != "Linux":
            raise RuntimeError("system.shutdown is currently implemented for Linux")
        if not bool(args.get("confirm", False)):
            raise ValueError("confirm=true is required")
        if bool(args.get("dry_run", False)):
            return {"scheduled": False, "dry_run": True, "action": "shutdown"}
        systemctl = shutil.which("systemctl")
        if not systemctl:
            raise RuntimeError("systemctl not available")
        delay = max(0, min(int(args.get("delay_seconds", 0)), 3600))
        if delay:
            shutdown = shutil.which("shutdown")
            if not shutdown:
                raise RuntimeError(
                    "shutdown utility not available for delayed poweroff"
                )
            minutes = max(1, (delay + 59) // 60)
            result = await self._run_argv(
                execution_id, [shutdown, "-h", f"+{minutes}"], output, timeout=15.0
            )
            return {
                **result,
                "scheduled": result.get("exit_code") == 0,
                "delay_seconds": delay,
                "action": "shutdown",
            }
        result = await self._run_argv(
            execution_id, [systemctl, "poweroff"], output, timeout=15.0
        )
        return {
            **result,
            "scheduled": result.get("exit_code") == 0,
            "action": "shutdown",
        }
