from __future__ import annotations
import asyncio, base64, os, platform, shutil, tempfile
from pathlib import Path
from typing import Any


class DesktopUnavailable(RuntimeError):
    pass


def desktop_capabilities() -> dict[str, bool]:
    if os.getenv("COMMANDCORE_DESKTOP_ENABLED", "false").lower() not in {
        "true",
        "1",
        "yes",
    }:
        return {
            name: False
            for name in ("desktop", "screen", "keyboard", "mouse", "clipboard")
        }
    sys = platform.system().lower()
    if sys == "windows":
        import ctypes

        session = ctypes.c_ulong()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        user = ctypes.WinDLL("user32", use_last_error=True)
        user.OpenInputDesktop.restype = ctypes.c_void_p
        user.CloseDesktop.argtypes = [ctypes.c_void_p]
        interactive = (
            bool(kernel.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)))
            and session.value != 0
        )
        desktop = user.OpenInputDesktop(0, False, 0x0100) if interactive else None
        if desktop:
            user.CloseDesktop(desktop)
        available = interactive and bool(desktop)
        return {
            name: available
            for name in ("desktop", "screen", "keyboard", "mouse", "clipboard")
        }
    session = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    xdotool = bool(shutil.which("xdotool"))
    screenshot = bool(
        shutil.which("grim")
        or shutil.which("gnome-screenshot")
        or shutil.which("import")
    )
    clipboard = bool(shutil.which("wl-copy") or shutil.which("xclip"))
    windows = bool(shutil.which("wmctrl") or xdotool)
    return {
        "desktop": session and windows,
        "screen": session and screenshot,
        "keyboard": session and xdotool,
        "mouse": session and xdotool,
        "clipboard": session and clipboard,
    }


async def _run(
    argv: list[str], input_text: str | None = None, timeout: float = 20
) -> tuple[int, bytes, bytes]:
    p = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if input_text is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await asyncio.wait_for(
        p.communicate(input_text.encode() if input_text is not None else None), timeout
    )
    return p.returncode, out, err


def _ps(script: str) -> list[str]:
    return [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]


async def windows_list() -> dict[str, Any]:
    if platform.system() == "Windows":
        rc, out, err = await _run(
            _ps(
                "Get-Process | Where-Object {$_.MainWindowTitle} | Select-Object Id,ProcessName,MainWindowTitle | ConvertTo-Json -Compress"
            )
        )
        if rc:
            raise DesktopUnavailable(err.decode(errors="replace"))
        import json

        raw = out.decode(errors="replace").strip()
        data = json.loads(raw) if raw else []
        return {"windows": data if isinstance(data, list) else [data]}
    if shutil.which("wmctrl"):
        rc, out, err = await _run(["wmctrl", "-lp"])
        if rc:
            raise DesktopUnavailable(err.decode(errors="replace"))
        rows = []
        for line in out.decode(errors="replace").splitlines():
            p = line.split(None, 4)
            if len(p) >= 5:
                rows.append(
                    {
                        "window_id": p[0],
                        "desktop": p[1],
                        "pid": int(p[2]) if p[2].isdigit() else None,
                        "host": p[3],
                        "title": p[4],
                    }
                )
        return {"windows": rows}
    raise DesktopUnavailable("window_enumeration_backend_unavailable")


async def screenshot() -> dict[str, Any]:
    suffix = ".png"
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    Path(path).unlink(missing_ok=True)
    try:
        if platform.system() == "Windows":
            esc = path.replace("'", "''")
            script = (
                "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; "
                "$b=[System.Windows.Forms.SystemInformation]::VirtualScreen; $i=New-Object System.Drawing.Bitmap $b.Width,$b.Height; "
                "$g=[System.Drawing.Graphics]::FromImage($i); $g.CopyFromScreen($b.Left,$b.Top,0,0,$i.Size); "
                f"$i.Save('{esc}',[System.Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $i.Dispose()"
            )
            rc, _, err = await _run(_ps(script))
        elif shutil.which("grim"):
            rc, _, err = await _run(["grim", path])
        elif shutil.which("gnome-screenshot"):
            rc, _, err = await _run(["gnome-screenshot", "-f", path])
        elif shutil.which("import"):
            rc, _, err = await _run(["import", "-window", "root", path])
        else:
            raise DesktopUnavailable("screenshot_backend_unavailable")
        if rc:
            raise DesktopUnavailable(err.decode(errors="replace"))
        data = Path(path).read_bytes()
        return {
            "mime_type": "image/png",
            "data_base64": base64.b64encode(data).decode(),
            "bytes": len(data),
        }
    finally:
        Path(path).unlink(missing_ok=True)


async def mouse_click(
    x: int, y: int, button: str = "left", double: bool = False
) -> dict[str, Any]:
    if platform.system() == "Windows":
        buttons = {
            "left": ("0x0002", "0x0004"),
            "right": ("0x0008", "0x0010"),
            "middle": ("0x0020", "0x0040"),
        }
        down, up = buttons.get(button, buttons["left"])
        count = 2 if double else 1
        script = (
            'Add-Type -TypeDefinition \'using System; using System.Runtime.InteropServices; public class CCU { [DllImport("user32.dll")] public static extern bool SetCursorPos(int X,int Y); [DllImport("user32.dll")] public static extern void mouse_event(uint f,uint dx,uint dy,uint d,UIntPtr e); }\'; '
            f"[CCU]::SetCursorPos({x},{y})|Out-Null; 1..{count}|%{{[CCU]::mouse_event({down},0,0,0,[UIntPtr]::Zero);[CCU]::mouse_event({up},0,0,0,[UIntPtr]::Zero)}}"
        )
        rc, _, err = await _run(_ps(script))
    elif shutil.which("xdotool"):
        b = {"left": "1", "middle": "2", "right": "3"}.get(button, "1")
        argv = ["xdotool", "mousemove", "--sync", str(x), str(y), "click"]
        if double:
            argv += ["--repeat", "2", "--delay", "80"]
        argv += [b]
        rc, _, err = await _run(argv)
    else:
        raise DesktopUnavailable("mouse_backend_unavailable")
    if rc:
        raise DesktopUnavailable(err.decode(errors="replace"))
    return {"x": x, "y": y, "button": button, "double": double}


async def type_text(text: str) -> dict[str, Any]:
    if platform.system() == "Windows":
        import base64 as b64

        # SendKeys metacharacters must not turn literal text into shortcuts.
        literal = "".join(
            "{" + char + "}" if char in "+^%~(){}[]" else char for char in text
        )
        enc = b64.b64encode(literal.encode("utf-16le")).decode()
        script = f"Add-Type -AssemblyName System.Windows.Forms; $s=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{enc}')); [System.Windows.Forms.SendKeys]::SendWait($s)"
        rc, _, err = await _run(_ps(script))
    elif shutil.which("xdotool"):
        rc, _, err = await _run(
            ["xdotool", "type", "--clearmodifiers", "--delay", "1", "--", text]
        )
    else:
        raise DesktopUnavailable("keyboard_backend_unavailable")
    if rc:
        raise DesktopUnavailable(err.decode(errors="replace"))
    return {"characters": len(text)}


async def keypress(keys: list[str]) -> dict[str, Any]:
    if not keys:
        raise ValueError("keys_required")
    if platform.system() == "Windows":
        # SendKeys supports common chords such as ^c, %f4; explicit key names are joined conservatively.
        mapping = {
            "CTRL": "^",
            "ALT": "%",
            "SHIFT": "+",
            "ENTER": "{ENTER}",
            "TAB": "{TAB}",
            "ESC": "{ESC}",
            "DELETE": "{DELETE}",
            "BACKSPACE": "{BACKSPACE}",
        }
        seq = "".join(
            mapping.get(k.upper(), k if len(k) == 1 else "{" + k.upper() + "}")
            for k in keys
        )
        escaped_sequence = seq.replace("'", "''")
        rc, _, err = await _run(
            _ps(
                f"Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('{escaped_sequence}')"
            )
        )
    elif shutil.which("xdotool"):
        rc, _, err = await _run(["xdotool", "key", "--clearmodifiers", "+".join(keys)])
    else:
        raise DesktopUnavailable("keyboard_backend_unavailable")
    if rc:
        raise DesktopUnavailable(err.decode(errors="replace"))
    return {"keys": keys}


async def clipboard_read() -> dict[str, Any]:
    if platform.system() == "Windows":
        rc, out, err = await _run(_ps("Get-Clipboard -Raw"))
    elif shutil.which("wl-paste"):
        rc, out, err = await _run(["wl-paste", "--no-newline"])
    elif shutil.which("xclip"):
        rc, out, err = await _run(["xclip", "-selection", "clipboard", "-o"])
    else:
        raise DesktopUnavailable("clipboard_backend_unavailable")
    if rc:
        raise DesktopUnavailable(err.decode(errors="replace"))
    return {"text": out.decode(errors="replace")}


async def clipboard_write(text: str) -> dict[str, Any]:
    if platform.system() == "Windows":
        import base64 as b64

        enc = b64.b64encode(text.encode("utf-16le")).decode()
        rc, _, err = await _run(
            _ps(
                f"$s=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{enc}')); Set-Clipboard -Value $s"
            )
        )
    elif shutil.which("wl-copy"):
        rc, _, err = await _run(["wl-copy"], text)
    elif shutil.which("xclip"):
        rc, _, err = await _run(["xclip", "-selection", "clipboard"], text)
    else:
        raise DesktopUnavailable("clipboard_backend_unavailable")
    if rc:
        raise DesktopUnavailable(err.decode(errors="replace"))
    return {"characters": len(text)}
