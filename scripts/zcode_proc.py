from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BUNDLE_ID = "dev.zcode.app"
APP_EXE = "/Applications/ZCode.app/Contents/MacOS/ZCode"
_libproc = ctypes.CDLL("/usr/lib/libproc.dylib")


def _run(argv: list[str], timeout: float = 5.0) -> str:
    try:
        env = {**os.environ, "LC_ALL": "C"}
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
        return p.stdout if p.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def proc_path(pid: int) -> str | None:
    if pid <= 0:
        return None
    buf = ctypes.create_string_buffer(4096)
    n = _libproc.proc_pidpath(pid, buf, 4096)
    return buf.value.decode("utf-8", errors="replace") if n > 0 else None


@dataclass(frozen=True)
class AppGen:
    pid: int
    lstart: float  # epoch 秒
    checkin: float | None  # lsappinfo checkin time；尚未 checkin 为 None

    @property
    def key(self) -> str:
        return f"{self.pid}:{int(self.lstart)}"


def current_app(expected_exe: str = APP_EXE) -> AppGen | None:
    out = _run(["/usr/bin/lsappinfo", "info", "-only", "pid", BUNDLE_ID]) or _run(
        ["/usr/bin/lsappinfo", "info", "-only", "pid", "-app", f"bundleid={BUNDLE_ID}"]
    )
    m = re.search(r'"pid"=(\d+)', out)
    if not m:
        return None
    pid = int(m.group(1))
    if proc_path(pid) != expected_exe:
        return None
    ls = " ".join(_run(["/bin/ps", "-p", str(pid), "-o", "lstart="]).split())
    if not ls:
        return None
    try:
        lstart = time.mktime(time.strptime(ls, "%a %b %d %H:%M:%S %Y"))
    except ValueError:
        return None
    info_out = _run(["/usr/bin/lsappinfo", "info", BUNDLE_ID]) or _run(
        ["/usr/bin/lsappinfo", "info", "-app", f"bundleid={BUNDLE_ID}"]
    )
    ck = re.search(r"checkin time = (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", info_out)
    checkin: float | None = None
    if ck:
        try:
            checkin = time.mktime(time.strptime(ck.group(1), "%Y/%m/%d %H:%M:%S"))
        except ValueError:
            checkin = None
    return AppGen(pid=pid, lstart=lstart, checkin=checkin)


def _lc_getenv(k: str) -> str:
    return _run(["/bin/launchctl", "getenv", k]).strip()


def resolve_session_dir() -> tuple[Path | None, str | None]:
    """返回 (sessionDir, 错误码)。依据 index.js:6 与 index.js:1673 的 setPath('sessionData', Bd)。"""
    if _lc_getenv("ZCODE_DESKTOP_USE_ELECTRON_DEFAULT_USER_DATA"):
        return None, "UNSUPPORTED_PROFILE"
    sd = _lc_getenv("ZCODE_DESKTOP_SESSION_DATA_DIR")
    if sd:
        return Path(sd), None
    app_name = _lc_getenv("ZCODE_DESKTOP_APPLICATION_NAME") or "ZCode"
    ud = _lc_getenv("ZCODE_DESKTOP_USER_DATA_DIR") or str(
        Path.home() / "Library" / "Application Support" / app_name
    )
    return Path(ud) / "session", None


def resolve_devtools_port_file() -> tuple[Path | None, str | None]:
    sd, err = resolve_session_dir()
    return (sd / "DevToolsActivePort", None) if sd else (None, err)


def cdp_http_get_json(port: int, path: str, timeout: float = 3.0) -> Any:
    """GET http://127.0.0.1:<port><path> without Origin header."""
    url = f"http://127.0.0.1:{int(port)}{path}"
    req = urllib.request.Request(url, method="GET")
    if req.has_header("Origin"):
        req.remove_header("Origin")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def verify_endpoint(gen: AppGen, port_file: Path | None = None) -> dict[str, Any]:
    """CDP_OK 要求：端口文件 mtime >= lstart；该 pid 只在 127.0.0.1 监听；无 Origin 的 /json/version 返回 200。"""
    if port_file is not None:
        pf, err = port_file, None
    else:
        pf, err = resolve_devtools_port_file()
    if not pf:
        return {"ok": False, "code": err}
    try:
        st = pf.stat()
        lines = pf.read_text(encoding="utf-8", errors="replace").splitlines()
        port = int(lines[0].strip())
        browser_path = lines[1].strip() if len(lines) > 1 else ""
    except (OSError, ValueError, IndexError):
        return {"ok": False, "code": "NO_PORT_FILE", "portFile": str(pf)}
    if st.st_mtime + 1 < gen.lstart:
        return {"ok": False, "code": "STALE_PORT_FILE", "portFile": str(pf)}
    out = _run(["/usr/sbin/lsof", "-nP", "-a", "-p", str(gen.pid), f"-iTCP:{port}", "-sTCP:LISTEN"])
    addrs = re.findall(r"TCP (\S+):\d+ \(LISTEN\)", out)
    if not addrs or any(a != "127.0.0.1" for a in addrs):
        return {"ok": False, "code": "LISTEN_NOT_LOOPBACK_OR_ABSENT", "addrs": addrs, "portFile": str(pf)}
    try:
        ver = cdp_http_get_json(port, "/json/version", timeout=3.0)
    except OSError as e:
        return {"ok": False, "code": "HTTP_FAILED", "detail": str(e), "portFile": str(pf)}
    browser_id = browser_path.rsplit("/", 1)[-1] if browser_path else ""
    return {
        "ok": True,
        "port": port,
        "browserId": browser_id,
        "portFile": str(pf),
        "browser": ver.get("Browser") if isinstance(ver, dict) else None,
        "protocolVersion": ver.get("Protocol-Version") if isinstance(ver, dict) else None,
    }
