"""Non-blocking launchd kickstart helper with independent agent-kick.lock cooldown."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any

try:
    from .driver import sanitize_subprocess_env
except ImportError:  # pragma: no cover
    from driver import sanitize_subprocess_env  # type: ignore

LABEL = "com.zcode.side-sessions"
COOLDOWN_SEC = 15.0
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _is_agent_lock_held(lock_p: Path) -> bool:
    if not lock_p.is_file() or lock_p.is_symlink():
        return False
    try:
        probe_fd = os.open(str(lock_p), os.O_RDONLY | _O_NOFOLLOW)
    except OSError:
        return False
    try:
        fcntl.fcntl(probe_fd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        try:
            fcntl.flock(probe_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            return True
        try:
            fcntl.flock(probe_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        return False
    finally:
        try:
            os.close(probe_fd)
        except OSError:
            pass


def probe_and_kick_nonblocking(
    state_root: Path | str,
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Probe `<state_root>/locks/agent.lock` with shared lock and gate cooldown on `agent-kick.lock`."""
    if deadline_monotonic is not None and (time.monotonic() + 0.35) > deadline_monotonic:
        return {"status": "budget_low"}

    root = Path(state_root).expanduser().resolve()
    ctrl_p = root / "agent-control.json"
    if not ctrl_p.is_file() or ctrl_p.is_symlink():
        return {"status": "disabled"}
    try:
        ctrl = json.loads(ctrl_p.read_text(encoding="utf-8"))
    except Exception:
        return {"status": "disabled"}
    if not (
        isinstance(ctrl, dict)
        and ctrl.get("installed") is True
        and ctrl.get("autostartFromHook") is True
        and ctrl.get("mode") == "agent"
    ):
        return {"status": "disabled"}

    locks_dir = root / "locks"
    try:
        locks_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError:
        return {"status": "error"}

    agent_lock_p = locks_dir / "agent.lock"
    if _is_agent_lock_held(agent_lock_p):
        return {"status": "alive"}

    kick_lock_p = locks_dir / "agent-kick.lock"
    existed_before = kick_lock_p.exists()
    try:
        fd = os.open(str(kick_lock_p), os.O_CREAT | os.O_RDWR | _O_NOFOLLOW, 0o600)
    except OSError:
        return {"status": "error"}

    try:
        fcntl.fcntl(fd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            return {"status": "cooldown"}

        try:
            now_wall = time.time()
            st = os.fstat(fd)
            raw_ts = os.pread(fd, 64, 0).decode("utf-8", errors="ignore").strip()
            last_kick_ts = 0.0
            if raw_ts:
                try:
                    last_kick_ts = float(raw_ts.splitlines()[0].strip())
                except ValueError:
                    last_kick_ts = 0.0
            if existed_before and st.st_mtime > last_kick_ts and st.st_size > 0:
                last_kick_ts = float(st.st_mtime)

            if last_kick_ts > 0.0 and (now_wall - last_kick_ts) < COOLDOWN_SEC:
                return {"status": "cooldown"}

            ts_bytes = f"{now_wall:.6f}\n".encode("ascii")
            os.ftruncate(fd, 0)
            os.pwrite(fd, ts_bytes, 0)
            os.utime(fd, (now_wall, now_wall))
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    if not os.environ.get("ZCODE_SIDE_SESSIONS_DISABLE_LAUNCHCTL") and Path("/bin/launchctl").is_file():
        uid = os.getuid()
        try:
            subprocess.Popen(
                ["/bin/launchctl", "kickstart", f"gui/{uid}/{LABEL}"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
                env=sanitize_subprocess_env(os.environ),
            )
        except OSError:
            return {"status": "kick_failed"}
    return {"status": "kicked"}


__all__ = ["COOLDOWN_SEC", "LABEL", "probe_and_kick_nonblocking"]
