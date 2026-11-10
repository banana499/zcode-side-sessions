from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import IO, Mapping

_FORBIDDEN_ENV_KEYS = (
    "CLAUDE_CODE_SESSION_ID",
    "CLAUDE_SESSION_ID",
    "CLAUDE_TURN_ID",
    "ZCODE_SESSION_ID",
    "MallocStackLogging",
    "MallocStackLoggingNoCompact",
    "MallocScribble",
)
_FORBIDDEN_ENV_PREFIXES = (
    "ZCODE_SESSION_",
    "ZCODE_TURN_",
    "ZCODE_TRACE_",
    "ZCODE_REQUEST_",
)
_FINGERPRINT_SUFFIXES = (".py", ".js", ".json")
_MAX_LOG_BYTES = 5 * 1024 * 1024


def _clean_env(base_env: Mapping[str, str] | None = None) -> dict[str, str]:
    src = os.environ if base_env is None else base_env
    out: dict[str, str] = {}
    for k, v in src.items():
        if k.startswith("ZCODE_SIDE_SESSIONS_"):
            out[k] = v
            continue
        if k in _FORBIDDEN_ENV_KEYS or k.startswith(_FORBIDDEN_ENV_PREFIXES):
            continue
        out[k] = v
    return out


def _compute_release_fingerprint(release_dir: Path) -> str:
    h = hashlib.sha256()
    for sub in ("scripts", "ui"):
        sub_dir = release_dir / sub
        if not sub_dir.is_dir():
            continue
        try:
            entries = sorted(sub_dir.rglob("*"))
        except OSError:
            continue
        for fp in entries:
            if "__pycache__" in fp.parts or fp.suffix not in _FINGERPRINT_SUFFIXES:
                continue
            try:
                st = fp.stat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            rel_p = fp.relative_to(release_dir).as_posix()
            mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))
            h.update(f"{rel_p}:{st.st_size}:{mtime_ns}\n".encode("utf-8"))
    return h.hexdigest()


def _release_sort_key(d: Path) -> tuple[float, int, str]:
    created_at = 0.0
    manifest_p = d / "release-manifest.json"
    if manifest_p.is_file():
        try:
            raw = json.loads(manifest_p.read_text(encoding="utf-8")).get("createdAt")
            if isinstance(raw, (int, float)):
                created_at = float(raw)
        except Exception:
            pass
    try:
        st = d.stat()
        mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))
    except OSError:
        mtime_ns = 0
    return (created_at, mtime_ns, d.name)


def _resolve_release_dir(root: Path) -> Path:
    cur_file = root / "sidebar-ui" / "current.json"
    if cur_file.is_file():
        try:
            cur = json.loads(cur_file.read_text(encoding="utf-8"))
            rel = Path(cur["releaseDir"])
            if rel.is_dir() and (rel / "scripts").is_dir():
                return rel
        except Exception:
            pass
    releases_dir = root / "sidebar-ui" / "releases"
    if releases_dir.is_dir():
        try:
            candidates = [
                d
                for d in releases_dir.iterdir()
                if d.is_dir() and not d.name.startswith(".") and (d / "scripts").is_dir()
            ]
            if candidates:
                return max(candidates, key=_release_sort_key)
        except OSError:
            pass
    return Path(__file__).resolve().parent.parent


def _select_python3(env: Mapping[str, str] | None = None) -> str:
    if sys.executable and sys.version_info >= (3, 11) and Path(sys.executable).is_file():
        return str(Path(sys.executable).absolute())
    env_map = os.environ if env is None else env
    path_val = env_map.get("PATH")
    candidates: list[str] = []
    for env_key in ("ZCODE_SIDE_SESSIONS_PYTHON", "ZCODE_SIDE_SESSIONS_PYTHON3"):
        explicit = (env_map.get(env_key) or "").strip()
        if explicit:
            candidates.append(explicit)
    for bin_name in ("python3.14", "python3.13", "python3.12", "python3.11", "python3"):
        found = shutil.which(bin_name, path=path_val)
        if found:
            candidates.append(found)
    candidates.extend(("/opt/homebrew/bin/python3", "/usr/local/bin/python3"))
    seen: set[str] = set()
    for cand in candidates:
        if not cand or cand in seen:
            continue
        seen.add(cand)
        p = Path(cand).expanduser()
        if not p.is_file():
            continue
        try:
            out = subprocess.run(
                [str(p), "-I", "-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"],
                capture_output=True,
                timeout=5,
            )
            if out.returncode == 0:
                return str(p.absolute())
        except Exception:
            continue
    return sys.executable


def _resolve_node_dir(env: Mapping[str, str] | None = None) -> str:
    env_map = os.environ if env is None else env
    explicit = (env_map.get("ZCODE_SIDE_SESSIONS_NODE_DIR") or "").strip()
    if explicit:
        return explicit
    which_node = shutil.which("node", path=env_map.get("PATH"))
    if which_node:
        return str(Path(which_node).parent)
    for fallback in ("/opt/homebrew/opt/node@22/bin", "/opt/homebrew/bin", "/usr/local/bin"):
        if (Path(fallback) / "node").is_file():
            return fallback
    for fallback in ("/opt/homebrew/opt/node@22/bin", "/opt/homebrew/bin", "/usr/local/bin"):
        if Path(fallback).is_dir():
            return fallback
    return "/usr/local/bin"


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--state-home" in args:
        idx = args.index("--state-home")
        root = Path(args[idx + 1]).expanduser().resolve()
    else:
        env_home = os.environ.get("ZCODE_SIDE_SESSIONS_HOME")
        root = Path(env_home).expanduser().resolve() if env_home else (Path.home() / ".zcode" / "side-sessions")

    for k in ("MallocStackLogging", "MallocStackLoggingNoCompact", "MallocScribble"):
        os.environ.pop(k, None)

    lock_p = root / "locks" / "agent.lock"
    lock_p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_fd = os.open(str(lock_p), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    fcntl.fcntl(lock_fd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    acquired = False
    for attempt in range(4):
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
            break
        except BlockingIOError:
            if attempt < 3:
                time.sleep(0.08)
        except OSError:
            break
    if not acquired:
        os.close(lock_fd)
        sleep_sec = float(
            os.environ.get(
                "ZCODE_SIDE_SESSIONS_LOCK_BUSY_SLEEP_SEC",
                "30" if os.environ.get("XPC_SERVICE_NAME") else "0",
            )
        )
        if sleep_sec > 0:
            time.sleep(sleep_sec)
        return 0

    proc_started_at = time.time()
    generation = 1
    rel = _resolve_release_dir(root)
    cur_fp = _compute_release_fingerprint(rel)
    py = _select_python3()
    cfg_p = root / "sidebar-ui" / "config.json"

    def build_specs(release_dir: Path) -> dict[str, list[str]]:
        return {
            "worker": [py, "-B", str(release_dir / "scripts" / "worker_runner.py"), "serve", "--state-home", str(root)],
            "sidebar": [
                py,
                "-B",
                str(release_dir / "scripts" / "zcode_sidebar_injector.py"),
                "serve",
                "--state-home",
                str(root),
                "--release",
                str(release_dir),
            ],
        }

    specs = build_specs(rel)
    procs: dict[str, subprocess.Popen[bytes]] = {}
    proc_releases: dict[str, str] = {}
    log_handles: dict[str, IO[bytes]] = {}
    backoff = {k: 5.0 for k in specs}
    next_at = {k: 0.0 for k in specs}
    reloading: set[str] = set()
    stopping = False

    def _write_agent_state() -> None:
        rt_dir = root / "sidebar-ui" / "runtime"
        try:
            rt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            st_p = rt_dir / "agent_state.json"
            tmp_p = rt_dir / f".agent_state.json.{os.getpid()}.tmp"
            w_proc = procs.get("worker")
            s_proc = procs.get("sidebar")
            obj = {
                "pid": os.getpid(),
                "processStartedAt": proc_started_at,
                "generation": generation,
                "releaseDir": str(rel),
                "releaseFingerprint": cur_fp,
                "workerReleaseDir": proc_releases.get("worker"),
                "sidebarReleaseDir": proc_releases.get("sidebar"),
                "workerPid": w_proc.pid if (w_proc is not None and w_proc.poll() is None) else None,
                "sidebarPid": s_proc.pid if (s_proc is not None and s_proc.poll() is None) else None,
                "updatedAt": time.time(),
            }
            tmp_p.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp_p, st_p)
        except OSError:
            pass

    def on_term(*_: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    logs = root / "logs"
    logs.mkdir(mode=0o700, parents=True, exist_ok=True)

    child_env = _clean_env(os.environ)
    node_dir = _resolve_node_dir(child_env)
    cur_path = child_env.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    if node_dir and node_dir not in cur_path.split(os.pathsep):
        child_env["PATH"] = f"{node_dir}{os.pathsep}{cur_path}"
    child_env.setdefault("ZCODE_SIDE_SESSIONS_HOME", str(root))
    child_env.setdefault("PYTHONUNBUFFERED", "1")
    child_env.setdefault("PYTHONDONTWRITEBYTECODE", "1")

    while not stopping:
        new_rel = _resolve_release_dir(root)
        new_fp = _compute_release_fingerprint(new_rel)
        if new_rel != rel or new_fp != cur_fp:
            rel = new_rel
            cur_fp = new_fp
            generation += 1
            specs = build_specs(rel)
            for name, p in list(procs.items()):
                reloading.add(name)
                try:
                    p.terminate()
                except OSError:
                    pass
                try:
                    p.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    try:
                        p.kill()
                        p.wait(timeout=2.0)
                    except OSError:
                        pass
                procs.pop(name, None)
                proc_releases.pop(name, None)
                fh = log_handles.pop(name, None)
                if fh:
                    try:
                        fh.close()
                    except OSError:
                        pass
                next_at[name] = 0.0
                backoff[name] = 1.0

        cfg = {}
        if cfg_p.exists():
            try:
                cfg = json.loads(cfg_p.read_text(encoding="utf-8"))
            except Exception:
                cfg = {}
        enabled = {
            "worker": True,
            "sidebar": bool(cfg.get("sidebar", {}).get("enabled", True)),
        }

        for name, cmd_argv in specs.items():
            p = procs.get(name)
            if p and p.poll() is not None:
                rc = p.returncode
                procs.pop(name, None)
                proc_releases.pop(name, None)
                fh = log_handles.pop(name, None)
                if fh:
                    try:
                        fh.close()
                    except OSError:
                        pass
                if name in reloading:
                    reloading.discard(name)
                    backoff[name] = 1.0
                    next_at[name] = 0.0
                else:
                    backoff[name] = 5.0 if rc == 0 else min(backoff[name] * 2, 60.0)
                    next_at[name] = time.time() + backoff[name]

            if name not in procs and enabled[name] and time.time() >= next_at[name]:
                log_path = logs / f"agent-{name}.log"
                try:
                    if log_path.is_file() and log_path.stat().st_size > _MAX_LOG_BYTES:
                        os.replace(log_path, logs / f"agent-{name}.log.1")
                except OSError:
                    pass
                log = open(log_path, "ab", buffering=0)
                log_handles[name] = log
                procs[name] = subprocess.Popen(
                    cmd_argv,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=log,
                    close_fds=True,
                    cwd=str(root),
                    env=child_env,
                )
                proc_releases[name] = str(rel)
                reloading.discard(name)

            if name in procs and not enabled[name]:
                procs[name].terminate()

        _write_agent_state()
        time.sleep(1.0)

    for p in procs.values():
        try:
            p.terminate()
        except OSError:
            pass
    for p in procs.values():
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            try:
                p.kill()
            except OSError:
                pass
    for fh in log_handles.values():
        try:
            fh.close()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
