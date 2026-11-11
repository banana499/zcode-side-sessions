from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import plistlib
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import asar_cdp_patch  # noqa: E402
from cdp_ws import CdpError, CdpSocket  # noqa: E402
from desktop_bridge import ProjectionReader  # noqa: E402
from state import resolve_state_root  # noqa: E402
from zcode_proc import (  # noqa: E402
    APP_EXE,
    AppGen,
    cdp_http_get_json,
    current_app,
    resolve_devtools_port_file,
    verify_endpoint,
)
from zcode_sidebar_injector import (  # noqa: E402
    ASAR,
    atomic_write_json,
    sha256_file,
    uninject_active_targets,
)

def _resolve_default_zcode_bin() -> str:
    return shutil.which("zcode") or str(Path.home() / ".local" / "bin" / "zcode")


def _resolve_default_node_dir(env: Mapping[str, str] | None = None) -> str:
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


def _probe_python311_candidate(cand: str) -> str | None:
    if not cand:
        return None
    p = Path(cand).expanduser()
    if not p.is_file():
        return None
    if os.path.abspath(cand) == os.path.abspath(sys.executable) and sys.version_info >= (3, 11):
        return str(p.absolute())
    try:
        out = subprocess.run(
            [str(p), "-I", "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode == 0:
            maj, minor = (int(x) for x in out.stdout.strip().split(".")[:2])
            if (maj, minor) >= (3, 11):
                return str(p.absolute())
    except Exception:
        return None
    return None


def _select_python3(env: Mapping[str, str] | None = None) -> str:
    env_map = os.environ if env is None else env
    path_val = env_map.get("PATH")
    candidates: list[str] = []
    if sys.executable and sys.version_info >= (3, 11):
        candidates.append(sys.executable)
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
        matched = _probe_python311_candidate(cand)
        if matched:
            return matched
    raise RuntimeError("Python >= 3.11 interpreter is required for com.zcode.side-sessions")


def _resolve_default_python3() -> str:
    try:
        return _select_python3()
    except RuntimeError:
        return sys.executable or "python3"


LABEL = "com.zcode.side-sessions"
APP_PATH = Path("/Applications/ZCode.app")
INFO_PLIST = APP_PATH / "Contents/Info.plist"
DEFAULT_PYTHON3 = _resolve_default_python3()
DEFAULT_ZCODE_BIN = _resolve_default_zcode_bin()
DEFAULT_NODE_DIR = _resolve_default_node_dir()


def _load_compat_builds(
    state_root: Path | None = None,
    release_dir: Path | None = None,
) -> dict[str, Any]:
    candidates: list[Path] = []
    if release_dir is not None:
        candidates.append(release_dir / "ui" / "compatibility.json")
    if state_root is not None:
        cur_file = state_root / "sidebar-ui" / "current.json"
        if cur_file.is_file():
            try:
                rel_p = Path(json.loads(cur_file.read_text(encoding="utf-8"))["releaseDir"])
                candidates.append(rel_p / "ui" / "compatibility.json")
            except Exception:
                pass
    candidates.append(HERE.parent / "ui" / "compatibility.json")
    for p in candidates:
        if p.is_file():
            try:
                builds = json.loads(p.read_text(encoding="utf-8")).get("builds", {})
                if isinstance(builds, dict):
                    return builds
            except Exception:
                continue
    return {}


def _pid_alive(pid: Any) -> bool:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _is_agent_lock_held(root: Path) -> bool:
    lock_p = root / "locks" / "agent.lock"
    if not lock_p.is_file() or lock_p.is_symlink():
        return False
    try:
        fd = os.open(str(lock_p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except BlockingIOError:
        return True
    except OSError:
        return False
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

PLUGIN_BUSY_SQL = """
SELECT node_id FROM turns WHERE execution_state IN ('queued','starting','running','waiting_input','stopping')
UNION
SELECT node_id FROM owners WHERE state='active' AND current_run_id IS NOT NULL
"""


def ro(path: Path) -> sqlite3.Connection:
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2.0)
    c.execute("PRAGMA query_only=ON")
    return c


def default_config() -> dict[str, Any]:
    return {
        "sidebar": {"enabled": True},
        "launchGuard": {
            "mode": "off",
            "startupWindowSec": 60,
            "quitTimeoutSec": 30,
            "maxRestartsPerBuild": 1,
        },
        "cdpPatch": {"enabled": False},
    }


def load_ui_config(state_root: Path) -> dict[str, Any]:
    cfg_path = state_root / "sidebar-ui" / "config.json"
    base = default_config()
    if cfg_path.is_file():
        try:
            loaded = json.loads(cfg_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                for section in ("sidebar", "launchGuard", "cdpPatch"):
                    if isinstance(loaded.get(section), dict):
                        base[section].update(loaded[section])
        except Exception:
            pass
    return base


def save_ui_config(state_root: Path, cfg: dict[str, Any]) -> Path:
    cfg_path = state_root / "sidebar-ui" / "config.json"
    atomic_write_json(cfg_path, cfg)
    return cfg_path


def probe_l0_existing_cdp(gen: AppGen | None = None) -> dict[str, Any]:
    """L0: Probe existing DevToolsActivePort without restarting or signaling ZCode."""
    app_gen = gen or current_app()
    if app_gen is None:
        return {"ok": False, "level": "L0", "code": "WAITING_FOR_APP"}
    ep = verify_endpoint(app_gen)
    return {"level": "L0", **ep}


def try_sigusr1_inject(
    gen: AppGen,
    entry: dict[str, Any],
    bundle_source: str,
    snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """L1: Node inspector injection via SIGUSR1.

    Strictly gated on `entry.get('sigusr1Inspector') == 'ok'` in compatibility.json
    AND Electron Fuse bit 3 (`node_cli_inspect`) == '1'. Never signals unknown builds.
    Always closes the inspector on port 9229 in `finally`.
    """
    if entry.get("sigusr1Inspector") != "ok":
        return {"ok": False, "level": "L1", "code": "SIGUSR1_NOT_APPROVED_FOR_BUILD"}
    wire, fuse_err = asar_cdp_patch.read_fuse_wire(entry)
    if fuse_err or not wire or len(wire) <= asar_cdp_patch.WIRE_IDX_NODE_CLI_INSPECT:
        return {"ok": False, "level": "L1", "code": fuse_err or "FUSE_WIRE_SHORT"}
    if wire[asar_cdp_patch.WIRE_IDX_NODE_CLI_INSPECT] != "1":
        return {"ok": False, "level": "L1", "code": "NODE_CLI_INSPECT_FUSE_OFF"}

    try:
        os.kill(gen.pid, signal.SIGUSR1)
    except OSError as e:
        return {"ok": False, "level": "L1", "code": "KILL_USR1_FAILED", "detail": str(e)}

    time.sleep(0.8)
    lsof_out = subprocess.run(
        ["/usr/sbin/lsof", "-nP", "-a", "-p", str(gen.pid), "-iTCP:9229", "-sTCP:LISTEN"],
        capture_output=True,
        text=True,
    ).stdout
    addrs = re.findall(r"TCP (\S+):9229 \(LISTEN\)", lsof_out)
    if not addrs or any(a != "127.0.0.1" for a in addrs):
        return {"ok": False, "level": "L1", "code": "INSPECTOR_NOT_LISTENING_LOOPBACK", "addrs": addrs}

    ws: CdpSocket | None = None
    try:
        targets = cdp_http_get_json(9229, "/json/list", timeout=3.0)
        node_targets = [t for t in (targets if isinstance(targets, list) else []) if t.get("type") == "node"]
        if not node_targets:
            return {"ok": False, "level": "L1", "code": "NO_NODE_TARGET"}
        ws_url = str(node_targets[0].get("webSocketDebuggerUrl") or "")
        ws = CdpSocket(ws_url, timeout=5.0)
        ws.call("Runtime.enable")
        js_src_lit = json.dumps(bundle_source)
        src_sha_lit = json.dumps(hashlib.sha256(bundle_source.encode("utf-8")).hexdigest())
        snap_lit = json.dumps(json.dumps(snapshot, ensure_ascii=True)) if snapshot else "null"
        expr = (
            "(async () => {"
            "  const { webContents } = require('electron');"
            "  const targets = webContents.getAllWebContents().filter(w => "
            "    w.getURL().startsWith('file:///Applications/ZCode.app/Contents/Resources/app.asar/out/renderer/index.html'));"
            f" const src = {js_src_lit};"
            f" const srcSha = {src_sha_lit};"
            f" const snapRaw = {snap_lit};"
            "  const statuses = {};"
            "  for (const w of targets) {"
            "    const alive = await w.executeJavaScript("
            f"     `Boolean(window.__SS_SIDEBAR_TREE__ && window.__SS_SIDEBAR_TREE__.alive && window.__SS_PAYLOAD_SHA__ === ${{JSON.stringify(srcSha)}})`"
            "    );"
            "    if (!alive) {"
            "      await w.executeJavaScript('try { window.__SS_SIDEBAR_TREE__ && window.__SS_SIDEBAR_TREE__.destroy(); delete window.__SS_ZCODE_ADAPTER__; } catch (_) {}');"
            "      await w.executeJavaScript(src);"
            "      await w.executeJavaScript(`window.__SS_PAYLOAD_SHA__ = ${JSON.stringify(srcSha)}`);"
            "    }"
            "    if (snapRaw) {"
            "      await w.executeJavaScript(`(async () => {"
            "        const s = JSON.parse(${JSON.stringify(snapRaw)});"
            "        if (window.__SS_ZCODE_ADAPTER__ && window.__SS_ZCODE_ADAPTER__.syncUnindexedNodes) {"
            "          try { await window.__SS_ZCODE_ADAPTER__.syncUnindexedNodes(s); } catch (_) {}"
            "        }"
            "        return window.__SS_SIDEBAR_TREE__ && window.__SS_SIDEBAR_TREE__.update(s);"
            "      })()`);"
            "    }"
            "    const st = await w.executeJavaScript('window.__SS_SIDEBAR_TREE__ ? window.__SS_SIDEBAR_TREE__.getStatus() : null');"
            "    if (st) statuses[String(w.id)] = st;"
            "  }"
            "  return { injectedCount: targets.length, targets: statuses };"
            "})()"
        )
        res = ws.call(
            "Runtime.evaluate",
            {"expression": expr, "includeCommandLineAPI": True, "awaitPromise": True, "returnByValue": True},
        )
        val = res.get("result", {}).get("value") or {}
        return {"ok": bool(val.get("injectedCount", 0) > 0), "level": "L1", **val}
    except (CdpError, OSError) as e:
        return {"ok": False, "level": "L1", "code": "INSPECTOR_RPC_FAILED", "detail": str(e)}
    finally:
        if ws is not None:
            try:
                ws.call(
                    "Runtime.evaluate",
                    {
                        "expression": "try { require('inspector').close(); } catch (_) {}",
                        "includeCommandLineAPI": True,
                        "returnByValue": True,
                    },
                )
            except Exception:
                pass
            ws.close()


class LaunchGuard:
    """L2: Opt-in early startup window safe relaunch state machine."""

    def __init__(
        self,
        state_root: Path,
        *,
        tasks_index_path: Path | None = None,
        cli_db_path: Path | None = None,
        pending_update_path: Path | None = None,
        info_plist_path: Path | None = None,
        asar_path: Path | None = None,
    ) -> None:
        self.root = Path(state_root).expanduser().resolve()
        full_cfg = load_ui_config(self.root)
        self.cfg = full_cfg.get("launchGuard", {})
        self.cdp_patch_cfg = full_cfg.get("cdpPatch", {})
        self.mode = str(self.cfg.get("mode", "off"))
        self.rt = self.root / "sidebar-ui" / "runtime" / "launch_guard.json"
        self.tasks_index_path = tasks_index_path or (Path.home() / ".zcode/v2/tasks-index.sqlite")
        self.cli_db_path = cli_db_path or (Path.home() / ".zcode/cli/db/db.sqlite")
        self.pending_update_path = pending_update_path or (
            Path.home() / "Library/Caches/@zcodedesktop-updater/pending/update-info.json"
        )
        self.info_plist_path = info_plist_path or INFO_PLIST
        self.asar_path = asar_path or ASAR
        self.last_gate_errors: dict[str, str] = {}

    def gate(self, gen: AppGen) -> list[str]:
        blocked: list[str] = []
        self.last_gate_errors = {}
        proc_ms = int(gen.lstart * 1000)

        state_db = self.root / "state.sqlite3"
        if state_db.is_file():
            try:
                with closing(ro(state_db)) as c:
                    if c.execute(PLUGIN_BUSY_SQL).fetchone():
                        blocked.append("plugin_busy")
            except (sqlite3.Error, OSError) as e:
                blocked.append("plugin_state_unreadable")
                self.last_gate_errors["plugin_state_unreadable"] = str(e)

        if self.tasks_index_path.is_file():
            try:
                with closing(ro(self.tasks_index_path)) as c:
                    row = c.execute(
                        "SELECT count(*) FROM tasks WHERE task_status='running' "
                        "AND deleted=0 AND archived=0 AND updated_at >= ?",
                        (proc_ms,),
                    ).fetchone()
                    if row and row[0]:
                        blocked.append("desktop_task_running")
            except (sqlite3.Error, OSError) as e:
                blocked.append("desktop_state_unreadable")
                self.last_gate_errors["desktop_state_unreadable"] = str(e)

        if self.cli_db_path.is_file():
            try:
                with closing(ro(self.cli_db_path)) as c:
                    row = c.execute(
                        "SELECT count(*) FROM message WHERE time_created >= ?",
                        (proc_ms,),
                    ).fetchone()
                    if row and row[0]:
                        blocked.append("messages_since_launch")
            except (sqlite3.Error, OSError) as e:
                blocked.append("cli_state_unreadable")
                self.last_gate_errors["cli_state_unreadable"] = str(e)

        st = self.load()
        cur_sha = sha256_file(self.asar_path) if self.asar_path.is_file() else st.get("asarSha", "")
        if st.get("restarts", {}).get(cur_sha, 0) >= int(self.cfg.get("maxRestartsPerBuild", 1)):
            blocked.append("restart_budget")

        if subprocess.run(["/usr/bin/pgrep", "-x", "ShipIt"], capture_output=True).returncode == 0:
            blocked.append("shipit_running")

        if self.pending_update_newer():
            blocked.append("pending_update")

        return blocked

    def pending_update_newer(self) -> bool:
        p = self.pending_update_path
        if not p.exists():
            return False
        try:
            installed = plistlib.loads(self.info_plist_path.read_bytes())["CFBundleShortVersionString"]
            name = json.loads(p.read_text(encoding="utf-8")).get("fileName", "")
        except Exception:
            return True
        m = re.search(r"ZCode-(\d+(?:\.\d+)+)-", str(name))
        if not m:
            return True
        v = lambda s: tuple(int(x) for x in str(s).split("."))
        return v(m.group(1)) > v(installed)

    def step(self, gen: AppGen) -> dict[str, Any]:
        if self.mode != "auto":
            return {"mode": self.mode, "state": "NOTIFY"}
        now = time.time()
        deadline = max(gen.lstart + 30, (gen.checkin or now) + 8)
        if gen.checkin is None or now < deadline:
            return {"mode": "auto", "state": "PROBE_CDP", "probeDeadline": deadline}
        if now > gen.checkin + int(self.cfg.get("startupWindowSec", 60)):
            return {"mode": "auto", "state": "NOTIFY", "reason": "outside_startup_window"}
        blocked = self.gate(gen)
        if blocked:
            res: dict[str, Any] = {"mode": "auto", "state": "NOTIFY", "gateBlockedBy": blocked}
            if self.last_gate_errors:
                res["gateErrors"] = dict(self.last_gate_errors)
            return res
        q = subprocess.run(
            ["/usr/bin/osascript", "-e", 'tell application id "dev.zcode.app" to quit'],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if q.returncode != 0 and "-1743" in (q.stderr or ""):
            return {"mode": "auto", "state": "AUTOMATION_DENIED"}
        t0 = time.time()
        while time.time() - t0 < int(self.cfg.get("quitTimeoutSec", 30)):
            if subprocess.run(["/bin/kill", "-0", str(gen.pid)], capture_output=True).returncode != 0:
                break
            time.sleep(0.5)
        else:
            return {"mode": "auto", "state": "RELAUNCH_ABORTED_QUIT_REFUSED"}
        while subprocess.run(["/usr/bin/pgrep", "-x", "ShipIt"], capture_output=True).returncode == 0:
            time.sleep(1)
        patch_res = None
        if self.cdp_patch_cfg.get("enabled"):
            manifest_p = self.root / "sidebar-ui" / "backups" / "asar_patch.json"
            builds = _load_compat_builds(self.root)
            b_entry, cur_sha, b_err = asar_cdp_patch.resolve_build_entry(self.asar_path, manifest_p, builds)
            if b_entry is None:
                patch_res = {
                    "ok": False,
                    "code": "UNSUPPORTED_ASAR_VERSION",
                    "asarSha": cur_sha,
                    "buildCheckError": b_err,
                }
            else:
                patch_res = asar_cdp_patch.apply(b_entry, manifest_p, builds=builds)
        self.bump_restart()
        subprocess.run(
            ["/usr/bin/open", "-a", "/Applications/ZCode.app", "--args", "--remote-debugging-port=0"],
            check=False,
        )
        out_res: dict[str, Any] = {"mode": "auto", "state": "RELAUNCHED"}
        if patch_res is not None:
            out_res["cdpPatch"] = patch_res
        return out_res

    def load(self) -> dict[str, Any]:
        try:
            return json.loads(self.rt.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def bump_restart(self) -> None:
        st = self.load()
        sha = sha256_file(self.asar_path) if self.asar_path.is_file() else ""
        st["asarSha"] = sha
        st.setdefault("restarts", {})[sha] = st.get("restarts", {}).get(sha, 0) + 1
        atomic_write_json(self.rt, st)


def build_launchd_plist_dict(
    state_root: Path,
    *,
    python_bin: str | None = None,
    zcode_bin: str | None = None,
    node_dir: str | None = None,
) -> dict[str, Any]:
    py = python_bin or _select_python3()
    zbin = zcode_bin or os.environ.get("ZCODE_SIDE_SESSIONS_ZCODE_BIN") or _resolve_default_zcode_bin()
    ndir = node_dir or _resolve_default_node_dir()
    s_root = str(state_root.resolve())
    return {
        "Label": LABEL,
        "ProgramArguments": [
            py,
            "-B",
            f"{s_root}/sidebar-ui/launcher/side_sessions_agent.py",
            "--state-home",
            s_root,
        ],
        "WorkingDirectory": s_root,
        "EnvironmentVariables": {
            "ZCODE_SIDE_SESSIONS_HOME": s_root,
            "ZCODE_SIDE_SESSIONS_ZCODE_BIN": zbin,
            "PATH": f"{ndir}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "ProcessType": "Background",
        "StandardOutPath": f"{s_root}/logs/agent.stdout.log",
        "StandardErrorPath": f"{s_root}/logs/agent.stderr.log",
    }


def _verify_staged_release(rel_dir: Path, expected_files: dict[str, str]) -> bool:
    manifest_p = rel_dir / "release-manifest.json"
    if not rel_dir.is_dir() or not manifest_p.is_file():
        return False
    try:
        manifest = json.loads(manifest_p.read_text(encoding="utf-8"))
    except Exception:
        return False
    if not isinstance(manifest, dict) or manifest.get("files") != expected_files:
        return False
    for rel_p, expected_sha in expected_files.items():
        fp = rel_dir / rel_p
        if not fp.is_file():
            return False
        try:
            if sha256_file(fp) != expected_sha:
                return False
        except OSError:
            return False
    return True


def _stage_release(plugin_root: Path, state_root: Path) -> tuple[Path, dict[str, Any]]:
    ui_root = state_root / "sidebar-ui"
    releases_dir = ui_root / "releases"
    launcher_dir = ui_root / "launcher"
    releases_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    launcher_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    (ui_root / "runtime").mkdir(mode=0o700, parents=True, exist_ok=True)
    (ui_root / "backups").mkdir(mode=0o700, parents=True, exist_ok=True)
    (state_root / "logs").mkdir(mode=0o700, parents=True, exist_ok=True)

    plugin_json = plugin_root / ".zcode-plugin" / "plugin.json"
    plugin_ver = "0.1.0"
    if plugin_json.is_file():
        try:
            plugin_ver = str(json.loads(plugin_json.read_text(encoding="utf-8")).get("version") or "0.1.0")
        except Exception:
            pass

    hasher = hashlib.sha256()
    file_hashes: dict[str, str] = {}
    for sub in ("scripts", "ui"):
        src_dir = plugin_root / sub
        if not src_dir.is_dir():
            continue
        for fp in sorted(src_dir.rglob("*")):
            if fp.is_file() and "__pycache__" not in fp.parts and not fp.name.endswith(".pyc"):
                rel_p = str(fp.relative_to(plugin_root))
                f_sha = sha256_file(fp)
                file_hashes[rel_p] = f_sha
                hasher.update(f"{rel_p}:{f_sha}\n".encode("utf-8"))

    sha8 = hasher.hexdigest()[:8]
    rel_id = f"{plugin_ver}-{sha8}"
    rel_dir = releases_dir / rel_id
    if not _verify_staged_release(rel_dir, file_hashes):
        staging_dir = releases_dir / f".staging-{rel_id}-{os.getpid()}"
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        for sub in ("scripts", "ui"):
            src_dir = plugin_root / sub
            if src_dir.is_dir():
                shutil.copytree(
                    src_dir,
                    staging_dir / sub,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
        manifest = {
            "pluginVersion": plugin_ver,
            "releaseId": rel_id,
            "createdAt": time.time(),
            "files": file_hashes,
        }
        atomic_write_json(staging_dir / "release-manifest.json", manifest)
        if rel_dir.exists():
            stale_dir = releases_dir / f".stale-{rel_id}-{os.getpid()}"
            if stale_dir.exists():
                shutil.rmtree(stale_dir, ignore_errors=True)
            os.replace(rel_dir, stale_dir)
            os.replace(staging_dir, rel_dir)
            shutil.rmtree(stale_dir, ignore_errors=True)
        else:
            os.replace(staging_dir, rel_dir)

    agent_src = rel_dir / "scripts" / "side_sessions_agent.py"
    if agent_src.is_file():
        agent_dst = launcher_dir / "side_sessions_agent.py"
        agent_tmp = launcher_dir / f".side_sessions_agent.py.{os.getpid()}.tmp"
        shutil.copy2(agent_src, agent_tmp)
        os.replace(agent_tmp, agent_dst)

    cur_path = ui_root / "current.json"
    prev_release = None
    if cur_path.is_file():
        try:
            old_cur = json.loads(cur_path.read_text(encoding="utf-8"))
            old_rel_dir = old_cur.get("releaseDir")
            if old_rel_dir and str(Path(old_rel_dir).resolve()) != str(rel_dir.resolve()):
                prev_release = old_rel_dir
            else:
                prev_release = old_cur.get("previousReleaseDir")
        except Exception:
            pass
    cur_obj = {
        "releaseId": rel_id,
        "releaseDir": str(rel_dir),
        "previousReleaseDir": prev_release,
        "updatedAt": time.time(),
    }
    atomic_write_json(cur_path, cur_obj)

    # Keep current, previous, and any actively running release
    keep = {str(rel_dir.resolve())}
    if prev_release:
        try:
            keep.add(str(Path(prev_release).resolve()))
        except OSError:
            pass
    agent_state_p = ui_root / "runtime" / "agent_state.json"
    if agent_state_p.is_file():
        try:
            ast = json.loads(agent_state_p.read_text(encoding="utf-8"))
            for k in ("releaseDir", "workerReleaseDir", "sidebarReleaseDir"):
                v = ast.get(k)
                if v:
                    keep.add(str(Path(v).resolve()))
        except Exception:
            pass
    for d in releases_dir.iterdir():
        if d.is_dir() and not d.name.startswith(".") and str(d.resolve()) not in keep:
            shutil.rmtree(d, ignore_errors=True)

    return rel_dir, cur_obj


def _launchctl_bootout_wait(uid: int, label: str, timeout_sec: float = 6.0) -> None:
    subprocess.run(
        ["/bin/launchctl", "bootout", f"gui/{uid}/{label}"],
        capture_output=True,
        text=True,
    )
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        chk = subprocess.run(
            ["/bin/launchctl", "print", f"gui/{uid}/{label}"],
            capture_output=True,
            text=True,
        )
        if chk.returncode != 0:
            return
        time.sleep(0.15)


def _launchctl_bootstrap_retry(
    uid: int,
    plist_path: Path,
    attempts: int = 10,
) -> subprocess.CompletedProcess[str]:
    last: subprocess.CompletedProcess[str] | None = None
    for idx in range(max(1, attempts)):
        bs = subprocess.run(
            ["/bin/launchctl", "bootstrap", f"gui/{uid}", str(plist_path)],
            capture_output=True,
            text=True,
        )
        last = bs
        if bs.returncode == 0 or "already loaded" in (bs.stderr or "").lower():
            return bs
        if idx + 1 < attempts:
            time.sleep(0.2)
    assert last is not None
    return last


def install(
    state_root: Path,
    *,
    plugin_root: Path | None = None,
    launch_guard_mode: str = "off",
    enable_cdp_patch: bool = False,
    manage_launchctl: bool = True,
    plist_dest: Path | None = None,
) -> dict[str, Any]:
    root = state_root.expanduser().resolve()
    p_root = (plugin_root or HERE.parent).expanduser().resolve()
    py = _select_python3()

    rel_dir, cur_obj = _stage_release(p_root, root)
    cfg = load_ui_config(root)
    cfg["sidebar"]["enabled"] = True
    cfg["launchGuard"]["mode"] = launch_guard_mode
    cfg["cdpPatch"]["enabled"] = bool(enable_cdp_patch)
    save_ui_config(root, cfg)
    atomic_write_json(
        root / "agent-control.json",
        {
            "installed": True,
            "autostartFromHook": True,
            "mode": "agent",
        },
    )

    compat_path = rel_dir / "ui" / "compatibility.json"
    compat = json.loads(compat_path.read_text(encoding="utf-8")) if compat_path.is_file() else {"builds": {}}
    builds_map = compat.get("builds", {}) if isinstance(compat.get("builds"), dict) else {}
    manifest_path = root / "sidebar-ui" / "backups" / "asar_patch.json"
    build_entry, asar_sha, build_err = asar_cdp_patch.resolve_build_entry(
        ASAR,
        manifest_path,
        builds_map,
    )
    build_status = build_entry.get("status", "supported") if build_entry else "experimental"

    patch_res = None
    if enable_cdp_patch:
        if build_entry is None:
            patch_res = {
                "ok": False,
                "code": "UNSUPPORTED_ASAR_VERSION",
                "asarSha": asar_sha,
                "buildCheckError": build_err,
            }
        else:
            patch_res = asar_cdp_patch.apply(
                build_entry,
                manifest_path,
                builds=builds_map,
            )

    plist_path = plist_dest or (Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist")
    plist_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    plist_dict = build_launchd_plist_dict(root, python_bin=py)
    plist_path.write_bytes(plistlib.dumps(plist_dict))
    lint = subprocess.run(["/usr/bin/plutil", "-lint", str(plist_path)], capture_output=True, text=True)
    if lint.returncode != 0:
        raise RuntimeError(f"plutil -lint failed: {lint.stderr or lint.stdout}")

    uid = os.getuid()
    launchctl_ok = True
    if manage_launchctl:
        _launchctl_bootout_wait(uid, LABEL)
        bs = _launchctl_bootstrap_retry(uid, plist_path)
        ks = subprocess.run(
            ["/bin/launchctl", "kickstart", "-k", f"gui/{uid}/{LABEL}"],
            capture_output=True,
            text=True,
        )
        launchctl_ok = bs.returncode == 0 or ks.returncode == 0
        if launchctl_ok:
            wait_until = time.monotonic() + 2.5
            agent_st_p = root / "sidebar-ui" / "runtime" / "agent_state.json"
            while time.monotonic() < wait_until:
                if _is_agent_lock_held(root) and agent_st_p.is_file():
                    break
                time.sleep(0.1)

    patch_ok = (not enable_cdp_patch) or bool(patch_res and patch_res.get("ok"))
    doc = doctor(root)
    return {
        "ok": bool(patch_ok and launchctl_ok),
        "stateRoot": str(root),
        "release": cur_obj,
        "buildStatus": build_status,
        "plistPath": str(plist_path),
        "cdpPatch": patch_res,
        "health": doc.get("injector"),
        "doctor": doc,
    }


def doctor(state_root: Path) -> dict[str, Any]:
    root = state_root.expanduser().resolve()
    ui_dir = root / "sidebar-ui"
    cfg = load_ui_config(root)

    uid = os.getuid()
    lc = subprocess.run(
        ["/bin/launchctl", "print", f"gui/{uid}/{LABEL}"],
        capture_output=True,
        text=True,
    )
    loaded = lc.returncode == 0
    pid_match = re.search(r"\bpid\s*=\s*(\d+)", lc.stdout or "")
    lc_pid = int(pid_match.group(1)) if pid_match else 0

    compat_path = HERE.parent / "ui" / "compatibility.json"
    cur_file = ui_dir / "current.json"
    if cur_file.is_file():
        try:
            rel_dir = Path(json.loads(cur_file.read_text(encoding="utf-8"))["releaseDir"])
            if (rel_dir / "ui" / "compatibility.json").is_file():
                compat_path = rel_dir / "ui" / "compatibility.json"
        except Exception:
            pass
    compat = json.loads(compat_path.read_text(encoding="utf-8")) if compat_path.is_file() else {"builds": {}}

    app_ver = "unknown"
    if INFO_PLIST.is_file():
        try:
            app_ver = str(plistlib.loads(INFO_PLIST.read_bytes()).get("CFBundleShortVersionString") or "unknown")
        except Exception:
            pass
    manifest_p = ui_dir / "backups" / "asar_patch.json"
    patch_st = asar_cdp_patch.status(manifest_p)
    build_entry, asar_sha, build_err = asar_cdp_patch.resolve_build_entry(
        ASAR,
        manifest_p,
        compat.get("builds", {}),
    )
    codesign_state = patch_st.get("codesign", "invalid")

    pf, _ = resolve_devtools_port_file()
    gen = current_app()
    if gen is not None:
        ep = verify_endpoint(gen)
        if ep.get("ok"):
            ep_state = "ok"
        elif ep.get("code") == "STALE_PORT_FILE":
            ep_state = "stale"
        else:
            ep_state = "absent"
    else:
        ep_state = "absent"

    health_file = ui_dir / "health.json"
    health: dict[str, Any] = {}
    if health_file.is_file():
        try:
            health = json.loads(health_file.read_text(encoding="utf-8"))
        except Exception:
            health = {}

    lg_info = health.get("launchGuard") or {
        "mode": cfg.get("launchGuard", {}).get("mode", "off"),
        "probeDeadline": 0,
        "gateBlockedBy": [],
    }
    targets_map = health.get("targets") if isinstance(health.get("targets"), dict) else {}
    first_target = next(iter(targets_map.values()), {}) if targets_map else {}

    reader = ProjectionReader(root, persist_export=False)
    try:
        snap = reader.snapshot()
    finally:
        reader.close()

    kick_log = root / "logs" / "worker-kick.log"
    last_kick_at = kick_log.stat().st_mtime if kick_log.is_file() else None

    sidebar_enabled = bool(cfg.get("sidebar", {}).get("enabled", True))
    ctrl: dict[str, Any] | None = None
    ctrl_p = root / "agent-control.json"
    if ctrl_p.is_file():
        try:
            raw_ctrl = json.loads(ctrl_p.read_text(encoding="utf-8"))
            if isinstance(raw_ctrl, dict):
                ctrl = raw_ctrl
        except Exception:
            ctrl = None

    agent_st: dict[str, Any] = {}
    agent_st_p = ui_dir / "runtime" / "agent_state.json"
    if agent_st_p.is_file():
        try:
            raw_ast = json.loads(agent_st_p.read_text(encoding="utf-8"))
            if isinstance(raw_ast, dict):
                agent_st = raw_ast
        except Exception:
            agent_st = {}

    agent_lock_held = _is_agent_lock_held(root)
    worker_pid = agent_st.get("workerPid")
    sidebar_pid = agent_st.get("sidebarPid")
    worker_pid_alive = _pid_alive(worker_pid)
    sidebar_pid_alive = _pid_alive(sidebar_pid)

    if ctrl is not None and ctrl.get("installed") is False:
        ctrl_mode = str(ctrl.get("mode") or "disabled")
        if ctrl_mode == "worker_only":
            worker_state = "running" if (loaded and _pid_alive(lc_pid)) else "worker_only"
        else:
            worker_state = "disabled"
        sidebar_state = "disabled"
    else:
        if agent_lock_held:
            if "workerPid" in agent_st:
                worker_state = "running" if worker_pid_alive else "backoff"
            else:
                worker_state = "running" if agent_st.get("workerReleaseDir") else "starting"
        else:
            worker_state = "backoff" if loaded else ("stopped" if (ctrl and ctrl.get("installed") is True) else "disabled")

        if not sidebar_enabled:
            sidebar_state = "disabled"
        elif agent_lock_held:
            if "sidebarPid" in agent_st:
                sidebar_state = "running" if sidebar_pid_alive else "backoff"
            else:
                sidebar_state = "running" if agent_st.get("sidebarReleaseDir") else "starting"
        else:
            sidebar_state = "backoff" if loaded else ("stopped" if (ctrl and ctrl.get("installed") is True) else "disabled")

    return {
        "launchd": {
            "label": LABEL,
            "loaded": loaded,
            "pid": lc_pid,
            "agentLockHeld": agent_lock_held,
            "workerPid": worker_pid if worker_pid_alive else None,
            "sidebarPid": sidebar_pid if sidebar_pid_alive else None,
        },
        "children": {"worker": worker_state, "sidebar": sidebar_state},
        "app": {
            "version": app_ver,
            "asarSha": asar_sha,
            "supported": bool(build_entry),
            "codesign": codesign_state,
            "buildCheckError": build_err,
            **(
                {"remediation": "PATCH_MANIFEST_INCOMPLETE: re-run sidebar_ui_ctl.py install"}
                if build_err == "PATCH_MANIFEST_INCOMPLETE"
                else {}
            ),
        },
        "launch": {
            "portFile": str(pf) if pf else None,
            "endpoint": ep_state,
            "sigusr1Inspector": (build_entry or {}).get("sigusr1Inspector", "untested"),
            "launchGuard": lg_info,
            "cdpPatch": (
                "PATCH_MANIFEST_INCOMPLETE"
                if build_err == "PATCH_MANIFEST_INCOMPLETE"
                else patch_st.get("state", "absent")
            ),
        },
        "injector": {
            "state": health.get("state", "WAITING_FOR_APP"),
            "targets": len(targets_map),
            "sidebarFound": bool(first_target.get("sidebarFound", False)),
            "navigatorResolved": bool(first_target.get("navigatorResolved", False)),
            "mountedParentCount": int(first_target.get("mountedParentCount", 0)),
            "childCount": int(first_target.get("childCount", 0)),
            "dedup": list(first_target.get("dedup") or []),
            "lastNav": first_target.get("lastNav"),
            "lastError": health.get("lastError") or first_target.get("lastError"),
        },
        "bridge": {
            "projectionRevision": int(snap.get("projectionRevision") or 0),
            "nodes": len(snap.get("nodes") or []),
        },
        "worker": {
            "kickLog": str(kick_log),
            "lastKickAt": last_kick_at,
        },
    }


def start_zcode() -> dict[str, Any]:
    gen = current_app()
    if gen is not None:
        ep = verify_endpoint(gen)
        if ep.get("ok"):
            return {"ok": True, "state": "ALREADY_RUNNING_WITH_CDP", "app": gen.key, "endpoint": ep}
        return {"ok": False, "state": "WAITING_FOR_DEBUG_LAUNCH", "app": gen.key, "endpoint": ep}
    subprocess.run(
        ["/usr/bin/open", "-a", str(APP_PATH), "--args", "--remote-debugging-port=0"],
        check=False,
    )
    return {"ok": True, "state": "LAUNCH_REQUESTED", "args": ["--remote-debugging-port=0"]}


def set_sidebar_enabled(state_root: Path, enabled: bool) -> dict[str, Any]:
    root = state_root.expanduser().resolve()
    cfg = load_ui_config(root)
    cfg["sidebar"]["enabled"] = bool(enabled)
    save_ui_config(root, cfg)
    uninject_res = None
    if not enabled:
        gen = current_app()
        if gen is not None:
            ep = verify_endpoint(gen)
            if ep.get("ok"):
                uninject_res = uninject_active_targets(int(ep["port"]))
    return {"ok": True, "enabled": bool(enabled), "uninject": uninject_res}


def uninstall(
    state_root: Path,
    *,
    keep_data: bool = True,
    keep_worker: bool = False,
    manage_launchctl: bool = True,
    plist_dest: Path | None = None,
) -> dict[str, Any]:
    root = state_root.expanduser().resolve()
    ui_dir = root / "sidebar-ui"

    # 1. Disable sidebar in config.json and destroy active controller in CDP targets if reachable
    had_cdp_patch_cfg = False
    if ui_dir.exists():
        cfg = load_ui_config(root)
        had_cdp_patch_cfg = bool(cfg.get("cdpPatch", {}).get("enabled"))
        cfg["sidebar"]["enabled"] = False
        save_ui_config(root, cfg)

    cdp_cleanup: dict[str, Any] = {"reachable": False}
    gen = current_app()
    if gen is not None:
        ep = verify_endpoint(gen)
        if ep.get("ok"):
            cdp_cleanup = {"reachable": True, **uninject_active_targets(int(ep["port"]))}
        else:
            cdp_cleanup = {
                "reachable": False,
                "note": "内存中的增强将在下次页面重载/应用重启后消失",
            }
    else:
        cdp_cleanup = {
            "reachable": False,
            "note": "ZCode 未运行，无需清理内存控制器",
        }

    # 2. Write agent-control.json before bootout so SessionStart hook never re-starts agent
    atomic_write_json(
        root / "agent-control.json",
        {
            "installed": False,
            "autostartFromHook": False,
            "mode": "worker_only" if keep_worker else "disabled",
        },
    )

    # Bootout launchd agent and remove plist
    plist_path = plist_dest or (Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist")
    uid = os.getuid()
    if manage_launchctl:
        _launchctl_bootout_wait(uid, LABEL)
    if plist_path.is_file():
        plist_path.unlink(missing_ok=True)

    worker_bootstrap_ok = True
    if keep_worker and manage_launchctl:
        py = _select_python3()
        zbin = os.environ.get("ZCODE_SIDE_SESSIONS_ZCODE_BIN") or _resolve_default_zcode_bin()
        ndir = _resolve_default_node_dir()
        worker_plist = {
            "Label": LABEL,
            "ProgramArguments": [
                py,
                "-B",
                str(HERE / "worker_runner.py"),
                "serve",
                "--state-home",
                str(root),
            ],
            "WorkingDirectory": str(root),
            "EnvironmentVariables": {
                "ZCODE_SIDE_SESSIONS_HOME": str(root),
                "ZCODE_SIDE_SESSIONS_ZCODE_BIN": zbin,
                "PATH": f"{ndir}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONUNBUFFERED": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
            "ThrottleInterval": 5,
            "ProcessType": "Background",
            "StandardOutPath": f"{root}/logs/supervisor.stdout.log",
            "StandardErrorPath": f"{root}/logs/supervisor.stderr.log",
        }
        plist_path.write_bytes(plistlib.dumps(worker_plist))
        bs_worker = _launchctl_bootstrap_retry(uid, plist_path)
        worker_bootstrap_ok = bs_worker.returncode == 0

    # 3. Restore ASAR patch if backups/asar_patch.json exists
    patch_restore_res = None
    restore_ok = True
    manifest_p = ui_dir / "backups" / "asar_patch.json"
    if manifest_p.is_file():
        patch_restore_res = asar_cdp_patch.restore(manifest_p, builds=_load_compat_builds(root))
        if not patch_restore_res.get("ok"):
            restore_ok = False
    elif had_cdp_patch_cfg:
        cur_patch_st = asar_cdp_patch.status(manifest_p)
        if cur_patch_st.get("state") == "applied":
            patch_restore_res = {"ok": False, "code": "MANIFEST_NOT_FOUND", "manifest": str(manifest_p)}
            restore_ok = False

    # 4. Remove sidebar-ui/{releases,launcher,runtime,health.json} and exports/sidebar-tree-v1.json
    for sub in ("releases", "launcher", "runtime"):
        p = ui_dir / sub
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
    for f_rel in (
        ui_dir / "health.json",
        ui_dir / "current.json",
        ui_dir / "config.json",
        root / "exports" / "sidebar-tree-v1.json",
    ):
        if f_rel.is_file():
            f_rel.unlink(missing_ok=True)
    try:
        if (ui_dir / "backups").is_dir() and not any((ui_dir / "backups").iterdir()):
            (ui_dir / "backups").rmdir()
        if ui_dir.is_dir() and not any(ui_dir.iterdir()):
            ui_dir.rmdir()
    except OSError:
        pass

    post_doc = doctor(root)
    return {
        "ok": bool(restore_ok and worker_bootstrap_ok),
        "keepData": keep_data,
        "cdpCleanup": cdp_cleanup,
        "patchRestore": patch_restore_res,
        "doctor": post_doc,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ZCode in-place sidebar tree controller and LaunchGuard CLI")
    sub = parser.add_subparsers(dest="cmd")

    p_inst = sub.add_parser("install", help="Install release snapshot and LaunchAgent")
    p_inst.add_argument("--state-home", default=None)
    p_inst.add_argument("--launch-guard", choices=("off", "notify", "auto"), default="off")
    p_inst.add_argument("--cdp-patch", action="store_true")
    p_inst.add_argument("--no-launchctl", action="store_true")

    for doc_cmd in ("doctor", "status"):
        p_doc = sub.add_parser(doc_cmd, help="Read-only health and compatibility check")
        p_doc.add_argument("--state-home", default=None)
        p_doc.add_argument("--json", action="store_true")

    for toggle_cmd in ("enable", "disable"):
        p_tog = sub.add_parser(toggle_cmd, help=f"{toggle_cmd.capitalize()} sidebar tree UI injection")
        p_tog.add_argument("--state-home", default=None)

    sub.add_parser("start-zcode", help="Launch ZCode with --remote-debugging-port=0 when not running")

    p_lg = sub.add_parser("launch-guard", help="Configure or inspect LaunchGuard")
    p_lg.add_argument("action", choices=("set", "status", "step"))
    p_lg.add_argument("mode", nargs="?", choices=("off", "notify", "auto"))
    p_lg.add_argument("--state-home", default=None)

    p_patch = sub.add_parser("cdp-patch", help="Manage opt-in ASAR CDP port byte patch")
    p_patch.add_argument("action", choices=("status", "apply", "restore"))
    p_patch.add_argument("--state-home", default=None)
    p_patch.add_argument("--app", default=None)

    p_upd = sub.add_parser("update", help="Stage and switch to a new plugin release")
    p_upd.add_argument("--release", required=True, help="Plugin directory to stage")
    p_upd.add_argument("--state-home", default=None)

    p_uninst = sub.add_parser("uninstall", help="Uninstall sidebar tree enhancement and restore host state")
    p_uninst.add_argument("--state-home", default=None)
    p_uninst.add_argument("--keep-data", action="store_true", default=True)
    p_uninst.add_argument("--keep-worker", action="store_true", default=False)
    p_uninst.add_argument("--no-launchctl", action="store_true")

    args = parser.parse_args(argv)
    cmd = args.cmd or "status"
    state_root = Path(getattr(args, "state_home", None) or resolve_state_root()).expanduser().resolve()

    if cmd == "install":
        res = install(
            state_root,
            launch_guard_mode=args.launch_guard,
            enable_cdp_patch=bool(args.cdp_patch),
            manage_launchctl=not bool(args.no_launchctl),
        )
    elif cmd in ("doctor", "status"):
        res = doctor(state_root)
    elif cmd == "enable":
        res = set_sidebar_enabled(state_root, True)
    elif cmd == "disable":
        res = set_sidebar_enabled(state_root, False)
    elif cmd == "start-zcode":
        res = start_zcode()
    elif cmd == "launch-guard":
        if args.action == "set":
            if not args.mode:
                parser.error("launch-guard set requires mode (off|notify|auto)")
            cfg = load_ui_config(state_root)
            cfg["launchGuard"]["mode"] = args.mode
            save_ui_config(state_root, cfg)
            res = {"ok": True, "launchGuard": cfg["launchGuard"]}
        elif args.action == "step":
            gen = current_app()
            res = LaunchGuard(state_root).step(gen) if gen else {"state": "WAITING_FOR_APP"}
        else:
            cfg = load_ui_config(state_root)
            res = {"ok": True, "launchGuard": cfg["launchGuard"], "runtime": LaunchGuard(state_root).load()}
    elif cmd == "cdp-patch":
        manifest_p = state_root / "sidebar-ui" / "backups" / "asar_patch.json"
        app_p = Path(args.app).expanduser().resolve() if getattr(args, "app", None) else None
        if args.action == "status":
            res = asar_cdp_patch.status(manifest_p, app_path=app_p)
        elif args.action == "apply":
            target_asar = (app_p / "Contents/Resources/app.asar") if app_p else ASAR
            builds = _load_compat_builds(state_root)
            b_entry, cur_sha, b_err = asar_cdp_patch.resolve_build_entry(target_asar, manifest_p, builds)
            if b_entry is None:
                res = {
                    "ok": False,
                    "code": "UNSUPPORTED_ASAR_VERSION",
                    "asarSha": cur_sha,
                    "buildCheckError": b_err,
                }
            else:
                res = asar_cdp_patch.apply(b_entry, manifest_p, app_path=app_p, builds=builds)
        else:
            res = asar_cdp_patch.restore(manifest_p, app_path=app_p, builds=_load_compat_builds(state_root))
    elif cmd == "update":
        rel_dir, cur_obj = _stage_release(Path(args.release).expanduser().resolve(), state_root)
        res = {"ok": True, "releaseDir": str(rel_dir), "current": cur_obj}
    elif cmd == "uninstall":
        res = uninstall(
            state_root,
            keep_data=bool(args.keep_data),
            keep_worker=bool(args.keep_worker),
            manage_launchctl=not bool(args.no_launchctl),
        )
    else:
        res = {"ok": False, "code": "UNKNOWN_COMMAND"}

    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())
