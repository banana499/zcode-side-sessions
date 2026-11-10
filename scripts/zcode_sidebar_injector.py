from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from cdp_ws import CdpError, CdpSocket  # noqa: E402
from desktop_bridge import ProjectionReader, validate_public_projection  # noqa: E402
from state import open_store, resolve_state_root  # noqa: E402
from zcode_proc import (  # noqa: E402
    APP_EXE,
    BUNDLE_ID,
    AppGen,
    cdp_http_get_json,
    current_app,
    proc_path,
    resolve_devtools_port_file,
    resolve_session_dir,
    verify_endpoint,
)

MAIN_URL = "file:///Applications/ZCode.app/Contents/Resources/app.asar/out/renderer/index.html"
EXCLUDE = ("plugin-sandbox.html", "resource-manager.html", "cua-permission-panel.html")
ASAR = Path("/Applications/ZCode.app/Contents/Resources/app.asar")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


class Injector:
    L1_CACHE_TTL_SEC = 15.0

    def __init__(self, state_root: Path, release_dir: Path | None = None) -> None:
        self.root = Path(state_root).expanduser().resolve()
        self.rel = Path(release_dir).expanduser().resolve() if release_dir else HERE.parent
        self.ui_dir = self.root / "sidebar-ui"
        compat_path = self.rel / "ui" / "compatibility.json"
        self.compat: dict[str, Any] = (
            json.loads(compat_path.read_text(encoding="utf-8")) if compat_path.is_file() else {"builds": {}}
        )
        self.health: dict[str, Any] = {"state": "WAITING_FOR_APP"}
        self.gen: AppGen | None = None
        self.sessions: dict[str, CdpSocket] = {}  # targetId -> socket
        self.script_ids: dict[str, str] = {}  # targetId -> scriptIdentifier
        self.payload_shas: dict[str, str] = {}  # targetId -> sha256(src)
        self.reader = ProjectionReader(self.root)
        self.pushed_rev: dict[str, int] = {}
        self.l1_cache: dict[str, dict[str, Any]] = {}
        self.last_asar_sha: str = ""
        self.last_build_error: str | None = None
        self._asar_sha_cache: dict[str, Any] = {}

    def reload_compat(self) -> None:
        compat_path = self.rel / "ui" / "compatibility.json"
        if compat_path.is_file():
            try:
                self.compat = json.loads(compat_path.read_text(encoding="utf-8"))
            except Exception:
                pass

    def payload(self, adapter_id: str) -> str:
        a = (self.rel / "ui" / "adapters" / f"{adapter_id}.js").read_text(encoding="utf-8")
        b = (self.rel / "ui" / "sidebar_tree_bundle.js").read_text(encoding="utf-8")
        return a + "\n;\n" + b

    def build_entry(self, asar_path: Path = ASAR) -> dict[str, Any] | None:
        import asar_cdp_patch

        self.reload_compat()
        builds = self.compat.get("builds", {})
        manifest_p = self.ui_dir / "backups" / "asar_patch.json"
        entry, cur_sha, err_code = asar_cdp_patch.resolve_build_entry(
            asar_path,
            manifest_p,
            builds,
            cache=self._asar_sha_cache,
        )
        self.last_asar_sha = cur_sha
        self.last_build_error = err_code
        return entry

    def _attach_target(self, tid: str, ws: CdpSocket, src: str, src_sha: str) -> None:
        old_sid = self.script_ids.pop(tid, None)
        if old_sid:
            try:
                ws.call("Page.removeScriptToEvaluateOnNewDocument", {"identifier": old_sid})
            except CdpError:
                pass
        ws.call(
            "Runtime.evaluate",
            {
                "expression": (
                    "try { window.__SS_SIDEBAR_TREE__ && window.__SS_SIDEBAR_TREE__.destroy(); "
                    "delete window.__SS_ZCODE_ADAPTER__; } catch (_) {}"
                ),
                "returnByValue": True,
            },
        )
        doc_res = ws.call("Page.addScriptToEvaluateOnNewDocument", {"source": src})
        if isinstance(doc_res, dict) and doc_res.get("identifier"):
            self.script_ids[tid] = str(doc_res["identifier"])
        res = ws.call("Runtime.evaluate", {"expression": src, "returnByValue": True})
        if "exceptionDetails" in res:
            raise CdpError(f"inject exception: {res['exceptionDetails'].get('text')}")
        self.sessions[tid] = ws
        self.payload_shas[tid] = src_sha
        self.pushed_rev.pop(tid, None)

    def attach(
        self,
        port: int | str,
        entry: dict[str, Any] | CdpSocket,
        main_url_prefix: str = MAIN_URL,
        src_sha: str | None = None,
    ) -> None:
        if isinstance(port, str) and src_sha is not None:
            self._attach_target(port, entry, main_url_prefix, src_sha)  # type: ignore[arg-type]
            return

        assert isinstance(port, int) and isinstance(entry, dict)
        targets = cdp_http_get_json(port, "/json/list", timeout=3.0)
        pages = [
            t
            for t in (targets if isinstance(targets, list) else [])
            if t.get("type") == "page"
            and str(t.get("url", "")).startswith(main_url_prefix)
            and not any(x in str(t.get("url", "")) for x in EXCLUDE)
        ]
        src = self.payload(entry["adapter"])
        computed_sha = hashlib.sha256(src.encode("utf-8")).hexdigest()

        live_ids = {str(t["id"]) for t in pages if "id" in t}
        for stale_tid in list(self.sessions):
            if stale_tid not in live_ids:
                ws = self.sessions.pop(stale_tid, None)
                if ws:
                    ws.close()
                self.script_ids.pop(stale_tid, None)
                self.payload_shas.pop(stale_tid, None)
                self.pushed_rev.pop(stale_tid, None)

        for t in pages:
            tid = str(t["id"])
            ws_url = str(t.get("webSocketDebuggerUrl") or "")
            if not ws_url:
                continue
            if tid in self.sessions:
                if self.payload_shas.get(tid) == computed_sha:
                    continue
                # Bundle/adapter hash changed -> hot swap controller cleanly
                self._attach_target(tid, self.sessions[tid], src, computed_sha)
                continue

            ws = CdpSocket(ws_url)
            try:
                ws.call("Page.enable")
                ws.call("Runtime.enable")
                self._attach_target(tid, ws, src, computed_sha)
            except Exception:
                self.sessions.pop(tid, None)
                self.script_ids.pop(tid, None)
                self.payload_shas.pop(tid, None)
                ws.close()
                raise

    def push(self, tid: str, ws: CdpSocket, snap: dict[str, Any]) -> dict[str, Any]:
        if self.pushed_rev.get(tid) == snap["projectionRevision"]:
            return {"ok": True, "unchanged": True}
        validate_public_projection(snap)
        # 快照双重 json.dumps：作为 JS 字符串字面量传入后 JSON.parse，禁止把标题拼成代码
        expr = (
            "(async () => {"
            "  const s = JSON.parse(%s);"
            "  if (window.__SS_ZCODE_ADAPTER__ && window.__SS_ZCODE_ADAPTER__.syncUnindexedNodes) {"
            "    try { await window.__SS_ZCODE_ADAPTER__.syncUnindexedNodes(s); } catch (_) {}"
            "  }"
            "  return window.__SS_SIDEBAR_TREE__ ? window.__SS_SIDEBAR_TREE__.update(s) : {ok:false,code:'NO_CONTROLLER'};"
            "})()"
            % json.dumps(json.dumps(snap, ensure_ascii=True))
        )
        res = ws.call("Runtime.evaluate", {"expression": expr, "awaitPromise": True, "returnByValue": True})
        val = res.get("result", {}).get("value")
        out = val if isinstance(val, dict) else {}
        if out.get("ok"):
            self.pushed_rev[tid] = snap["projectionRevision"]
        return out

    def poll_ui_actions(self, ws: CdpSocket) -> list[dict[str, Any]]:
        res = ws.call(
            "Runtime.evaluate",
            {
                "expression": (
                    "window.__SS_SIDEBAR_TREE__ && typeof window.__SS_SIDEBAR_TREE__.drainActions === 'function' "
                    "? window.__SS_SIDEBAR_TREE__.drainActions() : []"
                ),
                "returnByValue": True,
            },
        )
        actions = res.get("result", {}).get("value")
        if not isinstance(actions, list) or not actions:
            return []

        from driver import ZCodeDriver
        from engine import Engine

        receipts: list[dict[str, Any]] = []
        with open_store(self.root, writable=True) as store:
            eng = Engine(store, runtime_execution="deferred", driver=ZCodeDriver())
            for act in actions[:16]:
                if not isinstance(act, dict):
                    continue
                kind = str(act.get("kind") or "")
                receipt = eng.execute_ui_action(kind, act)
                receipts.append(receipt)

        if receipts:
            ack_expr = (
                "window.__SS_SIDEBAR_TREE__ && typeof window.__SS_SIDEBAR_TREE__.ackActions === 'function' "
                "&& window.__SS_SIDEBAR_TREE__.ackActions(JSON.parse(%s))"
                % json.dumps(json.dumps(receipts, ensure_ascii=True))
            )
            ws.call("Runtime.evaluate", {"expression": ack_expr, "returnByValue": True})
        return receipts

    def _destroy_and_drop_all(self) -> None:
        for tid, ws in list(self.sessions.items()):
            old_sid = self.script_ids.pop(tid, None)
            if old_sid:
                try:
                    ws.call("Page.removeScriptToEvaluateOnNewDocument", {"identifier": old_sid})
                except Exception:
                    pass
            try:
                ws.call(
                    "Runtime.evaluate",
                    {
                        "expression": (
                            "try { window.__SS_SIDEBAR_TREE__ && window.__SS_SIDEBAR_TREE__.destroy(); "
                            "delete window.__SS_ZCODE_ADAPTER__; } catch (_) {}"
                        ),
                        "returnByValue": True,
                    },
                )
            except Exception:
                pass
        self.drop_all()

    def status(self, ws: CdpSocket) -> dict[str, Any]:
        res = ws.call(
            "Runtime.evaluate",
            {
                "expression": (
                    "window.__SS_SIDEBAR_TREE__ && window.__SS_SIDEBAR_TREE__.alive "
                    "? Object.assign({ alive: true }, window.__SS_SIDEBAR_TREE__.getStatus() || {}) : {}"
                ),
                "returnByValue": True,
            },
        )
        val = res.get("result", {}).get("value")
        return val if isinstance(val, dict) else {}

    def loop_once(self) -> None:
        gen = current_app()
        if gen is None:
            self.drop_all()
            self.health = {"state": "WAITING_FOR_APP"}
            return
        if self.gen and gen.key != self.gen.key:
            self.drop_all()
            self.health["state"] = "RECONNECTING"
        self.gen = gen
        self.health["state"] = "DISCOVER_ENDPOINT"
        ep = verify_endpoint(gen)
        if not ep["ok"]:
            self.health = {"state": "WAITING_FOR_DEBUG_LAUNCH", "endpoint": ep, "app": gen.key}
            self.on_no_endpoint(gen)
            return
        self.health["state"] = "VERIFY_BUILD"
        entry = self.build_entry()
        if not entry:
            self._destroy_and_drop_all()
            self.health = {
                "state": "UNSUPPORTED_VERSION",
                "app": gen.key,
                "buildError": self.last_build_error,
            }
            return
        src = self.payload(entry["adapter"])
        src_sha = hashlib.sha256(src.encode("utf-8")).hexdigest()
        self.health["state"] = "ATTACH_TARGETS"
        self.attach(ep["port"], entry)
        snap = self.reader.snapshot()
        statuses: dict[str, dict[str, Any]] = {}
        for tid, ws in list(self.sessions.items()):
            try:
                needs_reinject = False
                for ev in ws.poll_events(0):
                    if ev.get("method") in ("Runtime.executionContextCreated", "Page.frameNavigated"):
                        self.pushed_rev.pop(tid, None)
                    if ev.get("method") in ("Inspector.detached", "Target.targetDestroyed"):
                        raise CdpError("detached")
                push_res = self.push(tid, ws, snap)
                if push_res.get("code") == "NO_CONTROLLER":
                    needs_reinject = True
                else:
                    actions_handled = self.poll_ui_actions(ws)
                    if actions_handled:
                        snap = self.reader.snapshot()
                        push_res = self.push(tid, ws, snap)
                        if push_res.get("code") == "NO_CONTROLLER":
                            needs_reinject = True
                st = {} if needs_reinject else self.status(ws)
                if needs_reinject or not st or st.get("alive") is not True:
                    self.payload_shas.pop(tid, None)
                    self.pushed_rev.pop(tid, None)
                    self.attach(tid, ws, src, src_sha)
                    self.push(tid, ws, snap)
                    st = self.status(ws)
                statuses[tid] = st
            except (CdpError, OSError):
                old_ws = self.sessions.pop(tid, None)
                if old_ws:
                    old_ws.close()
                self.script_ids.pop(tid, None)
                self.payload_shas.pop(tid, None)
                self.pushed_rev.pop(tid, None)
        ready = bool(statuses) and all(
            s.get("sidebarFound") and s.get("navigatorResolved") for s in statuses.values()
        )
        self.health = {
            "state": "READY" if ready else "WAITING_FOR_SIDEBAR",
            "app": gen.key,
            "endpoint": ep,
            "adapterId": entry["adapter"],
            "projectionRevision": snap["projectionRevision"],
            "targets": statuses,
        }

    def on_no_endpoint(self, gen: AppGen) -> None:
        from sidebar_ui_ctl import LaunchGuard, try_sigusr1_inject  # noqa: E402

        entry = self.build_entry()
        if entry and entry.get("sigusr1Inspector") == "ok":
            src = self.payload(entry["adapter"])
            src_sha = hashlib.sha256(src.encode("utf-8")).hexdigest()
            snap = self.reader.snapshot()
            rev = int(snap.get("projectionRevision") or 0)
            now = time.time()
            cached = self.l1_cache.get(gen.key)
            if (
                cached
                and cached.get("rev") == rev
                and cached.get("src_sha") == src_sha
                and (now - float(cached.get("ts") or 0.0)) < self.L1_CACHE_TTL_SEC
            ):
                l1_res = cached["res"]
            else:
                l1_res = try_sigusr1_inject(gen, entry, src, snap)
                if l1_res.get("ok"):
                    targets_chk = l1_res.get("targets") if isinstance(l1_res.get("targets"), dict) else {}
                    ready_chk = (
                        all(s.get("sidebarFound") and s.get("navigatorResolved") for s in targets_chk.values())
                        if targets_chk
                        else True
                    )
                    if ready_chk:
                        self.l1_cache[gen.key] = {
                            "rev": rev,
                            "src_sha": src_sha,
                            "ts": now,
                            "res": l1_res,
                        }
                    else:
                        self.l1_cache.pop(gen.key, None)
                else:
                    self.l1_cache.pop(gen.key, None)
            self.health["sigusr1"] = l1_res
            if l1_res.get("ok"):
                targets = l1_res.get("targets") if isinstance(l1_res.get("targets"), dict) else {}
                ready = (
                    all(s.get("sidebarFound") and s.get("navigatorResolved") for s in targets.values())
                    if targets
                    else True
                )
                self.health["state"] = "READY" if ready else "WAITING_FOR_SIDEBAR"
                self.health["adapterId"] = entry["adapter"]
                self.health["projectionRevision"] = rev
                self.health["targets"] = targets
                return
        self.health["launchGuard"] = LaunchGuard(self.root).step(gen)

    def drop_all(self) -> None:
        for ws in self.sessions.values():
            try:
                ws.close()
            except OSError:
                pass
        self.sessions.clear()
        self.script_ids.clear()
        self.payload_shas.clear()
        self.pushed_rev.clear()
        self.l1_cache.clear()

    def serve(self, interval: float = 1.0, once: bool = False) -> int:
        rt_dir = self.ui_dir / "runtime"
        rt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock = open(rt_dir / "injector.lock", "w", encoding="utf-8")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({"ok": True, "mode": "already_running"}))
            return 0
        try:
            while True:
                cfg_file = self.ui_dir / "config.json"
                if cfg_file.exists():
                    try:
                        cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
                        if not cfg.get("sidebar", {}).get("enabled", True):
                            break
                    except Exception:
                        pass
                try:
                    self.loop_once()
                    self.health.pop("lastError", None)
                except Exception as e:
                    self.health["lastError"] = repr(e)[:500]
                self.health["ts"] = time.time()
                atomic_write_json(self.ui_dir / "health.json", self.health)
                if once:
                    break
                time.sleep(interval if self.health.get("state") == "READY" else 3.0)
        finally:
            self.drop_all()
            self.reader.close()
            try:
                lock.close()
            except OSError:
                pass
        return 0


def uninject_active_targets(port: int, main_url_prefix: str = MAIN_URL) -> dict[str, Any]:
    """Connect to active CDP page targets, run __SS_SIDEBAR_TREE__.destroy(), and clean globals."""
    cleaned = 0
    errors: list[str] = []
    try:
        targets = cdp_http_get_json(port, "/json/list", timeout=3.0)
    except OSError as e:
        return {"ok": False, "code": "HTTP_FAILED", "detail": str(e), "cleaned": 0}
    pages = [
        t
        for t in (targets if isinstance(targets, list) else [])
        if t.get("type") == "page"
        and str(t.get("url", "")).startswith(main_url_prefix)
        and not any(x in str(t.get("url", "")) for x in EXCLUDE)
    ]
    for t in pages:
        ws_url = str(t.get("webSocketDebuggerUrl") or "")
        if not ws_url:
            continue
        try:
            ws = CdpSocket(ws_url, timeout=3.0)
            try:
                ws.call("Runtime.enable")
                ws.call(
                    "Runtime.evaluate",
                    {
                        "expression": (
                            "(() => { "
                            "if (window.__SS_SIDEBAR_TREE__ && window.__SS_SIDEBAR_TREE__.destroy) { "
                            "  window.__SS_SIDEBAR_TREE__.destroy(); "
                            "} "
                            "if (window.__SS_ZCODE_ADAPTER__ && window.__SS_ZCODE_ADAPTER__.restoreDedup) { "
                            "  window.__SS_ZCODE_ADAPTER__.restoreDedup(); "
                            "} "
                            "delete window.__SS_ZCODE_ADAPTER__; "
                            "return true; "
                            "})()"
                        ),
                        "returnByValue": True,
                    },
                )
                cleaned += 1
            finally:
                ws.close()
        except Exception as e:
            errors.append(str(e))
    return {"ok": len(errors) == 0, "cleaned": cleaned, "errors": errors}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ZCode in-place sidebar tree CDP injector daemon")
    sub = parser.add_subparsers(dest="cmd")

    p_serve = sub.add_parser("serve", help="Run long-lived CDP sidebar injector loop")
    p_serve.add_argument("--state-home", default=None, help="State root directory")
    p_serve.add_argument("--release", default=None, help="Release directory containing ui/ and scripts/")
    p_serve.add_argument("--interval", type=float, default=1.0, help="Poll interval when READY")
    p_serve.add_argument("--once", action="store_true", help="Run a single reconciliation pass and exit")

    p_status = sub.add_parser("status", help="Read current injector health.json")
    p_status.add_argument("--state-home", default=None, help="State root directory")

    args = parser.parse_args(argv)
    cmd = args.cmd or "serve"
    state_root = Path(getattr(args, "state_home", None) or resolve_state_root()).expanduser().resolve()

    if cmd == "status":
        hp = state_root / "sidebar-ui" / "health.json"
        if hp.is_file():
            print(hp.read_text(encoding="utf-8"))
        else:
            print(json.dumps({"state": "NOT_RUNNING"}, indent=2))
        return 0

    release_dir = Path(args.release).expanduser().resolve() if getattr(args, "release", None) else HERE.parent
    inj = Injector(state_root=state_root, release_dir=release_dir)
    return inj.serve(interval=float(getattr(args, "interval", 1.0)), once=bool(getattr(args, "once", False)))


if __name__ == "__main__":
    sys.exit(main())
