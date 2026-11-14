from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
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


def safe_app_gen(app_gen: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(app_gen or "unknown"))


def _is_safe_action_id(action_id: Any) -> bool:
    return isinstance(action_id, str) and bool(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", action_id))


def _read_regular_owned_json(path: Path, *, max_bytes: int = 65536) -> dict[str, Any] | None:
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), os.O_RDONLY | o_nofollow)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_size > max_bytes:
            return None
        try:
            lst = os.lstat(path)
        except OSError:
            return None
        if stat.S_ISLNK(lst.st_mode) or (lst.st_dev, lst.st_ino) != (st.st_dev, st.st_ino):
            return None
        chunks: list[bytes] = []
        off = 0
        while True:
            part = os.pread(fd, 65536, off)
            if not part:
                break
            chunks.append(part)
            off += len(part)
            if off > max_bytes:
                return None
        parsed = json.loads(b"".join(chunks).decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _atomic_write_private_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    p_lst = os.lstat(path.parent)
    if stat.S_ISLNK(p_lst.st_mode) or not stat.S_ISDIR(p_lst.st_mode) or p_lst.st_uid != os.getuid():
        raise OSError(f"Unsafe mailbox directory: {path.parent}")
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    tmp = path.parent / f".{path.name}.{os.getpid()}.tmp"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | o_nofollow, 0o600)
    try:
        payload = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        os.write(fd, payload)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def execute_ui_actions(state_root: Path, actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Shared business action executor for both CDP and L1 bridge file mailbox."""
    if not isinstance(actions, list) or not actions:
        return []
    from driver import ZCodeDriver
    from engine import Engine

    receipts: list[dict[str, Any]] = []
    with open_store(state_root, writable=True) as store:
        eng = Engine(store, runtime_execution="deferred", driver=ZCodeDriver())
        for act in actions[:16]:
            if not isinstance(act, dict):
                continue
            kind = str(act.get("kind") or "")
            receipt = eng.execute_ui_action(kind, act)
            receipts.append(receipt)
    return receipts


def atomic_write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


class Injector:
    BRIDGE_HANDSHAKE_STALE_SEC = 10.0
    BRIDGE_RETRY_BACKOFF_SEC = 10.0
    CONTRACT_ID = "sidebar-list-v1"

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
        self.pushed_version: dict[str, tuple[str, int]] = {}
        self.bridge_bootstrapped: dict[str, dict[str, Any]] = {}
        self.last_asar_sha: str = ""
        self.last_build_error: str | None = None
        self.last_probe: dict[str, Any] | None = None
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

    def bridge_source(self) -> str:
        return (self.rel / "ui" / "main_bridge.js").read_text(encoding="utf-8")

    def probe_build(self, asar_path: Path = ASAR) -> dict[str, Any]:
        import asar_cdp_patch

        self.reload_compat()
        builds = self.compat.get("builds", {})
        manifest_p = self.ui_dir / "backups" / "asar_patch.json"
        probe = asar_cdp_patch.probe_runtime_build(
            asar_path,
            manifest_p,
            builds,
            cache=self._asar_sha_cache,
            app_gen=self.gen.key if self.gen else None,
        )
        self.last_probe = probe
        self.last_asar_sha = str(probe.get("asarSha") or "")
        codes = (probe.get("diagnostics") or {}).get("codes") or []
        self.last_build_error = None if probe.get("ok") else (str(codes[0]) if codes else "BUILD_REJECTED")
        return probe

    def build_entry(self, asar_path: Path = ASAR) -> dict[str, Any] | None:
        probe = self.probe_build(asar_path)
        if not probe.get("ok") or probe.get("buildState") == "rejected":
            return None
        adapter = probe.get("adapterCandidate") or "zcode-3.17.2"
        return {
            "adapter": str(adapter),
            "buildState": probe.get("buildState"),
            "patchState": probe.get("patchState"),
            "fuse": probe.get("fuse") or {},
            "signature": probe.get("signature") or {},
        }

    def _attach_target(self, tid: str, ws: CdpSocket, src: str, src_sha: str) -> None:
        old_sid = self.script_ids.pop(tid, None)
        if old_sid:
            try:
                ws.call("Page.removeScriptToEvaluateOnNewDocument", {"identifier": old_sid})
            except CdpError:
                pass
        # Check if an identical bundle is already alive (e.g. handoff from L1 main_bridge -> CDP)
        # so unfinished actionIds in actionQueue are preserved across transport switch.
        already_same = False
        try:
            chk = ws.call(
                "Runtime.evaluate",
                {
                    "expression": (
                        f"Boolean(window.__SS_SIDEBAR_TREE__ && window.__SS_SIDEBAR_TREE__.alive "
                        f"&& window.__SS_PAYLOAD_SHA__ === {json.dumps(src_sha)})"
                    ),
                    "returnByValue": True,
                },
            )
            already_same = bool(chk.get("result", {}).get("value"))
        except Exception:
            already_same = False

        doc_src = (
            src
            + "\n;\n"
            + f"window.__SS_PAYLOAD_SHA__ = {json.dumps(src_sha)};\n"
            + "window.__SS_TRANSPORT_OWNER__ = 'cdp';\n"
        )
        doc_res = ws.call("Page.addScriptToEvaluateOnNewDocument", {"source": doc_src})
        if isinstance(doc_res, dict) and doc_res.get("identifier"):
            self.script_ids[tid] = str(doc_res["identifier"])

        if not already_same:
            # Drain any unfinished actions before hot-swap destroy so no actionId is dropped
            try:
                drained_res = ws.call(
                    "Runtime.evaluate",
                    {
                        "expression": (
                            "window.__SS_SIDEBAR_TREE__ && typeof window.__SS_SIDEBAR_TREE__.drainActions === 'function' "
                            "? window.__SS_SIDEBAR_TREE__.drainActions() : []"
                        ),
                        "returnByValue": True,
                    },
                )
                drained_acts = drained_res.get("result", {}).get("value")
                if isinstance(drained_acts, list) and drained_acts:
                    execute_ui_actions(self.root, drained_acts)
            except Exception:
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
            res = ws.call("Runtime.evaluate", {"expression": src, "returnByValue": True})
            if "exceptionDetails" in res:
                raise CdpError(f"inject exception: {res['exceptionDetails'].get('text')}")

        ws.call(
            "Runtime.evaluate",
            {
                "expression": (
                    f"window.__SS_PAYLOAD_SHA__ = {json.dumps(src_sha)}; "
                    "window.__SS_TRANSPORT_OWNER__ = 'cdp';"
                ),
                "returnByValue": True,
            },
        )
        self.sessions[tid] = ws
        self.payload_shas[tid] = src_sha
        self.pushed_version.pop(tid, None)

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
                self.pushed_version.pop(stale_tid, None)

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
        snap_key = (str(snap.get("storeInstanceId") or ""), int(snap.get("projectionRevision") or 0))
        if self.pushed_version.get(tid) == snap_key:
            return {"ok": True, "unchanged": True}
        validate_public_projection(snap)
        # 快照双重 json.dumps：作为 JS 字符串字面量传入后 JSON.parse，禁止把标题拼成代码
        expr = (
            "(async () => {"
            "  const s = JSON.parse(%s);"
            "  const a = window.__SS_ZCODE_ADAPTER__;"
            "  const st = a && typeof a.selfTest === 'function' ? a.selfTest() : null;"
            "  if ((!st || !st.capabilities || st.capabilities.hostIndexSync !== false) && a && a.syncUnindexedNodes) {"
            "    try { await a.syncUnindexedNodes(s); } catch (_) {}"
            "  }"
            "  return window.__SS_SIDEBAR_TREE__ ? window.__SS_SIDEBAR_TREE__.update(s) : {ok:false,code:'NO_CONTROLLER'};"
            "})()"
            % json.dumps(json.dumps(snap, ensure_ascii=True))
        )
        res = ws.call("Runtime.evaluate", {"expression": expr, "awaitPromise": True, "returnByValue": True})
        val = res.get("result", {}).get("value")
        out = val if isinstance(val, dict) else {}
        if out.get("ok"):
            self.pushed_version[tid] = snap_key
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

        receipts = execute_ui_actions(self.root, actions)

        if receipts:
            ack_expr = (
                "window.__SS_SIDEBAR_TREE__ && typeof window.__SS_SIDEBAR_TREE__.ackActions === 'function' "
                "&& window.__SS_SIDEBAR_TREE__.ackActions(JSON.parse(%s))"
                % json.dumps(json.dumps(receipts, ensure_ascii=True))
            )
            ws.call("Runtime.evaluate", {"expression": ack_expr, "returnByValue": True})
        return receipts

    def _set_transport_owner(self, gen: AppGen, owner: str) -> None:
        rt_dir = self.ui_dir / "runtime" / safe_app_gen(gen.key)
        if not rt_dir.is_dir() or rt_dir.is_symlink():
            return
        try:
            _atomic_write_private_json(
                rt_dir / "transport_owner.json",
                {
                    "schemaVersion": 1,
                    "appGen": gen.key,
                    "owner": owner,
                    "updatedAt": time.time(),
                },
            )
        except OSError:
            pass

    def _read_handshake(self, gen: AppGen) -> dict[str, Any] | None:
        hs_path = self.ui_dir / "runtime" / safe_app_gen(gen.key) / "handshake.json"
        return _read_regular_owned_json(hs_path, max_bytes=1024 * 1024)

    def _consume_bridge_mailbox(
        self,
        gen: AppGen,
        handshake: dict[str, Any] | None,
        snap: dict[str, Any],
        *,
        now_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        rt_dir = self.ui_dir / "runtime" / safe_app_gen(gen.key)
        actions_dir = rt_dir / "actions"
        receipts_dir = rt_dir / "receipts"
        if not rt_dir.is_dir() or rt_dir.is_symlink():
            return []
        if not actions_dir.is_dir() or actions_dir.is_symlink():
            return []
        if receipts_dir.is_symlink():
            return []

        hs = handshake if isinstance(handshake, dict) else self._read_handshake(gen)
        hs_valid = (
            isinstance(hs, dict)
            and hs.get("active") is True
            and hs.get("appGen") == gen.key
            and bool(hs.get("bootNonce"))
        )
        boot_nonce = str(hs.get("bootNonce") or "") if hs_valid else ""
        windows = hs.get("windows") if (hs_valid and isinstance(hs.get("windows"), dict)) else {}
        cur_store_id = str(snap.get("storeInstanceId") or "")
        cur_ms = int(time.time() * 1000) if now_ms is None else int(now_ms)

        written: list[dict[str, Any]] = []
        per_win_count: dict[str, int] = {}

        try:
            entries = sorted(actions_dir.iterdir(), key=lambda p: p.name)
        except OSError:
            return []

        for act_path in entries:
            if act_path.name.startswith(".") or not act_path.name.endswith(".json"):
                continue
            env = _read_regular_owned_json(act_path, max_bytes=65536)
            if not env:
                continue
            action_id = env.get("actionId")
            if not _is_safe_action_id(action_id) or act_path.name != f"{action_id}.json":
                continue

            receipt_path = receipts_dir / f"{action_id}.json"
            try:
                os.lstat(receipt_path)
                # Receipt already exists -> idempotent skip
                continue
            except OSError:
                pass

            wc_key = str(env.get("webContentsId"))
            if per_win_count.get(wc_key, 0) >= 16:
                continue
            per_win_count[wc_key] = per_win_count.get(wc_key, 0) + 1

            act = env.get("action")
            fail_code: str | None = None
            if env.get("appGen") != gen.key:
                fail_code = "STALE_APP_GEN"
            elif not hs_valid or not boot_nonce or env.get("bootNonce") != boot_nonce:
                fail_code = "STALE_BOOT_NONCE"
            else:
                win = windows.get(wc_key)
                if (
                    not isinstance(win, dict)
                    or not isinstance(env.get("rendererEpoch"), int)
                    or isinstance(env.get("rendererEpoch"), bool)
                    or env.get("rendererEpoch") != win.get("rendererEpoch")
                ):
                    fail_code = "STALE_RENDERER_EPOCH"
                elif cur_store_id and str(env.get("storeInstanceId") or "") != cur_store_id:
                    fail_code = "STALE_STORE_INSTANCE"
                else:
                    deadline_at = env.get("deadlineAt")
                    if (
                        not isinstance(deadline_at, (int, float))
                        or isinstance(deadline_at, bool)
                        or cur_ms > float(deadline_at)
                    ):
                        fail_code = "ACTION_EXPIRED"
                    elif (
                        not isinstance(act, dict)
                        or str(act.get("actionId") or act.get("action_id") or "") != action_id
                    ):
                        fail_code = "INVALID_ACTION_ENVELOPE"

            if fail_code is not None:
                receipt: dict[str, Any] = {
                    "schemaVersion": 1,
                    "actionId": action_id,
                    "ok": False,
                    "code": fail_code,
                    "message": f"Action rejected before execution: {fail_code}",
                    "kind": str(act.get("kind") or "") if isinstance(act, dict) else "",
                    "nodeId": str(act.get("nodeId") or "") if isinstance(act, dict) else "",
                    "appGen": env.get("appGen"),
                    "bootNonce": env.get("bootNonce"),
                    "webContentsId": env.get("webContentsId"),
                    "rendererEpoch": env.get("rendererEpoch"),
                    "storeInstanceId": env.get("storeInstanceId"),
                    "executedAt": cur_ms,
                }
            else:
                assert isinstance(act, dict)
                res_list = execute_ui_actions(self.root, [act])
                base_rcpt = (
                    dict(res_list[0])
                    if res_list
                    else {"actionId": action_id, "ok": False, "code": "EMPTY_RECEIPT"}
                )
                receipt = {
                    **base_rcpt,
                    "schemaVersion": 1,
                    "actionId": action_id,
                    "appGen": env.get("appGen"),
                    "bootNonce": env.get("bootNonce"),
                    "webContentsId": env.get("webContentsId"),
                    "rendererEpoch": env.get("rendererEpoch"),
                    "storeInstanceId": env.get("storeInstanceId"),
                    "executedAt": cur_ms,
                }

            try:
                _atomic_write_private_json(receipt_path, receipt)
                written.append(receipt)
            except OSError:
                pass

        return written

    def _build_health(
        self,
        *,
        gen: AppGen,
        transport: str,
        transport_ok: bool,
        adapter_id: str | None,
        source_sha: str | None,
        bundle_sha: str | None,
        snap: dict[str, Any],
        targets: dict[str, dict[str, Any]],
        endpoint: dict[str, Any] | None = None,
        sigusr1: dict[str, Any] | None = None,
        handshake: dict[str, Any] | None = None,
        launch_guard: dict[str, Any] | None = None,
        extra_degradations: list[str] | None = None,
    ) -> dict[str, Any]:
        degradation_reasons: list[str] = list(extra_degradations or [])
        probe = self.last_probe or {}

        agg_caps: dict[str, bool] = {
            "mount": False,
            "navigation": False,
            "chatViewport": False,
            "hostIndexSync": False,
            "dedup": False,
            "actions": bool(transport_ok),
        }
        all_targets_ready = bool(targets)
        any_unsupported = False
        total_pending = 0

        for st in targets.values():
            if not isinstance(st, dict):
                all_targets_ready = False
                continue
            total_pending += int(st.get("pendingActions") or 0)
            st_test = st.get("selfTest") if isinstance(st.get("selfTest"), dict) else None
            caps = (
                st_test.get("capabilities")
                if st_test and isinstance(st_test.get("capabilities"), dict)
                else {}
            )
            mount_ok = bool(caps.get("mount", st.get("sidebarFound")))
            nav_ok = bool(caps.get("navigation", st.get("navigatorResolved")))
            agg_caps["mount"] = agg_caps["mount"] or mount_ok
            agg_caps["navigation"] = agg_caps["navigation"] or nav_ok
            agg_caps["chatViewport"] = agg_caps["chatViewport"] or bool(caps.get("chatViewport", mount_ok))
            agg_caps["hostIndexSync"] = agg_caps["hostIndexSync"] or bool(caps.get("hostIndexSync", True))
            agg_caps["dedup"] = agg_caps["dedup"] or bool(caps.get("dedup", True))

            if st.get("alive") is not True or not mount_ok or not nav_ok:
                all_targets_ready = False
            if st_test:
                t_state = st_test.get("state")
                if t_state == "unsupported":
                    any_unsupported = True
                    all_targets_ready = False
                elif t_state != "ready":
                    all_targets_ready = False

            dedup_list = st.get("dedup")
            if isinstance(dedup_list, list) and any(
                isinstance(d, str) and d.startswith("disabled:") for d in dedup_list
            ):
                if "DEDUP_DISABLED" not in degradation_reasons:
                    degradation_reasons.append("DEDUP_DISABLED")

        if not transport_ok:
            if transport == "bridge":
                code = str((sigusr1 or {}).get("code") or "BRIDGE_UNHEALTHY")
                if code not in degradation_reasons:
                    degradation_reasons.append(code)
            state = "BRIDGE_ERROR" if sigusr1 and not sigusr1.get("ok") else "WAITING_FOR_DEBUG_LAUNCH"
        elif any_unsupported:
            state = "UNSUPPORTED_VERSION"
            if "ADAPTER_UNSUPPORTED" not in degradation_reasons:
                degradation_reasons.append("ADAPTER_UNSUPPORTED")
        elif all_targets_ready:
            state = "READY"
        else:
            state = "WAITING_FOR_SIDEBAR"
            if not targets and "NO_QUALIFIED_WINDOWS" not in degradation_reasons:
                degradation_reasons.append("NO_QUALIFIED_WINDOWS")

        return {
            "state": state,
            "app": gen.key,
            "appGen": gen.key,
            "sourceSha": source_sha,
            "bundleSha": bundle_sha,
            "contractId": self.CONTRACT_ID,
            "transport": transport,
            "adapterId": adapter_id,
            "buildState": probe.get("buildState"),
            "patchState": probe.get("patchState"),
            "capabilities": agg_caps,
            "degradationReasons": degradation_reasons,
            "snapshot": {
                "storeInstanceId": str(snap.get("storeInstanceId") or ""),
                "projectionRevision": int(snap.get("projectionRevision") or 0),
            },
            "projectionRevision": int(snap.get("projectionRevision") or 0),
            "pendingActions": total_pending,
            "lastHandshakeAt": handshake.get("updatedAt") if isinstance(handshake, dict) else None,
            "targets": targets,
            **({"endpoint": endpoint} if endpoint is not None else {}),
            **({"sigusr1": sigusr1} if sigusr1 is not None else {}),
            **({"launchGuard": launch_guard} if launch_guard is not None else {}),
        }

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
            self.health = {"state": "WAITING_FOR_APP", "transport": "none", "contractId": self.CONTRACT_ID}
            return
        if self.gen and gen.key != self.gen.key:
            self.drop_all()
            self.health["state"] = "RECONNECTING"
        self.gen = gen
        self.health["state"] = "DISCOVER_ENDPOINT"
        ep = verify_endpoint(gen)
        if not ep["ok"]:
            self.drop_all()
            self.health = {
                "state": "WAITING_FOR_DEBUG_LAUNCH",
                "endpoint": ep,
                "app": gen.key,
                "appGen": gen.key,
                "transport": "none",
                "contractId": self.CONTRACT_ID,
            }
            self.on_no_endpoint(gen)
            return
        self.health["state"] = "VERIFY_BUILD"
        entry = self.build_entry()
        if not entry:
            self._destroy_and_drop_all()
            self.health = {
                "state": "UNSUPPORTED_VERSION",
                "app": gen.key,
                "appGen": gen.key,
                "transport": "none",
                "contractId": self.CONTRACT_ID,
                "buildError": self.last_build_error,
                "buildState": (self.last_probe or {}).get("buildState"),
                "patchState": (self.last_probe or {}).get("patchState"),
            }
            return
        self._set_transport_owner(gen, "cdp")
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
                        self.pushed_version.pop(tid, None)
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
                    self.pushed_version.pop(tid, None)
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
                self.pushed_version.pop(tid, None)
        self.health = self._build_health(
            gen=gen,
            transport="cdp",
            transport_ok=True,
            adapter_id=entry["adapter"],
            source_sha=src_sha,
            bundle_sha=src_sha,
            snap=snap,
            targets=statuses,
            endpoint=ep,
        )

    def on_no_endpoint(self, gen: AppGen) -> None:
        from sidebar_ui_ctl import LaunchGuard, ensure_sigusr1_bridge  # noqa: E402

        probe = self.probe_build()
        snap = self.reader.snapshot()
        entry = self.build_entry() if probe.get("ok") and probe.get("buildState") != "rejected" else None
        fuse = probe.get("fuse") or {}

        if entry and fuse.get("found") and fuse.get("nodeCliInspect"):
            bundle_src = self.payload(entry["adapter"])
            bridge_src = self.bridge_source()
            bundle_sha = hashlib.sha256(bundle_src.encode("utf-8")).hexdigest()
            combined_sha = hashlib.sha256((bridge_src + "\n" + bundle_src).encode("utf-8")).hexdigest()

            self._set_transport_owner(gen, "bridge")
            hs = self._read_handshake(gen)
            now = time.time()
            hs_fresh = (
                isinstance(hs, dict)
                and hs.get("active") is True
                and hs.get("appGen") == gen.key
                and hs.get("sourceSha") == combined_sha
                and (now - float(hs.get("updatedAt") or 0.0)) < self.BRIDGE_HANDSHAKE_STALE_SEC
            )

            boot_rec = self.bridge_bootstrapped.get(gen.key)
            should_bootstrap = False
            if not boot_rec or boot_rec.get("sourceSha") != combined_sha:
                should_bootstrap = True
            elif not hs_fresh:
                # Re-bootstrap only if handshake is missing/stale/dead AND not in short error backoff
                if (now - float(boot_rec.get("ts") or 0.0)) >= self.BRIDGE_RETRY_BACKOFF_SEC:
                    should_bootstrap = True

            if should_bootstrap:
                l1_res = ensure_sigusr1_bridge(
                    gen,
                    bridge_src,
                    bundle_src,
                    {
                        "stateRoot": str(self.root),
                        "adapterId": entry["adapter"],
                        "contractId": self.CONTRACT_ID,
                        "probeResult": probe,
                        "builds": self.compat.get("builds", {}),
                    },
                )
                self.bridge_bootstrapped[gen.key] = {
                    "sourceSha": combined_sha,
                    "bundleSha": bundle_sha,
                    "ts": now,
                    "res": l1_res,
                }
                hs = self._read_handshake(gen)
            else:
                l1_res = boot_rec["res"]

            if l1_res.get("ok"):
                self._consume_bridge_mailbox(gen, hs, snap)
                snap = self.reader.snapshot()
                hs = self._read_handshake(gen)
                hs_fresh_now = (
                    isinstance(hs, dict)
                    and hs.get("active") is True
                    and hs.get("appGen") == gen.key
                    and hs.get("sourceSha") == combined_sha
                    and (time.time() - float(hs.get("updatedAt") or 0.0)) < self.BRIDGE_HANDSHAKE_STALE_SEC
                )
                targets_map: dict[str, dict[str, Any]] = {}
                if isinstance(hs, dict) and isinstance(hs.get("windows"), dict):
                    for wid, winfo in hs["windows"].items():
                        if not isinstance(winfo, dict):
                            continue
                        st = dict(winfo.get("status") or {})
                        if "alive" not in st:
                            st["alive"] = bool(winfo.get("alive"))
                        if winfo.get("capabilities") and "selfTest" not in st:
                            st["selfTest"] = {
                                "state": winfo.get("selfTestState") or "waiting",
                                "capabilities": winfo.get("capabilities"),
                                "diagnostics": winfo.get("diagnostics") or {},
                            }
                        targets_map[str(wid)] = st
                extra_deg = [] if hs_fresh_now else ["HANDSHAKE_STALE_OR_MISSING"]
                self.health = self._build_health(
                    gen=gen,
                    transport="bridge",
                    transport_ok=hs_fresh_now,
                    adapter_id=entry["adapter"],
                    source_sha=combined_sha,
                    bundle_sha=bundle_sha,
                    snap=snap,
                    targets=targets_map,
                    endpoint=self.health.get("endpoint"),
                    sigusr1=l1_res,
                    handshake=hs,
                    extra_degradations=extra_deg,
                )
                return

            self.health = self._build_health(
                gen=gen,
                transport="bridge",
                transport_ok=False,
                adapter_id=entry["adapter"],
                source_sha=combined_sha,
                bundle_sha=bundle_sha,
                snap=snap,
                targets={},
                endpoint=self.health.get("endpoint"),
                sigusr1=l1_res,
                handshake=hs,
                launch_guard=LaunchGuard(self.root).step(gen),
            )
            return

        if entry is None:
            self.health["state"] = "UNSUPPORTED_VERSION"
            self.health["buildError"] = self.last_build_error
            self.health["buildState"] = probe.get("buildState")
            self.health["patchState"] = probe.get("patchState")
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
        self.pushed_version.clear()
        self.bridge_bootstrapped.clear()

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
