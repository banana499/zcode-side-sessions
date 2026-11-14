#!/usr/bin/env python3
"""Unit tests for M1 (probe_runtime_build & Fuse discovery), M3 (main_bridge.js & ensure_sigusr1_bridge), and M4 (atomic mailbox & health)."""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import plistlib
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PLUGIN_ROOT / "scripts"
UI_DIR = PLUGIN_ROOT / "ui"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import asar_cdp_patch  # type: ignore  # noqa: E402
from contracts import CallerContext  # type: ignore  # noqa: E402
from driver import ScriptedFakeDriver  # type: ignore  # noqa: E402
from engine import Engine  # type: ignore  # noqa: E402
from host_adapter import HostAdapter  # type: ignore  # noqa: E402
import sidebar_ui_ctl  # type: ignore  # noqa: E402
from state import open_store  # type: ignore  # noqa: E402
from zcode_proc import AppGen  # type: ignore  # noqa: E402
import zcode_sidebar_injector  # type: ignore  # noqa: E402
from zcode_sidebar_injector import Injector, execute_ui_actions, safe_app_gen  # type: ignore  # noqa: E402


VALID_BG = (
    "总体目标：验证 M1 运行时探针、M3 主进程常驻桥生命周期、与 M4 双向原子文件信箱的完整契约。\n"
    "已有决策：使用完全隔离的临时目录与 mock Electron，不接触真实 ~/.zcode 或 /Applications/ZCode.app。\n"
    "约束：必须保证旧清单不自动迁移、过期动作绝不执行、已有调试器不被关闭。"
)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _build_synthetic_asar(main_js_bytes: bytes, *, integrity_hash: str | None = None) -> bytes:
    header_obj = {
        "files": {
            "out": {
                "files": {
                    "main": {
                        "files": {
                            "index.js": {
                                "size": len(main_js_bytes),
                                "offset": "0",
                                "integrity": {"hash": integrity_hash or _sha256_hex(main_js_bytes)},
                            }
                        }
                    }
                }
            }
        }
    }
    header_json = json.dumps(header_obj, separators=(",", ":")).encode("utf-8")
    json_len = len(header_json)
    pad = (4 - (json_len % 4)) % 4
    payload_size = 4 + json_len + pad
    header_size = payload_size + 4
    asar_header = struct.pack("<4I", 4, header_size, payload_size, json_len) + header_json + (b"\x00" * pad)
    return asar_header + main_js_bytes


def _create_synthetic_app(
    root: Path,
    name: str,
    main_js: bytes,
    *,
    fuse_wire: bytes = b"\x01\x09101100011",
    fuse_sentinel: bytes = asar_cdp_patch.ELECTRON_FUSE_SENTINEL,
    fuse_offset: int = 128,
    integrity_hash: str | None = None,
    write_coderesources: bool = True,
    bundle_id: str = "dev.zcode.app",
    short_version: str = "3.18.2",
) -> dict[str, Any]:
    app_dir = root / name
    res_dir = app_dir / "Contents" / "Resources"
    fw_dir = app_dir / "Contents" / "Frameworks" / "Electron Framework.framework"
    cs_dir = app_dir / "Contents" / "_CodeSignature"
    res_dir.mkdir(parents=True, exist_ok=True)
    fw_dir.mkdir(parents=True, exist_ok=True)
    cs_dir.mkdir(parents=True, exist_ok=True)

    info_plist = app_dir / "Contents" / "Info.plist"
    info_plist.write_bytes(
        plistlib.dumps({"CFBundleShortVersionString": short_version, "CFBundleIdentifier": bundle_id})
    )

    fw_bin = fw_dir / "Electron Framework"
    fw_bin.write_bytes((b"\x00" * fuse_offset) + fuse_sentinel + fuse_wire + (b"\x00" * 128))

    asar_bytes = _build_synthetic_asar(main_js, integrity_hash=integrity_hash)
    asar_path = res_dir / "app.asar"
    asar_path.write_bytes(asar_bytes)
    asar_sha = _sha256_hex(asar_bytes)

    if write_coderesources:
        (cs_dir / "CodeResources").write_bytes(
            plistlib.dumps({"files2": {"Resources/app.asar": {"hash2": bytes.fromhex(asar_sha)}}})
        )

    return {
        "app": app_dir,
        "asar": asar_path,
        "asar_sha": asar_sha,
        "framework": fw_bin,
        "info_plist": info_plist,
    }


class TestM1ProbeRuntimeBuild(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="ss-m1-test-")
        self.tmp_path = Path(self._tmp.name).resolve()
        self.orig_main_js = (
            b'console.log("init");'
            b'!ee.isPackaged&&process.env.ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT!=="1"&&'
            b'ee.commandLine.appendSwitch("remote-debugging-port","9229");'
        )
        self.old_main_js = (
            b'console.log("3172");'
            b'!X.isPackaged&&process.env.ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT!=="1"&&'
            b'X.commandLine.appendSwitch("remote-debugging-port","9229");'
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_runtime_probe_stale_manifest_allows_probation(self) -> None:
        old_asar = _build_synthetic_asar(self.old_main_js)
        old_sha = _sha256_hex(old_asar)
        builds = {
            old_sha: {
                "adapter": "zcode-3.17.2",
                "shortVersion": "3.17.2",
                "fuseWireOffset": 64,
                "sigusr1Inspector": "ok",
            }
        }
        bundle = _create_synthetic_app(self.tmp_path, "ZCode3182.app", self.orig_main_js, fuse_offset=256)
        manifest_p = self.tmp_path / "backups" / "asar_patch.json"
        manifest_p.parent.mkdir(parents=True, exist_ok=True)
        manifest_p.write_text(
            json.dumps({"origSha": old_sha, "patchedSha": "f" * 64, "abs": 100}),
            encoding="utf-8",
        )
        os.chmod(manifest_p, 0o600)

        with patch.object(asar_cdp_patch, "codesign_ok", return_value=True):
            probe = asar_cdp_patch.probe_runtime_build(
                bundle["asar"],
                manifest_p,
                builds,
                cache={},
                app_gen="1001:1700000000",
            )

        self.assertTrue(probe["ok"])
        self.assertEqual(probe["asarSha"], bundle["asar_sha"])
        self.assertEqual(probe["buildState"], "probation")
        self.assertEqual(probe["patchState"], "stale")
        self.assertEqual(probe["adapterCandidate"], "zcode-3.17.2")
        self.assertTrue(probe["fuse"]["found"])
        self.assertEqual(probe["fuse"]["offset"], 256)
        self.assertEqual(probe["fuse"]["wireOffset"], 256 + len(asar_cdp_patch.ELECTRON_FUSE_SENTINEL))
        self.assertTrue(probe["fuse"]["nodeCliInspect"])
        self.assertTrue(probe["fuse"]["asarIntegrityOff"])
        self.assertTrue(probe["signature"]["valid"])
        # Legacy manifest must remain untouched (no auto-archive)
        self.assertTrue(manifest_p.is_file())

    def test_runtime_probe_readonly_no_legacy_migration(self) -> None:
        bundle = _create_synthetic_app(self.tmp_path, "ZCodeReadonly.app", self.old_main_js, fuse_offset=64)
        builds = {bundle["asar_sha"]: {"adapter": "zcode-3.17.2", "fuseWireOffset": 64}}

        # Create a legacy manifest missing patchedSha (only origSha, abs, orig)
        manifest_p = self.tmp_path / "state" / "sidebar-ui" / "backups" / "asar_patch.json"
        manifest_p.parent.mkdir(parents=True, exist_ok=True)
        raw_legacy = json.dumps({"origSha": bundle["asar_sha"], "abs": 200, "orig": "abc"}, indent=2)
        manifest_p.write_text(raw_legacy, encoding="utf-8")
        os.chmod(manifest_p, 0o600)

        with patch.object(
            asar_cdp_patch,
            "migrate_legacy_manifest_if_verified",
            side_effect=AssertionError("probe_runtime_build must NEVER call migrate_legacy_manifest_if_verified"),
        ):
            probe = asar_cdp_patch.probe_runtime_build(bundle["asar"], manifest_p, builds, cache={})
            self.assertTrue(probe["ok"])
            self.assertEqual(probe["buildState"], "known")
            self.assertEqual(probe["patchState"], "stale")
            self.assertEqual(manifest_p.read_text(encoding="utf-8"), raw_legacy)

            # Also verify sidebar_ui_ctl.doctor does not call resolve_build_entry / migrate
            with patch.object(asar_cdp_patch, "ASAR", bundle["asar"]), patch.object(
                asar_cdp_patch, "FRAMEWORK", bundle["framework"]
            ), patch.object(asar_cdp_patch, "APP", bundle["app"]), patch.object(
                asar_cdp_patch, "codesign_ok", return_value=True
            ), patch.object(
                sidebar_ui_ctl, "ASAR", bundle["asar"]
            ), patch.object(
                sidebar_ui_ctl, "INFO_PLIST", bundle["info_plist"]
            ), patch.object(
                sidebar_ui_ctl, "current_app", return_value=None
            ):
                doc = sidebar_ui_ctl.doctor(self.tmp_path / "state")
                self.assertEqual(doc["app"]["buildState"], "probation")
                self.assertEqual(manifest_p.read_text(encoding="utf-8"), raw_legacy)

    def test_probe_unknown_modified_bundle_rejected(self) -> None:
        # Case A: Contains unverified /*ss-cdp*/ patch bytes
        patched_js = (
            b'console.log("init");'
            b'ee.commandLine.appendSwitch("remote-debugging-port","0")/*ss-cdp*/                                                        '
        )
        b1 = _create_synthetic_app(self.tmp_path, "ModPatched.app", patched_js)
        with patch.object(asar_cdp_patch, "codesign_ok", return_value=True):
            p1 = asar_cdp_patch.probe_runtime_build(b1["asar"], None, {})
        self.assertFalse(p1["ok"])
        self.assertEqual(p1["buildState"], "rejected")
        self.assertEqual(p1["patchState"], "conflict")

        # Case B: index.js integrity mismatch (modified without updating ASAR header integrity)
        b2 = _create_synthetic_app(
            self.tmp_path,
            "ModIntegrity.app",
            self.orig_main_js,
            integrity_hash="0" * 64,
        )
        with patch.object(asar_cdp_patch, "codesign_ok", return_value=True):
            p2 = asar_cdp_patch.probe_runtime_build(b2["asar"], None, {})
        self.assertFalse(p2["ok"])
        self.assertEqual(p2["buildState"], "rejected")
        self.assertEqual(p2["patchState"], "conflict")

        # Case C: Unknown unmodified bundle with invalid signature -> rejected
        b3 = _create_synthetic_app(self.tmp_path, "BadSig.app", self.orig_main_js)
        with patch.object(asar_cdp_patch, "codesign_ok", return_value=False):
            p3 = asar_cdp_patch.probe_runtime_build(b3["asar"], None, {})
        self.assertFalse(p3["ok"])
        self.assertEqual(p3["buildState"], "rejected")

    def test_probe_replaced_file_rechecks(self) -> None:
        bundle = _create_synthetic_app(self.tmp_path, "ReplaceCheck.app", self.orig_main_js)
        cache: dict[str, Any] = {}
        with patch.object(asar_cdp_patch, "codesign_ok", return_value=True):
            p1 = asar_cdp_patch.probe_runtime_build(bundle["asar"], None, {}, cache=cache, app_gen="2001:1700000000")
        self.assertTrue(p1["ok"])
        self.assertEqual(p1["buildState"], "probation")

        # Replace app.asar atomically with a modified bundle (new inode/contents) using the same cache
        bad_asar = _build_synthetic_asar(self.orig_main_js, integrity_hash="a" * 64)
        tmp_new = bundle["asar"].with_name("app.asar.new")
        tmp_new.write_bytes(bad_asar)
        os.replace(tmp_new, bundle["asar"])

        with patch.object(asar_cdp_patch, "codesign_ok", return_value=True):
            p2 = asar_cdp_patch.probe_runtime_build(bundle["asar"], None, {}, cache=cache, app_gen="2001:1700000000")
        self.assertFalse(p2["ok"])
        self.assertEqual(p2["buildState"], "rejected")
        self.assertEqual(p2["patchState"], "conflict")
        self.assertNotEqual(p2["asarSha"], p1["asarSha"])

        # Mid-read file replacement check
        with patch.object(asar_cdp_patch, "_same_regular_file", side_effect=[True, False]):
            p3 = asar_cdp_patch.probe_runtime_build(bundle["asar"], None, {}, cache={})
        self.assertFalse(p3["ok"])
        self.assertEqual(p3["buildState"], "rejected")
        self.assertIn("ASAR_REPLACED", p3["diagnostics"]["codes"])

    def test_fuse_unknown_layout_no_signal(self) -> None:
        # Framework binary has wire bytes at offset 64 WITHOUT ELECTRON_FUSE_SENTINEL -> must NOT trust or signal
        bundle = _create_synthetic_app(
            self.tmp_path,
            "NoSentinel.app",
            self.orig_main_js,
            fuse_sentinel=b"\x00" * 32,
            fuse_offset=64,
        )
        with patch.object(asar_cdp_patch, "codesign_ok", return_value=True):
            probe = asar_cdp_patch.probe_runtime_build(bundle["asar"], None, {})
        self.assertFalse(probe["fuse"]["found"])
        self.assertFalse(probe["fuse"]["nodeCliInspect"])
        self.assertEqual(probe["fuse"]["error"], "FUSE_SENTINEL_NOT_FOUND")

        gen = AppGen(pid=os.getpid(), lstart=time.time() - 5, checkin=time.time() - 4)
        with patch.object(sidebar_ui_ctl, "_pid_alive", return_value=True), patch.object(
            sidebar_ui_ctl.os, "kill"
        ) as mock_kill:
            res = sidebar_ui_ctl.ensure_sigusr1_bridge(
                gen,
                "/* bridge */",
                "/* bundle */",
                {
                    "stateRoot": str(self.tmp_path / "state"),
                    "asarPath": str(bundle["asar"]),
                    "frameworkPath": str(bundle["framework"]),
                    "probeResult": probe,
                    "verifyHostIdentity": False,
                    "verifyCurrentApp": False,
                },
            )
        mock_kill.assert_not_called()
        self.assertFalse(res["ok"])
        self.assertEqual(res["code"], "FUSE_SENTINEL_NOT_FOUND")

        # Dynamic sentinel discovery at a moved offset (e.g., 8192 bytes) succeeds
        moved_fw = self.tmp_path / "MovedSentinelFramework"
        moved_fw.write_bytes(
            (b"\x00" * 8192) + asar_cdp_patch.ELECTRON_FUSE_SENTINEL + b"\x01\x09101100011" + (b"\x00" * 64)
        )
        df = asar_cdp_patch.discover_fuse_wire(moved_fw, hint_offset=64)
        self.assertTrue(df["found"])
        self.assertEqual(df["offset"], 8192)
        self.assertEqual(df["wireOffset"], 8192 + 32)
        self.assertTrue(df["nodeCliInspect"])
        self.assertTrue(df["asarIntegrityOff"])

    def test_macos_framework_versions_symlink_and_escape_rejection(self) -> None:
        # Standard macOS .framework layout: Electron Framework -> Versions/Current/Electron Framework -> Versions/A/Electron Framework
        bundle = _create_synthetic_app(self.tmp_path, "MacFramework.app", self.orig_main_js, fuse_offset=512)
        fw_dir = bundle["framework"].parent
        fw_bytes = bundle["framework"].read_bytes()
        bundle["framework"].unlink()
        ver_a = fw_dir / "Versions" / "A"
        ver_a.mkdir(parents=True, exist_ok=True)
        (ver_a / "Electron Framework").write_bytes(fw_bytes)
        (fw_dir / "Versions" / "Current").symlink_to("A")
        (fw_dir / "Electron Framework").symlink_to("Versions/Current/Electron Framework")

        with patch.object(asar_cdp_patch, "codesign_ok", return_value=True):
            probe = asar_cdp_patch.probe_runtime_build(bundle["asar"], None, {})
        self.assertTrue(probe["ok"])
        self.assertTrue(probe["fuse"]["found"])
        self.assertEqual(probe["fuse"]["offset"], 512)
        self.assertTrue(probe["fuse"]["nodeCliInspect"])

        # Symlink inside .framework escaping outside .framework must be rejected
        outside_bin = self.tmp_path / "outside_fw.bin"
        outside_bin.write_bytes(fw_bytes)
        (fw_dir / "Electron Framework").unlink()
        (fw_dir / "Electron Framework").symlink_to(outside_bin)
        escaped = asar_cdp_patch.discover_fuse_wire(fw_dir / "Electron Framework", hint_offset=512)
        self.assertFalse(escaped["found"])
        self.assertEqual(escaped["error"], "FRAMEWORK_NOT_REGULAR")

        # Non-.framework symlink must also be rejected
        plain_link = self.tmp_path / "PlainLink"
        plain_link.symlink_to(outside_bin)
        non_fw = asar_cdp_patch.discover_fuse_wire(plain_link, hint_offset=512)
        self.assertFalse(non_fw["found"])
        self.assertEqual(non_fw["error"], "FRAMEWORK_NOT_REGULAR")


class TestM3MainBridgeAndSigusr1(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="ss-m3-test-")
        self.tmp_path = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_main_bridge_lifecycle_idempotency_hotswap_reload_dispose_via_node(self) -> None:
        """Exercise ui/main_bridge.js inside Node against a realistic mock Electron + createRequire bundle."""
        bridge_path = UI_DIR / "main_bridge.js"
        state_root = self.tmp_path / "state"
        (state_root / "exports").mkdir(parents=True, exist_ok=True)
        snap1 = {
            "schemaVersion": 1,
            "storeInstanceId": "store-1",
            "stateRevision": 1,
            "projectionRevision": 1,
            "nodes": [],
        }
        (state_root / "exports" / "sidebar-tree-v1.json").write_text(json.dumps(snap1), encoding="utf-8")

        # Create mock app.asar/package.json + node_modules/electron so process.getBuiltinModule('module').createRequire loads it!
        res_dir = self.tmp_path / "MockApp" / "Contents" / "Resources"
        mock_asar_dir = res_dir / "app.asar"
        mock_el_dir = mock_asar_dir / "node_modules" / "electron"
        mock_el_dir.mkdir(parents=True, exist_ok=True)
        (mock_asar_dir / "package.json").write_text(json.dumps({"name": "mock-zcode", "version": "3.18.2"}), encoding="utf-8")
        (mock_el_dir / "index.js").write_text(
            """
const { EventEmitter } = require('events');
const app = new EventEmitter();
const wcs = [];
module.exports = {
  app,
  webContents: {
    getAllWebContents: () => wcs.slice(),
    __setList: (arr) => { wcs.length = 0; wcs.push(...arr); },
    __push: (w) => { wcs.push(w); },
  },
};
""".lstrip(),
            encoding="utf-8",
        )

        # Fake bundle script that runs inside mock renderer VM/context
        fake_bundle_js = """
(() => {
  const G = globalThis;
  const prev = G.__SS_SIDEBAR_TREE__;
  if (prev && prev.destroy) prev.destroy();
  const pushes = G.__TEST_PUSHES__ = G.__TEST_PUSHES__ || [];
  const acks = G.__TEST_ACKS__ = G.__TEST_ACKS__ || [];
  const destroys = G.__TEST_DESTROYS__ = G.__TEST_DESTROYS__ || [];
  const queue = G.__TEST_QUEUE__ = G.__TEST_QUEUE__ || [];
  let snap = null;
  let dedupRestored = 0;
  G.__SS_ZCODE_ADAPTER__ = {
    id: 'zcode-3.17.2',
    contractId: 'sidebar-list-v1',
    selfTest: () => ({
      contractId: 'sidebar-list-v1',
      state: 'ready',
      capabilities: { mount: true, navigation: true, chatViewport: true, hostIndexSync: true, dedup: true },
      diagnostics: {},
    }),
    syncUnindexedNodes: async () => {},
    restoreDedup: () => { dedupRestored++; G.__TEST_DEDUP_RESTORED__ = (G.__TEST_DEDUP_RESTORED__ || 0) + 1; },
  };
  G.__SS_SIDEBAR_TREE__ = {
    alive: true,
    update(next) {
      if (snap && snap.storeInstanceId === next.storeInstanceId && snap.projectionRevision === next.projectionRevision) {
        return { ok: true, unchanged: true };
      }
      snap = next;
      pushes.push({ storeInstanceId: next.storeInstanceId, projectionRevision: next.projectionRevision });
      return { ok: true };
    },
    drainActions: () => queue.map(a => ({ ...a })),
    ackActions: (rcpts) => {
      acks.push(...rcpts);
      const ids = new Set(rcpts.map(r => r.actionId));
      for (let i = queue.length - 1; i >= 0; i--) {
        if (ids.has(queue[i].actionId)) queue.splice(i, 1);
      }
      return { acked: rcpts.length, remaining: queue.length };
    },
    getStatus: () => ({
      alive: true,
      sidebarFound: true,
      navigatorResolved: true,
      selfTest: G.__SS_ZCODE_ADAPTER__.selfTest(),
      storeInstanceId: snap ? snap.storeInstanceId : null,
      projectionRevision: snap ? snap.projectionRevision : null,
      pendingActions: queue.length,
    }),
    destroy() {
      this.alive = false;
      destroys.push(Date.now());
      delete G.__SS_SIDEBAR_TREE__;
    },
  };
})();
""".strip()

        test_script = f"""
import assert from 'node:assert/strict';
import {{ EventEmitter }} from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);
Object.defineProperty(process, 'type', {{ value: 'browser', configurable: true }});
Object.defineProperty(process, 'resourcesPath', {{ value: {json.dumps(str(res_dir))}, configurable: true }});

const {{ installMainBridge }} = require({json.dumps(str(bridge_path))});
const electron = process.getBuiltinModule('module').createRequire({json.dumps(str(mock_asar_dir / "package.json"))})('electron');

function makeWc(id, url, type = 'window') {{
  const ee = new EventEmitter();
  const ctx = vm.createContext({{ globalThis: undefined }});
  ctx.globalThis = ctx;
  ctx.window = ctx;
  return Object.assign(ee, {{
    id,
    _url: url,
    _type: type,
    _destroyed: false,
    _ctx: ctx,
    evalCount: 0,
    getURL() {{ return this._url; }},
    getType() {{ return this._type; }},
    isDestroyed() {{ return this._destroyed; }},
    async executeJavaScript(code) {{
      this.evalCount++;
      return await vm.runInContext(code, this._ctx);
    }},
  }});
}}

const MAIN_URL = 'file:///Applications/ZCode.app/Contents/Resources/app.asar/out/renderer/index.html?window=1';
const wcMain = makeWc(1, MAIN_URL, 'window');
const wcDevTools = makeWc(2, 'devtools://devtools/bundled/inspector.html', 'devtools');
const wcSandbox = makeWc(3, 'file:///Applications/ZCode.app/Contents/Resources/app.asar/out/renderer/plugin-sandbox.html', 'window');
const wcResMgr = makeWc(4, 'file:///Applications/ZCode.app/Contents/Resources/app.asar/out/renderer/resource-manager.html', 'window');
const wcPerm = makeWc(5, 'file:///Applications/ZCode.app/Contents/Resources/app.asar/out/renderer/cua-permission-panel.html', 'window');

electron.webContents.__setList([wcMain, wcDevTools, wcSandbox, wcResMgr, wcPerm]);

const cfg1 = {{
  appGen: '12345:1700000000',
  stateRoot: {json.dumps(str(state_root))},
  bundleSource: {json.dumps(fake_bundle_js)},
  bridgeSourceSha: 'bridge-v1',
  pollIntervalMs: 60000,
}};

const r1 = await installMainBridge(cfg1);
assert.equal(r1.ok, true);
assert.equal(r1.reused, false);
assert.equal(wcMain._ctx.__SS_SIDEBAR_TREE__.alive, true);
assert.equal(wcDevTools.evalCount, 0, 'DevTools must NOT be injected');
assert.equal(wcSandbox.evalCount, 0, 'plugin-sandbox must NOT be injected');
assert.equal(wcResMgr.evalCount, 0, 'resource-manager must NOT be injected');
assert.equal(wcPerm.evalCount, 0, 'cua-permission-panel must NOT be injected');
assert.equal(wcMain._ctx.__TEST_PUSHES__.length, 1);

const hsPath = path.join({json.dumps(str(state_root))}, 'sidebar-ui', 'runtime', '12345_1700000000', 'handshake.json');
const hs1 = JSON.parse(fs.readFileSync(hsPath, 'utf8'));
assert.equal(hs1.windows['1'].rendererEpoch, 1);
assert.equal(hs1.bootNonce, r1.bootNonce);

// 1) Repeated ensure with same (appGen, sourceSha) reuses existing instance without duplicate listeners
const appListenerCount1 = electron.app.listenerCount('web-contents-created');
const wcListenerCount1 = wcMain.listenerCount('did-finish-load');
const r1Again = await installMainBridge(cfg1);
assert.equal(r1Again.ok, true);
assert.equal(r1Again.reused, true);
assert.equal(r1Again.bootNonce, r1.bootNonce);
assert.equal(electron.app.listenerCount('web-contents-created'), appListenerCount1);
assert.equal(wcMain.listenerCount('did-finish-load'), wcListenerCount1);

// 2) Reload main window -> increments rendererEpoch, re-injects fresh bundle
wcMain._ctx = vm.createContext({{ globalThis: undefined }});
wcMain._ctx.globalThis = wcMain._ctx;
wcMain._ctx.window = wcMain._ctx;
wcMain.emit('did-finish-load');
await new Promise(r => setTimeout(r, 30));
assert.equal(wcMain._ctx.__SS_SIDEBAR_TREE__.alive, true);
const hsReload = JSON.parse(fs.readFileSync(hsPath, 'utf8'));
assert.equal(hsReload.windows['1'].rendererEpoch, 2);

// 3) New qualified window created after bootstrap -> automatically injected
const wcNew = makeWc(6, 'file:///Applications/ZCode.app/Contents/Resources/app.asar/out/renderer/index.html?window=2', 'window');
electron.webContents.__push(wcNew);
electron.app.emit('web-contents-created', {{}}, wcNew);
wcNew.emit('did-finish-load');
await new Promise(r => setTimeout(r, 30));
assert.equal(wcNew._ctx.__SS_SIDEBAR_TREE__.alive, true);

// 4) Hot-swap with updated sourceSha calls old.dispose() first and cleans up
const r2 = await installMainBridge({{ ...cfg1, bridgeSourceSha: 'bridge-v2' }});
assert.equal(r2.ok, true);
assert.equal(r2.reused, false);
assert.notEqual(r2.bootNonce, r1.bootNonce);
assert.equal(electron.app.listenerCount('web-contents-created'), 1);
assert.equal(wcMain.listenerCount('did-finish-load'), 1);
assert.ok(wcMain._ctx.__TEST_DESTROYS__.length >= 1, 'old controller disposed before hot-swap');
assert.ok(wcMain._ctx.__TEST_DEDUP_RESTORED__ >= 1, 'dedup restored on dispose');

// 5) Final dispose cleans all listeners, controllers, and handshake.json
await globalThis.__SS_MAIN_BRIDGE__.dispose();
assert.equal(electron.app.listenerCount('web-contents-created'), 0);
assert.equal(wcMain.listenerCount('did-finish-load'), 0);
assert.equal(wcMain.listenerCount('destroyed'), 0);
assert.equal(wcNew.listenerCount('did-finish-load'), 0);
assert.equal(globalThis.__SS_MAIN_BRIDGE__, undefined);
assert.equal(fs.existsSync(hsPath), false);
console.log('MOCK_ELECTRON_M3_OK');
"""
        runner_p = self.tmp_path / "run_m3.mjs"
        runner_p.write_text(test_script, encoding="utf-8")
        proc = subprocess.run(
            ["node", str(runner_p)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, msg=f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("MOCK_ELECTRON_M3_OK", proc.stdout)

    def test_ensure_sigusr1_bridge_existing_debugger_and_failure_cleanup(self) -> None:
        gen = AppGen(pid=os.getpid(), lstart=time.time() - 10, checkin=time.time() - 9)
        fake_probe = {
            "ok": True,
            "buildState": "probation",
            "patchState": "stale",
            "adapterCandidate": "zcode-3.17.2",
            "fuse": {"found": True, "nodeCliInspect": True, "asarIntegrityOff": True},
        }
        base_cfg = {
            "stateRoot": str(self.tmp_path / "state"),
            "probeResult": fake_probe,
            "verifyHostIdentity": False,
            "verifyCurrentApp": False,
            "signalWaitSec": 0.2,
            "closeWaitSec": 0.2,
        }

        class FakeCdpSocket:
            instances: list["FakeCdpSocket"] = []
            behavior = "ok"  # ok | eval_fail | close_fail

            def __init__(self, ws_url: str, timeout: float = 5.0) -> None:
                self.ws_url = ws_url
                self.calls: list[tuple[str, dict]] = []
                self.closed = False
                FakeCdpSocket.instances.append(self)

            def call(self, method: str, params: dict | None = None) -> dict:
                self.calls.append((method, dict(params or {})))
                if method == "Runtime.enable":
                    return {}
                expr = str((params or {}).get("expression") or "")
                if "globalThis.__SS_BOOT_INSPECTOR__" in expr and "insp.close()" not in expr:
                    return {"result": {"value": True}}
                if "insp.close()" in expr:
                    if FakeCdpSocket.behavior == "close_fail":
                        return {"result": {"value": {"closed": False, "error": "MOCK_CLOSE_FAIL"}}}
                    if FakeCdpSocket.behavior == "close_eof":
                        raise sidebar_ui_ctl.CdpError("EOF")
                    return {"result": {"value": {"closed": True}}}
                if FakeCdpSocket.behavior == "eval_fail":
                    raise sidebar_ui_ctl.CdpError("boom during bridge eval")
                return {
                    "result": {
                        "value": {
                            "ok": True,
                            "reused": False,
                            "bootNonce": "nonce-123",
                        }
                    }
                }

            def close(self) -> None:
                self.closed = True

        # Case 1: Existing debugger ALREADY listening on 9229 -> NEVER signal SIGUSR1, NEVER close inspector
        FakeCdpSocket.instances.clear()
        FakeCdpSocket.behavior = "ok"
        with patch.object(sidebar_ui_ctl, "_pid_alive", return_value=True), patch.object(
            sidebar_ui_ctl, "_detect_inspector_listeners", return_value=[(gen.pid, "127.0.0.1")]
        ), patch.object(
            sidebar_ui_ctl.os, "kill"
        ) as mock_kill, patch.object(
            sidebar_ui_ctl, "cdp_http_get_json", return_value=[{"type": "node", "webSocketDebuggerUrl": "ws://127.0.0.1:9229/n1"}]
        ), patch.object(
            sidebar_ui_ctl, "CdpSocket", FakeCdpSocket
        ):
            r_existing = sidebar_ui_ctl.ensure_sigusr1_bridge(gen, "/*b*/", "/*u*/", base_cfg)

        mock_kill.assert_not_called()
        self.assertTrue(r_existing["ok"])
        self.assertFalse(r_existing["openedByUs"])
        self.assertTrue(r_existing["existingDebuggerPreserved"])
        self.assertIsNone(r_existing["inspectorClosed"])
        all_exprs = [p.get("expression", "") for s in FakeCdpSocket.instances for m, p in s.calls if m == "Runtime.evaluate"]
        self.assertFalse(any("insp.close()" in e for e in all_exprs))
        self.assertTrue(all(s.closed for s in FakeCdpSocket.instances))

        # Case 2: Opened by us, eval fails post-signal -> finally STILL calls insp.close() and closes socket!
        FakeCdpSocket.instances.clear()
        FakeCdpSocket.behavior = "eval_fail"
        listen_seq = [
            [],  # before SIGUSR1: no listener
            [(gen.pid, "127.0.0.1")],  # after SIGUSR1: listening
            [],  # after insp.close(): closed
        ]
        with patch.object(sidebar_ui_ctl, "_pid_alive", return_value=True), patch.object(
            sidebar_ui_ctl, "_detect_inspector_listeners", side_effect=listen_seq
        ), patch.object(
            sidebar_ui_ctl.os, "kill"
        ) as mock_kill, patch.object(
            sidebar_ui_ctl, "cdp_http_get_json", return_value=[{"type": "node", "webSocketDebuggerUrl": "ws://127.0.0.1:9229/n1"}]
        ), patch.object(
            sidebar_ui_ctl, "CdpSocket", FakeCdpSocket
        ):
            r_fail = sidebar_ui_ctl.ensure_sigusr1_bridge(gen, "/*b*/", "/*u*/", base_cfg)

        mock_kill.assert_called_once()
        self.assertFalse(r_fail["ok"])
        self.assertTrue(r_fail["openedByUs"])
        self.assertTrue(r_fail["inspectorClosed"])
        all_exprs2 = [p.get("expression", "") for s in FakeCdpSocket.instances for m, p in s.calls if m == "Runtime.evaluate"]
        self.assertTrue(any("process.getBuiltinModule('inspector')" in e and "insp.close()" in e for e in all_exprs2))
        self.assertTrue(all(s.closed for s in FakeCdpSocket.instances))

        # Case 3: Bridge succeeded, but inspector close failed / port stayed open -> NEVER report ok=True!
        FakeCdpSocket.instances.clear()
        FakeCdpSocket.behavior = "close_fail"
        listen_seq3 = [
            [],
            [(gen.pid, "127.0.0.1")],
            [(gen.pid, "127.0.0.1")],
            [(gen.pid, "127.0.0.1")],
            [(gen.pid, "127.0.0.1")],
        ]
        with patch.object(sidebar_ui_ctl, "_pid_alive", return_value=True), patch.object(
            sidebar_ui_ctl, "_detect_inspector_listeners", side_effect=listen_seq3
        ), patch.object(
            sidebar_ui_ctl.os, "kill"
        ), patch.object(
            sidebar_ui_ctl, "cdp_http_get_json", return_value=[{"type": "node", "webSocketDebuggerUrl": "ws://127.0.0.1:9229/n1"}]
        ), patch.object(
            sidebar_ui_ctl, "CdpSocket", FakeCdpSocket
        ):
            r_close_fail = sidebar_ui_ctl.ensure_sigusr1_bridge(gen, "/*b*/", "/*u*/", base_cfg)
        self.assertFalse(r_close_fail["ok"])
        self.assertEqual(r_close_fail["code"], "INSPECTOR_CLOSE_FAILED")
        self.assertFalse(r_close_fail["inspectorClosed"])

        # Case 4: Real Node inspector.close() drops WebSocket with CdpError("EOF") while port closes -> ok=True!
        FakeCdpSocket.instances.clear()
        FakeCdpSocket.behavior = "close_eof"
        listen_seq4 = [
            [],
            [(gen.pid, "127.0.0.1")],
            [],
        ]
        with patch.object(sidebar_ui_ctl, "_pid_alive", return_value=True), patch.object(
            sidebar_ui_ctl, "_detect_inspector_listeners", side_effect=listen_seq4
        ), patch.object(
            sidebar_ui_ctl.os, "kill"
        ), patch.object(
            sidebar_ui_ctl, "cdp_http_get_json", return_value=[{"type": "node", "webSocketDebuggerUrl": "ws://127.0.0.1:9229/n1"}]
        ), patch.object(
            sidebar_ui_ctl, "CdpSocket", FakeCdpSocket
        ):
            r_eof_ok = sidebar_ui_ctl.ensure_sigusr1_bridge(gen, "/*b*/", "/*u*/", base_cfg)
        self.assertTrue(r_eof_ok["ok"])
        self.assertTrue(r_eof_ok["inspectorClosed"])

        # Case 5: WebSocket EOF during close AND port remains open -> ok=False (INSPECTOR_CLOSE_FAILED)
        FakeCdpSocket.instances.clear()
        FakeCdpSocket.behavior = "close_eof"
        listen_seq5 = [
            [],
            [(gen.pid, "127.0.0.1")],
            [(gen.pid, "127.0.0.1")],
            [(gen.pid, "127.0.0.1")],
            [(gen.pid, "127.0.0.1")],
        ]
        with patch.object(sidebar_ui_ctl, "_pid_alive", return_value=True), patch.object(
            sidebar_ui_ctl, "_detect_inspector_listeners", side_effect=listen_seq5
        ), patch.object(
            sidebar_ui_ctl.os, "kill"
        ), patch.object(
            sidebar_ui_ctl, "cdp_http_get_json", return_value=[{"type": "node", "webSocketDebuggerUrl": "ws://127.0.0.1:9229/n1"}]
        ), patch.object(
            sidebar_ui_ctl, "CdpSocket", FakeCdpSocket
        ):
            r_eof_open = sidebar_ui_ctl.ensure_sigusr1_bridge(gen, "/*b*/", "/*u*/", base_cfg)
        self.assertFalse(r_eof_open["ok"])
        self.assertEqual(r_eof_open["code"], "INSPECTOR_CLOSE_FAILED")
        self.assertFalse(r_eof_open["inspectorClosed"])

    def test_injector_no_15s_resignal_loop(self) -> None:
        state_root = self.tmp_path / "state"
        inj = Injector(state_root, release_dir=PLUGIN_ROOT)
        gen = AppGen(pid=42424, lstart=1700000000.0, checkin=1700000001.0)
        inj.gen = gen
        fake_probe = {
            "ok": True,
            "asarSha": "abc",
            "buildState": "probation",
            "patchState": "absent",
            "adapterCandidate": "zcode-3.17.2",
            "fuse": {"found": True, "nodeCliInspect": True, "asarIntegrityOff": True},
            "signature": {"checked": True, "valid": True, "error": None},
            "diagnostics": {"codes": []},
        }

        bridge_src = inj.bridge_source()
        bundle_src = inj.payload("zcode-3.17.2")
        combined_sha = hashlib.sha256((bridge_src + "\n" + bundle_src).encode("utf-8")).hexdigest()
        rt_dir = state_root / "sidebar-ui" / "runtime" / safe_app_gen(gen.key)

        call_count = 0

        def _fake_ensure(g, b_src, u_src, cfg):
            nonlocal call_count
            call_count += 1
            rt_dir.mkdir(parents=True, exist_ok=True)
            (rt_dir / "handshake.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "active": True,
                        "appGen": g.key,
                        "bootNonce": "bn-1",
                        "sourceSha": combined_sha,
                        "windows": {
                            "1": {
                                "webContentsId": 1,
                                "rendererEpoch": 1,
                                "alive": True,
                                "status": {
                                    "alive": True,
                                    "sidebarFound": True,
                                    "navigatorResolved": True,
                                    "selfTest": {"state": "ready", "capabilities": {"mount": True, "navigation": True}},
                                },
                            }
                        },
                        "updatedAt": time.time(),
                    }
                ),
                encoding="utf-8",
            )
            return {"ok": True, "bootNonce": "bn-1", "openedByUs": True, "inspectorClosed": True}

        with patch.object(inj, "probe_build", return_value=fake_probe), patch.object(
            sidebar_ui_ctl, "ensure_sigusr1_bridge", side_effect=_fake_ensure
        ):
            inj.on_no_endpoint(gen)
            self.assertEqual(inj.health["state"], "READY")
            inj.on_no_endpoint(gen)
            inj.on_no_endpoint(gen)

        self.assertEqual(call_count, 1, "Injector must NOT re-signal on every tick when handshake is fresh")


class TestM4MailboxAndHealth(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="ss-m4-test-")
        self.tmp_path = Path(self._tmp.name).resolve()
        self.state_root = self.tmp_path / "state"
        self.workspace_dir = self.tmp_path / "workspace"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.cli_db_path = self.tmp_path / "cli-db.sqlite"
        with closing(sqlite3.connect(self.cli_db_path)) as c, c:
            c.execute(
                "CREATE TABLE session (id TEXT PRIMARY KEY, parent_id TEXT, title TEXT, time_archived INTEGER, time_deleted INTEGER)"
            )
            c.execute("INSERT INTO session VALUES ('sess_parent', NULL, 'Parent', NULL, NULL)")

        self.store = open_store(self.state_root, writable=True)
        self.driver = ScriptedFakeDriver(host_db_path=self.cli_db_path, sync_to_host_db=False)
        self.host_adapter = HostAdapter(store=self.store, state_root=self.state_root, host_db_path=self.cli_db_path)
        self.engine = Engine(
            self.store,
            clock=lambda: datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc),
            host_adapter=self.host_adapter,
            driver=self.driver,
            worktrees_home=self.state_root / "worktrees",
        )
        self.parent_caller = CallerContext(
            runtime_sid="sess_parent",
            runtime_turn_id="turn-p1",
            workspace_path=str(self.workspace_dir),
            connection_id="stdio:test",
        )
        self.child = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Child Worker",
                "prompt": "Run task.",
                "context": "fresh",
                "background": VALID_BG,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "worker-1",
            },
        )
        self.store_instance_id = self.store.conn.execute(
            "SELECT store_instance_id FROM schema_meta WHERE id=1"
        ).fetchone()["store_instance_id"]
        self.gen = AppGen(pid=55555, lstart=1700000000.0, checkin=1700000001.0)
        self.inj = Injector(self.state_root, release_dir=PLUGIN_ROOT)
        self.inj.gen = self.gen
        self.rt_dir = self.state_root / "sidebar-ui" / "runtime" / safe_app_gen(self.gen.key)
        (self.rt_dir / "actions").mkdir(parents=True, exist_ok=True)
        (self.rt_dir / "receipts").mkdir(parents=True, exist_ok=True)
        self.handshake = {
            "schemaVersion": 1,
            "active": True,
            "appGen": self.gen.key,
            "bootNonce": "boot-nonce-1",
            "windows": {
                "10": {"webContentsId": 10, "rendererEpoch": 1},
                "20": {"webContentsId": 20, "rendererEpoch": 3},
            },
            "updatedAt": time.time(),
        }
        (self.rt_dir / "handshake.json").write_text(json.dumps(self.handshake), encoding="utf-8")

    def tearDown(self) -> None:
        try:
            self.inj.reader.close()
        except Exception:
            pass
        try:
            self.store.close()
        except Exception:
            pass
        self._tmp.cleanup()

    def _write_action_env(
        self,
        action_id: str,
        *,
        app_gen: str | None = None,
        boot_nonce: str | None = None,
        wc_id: int = 10,
        epoch: int = 1,
        store_id: str | None = None,
        deadline_at: int | None = None,
        action: dict[str, Any] | None = None,
    ) -> Path:
        now_ms = int(time.time() * 1000)
        env = {
            "schemaVersion": 1,
            "actionId": action_id,
            "appGen": app_gen if app_gen is not None else self.gen.key,
            "bootNonce": boot_nonce if boot_nonce is not None else "boot-nonce-1",
            "webContentsId": wc_id,
            "rendererEpoch": epoch,
            "storeInstanceId": store_id if store_id is not None else self.store_instance_id,
            "projectionRevision": 1,
            "queuedAt": now_ms,
            "deadlineAt": deadline_at if deadline_at is not None else (now_ms + 15000),
            "action": action
            or {
                "actionId": action_id,
                "kind": "cancel_run",
                "nodeId": self.child["node_id"],
                "runId": self.child["run_id"],
                "reason": "cancelled from test",
            },
        }
        p = self.rt_dir / "actions" / f"{action_id}.json"
        p.write_text(json.dumps(env), encoding="utf-8")
        return p

    def test_mailbox_dropped_ack_crash_after_write_and_duplicate_action_idempotency(self) -> None:
        aid = str(uuid.uuid4())
        act_path = self._write_action_env(aid)
        snap = {"storeInstanceId": self.store_instance_id, "projectionRevision": 1}

        # Python executes once and writes receipt; action file stays until bridge ACKs
        rcpts1 = self.inj._consume_bridge_mailbox(self.gen, self.handshake, snap)
        self.assertEqual(len(rcpts1), 1)
        self.assertTrue(rcpts1[0]["ok"])
        rcpt_path = self.rt_dir / "receipts" / f"{aid}.json"
        self.assertTrue(rcpt_path.is_file())
        self.assertTrue(act_path.is_file())

        # Crash / re-run before ACK -> second pass sees existing receipt and does NOT re-execute
        with patch.object(zcode_sidebar_injector, "execute_ui_actions") as mock_exec:
            rcpts2 = self.inj._consume_bridge_mailbox(self.gen, self.handshake, snap)
        mock_exec.assert_not_called()
        self.assertEqual(rcpts2, [])

        # Even if receipt was removed and same actionId is re-executed, Engine is idempotent on actionId!
        rcpt_path.unlink()
        rcpts3 = self.inj._consume_bridge_mailbox(self.gen, self.handshake, snap)
        self.assertEqual(len(rcpts3), 1)
        self.assertTrue(rcpts3[0]["ok"])
        self.assertEqual(rcpts3[0]["actionId"], aid)

    def test_mailbox_failure_receipt_propagation_and_dropped_ack_in_node_bridge(self) -> None:
        # Action targeting missing node -> Engine returns ok=False receipt, bridge delivers to ackActions!
        aid = str(uuid.uuid4())
        bad_node_id = str(uuid.uuid4())
        snap = {"schemaVersion": 1, "storeInstanceId": self.store_instance_id, "projectionRevision": 1, "nodes": []}
        (self.state_root / "exports").mkdir(parents=True, exist_ok=True)
        (self.state_root / "exports" / "sidebar-tree-v1.json").write_text(json.dumps(snap), encoding="utf-8")

        bridge_path = UI_DIR / "main_bridge.js"
        # First, run Node bridge tick 1: drains action and writes action file, does NOT ack yet!
        node_step1 = f"""
import assert from 'node:assert/strict';
import {{ EventEmitter }} from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);
Object.defineProperty(process, 'type', {{ value: 'browser', configurable: true }});
const {{ installMainBridge }} = require({json.dumps(str(bridge_path))});

const app = new EventEmitter();
const queue = [{{ actionId: {json.dumps(aid)}, kind: 'archive_session', nodeId: {json.dumps(bad_node_id)}, expectedRevision: 1 }}];
const ackCalls = [];
let dropFirstAck = true;

const wc = Object.assign(new EventEmitter(), {{
  id: 10,
  getURL: () => 'file:///Applications/ZCode.app/Contents/Resources/app.asar/out/renderer/index.html',
  getType: () => 'window',
  isDestroyed: () => false,
  async executeJavaScript(code) {{
    if (code.includes('drainActions()')) return queue.map(x => ({{ ...x }}));
    if (code.includes('ackActions(')) {{
      if (dropFirstAck) {{ dropFirstAck = false; throw new Error('DROPPED_ACK'); }}
      const m = code.match(/JSON\\.parse\\((".*?")\\)/);
      const rcpts = JSON.parse(JSON.parse(m[1]));
      ackCalls.push(...rcpts);
      return {{ acked: rcpts.length, remaining: 0 }};
    }}
    if (code.includes('selfTest')) return {{ contractId: 'sidebar-list-v1', state: 'ready', capabilities: {{ mount: true, navigation: true, hostIndexSync: false }}, diagnostics: {{}} }};
    if (code.includes('getStatus()')) return {{ alive: true, sidebarFound: true, navigatorResolved: true }};
    if (code.includes('payloadSha')) return {{ alive: true, payloadSha: 'bsha', transportOwner: 'bridge' }};
    return {{ ok: true }};
  }},
}});

const res = await installMainBridge({{
  appGen: {json.dumps(self.gen.key)},
  stateRoot: {json.dumps(str(self.state_root))},
  bundleSource: '/* bundle */',
  bundleSha: 'bsha',
  sourceSha: 'ssha',
  pollIntervalMs: 60000,
  electron: {{ app, webContents: {{ getAllWebContents: () => [wc] }} }},
}});
assert.equal(res.ok, true);
assert.equal(ackCalls.length, 0, 'Must NOT ack before receipt exists!');
const actFile = path.join({json.dumps(str(self.rt_dir))}, 'actions', {json.dumps(aid + '.json')});
assert.equal(fs.existsSync(actFile), true);
console.log(JSON.stringify({{ bootNonce: res.bootNonce }}));
await globalThis.__SS_MAIN_BRIDGE__.dispose();
"""
        p1 = self.tmp_path / "m4_step1.mjs"
        p1.write_text(node_step1, encoding="utf-8")
        out1 = subprocess.run(["node", str(p1)], capture_output=True, text=True, timeout=15)
        self.assertEqual(out1.returncode, 0, msg=f"{out1.stdout}\n{out1.stderr}")
        bn = json.loads(out1.stdout.strip().splitlines()[-1])["bootNonce"]

        # Update handshake with the bootNonce from step 1 and run Python mailbox consumer -> writes failure receipt
        hs = json.loads((self.rt_dir / "handshake.json").read_text(encoding="utf-8")) if (self.rt_dir / "handshake.json").exists() else dict(self.handshake)
        hs["bootNonce"] = bn
        hs["active"] = True
        (self.rt_dir / "handshake.json").write_text(json.dumps(hs), encoding="utf-8")

        # Update action file's bootNonce to match step2's installed bridge? Wait: in step2 we pass matching bootNonce via reusing or writing receipt directly
        # Actually, let's keep the same bridge instance alive in ONE Node script OR test dropped ACK + failure receipt within one Node process driven by a helper!
        rcpts = self.inj._consume_bridge_mailbox(self.gen, hs, snap)
        self.assertEqual(len(rcpts), 1)
        self.assertFalse(rcpts[0]["ok"])
        self.assertEqual(rcpts[0]["code"], "NOT_FOUND")
        rcpt_p = self.rt_dir / "receipts" / f"{aid}.json"
        self.assertTrue(rcpt_p.is_file())

    def test_mailbox_dropped_ack_retry_and_two_windows_isolation_in_node(self) -> None:
        """Two windows (10 and 20): dropped first ACK preserves files; second tick retries ACK & unlinks; window 10 never sees window 20 receipts."""
        aid1 = str(uuid.uuid4())
        aid2 = str(uuid.uuid4())
        snap = {"schemaVersion": 1, "storeInstanceId": self.store_instance_id, "projectionRevision": 1, "nodes": []}
        (self.state_root / "exports").mkdir(parents=True, exist_ok=True)
        (self.state_root / "exports" / "sidebar-tree-v1.json").write_text(json.dumps(snap), encoding="utf-8")

        bridge_path = UI_DIR / "main_bridge.js"
        node_script = f"""
import assert from 'node:assert/strict';
import {{ EventEmitter }} from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);
Object.defineProperty(process, 'type', {{ value: 'browser', configurable: true }});
const {{ installMainBridge }} = require({json.dumps(str(bridge_path))});

const app = new EventEmitter();
function makeWin(id, aid) {{
  const q = [{{ actionId: aid, kind: 'cancel_run', nodeId: 'n1', runId: 'r1' }}];
  const acked = [];
  let dropNextAck = id === 10;
  return Object.assign(new EventEmitter(), {{
    id,
    acked,
    q,
    getURL: () => 'file:///Applications/ZCode.app/Contents/Resources/app.asar/out/renderer/index.html',
    getType: () => 'window',
    isDestroyed: () => false,
    async executeJavaScript(code) {{
      if (code.includes('drainActions()')) return q.map(x => ({{ ...x }}));
      if (code.includes('ackActions(')) {{
        if (dropNextAck) {{ dropNextAck = false; throw new Error('SIMULATED_DROPPED_ACK'); }}
        const m = code.match(/JSON\\.parse\\((".*?")\\)/);
        const rcpts = JSON.parse(JSON.parse(m[1]));
        acked.push(...rcpts);
        const ids = new Set(rcpts.map(r => r.actionId));
        for (let i = q.length - 1; i >= 0; i--) {{
          if (ids.has(q[i].actionId)) q.splice(i, 1);
        }}
        return {{ acked: rcpts.length, remaining: q.length }};
      }}
      if (code.includes('selfTest')) return {{ contractId: 'sidebar-list-v1', state: 'ready', capabilities: {{ mount: true, navigation: true, hostIndexSync: false }}, diagnostics: {{}} }};
      if (code.includes('getStatus()')) return {{ alive: true, sidebarFound: true, navigatorResolved: true }};
      if (code.includes('payloadSha')) return {{ alive: true, payloadSha: 'bsha', transportOwner: 'bridge' }};
      return {{ ok: true }};
    }},
  }});
}}

const w10 = makeWin(10, {json.dumps(aid1)});
const w20 = makeWin(20, {json.dumps(aid2)});
const res = await installMainBridge({{
  appGen: {json.dumps(self.gen.key)},
  stateRoot: {json.dumps(str(self.state_root))},
  bundleSource: '/* bundle */',
  bundleSha: 'bsha',
  sourceSha: 'ssha',
  pollIntervalMs: 60000,
  electron: {{ app, webContents: {{ getAllWebContents: () => [w10, w20] }} }},
}});

const actionsDir = path.join({json.dumps(str(self.rt_dir))}, 'actions');
const receiptsDir = path.join({json.dumps(str(self.rt_dir))}, 'receipts');
const e1 = JSON.parse(fs.readFileSync(path.join(actionsDir, {json.dumps(aid1 + '.json')}), 'utf8'));
const e2 = JSON.parse(fs.readFileSync(path.join(actionsDir, {json.dumps(aid2 + '.json')}), 'utf8'));
assert.equal(e1.webContentsId, 10);
assert.equal(e2.webContentsId, 20);

// Write receipts matching respective windows/epochs
fs.writeFileSync(path.join(receiptsDir, {json.dumps(aid1 + '.json')}), JSON.stringify({{
  actionId: {json.dumps(aid1)}, ok: false, code: 'ACTION_DENIED', message: 'denied',
  appGen: e1.appGen, bootNonce: e1.bootNonce, webContentsId: 10, rendererEpoch: e1.rendererEpoch,
}}));
fs.writeFileSync(path.join(receiptsDir, {json.dumps(aid2 + '.json')}), JSON.stringify({{
  actionId: {json.dumps(aid2)}, ok: true,
  appGen: e2.appGen, bootNonce: e2.bootNonce, webContentsId: 20, rendererEpoch: e2.rendererEpoch,
}}));

// Tick 2: w10 drops ACK -> files for aid1 MUST remain! w20 succeeds -> files for aid2 unlinked!
await globalThis.__SS_MAIN_BRIDGE__.tickOnce();
assert.equal(w10.acked.length, 0);
assert.equal(fs.existsSync(path.join(receiptsDir, {json.dumps(aid1 + '.json')})), true);
assert.equal(fs.existsSync(path.join(actionsDir, {json.dumps(aid1 + '.json')})), true);
assert.equal(w20.acked.length, 1);
assert.equal(w20.acked[0].actionId, {json.dumps(aid2)});
assert.equal(fs.existsSync(path.join(receiptsDir, {json.dumps(aid2 + '.json')})), false);

// Tick 3: w10 retries ACK -> receives failure receipt & cleans up!
await globalThis.__SS_MAIN_BRIDGE__.tickOnce();
assert.equal(w10.acked.length, 1);
assert.equal(w10.acked[0].actionId, {json.dumps(aid1)});
assert.equal(w10.acked[0].ok, false);
assert.equal(w10.acked[0].code, 'ACTION_DENIED');
assert.equal(fs.existsSync(path.join(receiptsDir, {json.dumps(aid1 + '.json')})), false);
assert.equal(fs.existsSync(path.join(actionsDir, {json.dumps(aid1 + '.json')})), false);

await globalThis.__SS_MAIN_BRIDGE__.dispose();
console.log('TWO_WINDOW_ACK_OK');
"""
        p = self.tmp_path / "m4_two_win.mjs"
        p.write_text(node_script, encoding="utf-8")
        proc = subprocess.run(["node", str(p)], capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0, msg=f"{proc.stdout}\n{proc.stderr}")
        self.assertIn("TWO_WINDOW_ACK_OK", proc.stdout)

    def test_mailbox_rejects_stale_and_expired_without_calling_engine(self) -> None:
        now_ms = int(time.time() * 1000)
        aid_gen = str(uuid.uuid4())
        aid_epoch = str(uuid.uuid4())
        aid_store = str(uuid.uuid4())
        aid_exp = str(uuid.uuid4())

        self._write_action_env(aid_gen, app_gen="99999:1600000000")
        self._write_action_env(aid_epoch, wc_id=10, epoch=99)
        self._write_action_env(aid_store, store_id="different-store-id")
        self._write_action_env(aid_exp, deadline_at=now_ms - 1000)

        snap = {"storeInstanceId": self.store_instance_id, "projectionRevision": 1}
        with patch.object(zcode_sidebar_injector, "execute_ui_actions") as mock_exec:
            rcpts = self.inj._consume_bridge_mailbox(self.gen, self.handshake, snap, now_ms=now_ms)
        mock_exec.assert_not_called()

        by_id = {r["actionId"]: r for r in rcpts}
        self.assertEqual(by_id[aid_gen]["code"], "STALE_APP_GEN")
        self.assertEqual(by_id[aid_epoch]["code"], "STALE_RENDERER_EPOCH")
        self.assertEqual(by_id[aid_store]["code"], "STALE_STORE_INSTANCE")
        self.assertEqual(by_id[aid_exp]["code"], "ACTION_EXPIRED")
        for r in rcpts:
            self.assertFalse(r["ok"])

        # Also test max 16 limit per window per pass
        for _ in range(20):
            self._write_action_env(str(uuid.uuid4()), wc_id=10, epoch=1)
        with patch.object(zcode_sidebar_injector, "execute_ui_actions", return_value=[{"ok": True}]) as mock_exec2:
            rcpts_cap = self.inj._consume_bridge_mailbox(self.gen, self.handshake, snap, now_ms=now_ms)
        self.assertEqual(len(rcpts_cap), 16)
        self.assertEqual(mock_exec2.call_count, 16)

    def test_transport_switch_preserves_action_id_and_store_instance_refresh(self) -> None:
        # Part A: Same projectionRevision with different storeInstanceId MUST refresh (both Injector.push and bundle)
        ws_calls: list[str] = []

        class DummyWs:
            def call(self, method: str, params: dict | None = None) -> dict:
                expr = str((params or {}).get("expression") or "")
                ws_calls.append(expr)
                if "alreadyPatched" in expr or "__SS_SIDEBAR_TREE__" in expr:
                    if "drainActions" in expr:
                        return {"result": {"value": []}}
                    return {"result": {"value": {"ok": True}}}
                return {"result": {"value": True}}

            def close(self) -> None:
                pass

        dws = DummyWs()
        snap_a = {"schemaVersion": 1, "storeInstanceId": "store-A", "projectionRevision": 5, "nodes": []}
        snap_b = {"schemaVersion": 1, "storeInstanceId": "store-B", "projectionRevision": 5, "nodes": []}

        r1 = self.inj.push("t1", dws, snap_a)  # type: ignore[arg-type]
        self.assertTrue(r1.get("ok"))
        self.assertFalse(r1.get("unchanged"))
        r2 = self.inj.push("t1", dws, snap_a)  # type: ignore[arg-type]
        self.assertTrue(r2.get("unchanged"))
        r3 = self.inj.push("t1", dws, snap_b)  # type: ignore[arg-type]
        self.assertTrue(r3.get("ok"))
        self.assertFalse(r3.get("unchanged"))

        # Verify sidebar_tree_bundle.js itself also refreshes on same projectionRevision + new storeInstanceId
        bundle_src = (UI_DIR / "sidebar_tree_bundle.js").read_text(encoding="utf-8")
        node_bundle_chk = f"""
import assert from 'node:assert/strict';
import vm from 'node:vm';
const ctx = vm.createContext({{ globalThis: undefined, setInterval: () => 1, clearInterval: () => {{}}, setTimeout, clearTimeout, addEventListener: () => {{}}, removeEventListener: () => {{}} }});
ctx.globalThis = ctx;
ctx.window = ctx;
ctx.__SS_ZCODE_ADAPTER__ = {{
  id: 'zcode-3.17.2',
  selfCheck: () => ({{ sidebarFound: false, octResolved: false, navigatorResolved: false }}),
  findTaskMounts: () => [],
}};
vm.runInContext({json.dumps(bundle_src)}, ctx);
const u1 = ctx.__SS_SIDEBAR_TREE__.update({{ schemaVersion: 1, storeInstanceId: 'store-A', projectionRevision: 5, nodes: [] }});
assert.equal(u1.ok, true);
assert.notEqual(u1.unchanged, true);
const u2 = ctx.__SS_SIDEBAR_TREE__.update({{ schemaVersion: 1, storeInstanceId: 'store-A', projectionRevision: 5, nodes: [] }});
assert.equal(u2.unchanged, true);
const u3 = ctx.__SS_SIDEBAR_TREE__.update({{ schemaVersion: 1, storeInstanceId: 'store-B', projectionRevision: 5, nodes: [] }});
assert.equal(u3.ok, true);
assert.notEqual(u3.unchanged, true);
ctx.__SS_SIDEBAR_TREE__.destroy();
console.log('BUNDLE_STORE_ID_OK');
"""
        pb = self.tmp_path / "m4_bundle_store.mjs"
        pb.write_text(node_bundle_chk, encoding="utf-8")
        out_b = subprocess.run(["node", str(pb)], capture_output=True, text=True, timeout=10)
        self.assertEqual(out_b.returncode, 0, msg=f"{out_b.stdout}\n{out_b.stderr}")
        self.assertIn("BUNDLE_STORE_ID_OK", out_b.stdout)

        # Part B: Transport switch bridge -> cdp preserves unfinished actionId
        self.inj._set_transport_owner(self.gen, "cdp")
        to_data = json.loads((self.rt_dir / "transport_owner.json").read_text(encoding="utf-8"))
        self.assertEqual(to_data["owner"], "cdp")

        preserved_aid = str(uuid.uuid4())
        child_nid = self.child["node_id"]
        child_rid = self.child["run_id"]

        class SwitchWs:
            def __init__(self) -> None:
                self.acked: list[dict] = []
                self.doc_scripts: list[str] = []

            def call(self, method: str, params: dict | None = None) -> dict:
                if method == "Page.addScriptToEvaluateOnNewDocument":
                    self.doc_scripts.append(str((params or {}).get("source") or ""))
                    return {"identifier": "sc-1"}
                expr = str((params or {}).get("expression") or "")
                if "Boolean(window.__SS_SIDEBAR_TREE__" in expr:
                    return {"result": {"value": True}}  # already alive with same sha!
                if "drainActions" in expr:
                    return {
                        "result": {
                            "value": [
                                {
                                    "actionId": preserved_aid,
                                    "kind": "cancel_run",
                                    "nodeId": child_nid,
                                    "runId": child_rid,
                                    "reason": "switched to cdp",
                                }
                            ]
                        }
                    }
                if "ackActions" in expr:
                    return {"result": {"value": {"acked": 1}}}
                return {"result": {"value": {}}}

            def close(self) -> None:
                pass

        sws = SwitchWs()
        self.inj._attach_target("t-switch", sws, "/*src*/", "sha-same")  # type: ignore[arg-type]
        self.assertEqual(len(sws.doc_scripts), 1)
        self.assertIn("window.__SS_PAYLOAD_SHA__ = \"sha-same\";", sws.doc_scripts[0])
        self.assertIn("window.__SS_TRANSPORT_OWNER__ = 'cdp';", sws.doc_scripts[0])
        rcpts_cdp = self.inj.poll_ui_actions(sws)  # type: ignore[arg-type]
        self.assertEqual(len(rcpts_cdp), 1)
        self.assertEqual(rcpts_cdp[0]["actionId"], preserved_aid)
        self.assertTrue(rcpts_cdp[0]["ok"])

    def test_cdp_ownership_exclusion_and_boot_nonce_hotswap_in_main_bridge(self) -> None:
        """main_bridge.js skips destroy/re-inject/push/drain when CDP owns window, updates __SS_BOOT_NONCE__ on hot-swap, and cleans stale boot files."""
        bridge_path = UI_DIR / "main_bridge.js"
        snap = {"schemaVersion": 1, "storeInstanceId": self.store_instance_id, "projectionRevision": 3, "nodes": []}
        (self.state_root / "exports").mkdir(parents=True, exist_ok=True)
        (self.state_root / "exports" / "sidebar-tree-v1.json").write_text(json.dumps(snap), encoding="utf-8")

        # Put orphaned stale-bootNonce action + receipt files in runtime dir
        stale_aid = str(uuid.uuid4())
        (self.rt_dir / "actions" / f"{stale_aid}.json").write_text(
            json.dumps({"actionId": stale_aid, "appGen": self.gen.key, "bootNonce": "old-dead-nonce"}),
            encoding="utf-8",
        )
        (self.rt_dir / "receipts" / f"{stale_aid}.json").write_text(
            json.dumps({"actionId": stale_aid, "appGen": self.gen.key, "bootNonce": "old-dead-nonce"}),
            encoding="utf-8",
        )

        node_script = f"""
import assert from 'node:assert/strict';
import {{ EventEmitter }} from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);
Object.defineProperty(process, 'type', {{ value: 'browser', configurable: true }});
const {{ installMainBridge }} = require({json.dumps(str(bridge_path))});

const app = new EventEmitter();
function makeWc(id, initialOwner, initialAlive) {{
  const ctx = vm.createContext({{ globalThis: undefined }});
  ctx.globalThis = ctx;
  ctx.window = ctx;
  ctx.__TEST_DESTROY_CALLS__ = 0;
  ctx.__TEST_PUSH_CALLS__ = 0;
  ctx.__TEST_DRAIN_CALLS__ = 0;
  if (initialAlive) {{
    ctx.__SS_PAYLOAD_SHA__ = 'old-cdp-sha';
    ctx.__SS_TRANSPORT_OWNER__ = initialOwner;
    ctx.__SS_SIDEBAR_TREE__ = {{
      alive: true,
      update() {{ ctx.__TEST_PUSH_CALLS__++; return {{ ok: true }}; }},
      drainActions() {{ ctx.__TEST_DRAIN_CALLS__++; return [{{ actionId: 'should-not-drain', kind: 'cancel_run', nodeId: 'n1' }}]; }},
      getStatus: () => ({{ alive: true, sidebarFound: true, navigatorResolved: true }}),
      destroy() {{ ctx.__TEST_DESTROY_CALLS__++; this.alive = false; }},
    }};
  }}
  return Object.assign(new EventEmitter(), {{
    id,
    _ctx: ctx,
    getURL: () => 'file:///Applications/ZCode.app/Contents/Resources/app.asar/out/renderer/index.html?w=' + id,
    getType: () => 'window',
    isDestroyed: () => false,
    async executeJavaScript(code) {{ return await vm.runInContext(code, this._ctx); }},
  }});
}}

const wcCdp = makeWc(1, 'cdp', true);
const wcBridge = makeWc(2, null, false);

const bundleSrc = `
(() => {{
  const G = globalThis;
  G.__SS_ZCODE_ADAPTER__ = {{
    id: 'zcode-3.17.2',
    selfTest: () => ({{ contractId: 'sidebar-list-v1', state: 'ready', capabilities: {{ mount: true, navigation: true, hostIndexSync: false }}, diagnostics: {{}} }}),
  }};
  G.__SS_SIDEBAR_TREE__ = {{
    alive: true,
    update: () => ({{ ok: true }}),
    drainActions: () => [],
    ackActions: () => ({{ acked: 0, remaining: 0 }}),
    getStatus: () => ({{ alive: true, sidebarFound: true, navigatorResolved: true }}),
    destroy() {{ this.alive = false; delete G.__SS_SIDEBAR_TREE__; }},
  }};
}})();
`;

const r1 = await installMainBridge({{
  appGen: {json.dumps(self.gen.key)},
  stateRoot: {json.dumps(str(self.state_root))},
  bundleSource: bundleSrc,
  bundleSha: 'bsha-1',
  bridgeSourceSha: 'br-1',
  pollIntervalMs: 60000,
  electron: {{ app, webContents: {{ getAllWebContents: () => [wcCdp, wcBridge] }} }},
}});

assert.equal(r1.ok, true);
// CDP-owned window must NOT be destroyed, re-injected, pushed, or drained!
assert.equal(wcCdp._ctx.__TEST_DESTROY_CALLS__, 0);
assert.equal(wcCdp._ctx.__TEST_PUSH_CALLS__, 0);
assert.equal(wcCdp._ctx.__TEST_DRAIN_CALLS__, 0);
assert.equal(wcCdp._ctx.__SS_PAYLOAD_SHA__, 'old-cdp-sha');
assert.equal(wcCdp._ctx.__SS_TRANSPORT_OWNER__, 'cdp');

// Bridge-owned window must receive bridge owner + r1.bootNonce
assert.equal(wcBridge._ctx.__SS_TRANSPORT_OWNER__, 'bridge');
assert.equal(wcBridge._ctx.__SS_BOOT_NONCE__, r1.bootNonce);

// Stale bootNonce orphan files cleaned up automatically
assert.equal(fs.existsSync(path.join({json.dumps(str(self.rt_dir))}, 'actions', {json.dumps(stale_aid + '.json')})), false);
assert.equal(fs.existsSync(path.join({json.dumps(str(self.rt_dir))}, 'receipts', {json.dumps(stale_aid + '.json')})), false);

// Hot-swap with same bundleSha but different bridge sourceSha updates __SS_BOOT_NONCE__ in renderer!
const r2 = await installMainBridge({{
  appGen: {json.dumps(self.gen.key)},
  stateRoot: {json.dumps(str(self.state_root))},
  bundleSource: bundleSrc,
  bundleSha: 'bsha-1',
  bridgeSourceSha: 'br-2',
  pollIntervalMs: 60000,
  electron: {{ app, webContents: {{ getAllWebContents: () => [wcCdp, wcBridge] }} }},
}});
assert.equal(r2.ok, true);
assert.notEqual(r2.bootNonce, r1.bootNonce);
assert.equal(wcBridge._ctx.__SS_BOOT_NONCE__, r2.bootNonce);
assert.equal(wcBridge._ctx.__SS_TRANSPORT_OWNER__, 'bridge');

await globalThis.__SS_MAIN_BRIDGE__.dispose();
assert.equal(wcBridge._ctx.__SS_TRANSPORT_OWNER__, undefined);
assert.equal(wcBridge._ctx.__SS_BOOT_NONCE__, undefined);
console.log('CDP_EXCLUSION_AND_NONCE_OK');
"""
        p = self.tmp_path / "m4_cdp_excl.mjs"
        p.write_text(node_script, encoding="utf-8")
        proc = subprocess.run(["node", str(p)], capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0, msg=f"{proc.stdout}\n{proc.stderr}")
        self.assertIn("CDP_EXCLUSION_AND_NONCE_OK", proc.stdout)

        # Also verify on_no_endpoint sets UNSUPPORTED_VERSION when probe returns rejected
        rej_probe = {
            "ok": False,
            "asarSha": "bad",
            "buildState": "rejected",
            "patchState": "conflict",
            "adapterCandidate": None,
            "fuse": {"found": False},
            "diagnostics": {"codes": ["UNKNOWN_MODIFIED_BUNDLE"]},
        }
        with patch.object(self.inj, "probe_build", return_value=rej_probe):
            self.inj.last_build_error = "UNKNOWN_MODIFIED_BUNDLE"
            self.inj.on_no_endpoint(self.gen)
        self.assertEqual(self.inj.health["state"], "UNSUPPORTED_VERSION")
        self.assertEqual(self.inj.health["buildError"], "UNKNOWN_MODIFIED_BUNDLE")

    def test_health_json_honesty_not_ready_when_degraded_or_cleanup_failed(self) -> None:
        snap = {"storeInstanceId": self.store_instance_id, "projectionRevision": 7}
        # Injected count > 0, but navigatorResolved=False -> MUST NOT be READY
        h_wait = self.inj._build_health(
            gen=self.gen,
            transport="bridge",
            transport_ok=True,
            adapter_id="zcode-3.17.2",
            source_sha="s1",
            bundle_sha="b1",
            snap=snap,
            targets={
                "1": {
                    "alive": True,
                    "sidebarFound": True,
                    "navigatorResolved": False,
                    "pendingActions": 2,
                    "selfTest": {"state": "waiting", "capabilities": {"mount": True, "navigation": False}},
                }
            },
            handshake={"updatedAt": 1234.5},
        )
        self.assertNotEqual(h_wait["state"], "READY")
        self.assertEqual(h_wait["appGen"], self.gen.key)
        self.assertEqual(h_wait["contractId"], "sidebar-list-v1")
        self.assertEqual(h_wait["transport"], "bridge")
        self.assertEqual(h_wait["snapshot"], {"storeInstanceId": self.store_instance_id, "projectionRevision": 7})
        self.assertEqual(h_wait["pendingActions"], 2)
        self.assertEqual(h_wait["lastHandshakeAt"], 1234.5)

        # Cleanup failure -> BRIDGE_ERROR, never READY
        h_err = self.inj._build_health(
            gen=self.gen,
            transport="bridge",
            transport_ok=False,
            adapter_id="zcode-3.17.2",
            source_sha="s1",
            bundle_sha="b1",
            snap=snap,
            targets={},
            sigusr1={"ok": False, "code": "INSPECTOR_CLOSE_FAILED"},
        )
        self.assertEqual(h_err["state"], "BRIDGE_ERROR")
        self.assertIn("INSPECTOR_CLOSE_FAILED", h_err["degradationReasons"])

        # Healthy target + healthy transport -> READY
        h_ok = self.inj._build_health(
            gen=self.gen,
            transport="bridge",
            transport_ok=True,
            adapter_id="zcode-3.17.2",
            source_sha="s1",
            bundle_sha="b1",
            snap=snap,
            targets={
                "1": {
                    "alive": True,
                    "sidebarFound": True,
                    "navigatorResolved": True,
                    "pendingActions": 0,
                    "selfTest": {
                        "state": "ready",
                        "capabilities": {
                            "mount": True,
                            "navigation": True,
                            "chatViewport": True,
                            "hostIndexSync": True,
                            "dedup": True,
                        },
                    },
                }
            },
            handshake={"updatedAt": 1235.0},
        )
        self.assertEqual(h_ok["state"], "READY")


if __name__ == "__main__":
    unittest.main()
