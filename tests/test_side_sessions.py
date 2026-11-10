#!/usr/bin/env python3
"""Comprehensive automated acceptance test suite for the side-sessions plugin (Steps 1-9)."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
from typing import Any
import plistlib
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
MARKETPLACE_ROOT = PLUGIN_ROOT.parent
SCRIPTS_DIR = PLUGIN_ROOT / "scripts"
HOOKS_DIR = PLUGIN_ROOT / "hooks"

for _p in (str(SCRIPTS_DIR), str(HOOKS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import contracts  # type: ignore  # noqa: E402
from contracts import (  # type: ignore  # noqa: E402
    CallerContext,
    CanonicalReport,
    ErrorCode,
    ExitReceipt,
    HookContext,
    SideSessionError,
    WorktreeRecord,
    WorkspaceSpec,
    format_recap_400,
    normalize_request,
    sha256_hex,
    validate_fresh_background,
    validate_hook_output,
)
from driver import (  # type: ignore  # noqa: E402
    RuntimeEvent,
    ScriptedFakeDriver,
    build_create_payload,
    extract_workspace_path,
)
from engine import Engine  # type: ignore  # noqa: E402
from host_adapter import HostAdapter  # type: ignore  # noqa: E402
from mcp_server import (  # type: ignore  # noqa: E402
    ALLOWED_ENGINE_TOOLS,
    TrustedConnection,
    caller_from_meta,
    handle_rpc_message,
    handle_tool_call,
    serve_stdio,
)
from side_sessions_hook import (  # type: ignore  # noqa: E402
    main as hook_main,
    parse_hook_input,
)
from state import (  # type: ignore  # noqa: E402
    FileLock,
    Store,
    atomic_export,
    ensure_safe_dir,
    open_store,
    resolve_state_root,
    safe_resolve_under,
)
from worker_runner import (  # type: ignore  # noqa: E402
    OwnerContext,
    WorkerRunner,
)
import worktree  # type: ignore  # noqa: E402


VALID_BACKGROUND_80 = (
    "总体目标：在完全隔离的临时测试环境中验证 side-sessions 父子会话树、工作区隔离与事件汇报全流程。\n"
    "已有决策：全部测试采用 tempfile.TemporaryDirectory 与 ScriptedFakeDriver，零触碰用户真实目录。\n"
    "约束：严格遵守最小权限、四槽并发配额、唯一终态报告和同步 Hook 校验规范。"
)


def _init_temp_git_repo(repo_dir: Path) -> str:
    """Initialize a clean temporary git repository with one commit and NO .gitignore."""
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(repo_dir), "init"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.email", "test@side-sessions.local"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.name", "Side Sessions Test"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    (repo_dir / "README.md").write_text("# Temporary Fixture Repo\n", encoding="utf-8")
    (repo_dir / "app.py").write_text("def greet() -> str:\n    return 'hello'\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(repo_dir), "add", "README.md", "app.py"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "commit", "-m", "Initial commit"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    head = (
        subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "--verify", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        .stdout.decode("utf-8")
        .strip()
    )
    return head


class IsolatedSideSessionsTestCase(unittest.TestCase):
    """Base test case providing an isolated temporary state_root, workspace, and fake host DB."""

    def setUp(self) -> None:
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory(prefix="side-sessions-test-")
        self.tmp_path = Path(self._tmp.name).resolve()
        self.state_root = self.tmp_path / "state-root"
        self.workspace_dir = self.tmp_path / "workspace"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.host_db_path = self.tmp_path / "fake-host-db.sqlite"

        self._prev_env: dict[str, str | None] = {
            "ZCODE_SIDE_SESSIONS_HOME": os.environ.get("ZCODE_SIDE_SESSIONS_HOME"),
            "ZCODE_HOST_DB_PATH": os.environ.get("ZCODE_HOST_DB_PATH"),
        }
        os.environ["ZCODE_SIDE_SESSIONS_HOME"] = str(self.state_root)
        os.environ["ZCODE_HOST_DB_PATH"] = str(self.host_db_path)

        self.clock_now = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)
        self.store: Store = open_store(self.state_root, writable=True)
        self.driver = ScriptedFakeDriver(host_db_path=self.host_db_path, sync_to_host_db=False)
        self.host_adapter = HostAdapter(
            store=self.store,
            state_root=self.state_root,
            host_db_path=self.host_db_path,
        )
        self.engine = Engine(
            self.store,
            clock=lambda: self.clock_now,
            host_adapter=self.host_adapter,
            driver=self.driver,
            worktrees_home=self.state_root / "worktrees",
        )
        self.parent_caller = CallerContext(
            runtime_sid="sid-parent-main",
            runtime_turn_id="turn-parent-1",
            workspace_path=str(self.workspace_dir),
            connection_id="stdio:test-main",
        )

    def tearDown(self) -> None:
        try:
            self.store.close()
        except Exception:
            pass
        for k, v in self._prev_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()
        super().tearDown()

    def advance_clock(self, *, seconds: int = 0, minutes: int = 0, hours: int = 0) -> None:
        self.clock_now = self.clock_now + timedelta(seconds=seconds, minutes=minutes, hours=hours)

    def _trust_human(self, input_id: str, *, command_id: str = "/side-sessions:approve", runtime_sid: str | None = None) -> None:
        self.host_adapter.record_human_input(
            runtime_sid=runtime_sid or self.parent_caller.runtime_sid,
            input_id=input_id,
            origin="slash_command",
            command_id=command_id,
        )

    def _close_child_run(self, st: dict) -> None:
        self.engine.close_run(
            {"run_id": st["run_id"], "node_id": st["node_id"]},
            ExitReceipt(
                runtime_instance_id=str(st.get("runtime_session_id") or ""),
                process_identity={},
                exit_confirmed=True,
                runtime_outcome="success",
                ended_at=self.clock_now.isoformat().replace("+00:00", "Z"),
                exit_code=0,
                evidence_ref="test-close",
            ),
            run_id=st["run_id"],
        )


# ==============================================================================
# Step 1: 静态清单与模板契约测试
# ==============================================================================
class TestStep1StaticManifestsAndTemplates(unittest.TestCase):
    """Step 1: Verify plugin manifests, MCP config, hooks config, marketplace, skills, commands, plist, and lockfile."""

    def test_plugin_json_contract(self) -> None:
        manifest_path = PLUGIN_ROOT / ".zcode-plugin" / "plugin.json"
        self.assertTrue(manifest_path.is_file())
        self.assertFalse(manifest_path.is_symlink())

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["name"], "side-sessions")
        self.assertRegex(manifest["version"], r"^\d+\.\d+\.\d+$")
        self.assertEqual(manifest["skills"], "./skills")
        self.assertEqual(manifest["commands"], "./commands")
        self.assertNotIn("${CLAUDE_PLUGIN_ROOT}", manifest["skills"])
        self.assertNotIn("${CLAUDE_PLUGIN_ROOT}", manifest["commands"])
        self.assertNotIn("hooks", manifest)
        self.assertNotIn("mcpServers", manifest)

    def test_mcp_json_contract(self) -> None:
        mcp_path = PLUGIN_ROOT / ".mcp.json"
        self.assertTrue(mcp_path.is_file())
        self.assertFalse(mcp_path.is_symlink())

        mcp = json.loads(mcp_path.read_text(encoding="utf-8"))
        self.assertIn("mcpServers", mcp)
        server_cfg = mcp["mcpServers"]["side_sessions"]
        self.assertEqual(server_cfg["command"], "/bin/sh")
        self.assertEqual(
            server_cfg["args"],
            [
                "${CLAUDE_PLUGIN_ROOT}/scripts/run_py311.sh",
                "${CLAUDE_PLUGIN_ROOT}/scripts/mcp_server.py",
            ],
        )
        for arg in server_cfg["args"]:
            for forbidden in ("~", ">", "&&", '"', "'"):
                self.assertNotIn(forbidden, arg)

    def test_hooks_json_synchronous_process_contract(self) -> None:
        hooks_path = PLUGIN_ROOT / "hooks" / "hooks.json"
        self.assertTrue(hooks_path.is_file())
        self.assertFalse(hooks_path.is_symlink())

        hooks_cfg = json.loads(hooks_path.read_text(encoding="utf-8"))
        self.assertEqual(set(hooks_cfg.keys()), {"hooks"})
        expected_events = {"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"}
        self.assertEqual(set(hooks_cfg["hooks"].keys()), expected_events)

        for event_name, matcher_groups in hooks_cfg["hooks"].items():
            self.assertIsInstance(matcher_groups, list, f"{event_name} must be a list of matcher groups")
            self.assertGreaterEqual(len(matcher_groups), 1)
            hook_entry = matcher_groups[0]["hooks"][0]
            self.assertEqual(hook_entry["type"], "process")
            self.assertEqual(hook_entry["command"], "/bin/sh")
            self.assertEqual(
                hook_entry["args"],
                [
                    "${CLAUDE_PLUGIN_ROOT}/scripts/run_py311.sh",
                    "${CLAUDE_PLUGIN_ROOT}/hooks/side_sessions_hook.py",
                ],
            )
            self.assertEqual(hook_entry["timeoutMs"], 3000)
            self.assertNotIn("async", hook_entry)

    def test_marketplace_skills_commands_service_and_lockfile(self) -> None:
        manifest = json.loads((PLUGIN_ROOT / ".zcode-plugin" / "plugin.json").read_text(encoding="utf-8"))
        flat_marketplace_path = PLUGIN_ROOT / "marketplace.json"
        if flat_marketplace_path.is_file():
            marketplace_path = flat_marketplace_path
            expected_mkt_name: str | None = "side-sessions-marketplace"
            expected_source = "./"
        else:
            marketplace_path = MARKETPLACE_ROOT / "marketplace.json"
            expected_mkt_name = None
            expected_source = f"./{PLUGIN_ROOT.name}"
        self.assertTrue(marketplace_path.is_file())
        mkt = json.loads(marketplace_path.read_text(encoding="utf-8"))
        if expected_mkt_name is not None:
            self.assertEqual(mkt["name"], expected_mkt_name)
        else:
            self.assertTrue(isinstance(mkt.get("name"), str) and bool(mkt["name"].strip()))
        plugins = {p["name"]: p for p in mkt.get("plugins", [])}
        self.assertIn("side-sessions", plugins)
        self.assertEqual(plugins["side-sessions"]["source"], expected_source)
        self.assertEqual(plugins["side-sessions"]["version"], manifest["version"])

        skill_path = PLUGIN_ROOT / "skills" / "side-sessions" / "SKILL.md"
        self.assertTrue(skill_path.is_file())
        skill_text = skill_path.read_text(encoding="utf-8")
        self.assertTrue(skill_text.startswith("---\n"))
        self.assertIn("name: side-sessions", skill_text)
        self.assertIn("description:", skill_text)

        expected_commands = (
            "tree.md",
            "handoff.md",
            "approve.md",
            "dismiss.md",
            "continue.md",
            "respond.md",
            "cancel.md",
            "archive.md",
            "diff.md",
            "merge.md",
            "cleanup.md",
        )
        for cmd_name in expected_commands:
            cmd_path = PLUGIN_ROOT / "commands" / cmd_name
            self.assertTrue(cmd_path.is_file(), f"Missing command file: {cmd_name}")
            cmd_text = cmd_path.read_text(encoding="utf-8")
            self.assertTrue(cmd_text.startswith("---\n"), f"{cmd_name} missing YAML frontmatter")

        plist_path = PLUGIN_ROOT / "service" / "com.zcode.side-sessions.plist.example"
        self.assertTrue(plist_path.is_file())
        plist_data = plistlib.loads(plist_path.read_bytes())
        self.assertEqual(plist_data["Label"], "com.zcode.side-sessions")
        self.assertIn("serve", plist_data["ProgramArguments"])

        lock_path = PLUGIN_ROOT / "requirements.lock"
        self.assertTrue(lock_path.is_file())
        self.assertIn("Zero Third-Party Runtime Dependencies", lock_path.read_text(encoding="utf-8"))


# ==============================================================================
# Step 2: 状态存储、固定旁路锁、导出与软链防护测试
# ==============================================================================
class TestStep2StateStoreLocksExportsAndSymlinkDefense(IsolatedSideSessionsTestCase):
    """Step 2: Verify SQLite WAL tables, fixed lock inodes across atomic_export, symlink defense, and CAS."""

    def test_sqlite_wal_tables_and_revision_monotonicity(self) -> None:
        journal_mode = str(self.store.conn.execute("PRAGMA journal_mode;").fetchone()[0]).lower()
        fk_enabled = int(self.store.conn.execute("PRAGMA foreign_keys;").fetchone()[0])
        self.assertEqual(journal_mode, "wal")
        self.assertEqual(fk_enabled, 1)

        existing_tables = {
            str(r[0])
            for r in self.store.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        required_tables = {
            "schema_meta",
            "store_meta",
            "nodes",
            "bindings",
            "proposals",
            "requests",
            "parent_slots",
            "slots",
            "dispatch_groups",
            "dispatch_group_members",
            "dispatch_members",
            "operations",
            "context_snapshots",
            "context_acceptances",
            "worktrees",
            "inbox_messages",
            "messages",
            "owners",
            "turns",
            "reports",
            "artifacts",
            "outbox_events",
            "outbox",
            "event_acks",
            "wake_budget",
            "wake_state",
            "group_wakes",
            "tasks",
            "task_turn_bindings",
            "task_actions",
            "task_guards",
            "transfers",
            "wait_requests",
            "control_commands",
            "note_entries",
            "input_provenance",
        }
        self.assertTrue(required_tables.issubset(existing_tables))

        rev0 = self.store.get_revision()
        with self.store.transaction("IMMEDIATE") as txn:
            rev1 = txn.revision
        self.assertEqual(rev1, rev0 + 1)
        self.assertEqual(self.store.get_revision(), rev1)

    def test_fixed_lock_inodes_survive_atomic_exports(self) -> None:
        node_id = str(uuid.uuid4())
        maint_lock_path = self.state_root / "locks" / "maintenance.lock"
        sess_lock_path = self.state_root / "locks" / f"session-{node_id}.lock"

        with self.store.maintenance_lock(shared=True) as m_lock:
            m_lock.verify_inode()
            maint_ino_before = os.lstat(maint_lock_path).st_ino

        with self.store.session_lock(node_id, blocking=True, timeout_ms=1000) as n_lock:
            n_lock.verify_inode()
            sess_ino_before = os.lstat(sess_lock_path).st_ino
            # Worker holding session lock is allowed to run a short DB transaction
            with self.store.transaction("IMMEDIATE"):
                pass

        # Perform multiple atomic exports and projection rebuilds
        parent_node = self.engine.ensure_caller_node(self.parent_caller)
        parent_id = str(parent_node["node_id"])
        self.store.atomic_export("exports/custom-view.json", b'{"ok":true}')
        self.store.export_parent_notes(parent_id)
        self.store.rebuild_projections()

        self.assertEqual(os.lstat(maint_lock_path).st_ino, maint_ino_before)
        self.assertEqual(os.lstat(sess_lock_path).st_ino, sess_ino_before)

        # Attempting to overwrite a lock file via atomic_export must be rejected
        with self.assertRaises(SideSessionError) as ctx:
            self.store.atomic_export("locks/maintenance.lock", b"corrupt")
        self.assertEqual(ctx.exception.code, ErrorCode.LOCK_REPLACED)

        # Acquiring session lock inside an active DB transaction must violate lock order
        other_node_id = str(uuid.uuid4())
        with self.store.transaction("IMMEDIATE"):
            with self.assertRaises(SideSessionError) as order_ctx:
                with self.store.session_lock(other_node_id, blocking=False):
                    pass
            self.assertEqual(order_ctx.exception.code, ErrorCode.INVALID_REQUEST)

    def test_symlink_traversal_and_path_escape_rejected(self) -> None:
        outside_file = self.tmp_path / "outside-secret.txt"
        outside_file.write_text("top-secret", encoding="utf-8")
        outside_dir = self.tmp_path / "outside-dir"
        outside_dir.mkdir(parents=True, exist_ok=True)

        # 1. Symlink inside state_root subdir
        evil_link = self.state_root / "notes" / "evil-link"
        os.symlink(outside_dir, evil_link)
        with self.assertRaises(SideSessionError) as sym_ctx:
            safe_resolve_under(self.state_root, "notes/evil-link/pwned.md", mkdirs=True)
        self.assertEqual(sym_ctx.exception.code, "PATH_SECURITY_VIOLATION")
        self.assertEqual(sym_ctx.exception.code, ErrorCode.SYMLINK_FORBIDDEN)

        # 2. Symlink at export target
        file_link = self.state_root / "exports" / "evil-target.json"
        os.symlink(outside_file, file_link)
        with self.assertRaises(SideSessionError) as exp_ctx:
            self.store.atomic_export("exports/evil-target.json", b"overwrite")
        self.assertEqual(exp_ctx.exception.code, "PATH_SECURITY_VIOLATION")
        self.assertEqual(outside_file.read_text(encoding="utf-8"), "top-secret")

        # 3. Parent traversal `..` and absolute path
        for bad_rel in ("../escape.txt", "notes/../../escape.txt", "/etc/passwd", "notes\\backslash.md"):
            with self.assertRaises(SideSessionError) as esc_ctx:
                safe_resolve_under(self.state_root, bad_rel)
            self.assertEqual(esc_ctx.exception.code, "PATH_SECURITY_VIOLATION")
            self.assertEqual(esc_ctx.exception.code, ErrorCode.PATH_ESCAPE)

    def test_shared_notes_cas_and_revision_conflict(self) -> None:
        self.engine.ensure_caller_node(self.parent_caller)

        # Initial shared_context_revision is 0
        up1 = self.engine.update_shared_context(
            self.parent_caller,
            {
                "request_id": str(uuid.uuid4()),
                "expected_revision": 0,
                "content": "# Shared Context v1\nInitial architecture notes.",
            },
        )
        self.assertTrue(up1["ok"])
        self.assertEqual(up1["shared_context_revision"], 1)

        # Stale expected_revision=0 must raise REVISION_CONFLICT
        with self.assertRaises(SideSessionError) as cas_ctx:
            self.engine.update_shared_context(
                self.parent_caller,
                {
                    "request_id": str(uuid.uuid4()),
                    "expected_revision": 0,
                    "content": "# Conflicting update",
                },
            )
        self.assertEqual(cas_ctx.exception.code, ErrorCode.REVISION_CONFLICT)

        # Submit immutable note entry and read back
        note_res = self.engine.submit_note(
            self.parent_caller,
            {
                "request_id": str(uuid.uuid4()),
                "content": "Immutable child note entry #1",
            },
        )
        self.assertTrue(note_res["ok"])
        self.assertEqual(note_res["note_revision"], 1)

        ctx_view = self.engine.read_context(self.parent_caller, {})
        self.assertEqual(ctx_view["shared_context_revision"], 1)
        self.assertIn("Shared Context v1", ctx_view["content"])
        self.assertEqual(len(ctx_view["entries"]), 1)


# ==============================================================================
# Step 3: 身份绑定与授权边界测试（G01/G12）
# ==============================================================================
class TestStep3IdentityBindingAndAuthorizationBoundary(IsolatedSideSessionsTestCase):
    """Step 3: Verify MCP caller_from_meta, Hook parse_hook_input, anti-spoofing, and family boundaries."""

    def test_caller_from_meta_namespace_and_conflict_detection(self) -> None:
        conn = TrustedConnection(initialized=True)

        # 1. Valid namespace extraction
        caller = caller_from_meta(
            {
                "com.zcode/request-context": {
                    "session_id": "sid-alpha",
                    "turn_id": "turn-101",
                    "runtime_scope": "main",
                    "workspace_path": str(self.workspace_dir),
                    "trace_id": "trace-xyz",
                }
            },
            connection=conn,
        )
        self.assertEqual(caller.runtime_sid, "sid-alpha")
        self.assertEqual(caller.runtime_turn_id, "turn-101")
        self.assertEqual(caller.workspace_path, str(self.workspace_dir))

        # 2. Consistent flat + namespace succeeds
        caller_consistent = caller_from_meta(
            {
                "com.zcode/request-context": {"session_id": "sid-alpha", "turn_id": "turn-101"},
                "session_id": "sid-alpha",
                "turn_id": "turn-101",
            },
            connection=conn,
        )
        self.assertEqual(caller_consistent.runtime_sid, "sid-alpha")

        # 3. Conflict between namespace and flat raises CALLER_IDENTITY_CONFLICT / CALLER_CONTEXT_CONFLICT
        with self.assertRaises(SideSessionError) as conf_ctx:
            caller_from_meta(
                {
                    "com.zcode/request-context": {"session_id": "sid-alpha"},
                    "session_id": "sid-beta",
                },
                connection=conn,
            )
        self.assertEqual(conf_ctx.exception.code, "CALLER_IDENTITY_CONFLICT")
        self.assertEqual(conf_ctx.exception.code, ErrorCode.CALLER_CONTEXT_CONFLICT)

        # 4. Missing _meta or missing session_id raises CALLER_UNBOUND
        for empty_meta in (None, {}, {"turn_id": "turn-only"}):
            with self.assertRaises(SideSessionError) as unb_ctx:
                caller_from_meta(empty_meta, connection=conn)
            self.assertEqual(unb_ctx.exception.code, ErrorCode.CALLER_UNBOUND)

        # 5. Namespace present but missing session_id must NOT fall back to flat session_id
        with self.assertRaises(SideSessionError) as no_fb_ctx:
            caller_from_meta(
                {
                    "com.zcode/request-context": {"turn_id": "turn-1"},
                    "session_id": "sid-flat-fallback",
                },
                connection=conn,
            )
        self.assertEqual(no_fb_ctx.exception.code, "CALLER_IDENTITY_CONFLICT")

    def test_mcp_ignores_env_and_rejects_argument_identity_spoofing(self) -> None:
        conn = TrustedConnection(initialized=True)
        # Alternating SIDs A and B on same connection do not cross-contaminate
        res_a = handle_tool_call(
            {
                "name": "list_sessions",
                "arguments": {},
                "_meta": {"com.zcode/request-context": {"session_id": "sid-conn-A"}},
            },
            connection=conn,
            engine=self.engine,
        )
        res_b = handle_tool_call(
            {
                "name": "list_sessions",
                "arguments": {},
                "_meta": {"com.zcode/request-context": {"session_id": "sid-conn-B"}},
            },
            connection=conn,
            engine=self.engine,
        )
        self.assertTrue(res_a["ok"])
        self.assertTrue(res_b["ok"])
        self.assertNotEqual(res_a["caller_node_id"], res_b["caller_node_id"])

        # Attempting to spoof caller identity in arguments must fail with UNKNOWN_FIELD
        for spoof_field in ("caller_sid", "caller_session_id", "caller_node_id", "actor_node_id", "parent_sid", "_meta"):
            spoof_res = handle_tool_call(
                {
                    "name": "list_sessions",
                    "arguments": {spoof_field: "sid-spoofed"},
                    "_meta": {"com.zcode/request-context": {"session_id": "sid-conn-A"}},
                },
                connection=conn,
                engine=self.engine,
            )
            self.assertFalse(spoof_res["ok"])
            self.assertEqual(spoof_res["error"]["code"], ErrorCode.UNKNOWN_FIELD.value)

        # Without _meta, even if CLAUDE_SESSION_ID is set in os.environ, MCP tool call fails with CALLER_UNBOUND
        prev = os.environ.get("CLAUDE_SESSION_ID")
        os.environ["CLAUDE_SESSION_ID"] = "sid-from-env-ignored"
        try:
            unb_res = handle_tool_call(
                {"name": "list_sessions", "arguments": {}},
                connection=conn,
                engine=self.engine,
            )
            self.assertFalse(unb_res["ok"])
            self.assertEqual(unb_res["error"]["code"], ErrorCode.CALLER_UNBOUND.value)
        finally:
            if prev is None:
                os.environ.pop("CLAUDE_SESSION_ID", None)
            else:
                os.environ["CLAUDE_SESSION_ID"] = prev

    def test_hook_parse_input_validates_stdin_and_environment_consistency(self) -> None:
        # Consistent stdin and env succeeds
        h_ctx = parse_hook_input(
            json.dumps({"session_id": "sid-hook-1", "hook_event_name": "UserPromptSubmit", "cwd": str(self.workspace_dir)}),
            environ={"CLAUDE_SESSION_ID": "sid-hook-1", "ZCODE_SESSION_ID": "sid-hook-1"},
        )
        self.assertEqual(h_ctx.runtime_sid, "sid-hook-1")
        self.assertEqual(h_ctx.event, "UserPromptSubmit")

        # Mismatched session_id and sessionId inside stdin JSON raises HOOK_IDENTITY_MISMATCH
        with self.assertRaises(SideSessionError) as json_mis:
            parse_hook_input(
                json.dumps({"session_id": "sid-1", "sessionId": "sid-2"}),
                environ={},
            )
        self.assertEqual(json_mis.exception.code, "HOOK_IDENTITY_MISMATCH")
        self.assertEqual(json_mis.exception.code, "CALLER_IDENTITY_CONFLICT")

        # Mismatched stdin session_id vs environment variable raises HOOK_IDENTITY_MISMATCH
        with self.assertRaises(SideSessionError) as env_mis:
            parse_hook_input(
                json.dumps({"session_id": "sid-stdin", "hook_event_name": "PostToolUse"}),
                environ={"CLAUDE_SESSION_ID": "sid-env-different"},
            )
        self.assertEqual(env_mis.exception.code, "HOOK_IDENTITY_MISMATCH")

        # Conflicting env vars with missing stdin SID still refuse identity inference
        with self.assertRaises(SideSessionError) as multi_env_mis:
            parse_hook_input(
                "{}",
                environ={"CLAUDE_SESSION_ID": "sid-env-1", "ZCODE_SESSION_ID": "sid-env-2"},
            )
        self.assertIn(multi_env_mis.exception.code, ("HOOK_IDENTITY_MISMATCH", ErrorCode.CALLER_UNBOUND))

        # Missing in both stdin and env raises CALLER_UNBOUND
        with self.assertRaises(SideSessionError) as missing_sid:
            parse_hook_input("{}", environ={})
        self.assertEqual(missing_sid.exception.code, ErrorCode.CALLER_UNBOUND)

    def test_family_authorization_isolation_and_root_no_parent(self) -> None:
        # Root session resolving "parent" must raise NO_PARENT
        with self.assertRaises(SideSessionError) as np_ctx:
            self.engine.get_session(self.parent_caller, {"session_id": "parent"})
        self.assertEqual(np_ctx.exception.code, ErrorCode.NO_PARENT)

        # Start child in Family A
        start_a = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Family A Child",
                "prompt": "Analyze module A.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "child-a",
            },
        )
        child_a_id = start_a["node_id"]

        # Unrelated Family B caller cannot inspect or message child_a
        outsider_caller = CallerContext(runtime_sid="sid-outsider-family-b", workspace_path=str(self.workspace_dir))
        with self.assertRaises(SideSessionError) as get_err:
            self.engine.get_session(outsider_caller, {"session_id": child_a_id})
        self.assertEqual(get_err.exception.code, ErrorCode.FORBIDDEN)

        with self.assertRaises(SideSessionError) as send_err:
            self.engine.send_message_to_session(
                outsider_caller,
                {
                    "request_id": str(uuid.uuid4()),
                    "message_id": str(uuid.uuid4()),
                    "session_id": child_a_id,
                    "message": "Intrude",
                },
            )
        self.assertEqual(send_err.exception.code, ErrorCode.FORBIDDEN)


# ==============================================================================
# Step 4: 启动判别联合、提案状态机与四槽并发配额测试（G07/R02）
# ==============================================================================
class TestStep4InitiationUnionProposalsAndFourSlotQuota(IsolatedSideSessionsTestCase):
    """Step 4: Verify fresh background length, offer/own_initiative state machines, and 4-slot quota."""

    def test_fresh_background_length_and_normalization_gate(self) -> None:
        # 79 chars after stripping whitespace must be rejected with BACKGROUND_TOO_SHORT / INVALID_ARGUMENT
        short_79 = "   " + ("测" * 79) + "\n\t  "
        with self.assertRaises(SideSessionError) as short_ctx:
            self.engine.start_session(
                self.parent_caller,
                {
                    "initiation": "user_asked",
                    "request_id": str(uuid.uuid4()),
                    "title": "Short background test",
                    "prompt": "Run check.",
                    "context": "fresh",
                    "background": short_79,
                    "task_kind": "read_only",
                    "use_worktree": False,
                },
            )
        self.assertEqual(short_ctx.exception.code, ErrorCode.BACKGROUND_TOO_SHORT)
        self.assertEqual(short_ctx.exception.code, "INVALID_ARGUMENT")

        # Background without the three required section headers is INVALID_BACKGROUND
        exact_80 = "测" * 80
        with self.assertRaises(SideSessionError) as missing_sec:
            self.engine.start_session(
                self.parent_caller,
                {
                    "initiation": "user_asked",
                    "request_id": str(uuid.uuid4()),
                    "title": "Exact 80 background test",
                    "prompt": "Run check.",
                    "context": "fresh",
                    "background": exact_80,
                    "task_kind": "read_only",
                    "use_worktree": False,
                },
            )
        self.assertEqual(missing_sec.exception.code, ErrorCode.INVALID_BACKGROUND)

        ok_res = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Exact 80 background test",
                "prompt": "Run check.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
            },
        )
        self.assertTrue(ok_res["ok"])
        self.assertEqual(ok_res["status"], "running")

    def test_offer_proposal_lifecycle_and_approval_gate(self) -> None:
        # Offer with extra fields (e.g. prompt or use_worktree) must be rejected
        with self.assertRaises(SideSessionError) as extra_ctx:
            self.engine.start_session(
                self.parent_caller,
                {
                    "initiation": "offer",
                    "request_id": str(uuid.uuid4()),
                    "title": "Bad offer with prompt",
                    "prompt": "Should not be allowed",
                },
            )
        self.assertEqual(extra_ctx.exception.code, ErrorCode.UNKNOWN_FIELD)

        # Valid initial offer saves only title and enters waiting_user
        offer_res = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "offer",
                "request_id": str(uuid.uuid4()),
                "title": "Investigate memory footprint",
            },
        )
        self.assertEqual(offer_res["status"], "waiting_user")
        proposal_id = offer_res["proposal_id"]
        self.assertIsNotNone(proposal_id)
        self.assertIsNone(offer_res.get("node_id"))

        # Model attempting to claim offer before human approval must be rejected
        with self.assertRaises(SideSessionError) as unapproved_ctx:
            self.engine.start_session(
                self.parent_caller,
                {
                    "proposal_id": proposal_id,
                    "request_id": str(uuid.uuid4()),
                    "prompt": "Start without approval",
                    "background": VALID_BACKGROUND_80,
                },
            )
        self.assertEqual(unapproved_ctx.exception.code, ErrorCode.HUMAN_ACTION_REQUIRED)

        # Model self-approval attempt must be rejected by HostAdapter
        with self.assertRaises(SideSessionError) as self_app_ctx:
            self.engine.approve_proposal(
                self.parent_caller,
                {
                    "proposal_id": proposal_id,
                    "origin": "model",
                    "from_model": True,
                },
            )
        self.assertEqual(self_app_ctx.exception.code, ErrorCode.USER_APPROVAL_UNAVAILABLE)

        # Trusted human approval transitions offer -> awaiting_brief
        self._trust_human("human-inp-offer-1")
        app_res = self.engine.approve_proposal(
            proposal_id,
            {
                "real_input_id": "human-inp-offer-1",
                "command_id": "/side-sessions:approve",
                "origin": "slash_command",
            },
        )
        self.assertTrue(app_res["ok"])
        self.assertEqual(app_res["state"], "awaiting_brief")

        # Now ClaimOffer with prompt + background starts the session
        claim_res = self.engine.start_session(
            self.parent_caller,
            {
                "proposal_id": proposal_id,
                "request_id": str(uuid.uuid4()),
                "prompt": "Analyze memory allocations in module X.",
                "background": VALID_BACKGROUND_80,
            },
        )
        self.assertTrue(claim_res["ok"])
        self.assertEqual(claim_res["status"], "running")
        self.assertEqual(claim_res["task_kind"], "read_only")
        self.assertEqual(claim_res["workspace_mode"], "inherit")

    def test_own_initiative_proposal_approve_and_dismiss(self) -> None:
        # 1. Create own_initiative proposal -> waiting_user, then dismiss_task
        prop1 = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "own_initiative",
                "request_id": str(uuid.uuid4()),
                "title": "Optional lint scan",
                "prompt": "Run linter checks.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
            },
        )
        self.assertEqual(prop1["status"], "waiting_user")
        pid1 = prop1["proposal_id"]

        dis_res = self.engine.dismiss_task(
            self.parent_caller,
            {"request_id": str(uuid.uuid4()), "proposal_id": pid1},
        )
        self.assertEqual(dis_res["state"], "dismissed")

        # Dismissing again raises ALREADY_DISMISSED
        with self.assertRaises(SideSessionError) as dis2_ctx:
            self.engine.dismiss_task(
                self.parent_caller,
                {"request_id": str(uuid.uuid4()), "proposal_id": pid1},
            )
        self.assertEqual(dis2_ctx.exception.code, ErrorCode.ALREADY_DISMISSED)

        # 2. Create 2nd own_initiative proposal, approve and start, then verify dismiss_task raises ALREADY_STARTED
        prop2 = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "own_initiative",
                "request_id": str(uuid.uuid4()),
                "title": "Security audit proposal",
                "prompt": "Audit authentication handlers.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
            },
        )
        pid2 = prop2["proposal_id"]
        self._trust_human("human-inp-own-2")
        app2 = self.engine.approve_proposal(
            pid2,
            {
                "real_input_id": "human-inp-own-2",
                "command_id": "/side-sessions:approve",
                "origin": "slash_command",
            },
        )
        self.assertEqual(app2["state"], "approved")

        # Claiming full proposal with extra override fields is rejected
        with self.assertRaises(SideSessionError):
            self.engine.start_session(
                self.parent_caller,
                {
                    "proposal_id": pid2,
                    "request_id": str(uuid.uuid4()),
                    "prompt": "Tampered prompt",
                    "background": VALID_BACKGROUND_80,
                },
            )

        started2 = self.engine.start_session(
            self.parent_caller,
            {"proposal_id": pid2, "request_id": str(uuid.uuid4())},
        )
        self.assertEqual(started2["status"], "running")

        with self.assertRaises(SideSessionError) as already_ctx:
            self.engine.dismiss_task(
                self.parent_caller,
                {"request_id": str(uuid.uuid4()), "proposal_id": pid2},
            )
        self.assertEqual(already_ctx.exception.code, ErrorCode.ALREADY_STARTED)

    def test_four_slot_concurrent_quota_per_parent(self) -> None:
        started_ids: list[str] = []
        for idx in range(4):
            res = self.engine.start_session(
                self.parent_caller,
                {
                    "initiation": "user_asked",
                    "request_id": str(uuid.uuid4()),
                    "title": f"Parallel Worker {idx + 1}",
                    "prompt": f"Execute part {idx + 1}",
                    "context": "fresh",
                    "background": VALID_BACKGROUND_80,
                    "task_kind": "read_only",
                    "use_worktree": False,
                    "name": f"worker-{idx + 1}",
                },
            )
            self.assertEqual(res["status"], "running")
            started_ids.append(res["node_id"])

        tree = self.engine.list_sessions(self.parent_caller, {})
        self.assertEqual(tree["active_slots"], 4)

        # 5th concurrent child on same parent must immediately raise CAPACITY_EXCEEDED
        with self.assertRaises(SideSessionError) as cap_ctx:
            self.engine.start_session(
                self.parent_caller,
                {
                    "initiation": "user_asked",
                    "request_id": str(uuid.uuid4()),
                    "title": "Fifth Worker Overflow",
                    "prompt": "Should fail quota",
                    "context": "fresh",
                    "background": VALID_BACKGROUND_80,
                    "task_kind": "read_only",
                    "use_worktree": False,
                    "name": "worker-5",
                    "batch_id": str(uuid.uuid4()),
                },
            )
        self.assertEqual(cap_ctx.exception.code, ErrorCode.CAPACITY_EXCEEDED)

    def test_explicit_dispatch_group_seal_and_close_incomplete_r02(self) -> None:
        grp = self.engine.create_dispatch_group(
            self.parent_caller,
            {"request_id": str(uuid.uuid4()), "expected_members": 2},
        )
        gid = grp["dispatch_group_id"]
        self.assertEqual(grp["assembly_state"], "open")

        # Admit 1st member
        self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Group Member 1",
                "prompt": "Work 1",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "dispatch_group_id": gid,
                "name": "grp-m1",
            },
        )
        g_mid = self.engine.get_dispatch_group(self.parent_caller, {"dispatch_group_id": gid})
        self.assertEqual(g_mid["member_count"], 1)

        # Sealing before expected_members (1 < 2) must raise GROUP_INCOMPLETE
        with self.assertRaises(SideSessionError) as inc_ctx:
            self.engine.seal_dispatch_group(
                self.parent_caller,
                {
                    "request_id": str(uuid.uuid4()),
                    "dispatch_group_id": gid,
                    "expected_revision": g_mid["revision"],
                },
            )
        self.assertEqual(inc_ctx.exception.code, ErrorCode.GROUP_INCOMPLETE)

        # Admit 2nd member and seal
        self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Group Member 2",
                "prompt": "Work 2",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "dispatch_group_id": gid,
                "name": "grp-m2",
            },
        )
        g_full = self.engine.get_dispatch_group(self.parent_caller, {"dispatch_group_id": gid})
        sealed = self.engine.seal_dispatch_group(
            self.parent_caller,
            {
                "request_id": str(uuid.uuid4()),
                "dispatch_group_id": gid,
                "expected_revision": g_full["revision"],
            },
        )
        self.assertEqual(sealed["assembly_state"], "sealed")
        self.assertEqual(sealed["member_count"], 2)


# ==============================================================================
# Step 5: 工作区隔离、外部 Worktree 与连续派发测试（G02/G10/R05/R06/R08）
# ==============================================================================
class TestStep5WorkspaceIsolationExternalWorktreeAndForkContext(IsolatedSideSessionsTestCase):
    """Step 5: Verify task_kind/workspace pairing, NOT_GIT_REPO, R06 consecutive external worktrees, and R05/R08 fork."""

    def test_task_kind_workspace_pairing_and_not_git_repo(self) -> None:
        # read_only with use_worktree=True must fail
        with self.assertRaises(SideSessionError) as ro_err:
            self.engine.start_session(
                self.parent_caller,
                {
                    "initiation": "user_asked",
                    "request_id": str(uuid.uuid4()),
                    "title": "Invalid read_only worktree",
                    "prompt": "Read files",
                    "context": "fresh",
                    "background": VALID_BACKGROUND_80,
                    "task_kind": "read_only",
                    "use_worktree": True,
                },
            )
        self.assertEqual(ro_err.exception.code, ErrorCode.INVALID_TASK_WORKSPACE)

        # write_code with use_worktree=False must fail
        with self.assertRaises(SideSessionError) as wc_err:
            self.engine.start_session(
                self.parent_caller,
                {
                    "initiation": "user_asked",
                    "request_id": str(uuid.uuid4()),
                    "title": "Invalid write_code inherit",
                    "prompt": "Write files",
                    "context": "fresh",
                    "background": VALID_BACKGROUND_80,
                    "task_kind": "write_code",
                    "use_worktree": False,
                },
            )
        self.assertEqual(wc_err.exception.code, ErrorCode.INVALID_TASK_WORKSPACE)

        # Requesting write_code (branch) in non-Git directory self.workspace_dir must raise NOT_GIT_REPO
        with self.assertRaises(SideSessionError) as ng_err:
            self.engine.start_session(
                self.parent_caller,
                {
                    "initiation": "user_asked",
                    "request_id": str(uuid.uuid4()),
                    "title": "Branch in non-git dir",
                    "prompt": "Modify files",
                    "context": "fresh",
                    "background": VALID_BACKGROUND_80,
                    "task_kind": "write_code",
                    "use_worktree": True,
                },
            )
        self.assertEqual(ng_err.exception.code, ErrorCode.NOT_GIT_REPO)

    def test_r06_consecutive_write_code_dispatches_on_repo_without_gitignore(self) -> None:
        repo_dir = self.tmp_path / "unignored-git-repo"
        head_commit = _init_temp_git_repo(repo_dir)
        self.assertFalse((repo_dir / ".gitignore").exists())

        git_caller = CallerContext(
            runtime_sid="sid-git-parent",
            runtime_turn_id="turn-git-1",
            workspace_path=str(repo_dir),
        )

        # Configuring worktrees_home inside source repository must be rejected with WORKTREE_HOME_INSIDE_SOURCE
        with self.assertRaises(SideSessionError) as inside_err:
            worktree.prepare(
                WorkspaceSpec(
                    node_id=str(uuid.uuid4()),
                    workspace_mode="branch",
                    source_cwd=str(repo_dir),
                    name="bad-inside",
                ),
                operation_id=str(uuid.uuid4()),
                worktrees_home=repo_dir / ".zcode" / "worktrees",
            )
        self.assertEqual(inside_err.exception.code, ErrorCode.WORKTREE_HOME_INSIDE_SOURCE)

        # 1st write_code (branch) child session dispatch
        child1 = self.engine.start_session(
            git_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Write Feature 1",
                "prompt": "Implement feature 1 in isolated worktree.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "write_code",
                "use_worktree": True,
                "name": "feat-one",
            },
        )
        self.assertTrue(child1["ok"])
        self.assertEqual(child1["workspace_mode"], "branch")
        wt1_path = Path(child1["worktree_path"])
        self.assertTrue(wt1_path.exists())
        self.assertTrue(str(wt1_path).startswith(str((self.state_root / "worktrees").resolve())))
        self.assertFalse(str(wt1_path).startswith(str(repo_dir.resolve())))

        # Modify tracked file and create untracked files inside child1's worktree
        (wt1_path / "app.py").write_text("def greet() -> str:\n    return 'modified in wt1'\n", encoding="utf-8")
        (wt1_path / "untracked_wt1.txt").write_text("wt1 untracked artifact\n", encoding="utf-8")

        # Verify source checkout remains 100% clean and no .gitignore was added
        snap_after_1 = worktree.inspect_source(repo_dir, require_git=True)
        self.assertFalse(snap_after_1.is_dirty)
        self.assertEqual(snap_after_1.porcelain_output.strip(), "")
        self.assertEqual(snap_after_1.head_commit, head_commit)
        self.assertFalse((repo_dir / ".gitignore").exists())
        self.assertFalse((repo_dir / ".zcode").exists())

        # 2nd consecutive write_code (branch) child session dispatch on the same repo must succeed without DIRTY_SOURCE
        child2 = self.engine.start_session(
            git_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Write Feature 2",
                "prompt": "Implement feature 2 in second isolated worktree.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "write_code",
                "use_worktree": True,
                "name": "feat-two",
            },
        )
        self.assertTrue(child2["ok"])
        self.assertEqual(child2["workspace_mode"], "branch")
        wt2_path = Path(child2["worktree_path"])
        self.assertNotEqual(wt1_path, wt2_path)
        self.assertTrue(wt2_path.exists())
        self.assertNotEqual(child1["branch"], child2["branch"])

        # Also dispatch a read_only (inherit) child on the same repo
        child3 = self.engine.start_session(
            git_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Read-only Audit",
                "prompt": "Audit repo.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "audit-ro",
            },
        )
        self.assertTrue(child3["ok"])
        self.assertEqual(child3["workspace_mode"], "inherit")
        self.assertEqual(Path(child3["worktree_path"]).resolve(), repo_dir.resolve())

    def test_r05_r08_fork_summary_copy_anchor_and_brief_only_quality_gate(self) -> None:
        # Case A: Seeded source session with completed turn, trigger turn user input, incomplete tool assistant, and post-cutoff msg
        req_id_stable = str(uuid.uuid4())
        self.driver.seed_source_session(
            "sid-parent-main",
            messages=[
                {
                    "id": "msg-1",
                    "sequence": 1,
                    "role": "user",
                    "turn_id": "turn-parent-0",
                    "input_id": "inp-0",
                    "content": "Initial user question",
                },
                {
                    "id": "msg-2",
                    "sequence": 2,
                    "role": "assistant",
                    "turn_id": "turn-parent-0",
                    "content": "Initial completed assistant answer",
                },
                {
                    "id": "msg-3",
                    "sequence": 3,
                    "role": "user",
                    "turn_id": "turn-parent-1",
                    "input_id": req_id_stable,
                    "content": "Please fork a side session to analyze logs",
                },
                {
                    "id": "msg-4",
                    "sequence": 4,
                    "role": "assistant",
                    "turn_id": "turn-parent-1",
                    "has_incomplete_tool": True,
                    "content": "In-progress tool call that must be excluded",
                },
                {
                    "id": "msg-5",
                    "sequence": 5,
                    "role": "user",
                    "turn_id": "turn-parent-2",
                    "input_id": "inp-later",
                    "content": "Post-cutoff user message that must be excluded",
                },
            ],
            directory=str(self.workspace_dir),
        )

        stable_res = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": req_id_stable,
                "title": "Fork with stable projection",
                "prompt": "Continue log analysis.",
                "context": "fork",
                "context_strategy": "summary_copy",
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "fork-stable",
            },
        )
        self.assertTrue(stable_res["ok"])
        self.assertEqual(stable_res["status"], "running")
        self.assertEqual(stable_res["context_applied"], "summary_copy")
        self.assertEqual(stable_res["history_quality"], "stable_projection")

        brief = self.engine.read_brief(self.parent_caller, {"session_id": stable_res["node_id"]})
        self.assertIn("Initial completed assistant answer", brief["content"])
        self.assertNotIn("In-progress tool call that must be excluded", brief["content"])
        self.assertNotIn("Post-cutoff user message that must be excluded", brief["content"])

        # Case B: Unseeded / unavailable source history -> history_quality='brief_only' requires R08 approve_context
        unseeded_caller = CallerContext(
            runtime_sid="sid-parent-unseeded",
            runtime_turn_id="turn-unseeded-1",
            workspace_path=str(self.workspace_dir),
        )
        req_id_degraded = str(uuid.uuid4())
        degraded_res = self.engine.start_session(
            unseeded_caller,
            {
                "initiation": "user_asked",
                "request_id": req_id_degraded,
                "title": "Fork with brief_only quality",
                "prompt": "Investigate issue with degraded context.",
                "context": "fork",
                "context_strategy": "summary_copy",
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "fork-degraded",
            },
        )
        self.assertTrue(degraded_res["ok"])
        self.assertEqual(degraded_res["status"], "awaiting_context_approval")
        self.assertEqual(degraded_res["code"], ErrorCode.CONTEXT_QUALITY_APPROVAL_REQUIRED.value)
        self.assertEqual(degraded_res["history_quality"], "brief_only")
        self.assertIsNone(degraded_res["node_id"])

        op_id = degraded_res["operation_id"]
        snap_hash = degraded_res["snapshot_hash"]
        brief_hash = degraded_res["brief_hash"]

        # Verify no slot was reserved while awaiting context quality approval
        tree_before = self.engine.list_sessions(unseeded_caller, {})
        self.assertEqual(tree_before["active_slots"], 0)

        # Approving with wrong snapshot_hash must raise CONTEXT_ACCEPTANCE_STALE
        self._trust_human("human-ctx-bad", runtime_sid="sid-parent-unseeded")
        with self.assertRaises(SideSessionError) as stale_ctx:
            self.engine.approve_context(
                unseeded_caller,
                {
                    "operation_id": op_id,
                    "snapshot_hash": "0" * 64,
                    "history_quality": "brief_only",
                    "brief_hash": brief_hash,
                    "real_input_id": "human-ctx-bad",
                    "command_id": "/side-sessions:approve",
                },
            )
        self.assertEqual(stale_ctx.exception.code, ErrorCode.CONTEXT_ACCEPTANCE_STALE)

        # Approve exact candidate snapshot
        self._trust_human("human-ctx-ok", runtime_sid="sid-parent-unseeded")
        acc_res = self.engine.approve_context(
            unseeded_caller,
            {
                "operation_id": op_id,
                "snapshot_hash": snap_hash,
                "history_quality": "brief_only",
                "brief_hash": brief_hash,
                "real_input_id": "human-ctx-ok",
                "command_id": "/side-sessions:approve",
            },
        )
        self.assertTrue(acc_res["ok"])
        self.assertEqual(acc_res["stage"], "ready_for_admission")

        # Re-invoking start_session with the approved operation now starts the child session
        resumed_start = self.engine.start_session(
            unseeded_caller,
            {
                "initiation": "user_asked",
                "request_id": req_id_degraded,
                "title": "Fork with brief_only quality",
                "prompt": "Investigate issue with degraded context.",
                "context": "fork",
                "context_strategy": "summary_copy",
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "fork-degraded",
            },
        )
        self.assertTrue(resumed_start["ok"])
        self.assertEqual(resumed_start["status"], "running")
        self.assertEqual(resumed_start["context_applied"], "brief_only")
        self.assertIsNotNone(resumed_start["node_id"])


# ==============================================================================
# Step 6: 后台 Worker、双端汇报幂等去重、报告读取与 ACK 闭环测试（G06/G08/R01）
# ==============================================================================
class TestStep6WorkerRunnerDualReportDeduplicationAndReadAckLoop(IsolatedSideSessionsTestCase):
    """Step 6: Verify 400-char recap formatting, child + runner fallback idempotency, read_report/read_artifact, and ack_events."""

    def test_dual_report_deduplication_400_recap_and_read_ack_loop(self) -> None:
        start_res = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Deep Analysis Child",
                "prompt": "Produce detailed report and binary artifact.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "reporter-child",
            },
        )
        child_id = start_res["node_id"]
        child_sid = start_res["runtime_session_id"]
        run_id = start_res["run_id"]
        turn_seq = start_res["turn_seq"]
        worker_turn_id = start_res["worker_turn_id"]

        child_caller = CallerContext(
            runtime_sid=child_sid,
            runtime_turn_id=self.store.conn.execute("SELECT runtime_turn_id FROM turns WHERE run_id = ?", (run_id,)).fetchone()[0],
            workspace_path=str(self.workspace_dir),
        )

        # Create a multi-kilobyte binary artifact in workspace and publish it
        art_bytes = b"\x89PNG\r\n\x1a\n" + (b"side-sessions-binary-payload-" * 400)
        art_file = self.workspace_dir / "diagram.bin"
        art_file.write_bytes(art_bytes)
        art_sha = sha256_hex(art_bytes)

        pub_res = self.engine.publish_artifact(
            child_caller,
            {
                "request_id": str(uuid.uuid4()),
                "run_id": run_id,
                "relative_path": "diagram.bin",
                "expected_sha256": art_sha,
                "media_type": "application/octet-stream",
            },
        )
        self.assertTrue(pub_res["ok"])
        art_ref_obj = {
            "ref": pub_res["ref"],
            "sha256": pub_res["sha256"],
            "byte_length": pub_res["byte_length"],
            "media_type": pub_res["media_type"],
        }

        # Submit final report from child with multi-line >400 char recap and >10KB full_report
        raw_recap = "第一行关键结论\n第二行详细指标\n" + ("第三行填充摘要数据-" * 45)
        large_full_report = "# Full Analysis Report\n\n" + ("Detailed paragraph of findings.\n" * 350)

        rep_rcpt = self.engine.report_child_turn(
            child_caller,
            {
                "request_id": str(uuid.uuid4()),
                "run_id": run_id,
                "turn_seq": turn_seq,
                "worker_turn_id": worker_turn_id,
                "phase": "final",
                "report_revision": None,
                "outcome": "success",
                "recap": raw_recap,
                "full_report": large_full_report,
                "blocked": False,
                "block_reason": None,
                "artifacts": [art_ref_obj],
            },
        )
        self.assertTrue(rep_rcpt["ok"])
        self.assertFalse(rep_rcpt["duplicate"])
        event_id = rep_rcpt["event_id"]
        report_id = rep_rcpt["report_id"]

        # Verify 400-char recap with ' ⏎ ' newline replacement on node
        sess_info = self.engine.get_session(self.parent_caller, {"session_id": child_id})
        self.assertIn(" ⏎ ", sess_info["last_turn_report"])
        self.assertNotIn("\n", sess_info["last_turn_report"])
        self.assertEqual(len(sess_info["last_turn_report"]), 400)
        self.assertEqual(sess_info["last_turn_report"], format_recap_400(raw_recap))

        # Child submitting conflicting final report for the same turn must raise REPORT_CONFLICT
        with self.assertRaises(SideSessionError) as conf_ctx:
            self.engine.report_child_turn(
                child_caller,
                {
                    "request_id": str(uuid.uuid4()),
                    "run_id": run_id,
                    "turn_seq": turn_seq,
                    "worker_turn_id": worker_turn_id,
                    "phase": "final",
                    "report_revision": None,
                    "outcome": "failed",
                    "recap": raw_recap,
                    "full_report": large_full_report,
                    "blocked": False,
                    "block_reason": None,
                    "artifacts": [art_ref_obj],
                },
            )
        self.assertEqual(conf_ctx.exception.code, ErrorCode.REPORT_CONFLICT)

        # WorkerRunner exit fallback calls finalize_from_owner -> must idempotently return the SAME event_id and report_id
        t_row = self.store.conn.execute("SELECT * FROM turns WHERE run_id = ?", (run_id,)).fetchone()
        owner_ctx = OwnerContext(
            node_id=child_id,
            run_id=run_id,
            worker_id="worker-test",
            owner_epoch=int(t_row["owner_epoch"]),
            fencing_token=str(t_row["fencing_token"]),
        )
        fallback_report = CanonicalReport(
            node_id=child_id,
            run_id=run_id,
            turn_seq=turn_seq,
            worker_turn_id=worker_turn_id,
            runtime_turn_id=t_row["runtime_turn_id"],
            phase="final",
            report_revision=None,
            outcome="success",
            blocked=False,
            block_reason=None,
            recap="Worker fallback recap that must NOT overwrite explicit child final report",
            full_report="Worker fallback full report",
            artifacts=[],
        )
        fb_rcpt = self.engine.finalize_from_owner(owner_ctx, run_id, fallback_report)
        self.assertTrue(fb_rcpt["duplicate"])
        self.assertEqual(fb_rcpt["event_id"], event_id)
        self.assertEqual(fb_rcpt["report_id"], report_id)
        self.assertEqual(fb_rcpt["semantic_sha256"], rep_rcpt["semantic_sha256"])

        # Verify outbox_events has exactly 1 event
        ev_count = self.store.conn.execute("SELECT COUNT(*) FROM outbox_events WHERE child_node_id = ?", (child_id,)).fetchone()[0]
        self.assertEqual(ev_count, 1)

        # Parent reads events, full report, and paged binary artifact, then ACKs
        ev_page = self.engine.list_events(self.parent_caller, {"states": ["pending", "presented"]})
        self.assertEqual(len(ev_page["items"]), 1)
        ev_item = ev_page["items"][0]
        self.assertEqual(ev_item["event_id"], event_id)
        self.assertEqual(ev_item["state"], "pending")

        rep_view = self.engine.read_report(self.parent_caller, {"report_ref": ev_item["report_ref"]})
        self.assertTrue(rep_view["integrity_verified"])
        self.assertEqual(rep_view["semantic_sha256"], rep_rcpt["semantic_sha256"])
        self.assertEqual(rep_view["full_report"], large_full_report.strip())

        # Read binary artifact in 4096-byte chunks and reassemble
        reassembled = bytearray()
        offset = 0
        while True:
            chunk = self.engine.read_artifact(
                self.parent_caller,
                {"artifact_ref": pub_res["ref"], "offset": offset, "max_bytes": 4096},
            )
            raw_chunk = base64.b64decode(chunk["data_base64"])
            self.assertEqual(sha256_hex(raw_chunk), chunk["chunk_sha256"])
            reassembled.extend(raw_chunk)
            offset = chunk["next_offset"]
            if chunk["eof"]:
                break
        self.assertEqual(bytes(reassembled), art_bytes)

        # Acknowledge event
        ack_res = self.engine.ack_events(
            self.parent_caller,
            {"request_id": str(uuid.uuid4()), "event_ids": [event_id]},
        )
        self.assertTrue(ack_res["ok"])
        self.assertEqual(ack_res["acked_count"], 1)

        ev_after = self.engine.get_event(self.parent_caller, {"event_id": event_id})
        self.assertEqual(ev_after["state"], "acked")

    def test_worker_crash_recovery_and_post_final_execution_failure(self) -> None:
        st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Crash Recovery Child",
                "prompt": "Run task that crashes.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "crash-child",
            },
        )
        child_id = st["node_id"]
        run_id = st["run_id"]

        # Simulate dead worker process by setting non-existent PID on owners
        with self.store.transaction("IMMEDIATE") as txn:
            txn.execute(
                "UPDATE owners SET pid = 999999, process_started_at = 'dead-proc' WHERE node_id = ?",
                (child_id,),
            )

        runner = WorkerRunner(
            self.store,
            engine=self.engine,
            driver=self.driver,
            host_adapter=self.host_adapter,
        )
        rec = runner.recover()
        self.assertTrue(rec["ok"])
        self.assertEqual(len(rec["recovered_runs"]), 1)
        self.assertEqual(rec["recovered_runs"][0]["run_id"], run_id)
        self.assertEqual(rec["recovered_runs"][0]["outcome"], "failed")
        self.assertTrue(rec["recovered_runs"][0]["slot_released"])


# ==============================================================================
# Step 7: 消息跟进 FIFO、等待回应与取消生命周期测试（G09/R04）
# ==============================================================================
class TestStep7MessageRoutingFifoWaitingInputAndCancellation(IsolatedSideSessionsTestCase):
    """Step 7: Verify send_message_to_session routing, AMBIGUOUS_SESSION, waiting_input/respond_to_wait, and cancel_message/cancel_run."""

    def test_message_routing_by_name_id_parent_and_ambiguity_or_archived(self) -> None:
        c1 = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Child Alpha",
                "prompt": "Initial task",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "alpha-node",
            },
        )
        c1_id = c1["node_id"]
        c1_sid = c1["runtime_session_id"]

        # Route by short name
        q1 = self.engine.send_message_to_session(
            self.parent_caller,
            {
                "request_id": str(uuid.uuid4()),
                "message_id": str(uuid.uuid4()),
                "session_id": "alpha-node",
                "message": "Follow-up 1 by name",
            },
        )
        self.assertEqual(q1["node_id"], c1_id)
        self.assertEqual(q1["seq"], 2)

        # Route by node_id (session_id)
        q2 = self.engine.send_message_to_session(
            self.parent_caller,
            {
                "request_id": str(uuid.uuid4()),
                "message_id": str(uuid.uuid4()),
                "session_id": c1_id,
                "message": "Follow-up 2 by UUID",
            },
        )
        self.assertEqual(q2["node_id"], c1_id)
        self.assertEqual(q2["seq"], 3)

        # Child routes message to "parent"
        c1_caller = CallerContext(runtime_sid=c1_sid, workspace_path=str(self.workspace_dir))
        parent_node_id = self.engine.ensure_caller_node(self.parent_caller)["node_id"]
        q_parent = self.engine.send_message_to_session(
            c1_caller,
            {
                "request_id": str(uuid.uuid4()),
                "message_id": str(uuid.uuid4()),
                "session_id": "parent",
                "message": "Message from child to parent",
            },
        )
        self.assertEqual(q_parent["node_id"], parent_node_id)

        # Create grandchild under c1 with the SAME short name "dup-name" as a second child under parent -> AMBIGUOUS_SESSION
        self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Direct Dup",
                "prompt": "Work",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "dup-name",
            },
        )
        self.engine.start_session(
            c1_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Grandchild Dup",
                "prompt": "Work",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "dup-name",
            },
        )
        with self.assertRaises(SideSessionError) as amb_ctx:
            self.engine.send_message_to_session(
                self.parent_caller,
                {
                    "request_id": str(uuid.uuid4()),
                    "message_id": str(uuid.uuid4()),
                    "session_id": "dup-name",
                    "message": "Which dup-name?",
                },
            )
        self.assertEqual(amb_ctx.exception.code, ErrorCode.AMBIGUOUS_SESSION)

    def test_waiting_input_blocks_ordinary_send_and_resumes_via_respond_to_wait(self) -> None:
        start_res = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Interactive Wait Child",
                "prompt": "Ask question if needed.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "wait-child",
            },
        )
        child_id = start_res["node_id"]
        child_sid = start_res["runtime_session_id"]
        run_id = start_res["run_id"]

        # Queue a permission wait_request event on the fake driver and run WorkerRunner with short wait poll timeout
        self.driver.queue_event(
            child_sid,
            {
                "kind": "wait_request",
                "runtime_turn_id": f"rturn:{run_id[:8]}",
                "wait_request": {
                    "host_request_id": "host-perm-1",
                    "kind": "permission",
                    "nonce": "nonce-secret-42",
                    "question": "Allow reading sensitive config?",
                    "options": ["allow_once", "deny"],
                    "required_authority": "human",
                },
            },
        )

        runner = WorkerRunner(
            self.store,
            engine=self.engine,
            driver=self.driver,
            host_adapter=self.host_adapter,
            wait_poll_timeout_ms=250,
        )

        def _on_wait(_assignment: Any, _handle: Any) -> None:
            with self.assertRaises(SideSessionError) as busy_ctx:
                self.store.session_lock(child_id, blocking=False, timeout_ms=0).acquire()
            self.assertEqual(busy_ctx.exception.code, ErrorCode.LOCK_BUSY)
            waits_res = self.engine.list_waits(self.parent_caller, {"session_id": child_id})
            self.assertEqual(len(waits_res["waits"]), 1)
            wait_item = waits_res["waits"][0]
            self.assertEqual(wait_item["nonce"], "nonce-secret-42")
            queued = self.engine.send_message_to_session(
                self.parent_caller,
                {
                    "request_id": str(uuid.uuid4()),
                    "message_id": str(uuid.uuid4()),
                    "session_id": child_id,
                    "message": "Ordinary FIFO follow-up while waiting",
                },
            )
            self.assertEqual(queued["status"], "queued")
            self._trust_human("human-wait-1", command_id="/side-sessions:respond")
            with self.assertRaises(SideSessionError) as nonce_err:
                self.engine.respond_to_wait(
                    self.parent_caller,
                    {
                        "request_id": str(uuid.uuid4()),
                        "wait_id": wait_item["wait_id"],
                        "nonce": "wrong-nonce",
                        "response": {"kind": "permission", "option_id": "allow_once", "decision": "allow_once"},
                        "real_input_id": "human-wait-1",
                        "command_id": "/side-sessions:respond",
                    },
                )
            self.assertEqual(nonce_err.exception.code, ErrorCode.WAIT_STALE)
            resp_res = self.engine.respond_to_wait(
                self.parent_caller,
                {
                    "request_id": str(uuid.uuid4()),
                    "wait_id": wait_item["wait_id"],
                    "nonce": "nonce-secret-42",
                    "response": {"kind": "permission", "option_id": "allow_once", "decision": "allow_once"},
                    "real_input_id": "human-wait-1",
                    "command_id": "/side-sessions:respond",
                },
            )
            self.assertTrue(resp_res["ok"])
            self.driver.queue_event(
                child_sid,
                {
                    "kind": "turn.terminal",
                    "runtime_turn_id": f"rturn:{run_id[:8]}",
                    "outcome": "success",
                },
            )

        runner.on_wait = _on_wait
        first_pass = runner.run_node(child_id, once=True)
        self.assertTrue(first_pass["ok"])
        self.assertTrue(first_pass["receipts"][0]["exit_confirmed"])
        self.assertEqual(len(self.driver.wait_responses), 1)
        self.assertEqual(self.driver.wait_responses[0]["response"]["decision"], "allow_once")

    def test_cancel_message_and_cancel_run_slot_lifecycle(self) -> None:
        start_res = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Cancel Lifecycle Child",
                "prompt": "Run initial turn.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "cancel-child",
            },
        )
        child_id = start_res["node_id"]
        run1_id = start_res["run_id"]
        first_msg_id = self.store.conn.execute(
            "SELECT message_id FROM turns WHERE run_id = ?",
            (run1_id,),
        ).fetchone()[0]

        # Attempting cancel_message on the already-running initial message must raise MESSAGE_IN_FLIGHT
        with self.assertRaises(SideSessionError) as in_flight_ctx:
            self.engine.cancel_message(
                self.parent_caller,
                {
                    "request_id": str(uuid.uuid4()),
                    "session_id": child_id,
                    "message_id": first_msg_id,
                    "reason": "Too late for cancel_message",
                },
            )
        self.assertEqual(in_flight_ctx.exception.code, ErrorCode.MESSAGE_IN_FLIGHT)

        # Enqueue a follow-up message (remains 'queued' while run1 is active) and cancel it via cancel_message
        q_msg = self.engine.send_message_to_session(
            self.parent_caller,
            {
                "request_id": str(uuid.uuid4()),
                "message_id": str(uuid.uuid4()),
                "session_id": child_id,
                "message": "Queued follow-up to be cancelled",
            },
        )
        cancel_msg_res = self.engine.cancel_message(
            self.parent_caller,
            {
                "request_id": str(uuid.uuid4()),
                "session_id": child_id,
                "message_id": q_msg["message_id"],
                "reason": "No longer needed",
            },
        )
        self.assertTrue(cancel_msg_res["ok"])
        self.assertEqual(cancel_msg_res["state"], "cancelled")
        self.assertEqual(cancel_msg_res["exit_confirmed"], "not_started_proven")

        # Now call cancel_run on active run1: state becomes 'stopping', and slot is NOT released yet!
        cancel_run_res = self.engine.cancel_run(
            self.parent_caller,
            {
                "request_id": str(uuid.uuid4()),
                "session_id": child_id,
                "run_id": run1_id,
                "reason": "Stop active run",
            },
        )
        self.assertTrue(cancel_run_res["ok"])
        self.assertEqual(cancel_run_res["state"], "stopping")
        self.assertFalse(cancel_run_res["slot_released"])

        slot_state_stopping = self.store.conn.execute(
            "SELECT state FROM parent_slots WHERE node_id = ?",
            (child_id,),
        ).fetchone()[0]
        self.assertEqual(slot_state_stopping, "stopping")

        # WorkerRunner processes cancel_run -> calls driver.stop_and_wait -> close_run confirms exit and releases slot
        runner = WorkerRunner(
            self.store,
            engine=self.engine,
            driver=self.driver,
            host_adapter=self.host_adapter,
        )
        run_res = runner.run_node(child_id, once=True)
        self.assertTrue(run_res["ok"])
        self.assertEqual(run_res["receipts"][0]["runtime_outcome"], "cancelled")

        slot_state_after = self.store.conn.execute(
            "SELECT state FROM parent_slots WHERE node_id = ?",
            (child_id,),
        ).fetchone()[0]
        self.assertEqual(slot_state_after, "released")

        # Archive idle session after run exit, then verify send_message_to_session raises SESSION_ARCHIVED
        arch_res = self.engine.archive_session(
            self.parent_caller,
            {"request_id": str(uuid.uuid4()), "session_id": child_id},
        )
        self.assertEqual(arch_res["status"], "archived")

        with self.assertRaises(SideSessionError) as arch_err:
            self.engine.send_message_to_session(
                self.parent_caller,
                {
                    "request_id": str(uuid.uuid4()),
                    "message_id": str(uuid.uuid4()),
                    "session_id": child_id,
                    "message": "Cannot message archived session",
                },
            )
        self.assertEqual(arch_err.exception.code, ErrorCode.SESSION_ARCHIVED)


# ==============================================================================
# Step 8: 任务交接 `hand_off_to_session` 与 Task Guard 测试（R03/R07）
# ==============================================================================
class TestStep8TaskHandoffAndTaskGuard(IsolatedSideSessionsTestCase):
    """Step 8: Verify R07 full-slot handoff rejection without side effects and R03 guarded handoff with patch_snapshot."""

    def test_r07_full_slots_handoff_rejected_without_freezing_parent_task(self) -> None:
        reg = self.engine.register_task(
            self.parent_caller,
            {
                "request_id": str(uuid.uuid4()),
                "title": "Parent Core Task",
                "remaining_plan": "Step 1: Refactor parser; Step 2: Run suite.",
                "task_kind": "read_only",
                "scope": {
                    "resource_keys": ["parser-module"],
                    "write_path_roots": [],
                    "artifact_source_roots": [str(self.workspace_dir)],
                },
            },
        )
        task_id = reg["task_id"]
        self.assertEqual(reg["state"], "active")
        self.assertEqual(reg["task_revision"], 1)

        self.driver.seed_source_session(
            "sid-parent-main",
            messages=[
                {
                    "id": "msg-r07-1",
                    "sequence": 1,
                    "role": "user",
                    "turn_id": "turn-parent-1",
                    "input_id": "inp-r07",
                    "content": "Parent work that will be handed off",
                }
            ],
            directory=str(self.workspace_dir),
        )

        # Fill all 4 parent slots
        for idx in range(4):
            self.engine.start_session(
                self.parent_caller,
                {
                    "initiation": "user_asked",
                    "request_id": str(uuid.uuid4()),
                    "title": f"Slot Filler {idx + 1}",
                    "prompt": "Hold slot.",
                    "context": "fresh",
                    "background": VALID_BACKGROUND_80,
                    "task_kind": "read_only",
                    "use_worktree": False,
                    "name": f"filler-{idx + 1}",
                },
            )

        # Attempt hand_off_to_session when 4 slots are full -> must raise CAPACITY_EXCEEDED with ZERO side effects
        handoff_req_id = str(uuid.uuid4())
        self.driver.seed_source_session(
            "sid-parent-main",
            messages=[
                {
                    "id": "msg-r07-h",
                    "sequence": 1,
                    "role": "user",
                    "turn_id": "turn-parent-1",
                    "input_id": handoff_req_id,
                    "content": "Hand off parser task now",
                }
            ],
            directory=str(self.workspace_dir),
        )
        with self.assertRaises(SideSessionError) as cap_ctx:
            self.engine.hand_off_to_session(
                self.parent_caller,
                {
                    "request_id": handoff_req_id,
                    "transfer_id": str(uuid.uuid4()),
                    "task_id": task_id,
                    "title": "Hand off parser task",
                    "remaining_plan": "Finish Step 1 and Step 2",
                    "task_kind": "read_only",
                    "use_worktree": False,
                    "context": "fork",
                    "context_strategy": "summary_copy",
                    "expected_task_revision": 1,
                },
            )
        self.assertEqual(cap_ctx.exception.code, ErrorCode.CAPACITY_EXCEEDED)

        # Verify parent task is still active, owned by parent, revision unchanged, and no transfer/guard created
        parent_node_id = self.engine.ensure_caller_node(self.parent_caller)["node_id"]
        task_after = self.engine.get_task(self.parent_caller, {"task_id": task_id})
        self.assertEqual(task_after["owner_node_id"], parent_node_id)
        self.assertEqual(task_after["state"], "active")
        self.assertEqual(task_after["task_revision"], 1)

        transfer_cnt = self.store.conn.execute("SELECT COUNT(*) FROM transfers WHERE task_id = ?", (task_id,)).fetchone()[0]
        guard_cnt = self.store.conn.execute("SELECT COUNT(*) FROM task_guards WHERE task_id = ?", (task_id,)).fetchone()[0]
        self.assertEqual(transfer_cnt, 0)
        self.assertEqual(guard_cnt, 0)

    def test_r03_handoff_freezes_parent_scope_switches_owner_and_applies_patch_snapshot(self) -> None:
        repo_dir = self.tmp_path / "handoff-git-repo"
        _init_temp_git_repo(repo_dir)

        git_parent = CallerContext(
            runtime_sid="sid-handoff-parent",
            runtime_turn_id="turn-handoff-1",
            workspace_path=str(repo_dir),
        )
        parent_node_id = self.engine.ensure_caller_node(git_parent)["node_id"]

        reg = self.engine.register_task(
            git_parent,
            {
                "request_id": str(uuid.uuid4()),
                "title": "Implement greeting v2",
                "remaining_plan": "Complete greeting v2 and unit tests.",
                "task_kind": "write_code",
                "scope": {
                    "resource_keys": ["app-greeting"],
                    "write_path_roots": [str(repo_dir)],
                    "artifact_source_roots": [str(repo_dir)],
                },
            },
        )
        task_id = reg["task_id"]

        # Make uncommitted tracked modification and untracked file in source repo before handoff
        (repo_dir / "app.py").write_text("def greet() -> str:\n    return 'dirty-in-progress'\n", encoding="utf-8")
        (repo_dir / "notes_wip.txt").write_text("work-in-progress notes\n", encoding="utf-8")

        handoff_req_id = str(uuid.uuid4())
        self.driver.seed_source_session(
            "sid-handoff-parent",
            messages=[
                {
                    "id": "msg-h1",
                    "sequence": 1,
                    "role": "user",
                    "turn_id": "turn-handoff-1",
                    "input_id": handoff_req_id,
                    "content": "Hand off current greeting implementation to a side session",
                }
            ],
            directory=str(repo_dir),
        )

        # Default dirty_policy='reject' must reject dirty source repo with DIRTY_SOURCE
        with self.assertRaises(SideSessionError) as dirty_err:
            self.engine.hand_off_to_session(
                git_parent,
                {
                    "request_id": handoff_req_id,
                    "transfer_id": str(uuid.uuid4()),
                    "task_id": task_id,
                    "title": "Handoff greeting v2",
                    "remaining_plan": "Finish greeting v2 in isolated branch worktree.",
                    "task_kind": "write_code",
                    "use_worktree": True,
                    "context": "fork",
                    "context_strategy": "summary_copy",
                    "expected_task_revision": 1,
                },
            )
        self.assertEqual(dirty_err.exception.code, ErrorCode.DIRTY_SOURCE)

        # Handoff with dirty_policy='patch_snapshot' succeeds, applies patch to new worktree, and transfers ownership
        handoff_req_id_2 = str(uuid.uuid4())
        self.driver.append_source_message(
            "sid-handoff-parent",
            {
                "id": "msg-h2",
                "sequence": 2,
                "role": "user",
                "turn_id": "turn-handoff-1",
                "input_id": handoff_req_id_2,
                "content": "Hand off with patch_snapshot approved",
            },
        )
        transfer_res = self.engine.hand_off_to_session(
            git_parent,
            {
                "request_id": handoff_req_id_2,
                "transfer_id": str(uuid.uuid4()),
                "task_id": task_id,
                "title": "Handoff greeting v2",
                "remaining_plan": "Finish greeting v2 in isolated branch worktree.",
                "task_kind": "write_code",
                "use_worktree": True,
                "context": "fork",
                "context_strategy": "summary_copy",
                "expected_task_revision": 1,
            },
            dirty_policy="patch_snapshot",
            approved_path_manifest=["app.py", "notes_wip.txt"],
        )
        self.assertTrue(transfer_res["ok"])
        child_id = transfer_res["child_node_id"]
        self.assertEqual(transfer_res["owner_node_id"], child_id)
        self.assertEqual(transfer_res["task_revision"], 2)
        self.assertEqual(transfer_res["status"], "committed")

        # Verify patch_snapshot was applied inside the child worktree
        child_wt = Path(transfer_res["worktree_path"])
        self.assertEqual((child_wt / "app.py").read_text(encoding="utf-8"), "def greet() -> str:\n    return 'dirty-in-progress'\n")
        self.assertEqual((child_wt / "notes_wip.txt").read_text(encoding="utf-8"), "work-in-progress notes\n")

        # Verify task owner_node_id is now child_id and parent's task_turn_binding is frozen
        task_now = self.engine.get_task(git_parent, {"task_id": task_id})
        self.assertEqual(task_now["owner_node_id"], child_id)
        self.assertEqual(task_now["task_revision"], 2)

        # Parent attempting a write tool action on the transferred task/scope must be blocked by task guard
        with self.assertRaises(SideSessionError) as guard_err:
            self.host_adapter.bind_task_action(
                {
                    "runtime_sid": "sid-handoff-parent",
                    "runtime_turn_id": "turn-handoff-1",
                    "tool_use_id": "tool-parent-write-after-handoff",
                    "tool_name": "Edit",
                    "scope": {"resource_keys": ["app-greeting"], "write_path_roots": [str(repo_dir)]},
                }
            )
        self.assertEqual(guard_err.exception.code, ErrorCode.TASK_OWNER_CHANGED)
        self.assertNotEqual(parent_node_id, child_id)


# ==============================================================================
# Step 9: 同步 Hook 投递与 `Stop` 自动续跑防死循环测试（G03/G05）
# ==============================================================================
class TestStep9SyncHooksAndStopAutoContinuationGuard(IsolatedSideSessionsTestCase):
    """Step 9: Verify UserPromptSubmit/PostToolUse presentation, Stop hook active guard, per-group 1x and per-epoch 10x limits."""

    def _spawn_and_complete_child(self, name: str, *, dispatch_group_id: str | None = None) -> dict[str, str]:
        args = {
            "initiation": "user_asked",
            "request_id": str(uuid.uuid4()),
            "title": f"Task {name}",
            "prompt": f"Run {name}",
            "context": "fresh",
            "background": VALID_BACKGROUND_80,
            "task_kind": "read_only",
            "use_worktree": False,
            "name": name,
        }
        if dispatch_group_id is not None:
            args["dispatch_group_id"] = dispatch_group_id
        st = self.engine.start_session(self.parent_caller, args)
        child_caller = CallerContext(
            runtime_sid=st["runtime_session_id"],
            workspace_path=str(self.workspace_dir),
        )
        rep = self.engine.report_child_turn(
            child_caller,
            {
                "request_id": str(uuid.uuid4()),
                "run_id": st["run_id"],
                "turn_seq": st["turn_seq"],
                "worker_turn_id": st["worker_turn_id"],
                "phase": "final",
                "report_revision": None,
                "outcome": "success",
                "recap": f"Completed {name} successfully",
                "full_report": f"# Full report for {name}\nAll checks passed.",
                "blocked": False,
                "block_reason": None,
                "artifacts": [],
            },
        )
        self._close_child_run(st)
        return {
            "node_id": st["node_id"],
            "dispatch_group_id": st["dispatch_group_id"],
            "event_id": rep["event_id"],
        }

    def test_user_prompt_submit_and_post_tool_use_present_without_acking(self) -> None:
        info = self._spawn_and_complete_child("hook-present-1")
        event_id = info["event_id"]

        # Run PostToolUse hook via hook_main
        stdin_buf = io.BytesIO(
            json.dumps(
                {
                    "session_id": "sid-parent-main",
                    "hook_event_name": "PostToolUse",
                    "cwd": str(self.workspace_dir),
                    "turn_id": "turn-parent-1",
                }
            ).encode("utf-8")
        )
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        rc = hook_main(
            stdin=stdin_buf,
            stdout=stdout_buf,
            stderr=stderr_buf,
            environ={"ZCODE_SIDE_SESSIONS_HOME": str(self.state_root), "CLAUDE_SESSION_ID": "sid-parent-main"},
        )
        self.assertEqual(rc, 0)
        self.assertEqual(stderr_buf.getvalue(), "")

        out_obj = json.loads(stdout_buf.getvalue().strip())
        self.assertNotIn("continue", out_obj)
        self.assertIn("<system-reminder>", out_obj["additionalContext"])
        self.assertIn("<side-sessions-event", out_obj["additionalContext"])
        self.assertIn(event_id, out_obj["additionalContext"])

        # Event state must be 'presented', NOT 'acked'
        ev_state = self.engine.get_event(self.parent_caller, {"event_id": event_id})["state"]
        self.assertEqual(ev_state, "presented")

    def test_stop_hook_active_guard_and_single_group_single_wake_and_epoch_10_limit(self) -> None:
        info = self._spawn_and_complete_child("stop-child-0")
        ev0_id = info["event_id"]

        # 1. When stop_hook_active=True, Stop hook MUST return None and leave event 'pending'
        out_active = self.engine.handle_hook(
            HookContext(
                event="Stop",
                invocation_id=str(uuid.uuid4()),
                runtime_sid="sid-parent-main",
                cwd=str(self.workspace_dir),
                stop_hook_active=True,
            )
        )
        self.assertIsNone(out_active)
        self.assertEqual(self.engine.get_event(self.parent_caller, {"event_id": ev0_id})["state"], "pending")

        # 2. When stop_hook_active=False and group is completed, Stop returns continue=True + <side-sessions-event>
        out_wake_1 = self.engine.handle_hook(
            HookContext(
                event="Stop",
                invocation_id=str(uuid.uuid4()),
                runtime_sid="sid-parent-main",
                cwd=str(self.workspace_dir),
                stop_hook_active=False,
            )
        )
        self.assertIsNotNone(out_wake_1)
        assert out_wake_1 is not None
        self.assertIs(out_wake_1["continue"], True)
        self.assertIn("<side-sessions-event", out_wake_1["additionalContext"])
        self.assertEqual(self.engine.get_event(self.parent_caller, {"event_id": ev0_id})["state"], "presented")

        # 3. Calling Stop again for the same completed group must return None (max 1 wake per group per epoch)
        out_wake_dup = self.engine.handle_hook(
            HookContext(
                event="Stop",
                invocation_id=str(uuid.uuid4()),
                runtime_sid="sid-parent-main",
                cwd=str(self.workspace_dir),
                stop_hook_active=False,
            )
        )
        self.assertIsNone(out_wake_dup)

        # ACK first event so we can test the 10-wake budget per user_epoch
        self.engine.ack_events(self.parent_caller, {"request_id": str(uuid.uuid4()), "event_ids": [ev0_id]})

        # We already used 1 wake in user_epoch=0; run 9 more groups (wakes #2..#10)
        for idx in range(1, 10):
            c_info = self._spawn_and_complete_child(f"stop-child-{idx}")
            w_out = self.engine.handle_hook(
                HookContext(
                    event="Stop",
                    invocation_id=str(uuid.uuid4()),
                    runtime_sid="sid-parent-main",
                    cwd=str(self.workspace_dir),
                    stop_hook_active=False,
                )
            )
            self.assertIsNotNone(w_out, f"Wake #{idx + 1} should succeed within 10-wake budget")
            self.engine.ack_events(self.parent_caller, {"request_id": str(uuid.uuid4()), "event_ids": [c_info["event_id"]]})

        # Verify wake_count is now 10 in user_epoch 0
        parent_id = self.engine.ensure_caller_node(self.parent_caller)["node_id"]
        wb = self.store.conn.execute("SELECT user_epoch, wake_count FROM wake_budget WHERE parent_node_id = ?", (parent_id,)).fetchone()
        self.assertEqual(int(wb["user_epoch"]), 0)
        self.assertEqual(int(wb["wake_count"]), 10)

        # 11th group in the same user_epoch must be blocked by the 10-wake cap!
        c11_info = self._spawn_and_complete_child("stop-child-11")
        w_out_11 = self.engine.handle_hook(
            HookContext(
                event="Stop",
                invocation_id=str(uuid.uuid4()),
                runtime_sid="sid-parent-main",
                cwd=str(self.workspace_dir),
                stop_hook_active=False,
            )
        )
        self.assertIsNone(w_out_11)

        # Unverified / system UserPromptSubmit must NOT advance user_epoch or reset wake_count
        self.engine.handle_hook(
            HookContext(
                event="UserPromptSubmit",
                invocation_id=str(uuid.uuid4()),
                runtime_sid="sid-parent-main",
                cwd=str(self.workspace_dir),
                raw_input={"origin": "auto_continuation", "input_id": "sys-inp-1"},
            )
        )
        wb_still = self.store.conn.execute("SELECT user_epoch, wake_count FROM wake_budget WHERE parent_node_id = ?", (parent_id,)).fetchone()
        self.assertEqual(int(wb_still["user_epoch"]), 0)
        self.assertEqual(int(wb_still["wake_count"]), 10)

        # Verified real human input on UserPromptSubmit advances user_epoch to 1 and resets wake_count to 0
        self.host_adapter.record_human_input(
            runtime_sid="sid-parent-main",
            input_id="real-human-inp-epoch-1",
            origin="human_prompt",
            runtime_turn_id="turn-parent-2",
        )
        self.engine.handle_hook(
            HookContext(
                event="UserPromptSubmit",
                invocation_id=str(uuid.uuid4()),
                runtime_sid="sid-parent-main",
                cwd=str(self.workspace_dir),
                runtime_turn_id="turn-parent-2",
                raw_input={"input_id": "real-human-inp-epoch-1", "origin": "human_prompt"},
            )
        )
        wb_reset = self.store.conn.execute("SELECT user_epoch, wake_count FROM wake_budget WHERE parent_node_id = ?", (parent_id,)).fetchone()
        self.assertEqual(int(wb_reset["user_epoch"]), 1)
        self.assertEqual(int(wb_reset["wake_count"]), 0)

        # Now Stop hook in user_epoch=1 can wake for c11_info!
        w_out_after_reset = self.engine.handle_hook(
            HookContext(
                event="Stop",
                invocation_id=str(uuid.uuid4()),
                runtime_sid="sid-parent-main",
                cwd=str(self.workspace_dir),
                stop_hook_active=False,
            )
        )
        self.assertIsNotNone(w_out_after_reset)
        assert w_out_after_reset is not None
        self.assertIs(w_out_after_reset["continue"], True)
        self.assertIn(c11_info["event_id"], w_out_after_reset["additionalContext"])


class TestRegressionConfirmedFixes(IsolatedSideSessionsTestCase):
    """Regression coverage for the 31 independently verified defect fixes."""

    def test_cleanup_owned_refuses_unmarked_and_foreign_worktrees(self) -> None:
        repo_dir = self.tmp_path / "cleanup-git"
        _init_temp_git_repo(repo_dir)
        subprocess.run(
            ["git", "-C", str(repo_dir), "worktree", "add", "-b", "user-feature", str(self.tmp_path / "user-feature")],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        record = WorktreeRecord(
            worktree_id=str(uuid.uuid4()),
            node_id=str(uuid.uuid4()),
            operation_id=str(uuid.uuid4()),
            canonical_worktree_path=str(self.tmp_path / "user-feature"),
            worktrees_home=str(self.tmp_path / "unrelated-home"),
            workspace_mode="branch",
            repo_root=str(repo_dir),
            base_commit=None,
            branch="user-feature",
            ownership_marker=None,
        )
        result = worktree.cleanup_owned(record, expected_operation_id=record.operation_id)
        self.assertFalse(result.cleaned)
        self.assertEqual(result.state, "ownership_mismatch")
        self.assertTrue((self.tmp_path / "user-feature").exists())
        branches = subprocess.run(
            ["git", "-C", str(repo_dir), "branch"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.decode()
        self.assertIn("user-feature", branches)

    def test_patch_snapshot_requires_manifest_and_openat(self) -> None:
        self.assertFalse(worktree._is_path_approved("secret.txt", None))
        self.assertFalse(worktree._is_path_approved("secret.txt", []))
        with self.assertRaises(SideSessionError) as ctx:
            worktree._capture_patch_snapshot(str(self.workspace_dir), None)
        self.assertEqual(ctx.exception.code, ErrorCode.DIRTY_SOURCE)

        repo_dir = self.tmp_path / "patch-git"
        _init_temp_git_repo(repo_dir)
        (repo_dir / "app.py").write_text("def greet() -> str:\n    return 'dirty'\n", encoding="utf-8")
        (repo_dir / "secret.txt").write_text("SECRET\n", encoding="utf-8")
        spec = WorkspaceSpec(
            node_id=str(uuid.uuid4()),
            workspace_mode="branch",
            source_cwd=str(repo_dir),
            dirty_policy="patch_snapshot",
            approved_path_manifest=None,
        )
        with self.assertRaises(SideSessionError) as dirty:
            worktree.prepare(spec, operation_id=str(uuid.uuid4()), worktrees_home=self.tmp_path / "wthome")
        self.assertEqual(dirty.exception.code, ErrorCode.DIRTY_SOURCE)

    def test_lock_order_lifo_and_no_state_lock(self) -> None:
        self.assertFalse(hasattr(self.store, "state_lock"))
        self.assertNotIn("worktrees", Store.SUBDIRS)
        a = str(uuid.uuid4())
        b = str(uuid.uuid4())
        first, second = sorted([a, b])
        lock_a = self.store.session_lock(first, blocking=True, timeout_ms=1000)
        lock_b = self.store.session_lock(second, blocking=True, timeout_ms=1000)
        lock_a.acquire()
        lock_b.acquire()
        with self.assertRaises(SideSessionError):
            lock_a.release()
        lock_b.release()
        lock_a.release()

    def test_short_name_and_fresh_background_and_hook_output(self) -> None:
        with self.assertRaises(SideSessionError) as num:
            normalize_request(
                "start_session",
                {
                    "initiation": "user_asked",
                    "request_id": str(uuid.uuid4()),
                    "title": "n",
                    "prompt": "p",
                    "context": "fresh",
                    "background": VALID_BACKGROUND_80,
                    "task_kind": "read_only",
                    "use_worktree": False,
                    "name": "1abc",
                },
            )
        self.assertEqual(num.exception.code, ErrorCode.INVALID_NAME)
        long_ok = "a" + ("b" * 47)
        self.assertEqual(contracts.validate_short_name(long_ok), long_ok)
        with self.assertRaises(SideSessionError):
            contracts.validate_fresh_background("测" * 80)
        with self.assertRaises(SideSessionError):
            normalize_request(
                "start_session",
                {
                    "initiation": "user_asked",
                    "request_id": str(uuid.uuid4()),
                    "title": "n",
                    "prompt": "p",
                    "context": None,
                    "background": VALID_BACKGROUND_80,
                    "task_kind": "read_only",
                    "use_worktree": False,
                },
            )
        with self.assertRaises(SideSessionError):
            normalize_request("get_session", {"session_id": "not-a-uuid"})
        with self.assertRaises(SideSessionError):
            normalize_request(
                "hand_off_to_session",
                {
                    "request_id": str(uuid.uuid4()),
                    "transfer_id": str(uuid.uuid4()),
                    "task_id": str(uuid.uuid4()),
                    "title": "t",
                    "remaining_plan": "plan",
                    "task_kind": "read_only",
                    "use_worktree": False,
                    "context": "fork",
                    "context_strategy": "summary_copy",
                    "expected_task_revision": 1,
                    "name": "worker-one",
                },
            )
        with self.assertRaises(SideSessionError):
            validate_hook_output("UserPromptSubmit", {"continue": True, "additionalContext": "hello context here"})
        with self.assertRaises(SideSessionError):
            validate_hook_output("Stop", {"hookSpecificOutput": {"hookEventName": "Stop", "evilAck": True}})

    def test_default_worktrees_home_and_engine_allocated_names(self) -> None:
        from state import resolve_worktrees_home
        self.assertTrue(str(resolve_worktrees_home(env={})).endswith("side-session-worktrees"))
        repo_dir = self.tmp_path / "named-git"
        _init_temp_git_repo(repo_dir)
        node_id = str(uuid.uuid4())
        rec = worktree.prepare(
            WorkspaceSpec(node_id=node_id, workspace_mode="branch", source_cwd=str(repo_dir)),
            operation_id=str(uuid.uuid4()),
            worktrees_home=self.tmp_path / "wt-home",
        )
        self.assertEqual(rec.branch, f"side/{uuid.UUID(node_id).hex}")
        self.assertTrue(Path(rec.canonical_worktree_path).name == uuid.UUID(node_id).hex)
        with self.assertRaises(SideSessionError):
            worktree.prepare(
                WorkspaceSpec(
                    node_id=str(uuid.uuid4()),
                    workspace_mode="branch",
                    source_cwd=str(repo_dir),
                    branch="-n",
                ),
                operation_id=str(uuid.uuid4()),
                worktrees_home=self.tmp_path / "wt-home",
            )

    def test_safe_resolve_missing_and_ensure_safe_dir_symlink_parent(self) -> None:
        base = self.tmp_path / "safe-base"
        base.mkdir()
        with self.assertRaises(SideSessionError) as missing:
            safe_resolve_under(base, "notes/missing/deep.md", mkdirs=False)
        self.assertEqual(missing.exception.code, ErrorCode.NOT_FOUND)
        outside = self.tmp_path / "outside-dir"
        outside.mkdir()
        linkparent = self.tmp_path / "linkparent"
        os.symlink(outside, linkparent)
        with self.assertRaises(SideSessionError):
            ensure_safe_dir(linkparent / "child")

    def test_stop_hook_active_missing_and_string_false(self) -> None:
        info = TestStep9SyncHooksAndStopAutoContinuationGuard._spawn_and_complete_child(self, "stop-missing")
        out_none = self.engine.handle_hook(
            HookContext(
                event="Stop",
                invocation_id=str(uuid.uuid4()),
                runtime_sid="sid-parent-main",
                cwd=str(self.workspace_dir),
                stop_hook_active=None,
            )
        )
        self.assertIsNone(out_none)
        with self.assertRaises(SideSessionError):
            parse_hook_input(
                json.dumps(
                    {
                        "session_id": "sid-parent-main",
                        "hook_event_name": "Stop",
                        "stop_hook_active": "false",
                    }
                ),
                environ={},
            )
        parsed_false = parse_hook_input(
            json.dumps(
                {
                    "session_id": "sid-parent-main",
                    "hook_event_name": "Stop",
                    "stop_hook_active": False,
                }
            ),
            environ={},
        )
        self.assertIs(parsed_false.stop_hook_active, False)
        parsed_true = parse_hook_input(
            json.dumps(
                {
                    "session_id": "sid-parent-main",
                    "hook_event_name": "Stop",
                    "stop_hook_active": True,
                }
            ),
            environ={},
        )
        self.assertIs(parsed_true.stop_hook_active, True)
        with self.assertRaises(SideSessionError) as env_only:
            parse_hook_input(
                json.dumps({"hook_event_name": "Stop"}),
                environ={"CLAUDE_SESSION_ID": "sid-from-env"},
            )
        self.assertEqual(env_only.exception.code, ErrorCode.CALLER_UNBOUND)
        with self.assertRaises(SideSessionError) as type_mis:
            parse_hook_input(
                json.dumps({"session_id": 123, "hook_event_name": "Stop"}),
                environ={},
            )
        self.assertEqual(type_mis.exception.code, "HOOK_IDENTITY_MISMATCH")
        _ = info

    def test_mcp_content_length_truncation_and_internal_ports(self) -> None:
        self.assertNotIn("approve_proposal", ALLOWED_ENGINE_TOOLS)
        self.assertNotIn("reject_proposal", ALLOWED_ENGINE_TOOLS)
        self.assertNotIn("approve_context", ALLOWED_ENGINE_TOOLS)
        uninit = TrustedConnection()
        self.assertFalse(uninit.initialized)
        denied = handle_rpc_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            connection=uninit,
            engine=self.engine,
        )
        self.assertEqual(denied["error"]["code"], -32600)
        body = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"}).encode()
        truncated = f"Content-Length: {len(body) + 20}\r\n\r\n".encode() + body
        stdin = io.BytesIO(truncated)
        stdout = io.BytesIO()
        stderr = io.StringIO()
        conn = TrustedConnection(initialized=True)
        serve_stdio(stdin=stdin, stdout=stdout, stderr=stderr, engine=self.engine, connection=conn)
        out = stdout.getvalue()
        self.assertIn(b"Content-Length:", out)
        self.assertIn(b"-32700", out)

    def test_capture_anchor_requires_stable_second_hash(self) -> None:
        from contracts import SourceCutoff
        from driver import ZCodeDriver

        class FlippingDriver(ZCodeDriver):
            def __init__(self) -> None:
                super().__init__()
                self._n = 0

            def _get_source_session_data(self, source_sid: str):  # type: ignore[override]
                self._n += 1
                msg_id = f"msg-{self._n}"
                msgs = [
                    {
                        "id": msg_id,
                        "sequence": self._n,
                        "role": "user",
                        "turn_id": "turn-1",
                        "input_id": "inp-1",
                        "content": f"payload-{self._n}",
                    }
                ]
                return {"id": source_sid, "revision": self._n}, msgs, None

        drv = FlippingDriver()
        cutoff = SourceCutoff(
            source_node_id=str(uuid.uuid4()),
            source_runtime_sid="sid-src",
            trigger_runtime_turn_id="turn-1",
            trigger_request_id=str(uuid.uuid4()),
            owner_id="owner",
            accepted_input_high_watermark="inp-1",
            source_revision=1,
        )
        anchor = drv.capture_anchor(cutoff)
        self.assertEqual(anchor.status, "unavailable")
        self.assertEqual(anchor.reason, "source_history_concurrently_changing")

    def test_run_turn_requires_stop_and_wait_to_release_slot(self) -> None:
        st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "No auto terminal",
                "prompt": "Keep running until stop_and_wait.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "no-auto-term",
            },
        )
        child_id = st["node_id"]
        slot = self.store.conn.execute("SELECT state FROM parent_slots WHERE node_id = ?", (child_id,)).fetchone()
        self.assertNotEqual(slot["state"], "released")
        self.driver.queue_event(
            st["runtime_session_id"],
            {"kind": "turn.started", "runtime_turn_id": "t-keep", "outcome": None},
        )
        runner = WorkerRunner(self.store, engine=self.engine, driver=self.driver, host_adapter=self.host_adapter)
        assignment_row = self.store.conn.execute("SELECT * FROM turns WHERE node_id = ?", (child_id,)).fetchone()
        from contracts import RunAssignment
        assignment = RunAssignment(
            node_id=child_id,
            runtime_sid=st["runtime_session_id"],
            turn_seq=int(assignment_row["turn_seq"]),
            run_id=st["run_id"],
            worker_turn_id=st["worker_turn_id"],
            input_id=str(assignment_row["input_id"]),
            message_id=str(assignment_row["message_id"]),
            parent_node_id=str(self.engine.ensure_caller_node(self.parent_caller)["node_id"]),
            dispatch_group_id=str(assignment_row["dispatch_group_id"] or ""),
            member_id=str(assignment_row["member_id"] or ""),
            task_id=assignment_row["task_id"],
            task_revision=assignment_row["task_revision"],
            owner_epoch=int(assignment_row["owner_epoch"]),
            fencing_token=str(assignment_row["fencing_token"]),
        )
        # Without turn.terminal, run_turn would poll forever; inject terminal then require stop_and_wait.
        self.driver.queue_event(
            st["runtime_session_id"],
            {"kind": "turn.terminal", "runtime_turn_id": "t-keep", "outcome": "success"},
        )
        rcpt = runner.run_turn(assignment)
        self.assertTrue(rcpt.exit_confirmed)
        self.assertTrue(any(c.get("method") == "stop_and_wait" for c in self.driver.call_log))
        slot_after = self.store.conn.execute("SELECT state FROM parent_slots WHERE node_id = ?", (child_id,)).fetchone()
        self.assertEqual(slot_after["state"], "released")

    def test_verify_approval_rejects_self_reported_origin(self) -> None:
        with self.assertRaises(SideSessionError) as ctx:
            self.host_adapter.verify_approval(
                {
                    "purpose": "proposal",
                    "real_input_id": "unregistered-input",
                    "command_id": "cmd-string-only",
                    "origin": "slash_command",
                    "verified_human": True,
                }
            )
        self.assertEqual(ctx.exception.code, ErrorCode.USER_APPROVAL_UNAVAILABLE)

    def test_bind_task_action_ignores_model_task_id(self) -> None:
        with self.assertRaises(SideSessionError) as ctx:
            self.host_adapter.bind_task_action(
                {
                    "runtime_sid": "sid-unbound",
                    "runtime_turn_id": "turn-unbound",
                    "tool_use_id": "tu-1",
                    "tool_name": "Write",
                    "task_id": str(uuid.uuid4()),
                    "binding_id": str(uuid.uuid4()),
                }
            )
        self.assertEqual(ctx.exception.code, ErrorCode.TASK_UNBOUND)

    def test_report_child_final_does_not_release_slot(self) -> None:
        st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Final no release",
                "prompt": "Report final without exit.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "final-hold",
            },
        )
        child_caller = CallerContext(runtime_sid=st["runtime_session_id"], workspace_path=str(self.workspace_dir))
        self.engine.report_child_turn(
            child_caller,
            {
                "request_id": str(uuid.uuid4()),
                "run_id": st["run_id"],
                "turn_seq": st["turn_seq"],
                "worker_turn_id": st["worker_turn_id"],
                "phase": "final",
                "report_revision": None,
                "outcome": "success",
                "recap": "done",
                "full_report": "full done",
                "blocked": False,
                "block_reason": None,
                "artifacts": [],
            },
        )
        slot = self.store.conn.execute("SELECT state FROM parent_slots WHERE node_id = ?", (st["node_id"],)).fetchone()
        self.assertNotEqual(slot["state"], "released")
        member = self.store.conn.execute(
            "SELECT state FROM dispatch_group_members WHERE node_id = ?",
            (st["node_id"],),
        ).fetchone()
        self.assertNotEqual(member["state"], "terminal")


# ==============================================================================
# Opus Three Principles Integration Tests (Principles I, II, III)
# ==============================================================================
class TestOpusThreePrinciplesIntegration(IsolatedSideSessionsTestCase):
    """Comprehensive automated coverage for side-sessions-sidebar-ui-plan-opus.md (Principles I, II, III)."""

    def _make_sample_assignment(self, runtime_sid: str = "sess_sample_1") -> contracts.RunAssignment:
        return contracts.RunAssignment(
            node_id=str(uuid.uuid4()),
            runtime_sid=runtime_sid,
            turn_seq=1,
            run_id=str(uuid.uuid4()),
            worker_turn_id=str(uuid.uuid4()),
            input_id=str(uuid.uuid4()),
            message_id=str(uuid.uuid4()),
            parent_node_id=str(uuid.uuid4()),
            dispatch_group_id=str(uuid.uuid4()),
            member_id=str(uuid.uuid4()),
            task_id=None,
            task_revision=None,
            owner_epoch=1,
            fencing_token="fence:test:1",
        )

    def test_runtime_profile_and_build_create_payload_and_sess_prefix(self) -> None:
        """1. runtime_profile_for_task_kind mapping for read_only vs write_code, payload omissions, and sess_ prefix."""
        from contracts import (
            CLI_SESSION_MODES,
            MCP_PLUGIN_TOOL_PREFIX,
            MCP_TOOL_PREFIX,
            READ_ONLY_BUILTIN_TOOLS,
            READ_ONLY_CONTROL_ALLOWLIST,
            READ_ONLY_DENYLIST,
            RuntimeCreateSpec,
            RuntimeResumeSpec,
            runtime_profile_for_task_kind,
        )
        from driver import ZCodeDriver, build_resume_payload

        ro_prof = runtime_profile_for_task_kind("read_only")
        self.assertEqual(ro_prof.mode, "plan")
        self.assertFalse(ro_prof.require_branch_worktree)
        self.assertEqual(ro_prof.tool_denylist, READ_ONLY_DENYLIST)
        self.assertIsNotNone(ro_prof.tool_allowlist)
        assert ro_prof.tool_allowlist is not None
        self.assertNotIn("LS", ro_prof.tool_allowlist)
        for tool in ro_prof.tool_allowlist:
            self.assertTrue(
                tool in READ_ONLY_BUILTIN_TOOLS
                or tool.startswith(MCP_TOOL_PREFIX)
                or tool.startswith(MCP_PLUGIN_TOOL_PREFIX),
                f"Unexpected tool in read_only allowlist: {tool}",
            )
        expected_mcp_tools = {MCP_TOOL_PREFIX + t for t in READ_ONLY_CONTROL_ALLOWLIST} | {
            MCP_PLUGIN_TOOL_PREFIX + t for t in READ_ONLY_CONTROL_ALLOWLIST
        }
        self.assertTrue(expected_mcp_tools.issubset(set(ro_prof.tool_allowlist)))

        wc_prof = runtime_profile_for_task_kind("write_code")
        self.assertEqual(wc_prof.mode, "build")
        self.assertIsNone(wc_prof.tool_allowlist)
        self.assertEqual(wc_prof.tool_denylist, ("CreateWorkflow", "AmendWorkflow"))
        self.assertTrue(wc_prof.require_branch_worktree)

        with self.assertRaises(SideSessionError) as bad_kind:
            runtime_profile_for_task_kind("yolo_mode")
        self.assertEqual(bad_kind.exception.code, ErrorCode.INVALID_REQUEST)

        asgn = self._make_sample_assignment()
        wc_spec = RuntimeCreateSpec(
            assignment=asgn,
            workspace_path=str(self.workspace_dir),
            parent_runtime_sid="sess_parent",
            mode=wc_prof.mode,
            model={},
            tool_allowlist=list(wc_prof.tool_allowlist or []),
            tool_denylist=list(wc_prof.tool_denylist),
        )
        wc_payload = build_create_payload(wc_spec)
        self.assertEqual(wc_payload["mode"], "build")
        self.assertNotIn("toolAllowlist", wc_payload)
        self.assertNotIn("model", wc_payload)
        self.assertEqual(wc_payload["toolDenylist"], ["CreateWorkflow", "AmendWorkflow"])

        wc_resume_payload = build_resume_payload(
            RuntimeResumeSpec(
                assignment=asgn,
                expected_workspace=str(self.workspace_dir),
                expected_parent_runtime_sid="sess_parent",
                mode=wc_prof.mode,
                model={},
                tool_allowlist=list(wc_prof.tool_allowlist or []),
                tool_denylist=list(wc_prof.tool_denylist),
            )
        )
        self.assertNotIn("toolAllowlist", wc_resume_payload)
        self.assertNotIn("model", wc_resume_payload)

        ro_spec = RuntimeCreateSpec(
            assignment=asgn,
            workspace_path=str(self.workspace_dir),
            parent_runtime_sid="sess_parent",
            mode=ro_prof.mode,
            model={},
            tool_allowlist=list(ro_prof.tool_allowlist or []),
            tool_denylist=list(ro_prof.tool_denylist),
        )
        ro_payload = build_create_payload(ro_spec)
        self.assertEqual(ro_payload["mode"], "plan")
        self.assertIn("toolAllowlist", ro_payload)
        self.assertNotIn("model", ro_payload)

        with self.assertRaises(SideSessionError) as bad_mode:
            build_create_payload(
                RuntimeCreateSpec(
                    assignment=asgn,
                    workspace_path=str(self.workspace_dir),
                    parent_runtime_sid="sess_parent",
                    mode="read_only",
                    model={},
                    tool_allowlist=[],
                    tool_denylist=[],
                )
            )
        self.assertEqual(bad_mode.exception.code, ErrorCode.INVALID_REQUEST)
        self.assertIn("plan", CLI_SESSION_MODES)

        # Verify ZCodeDriver._verify_runtime_config accepts mode='build' + planEnabled=True when spec.mode=='plan'
        zdrv = ZCodeDriver()
        zdrv._verify_runtime_config(
            {"mode": "build", "planEnabled": True},
            ro_spec,
            actual_ws=str(self.workspace_dir),
            expected_ws=str(self.workspace_dir),
        )

        # Verify child_runtime_sid uses sess_ prefix
        st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Verify sess prefix",
                "prompt": "Check session id prefix.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "sess-prefix-check",
            },
        )
        self.assertTrue(str(st["runtime_session_id"]).startswith("sess_"))

    def test_mcp_engine_is_deferred_and_worker_kicker_and_no_implicit_fallback_driver(self) -> None:
        """2. Engine(runtime_execution='deferred') + WorkerKicker delayed creation, wake, drain, and host DB verification."""
        from unittest.mock import patch
        from driver import ZCodeDriver
        from mcp_server import WorkerKicker

        # No implicit fallback driver when driver is None
        bare_engine = Engine(self.store)
        with self.assertRaises(SideSessionError) as no_drv:
            _ = bare_engine.driver
        self.assertEqual(no_drv.exception.code, ErrorCode.CAPABILITY_UNAVAILABLE)

        with self.assertRaises(SideSessionError) as bad_exec:
            Engine(self.store, driver=self.driver, runtime_execution="invalid_mode")
        self.assertEqual(bad_exec.exception.code, ErrorCode.INVALID_REQUEST)

        # Verify ZCodeDriver._spawn_app_server PATH and mailbox env when shutil.which('node') is None
        zdrv = ZCodeDriver(zcode_bin="/usr/bin/true")
        with (
            patch("shutil.which", return_value=None),
            patch.dict(os.environ, {"ZCODE_MAILBOX_ROOT": str(self.tmp_path / "mbox-spawn")}, clear=False),
            patch("subprocess.Popen") as mock_popen,
        ):
            os.environ.pop("ZCODE_SIDE_SESSIONS_NODE_DIR", None)
            zdrv._spawn_app_server(cwd=str(self.workspace_dir))
            self.assertEqual(mock_popen.call_count, 1)
            spawn_env = mock_popen.call_args.kwargs["env"]
            self.assertEqual(spawn_env.get("ZCODE_MESSAGE_ENABLED"), "1")
            self.assertEqual(spawn_env.get("ZCODE_MAILBOX_ROOT"), str(self.tmp_path / "mbox-spawn"))
            self.assertNotIn(".", spawn_env.get("PATH", "").split(os.pathsep))

        wake_calls: list[dict[str, Any]] = []

        class RecordingKicker:
            def wake(self, payload: dict[str, Any]) -> None:
                wake_calls.append(dict(payload))

        deferred_engine = Engine(
            self.store,
            clock=lambda: self.clock_now,
            host_adapter=self.host_adapter,
            driver=self.driver,
            supervisor_port=RecordingKicker(),
            worktrees_home=self.state_root / "worktrees",
            runtime_execution="deferred",
        )
        self.driver.call_log.clear()
        st = deferred_engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Deferred child start",
                "prompt": "Deferred worker execution check.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "deferred-child",
            },
        )
        self.assertEqual(st["status"], "starting")
        self.assertEqual(st["runtime_state"], "queued_for_worker")
        self.assertFalse(st["host_link_verified"])
        create_or_send = [c for c in self.driver.call_log if c.get("method") in ("create", "send")]
        self.assertEqual(len(create_or_send), 0)
        self.assertEqual(len(wake_calls), 1)
        self.assertEqual(wake_calls[0]["node_id"], st["node_id"])
        self.assertEqual(wake_calls[0]["event"], "session_started")

        turn_row = self.store.conn.execute("SELECT execution_state FROM turns WHERE run_id = ?", (st["run_id"],)).fetchone()
        node_row = self.store.conn.execute("SELECT host_link_verified FROM nodes WHERE node_id = ?", (st["node_id"],)).fetchone()
        self.assertEqual(turn_row["execution_state"], "starting")
        self.assertEqual(int(node_row["host_link_verified"]), 0)

        # Verify WorkerKicker spawns worker_runner.py serve --state-home <root> --drain --node-id <id>
        kicker = WorkerKicker(self.state_root)
        with patch("subprocess.Popen") as popen_mock:
            kicker.wake({"node_id": st["node_id"], "run_id": st["run_id"]})
            self.assertEqual(popen_mock.call_count, 1)
            spawn_argv = popen_mock.call_args.args[0]
            self.assertIn("serve", spawn_argv)
            self.assertIn("--drain", spawn_argv)
            self.assertIn("--node-id", spawn_argv)
            self.assertIn(st["node_id"], spawn_argv)

        # Now drain_node via WorkerRunner: first without host DB row -> host_link_verified remains 0
        self.driver.queue_event(
            st["runtime_session_id"],
            {"kind": "turn.terminal", "runtime_turn_id": "t-def-1", "outcome": "success"},
        )
        runner = WorkerRunner(self.store, engine=deferred_engine, driver=self.driver, host_adapter=self.host_adapter)
        drain_res = runner.drain_node(st["node_id"])
        self.assertTrue(drain_res["ok"])
        self.assertTrue(any(c.get("method") == "create" for c in self.driver.call_log))
        self.assertTrue(any(c.get("method") == "send" for c in self.driver.call_log))
        node_after_unverified = self.store.conn.execute(
            "SELECT host_link_verified FROM nodes WHERE node_id = ?",
            (st["node_id"],),
        ).fetchone()
        self.assertEqual(int(node_after_unverified["host_link_verified"]), 0)
        probe_row = self.store.conn.execute(
            "SELECT state FROM desktop_index_probe WHERE node_id = ?",
            (st["node_id"],),
        ).fetchone()
        self.assertIsNotNone(probe_row)
        self.assertEqual(probe_row["state"], "pending")

        # Second child with sync_to_host_db=True -> host_link_verified becomes 1 after worker create+send
        sync_driver = ScriptedFakeDriver(host_db_path=self.host_db_path, sync_to_host_db=True)
        deferred_engine_2 = Engine(
            self.store,
            clock=lambda: self.clock_now,
            host_adapter=self.host_adapter,
            driver=sync_driver,
            supervisor_port=RecordingKicker(),
            worktrees_home=self.state_root / "worktrees",
            runtime_execution="deferred",
        )
        st2 = deferred_engine_2.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Deferred child verified",
                "prompt": "Verify host DB parent_id link.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "deferred-verified",
            },
        )
        sync_driver.queue_event(
            st2["runtime_session_id"],
            {"kind": "turn.terminal", "runtime_turn_id": "t-def-2", "outcome": "success"},
        )
        runner2 = WorkerRunner(self.store, engine=deferred_engine_2, driver=sync_driver, host_adapter=self.host_adapter)
        runner2.drain_node(st2["node_id"])
        node_after_verified = self.store.conn.execute(
            "SELECT host_link_verified FROM nodes WHERE node_id = ?",
            (st2["node_id"],),
        ).fetchone()
        self.assertEqual(int(node_after_verified["host_link_verified"]), 1)

    def test_stop_hook_child_user_turn_and_parent_consumption(self) -> None:
        """3. Child Stop hook without external worker emits child_user_turn and parent UserPromptSubmit consumes it."""
        st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Direct user chat child",
                "prompt": "Initial brief.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "direct-chat-child",
            },
        )
        self._close_child_run(st)
        child_sid = st["runtime_session_id"]
        child_id = st["node_id"]

        long_assistant_msg = "Direct user turn summary: " + ("x" * 900)
        stop_ctx = HookContext(
            event="Stop",
            invocation_id=str(uuid.uuid4()),
            runtime_sid=child_sid,
            cwd=str(self.workspace_dir),
            runtime_turn_id="turn-user-direct-1",
            stop_hook_active=False,
            raw_input={
                "hook_event_name": "Stop",
                "session_id": child_sid,
                "turnId": "turn-user-direct-1",
                "stop_hook_active": False,
                "last_assistant_message": long_assistant_msg,
            },
        )
        self.engine.handle_hook(stop_ctx)
        # Replay identical turn Stop hook -> idempotent (still 1 event)
        self.engine.handle_hook(stop_ctx)

        events = self.store.conn.execute(
            "SELECT * FROM outbox_events WHERE child_node_id = ? AND kind = 'child_user_turn'",
            (child_id,),
        ).fetchall()
        self.assertEqual(len(events), 1)
        ev_row = events[0]
        ev_payload = json.loads(ev_row["payload"])
        self.assertLessEqual(len(ev_payload["recap"]), 400)
        self.assertTrue(ev_payload["recap"].startswith("Direct user turn summary:"))

        # Parent UserPromptSubmit consumes the child_user_turn event
        parent_hook_out = self.engine.handle_hook(
            HookContext(
                event="UserPromptSubmit",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=self.parent_caller.runtime_sid,
                cwd=str(self.workspace_dir),
                runtime_turn_id="turn-parent-consume-1",
            )
        )
        self.assertIsNotNone(parent_hook_out)
        assert parent_hook_out is not None
        self.assertIn(ev_row["event_id"], parent_hook_out["additionalContext"])
        self.assertIn('kind="child_user_turn"', parent_hook_out["additionalContext"])

    def test_interactive_lease_blocks_worker_and_child_hook_delivery(self) -> None:
        """4. interactive_leases blocks worker claim and child hook delivers & acks queued parent messages."""
        st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Interactive child lease test",
                "prompt": "Initial work.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "lease-child",
            },
        )
        self._close_child_run(st)
        child_sid = st["runtime_session_id"]
        child_id = st["node_id"]

        # Parent sends a follow-up message while child is idle (run_id is NULL, state is queued)
        send_res = self.engine.send_message_to_session(
            self.parent_caller,
            {
                "request_id": str(uuid.uuid4()),
                "session_id": child_id,
                "message_id": str(uuid.uuid4()),
                "message": "Parent guidance <check & verify>",
                "resume_policy": "explicit",
            },
        )
        msg_id = send_res["message_id"]

        # Human user submits a prompt directly in the child session -> creates 10-minute interactive lease
        self.host_adapter.record_human_input(
            runtime_sid=child_sid,
            input_id="human-child-inp-1",
            origin="human_prompt",
            runtime_turn_id="turn-child-human-1",
        )
        child_hook_out = self.engine.handle_hook(
            HookContext(
                event="UserPromptSubmit",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=child_sid,
                cwd=str(self.workspace_dir),
                runtime_turn_id="turn-child-human-1",
                raw_input={"input_id": "human-child-inp-1", "origin": "human_prompt"},
            )
        )
        lease_row = self.store.conn.execute(
            "SELECT * FROM interactive_leases WHERE node_id = ?",
            (child_id,),
        ).fetchone()
        self.assertIsNotNone(lease_row)

        # Child UserPromptSubmit also delivered the queued parent message via child_hook!
        self.assertIsNotNone(child_hook_out)
        assert child_hook_out is not None
        self.assertIn(f'<side-sessions-message from="parent" message_id="{msg_id}">', child_hook_out["additionalContext"])
        self.assertIn("Parent guidance &lt;check &amp; verify&gt;", child_hook_out["additionalContext"])

        # Queue another message to test worker blocking under active lease
        send_res_2 = self.engine.send_message_to_session(
            self.parent_caller,
            {
                "request_id": str(uuid.uuid4()),
                "session_id": child_id,
                "message_id": str(uuid.uuid4()),
                "message": "Second parent note while lease active",
                "resume_policy": "explicit",
            },
        )
        msg_id_2 = send_res_2["message_id"]

        runner = WorkerRunner(self.store, engine=self.engine, driver=self.driver, host_adapter=self.host_adapter)
        asgn, _, reason = runner._claim_next_assignment_for_node(child_id)
        self.assertIsNone(asgn)
        self.assertEqual(reason, "interactive_lease")
        node_run_res = runner.run_node(child_id)
        self.assertEqual(node_run_res["status"], "interactive_lease")

        # Next child hook in a new turn ('turn-child-human-2') auto-acks msg_id and presents msg_id_2
        child_hook_out_2 = self.engine.handle_hook(
            HookContext(
                event="PostToolUse",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=child_sid,
                cwd=str(self.workspace_dir),
                runtime_turn_id="turn-child-human-2",
            )
        )
        self.assertIsNotNone(child_hook_out_2)
        assert child_hook_out_2 is not None
        self.assertNotIn(msg_id, child_hook_out_2["additionalContext"])
        self.assertIn(msg_id_2, child_hook_out_2["additionalContext"])

        d1 = self.store.conn.execute(
            "SELECT state FROM inbox_deliveries WHERE target_node_id = ? AND message_id = ? AND channel = 'child_hook'",
            (child_id, msg_id),
        ).fetchone()
        m1 = self.store.conn.execute(
            "SELECT state FROM inbox_messages WHERE target_node_id = ? AND message_id = ?",
            (child_id, msg_id),
        ).fetchone()
        self.assertEqual(d1["state"], "acked")
        self.assertEqual(m1["state"], "completed")

    def test_worker_mailbox_envelope_delivery_and_fallback_recap(self) -> None:
        """5. worker_runner writes atomic mailbox envelopes under ZCODE_MAILBOX_ROOT and extracts fallback recap."""
        mbox_root = self.tmp_path / "mailbox-root"
        os.environ["ZCODE_MAILBOX_ROOT"] = str(mbox_root)
        try:
            sync_driver = ScriptedFakeDriver(host_db_path=self.host_db_path, sync_to_host_db=True)
            eng = Engine(
                self.store,
                clock=lambda: self.clock_now,
                host_adapter=self.host_adapter,
                driver=sync_driver,
                worktrees_home=self.state_root / "worktrees",
            )
            st = eng.start_session(
                self.parent_caller,
                {
                    "initiation": "user_asked",
                    "request_id": str(uuid.uuid4()),
                    "title": "Mailbox & fallback recap child",
                    "prompt": "Run turn and test mailbox + fallback recap.",
                    "context": "fresh",
                    "background": VALID_BACKGROUND_80,
                    "task_kind": "read_only",
                    "use_worktree": False,
                    "name": "mailbox-child",
                },
            )
            child_id = st["node_id"]
            child_sid = st["runtime_session_id"]

            # Queue two mid-turn messages from parent
            m1_res = eng.send_message_to_session(
                self.parent_caller,
                {
                    "request_id": str(uuid.uuid4()),
                    "session_id": child_id,
                    "message_id": str(uuid.uuid4()),
                    "message": "First mid-turn steer message",
                },
            )
            m2_res = eng.send_message_to_session(
                self.parent_caller,
                {
                    "request_id": str(uuid.uuid4()),
                    "session_id": child_id,
                    "message_id": str(uuid.uuid4()),
                    "message": "Second mid-turn unread message",
                },
            )

            runner = WorkerRunner(self.store, engine=eng, driver=sync_driver, host_adapter=self.host_adapter)
            turn_row = self.store.conn.execute("SELECT * FROM turns WHERE run_id = ?", (st["run_id"],)).fetchone()
            parent_node = eng.ensure_caller_node(self.parent_caller)
            assignment = contracts.RunAssignment(
                node_id=child_id,
                runtime_sid=child_sid,
                turn_seq=int(turn_row["turn_seq"]),
                run_id=st["run_id"],
                worker_turn_id=st["worker_turn_id"],
                input_id=str(turn_row["input_id"]),
                message_id=str(turn_row["message_id"]),
                parent_node_id=str(parent_node["node_id"]),
                dispatch_group_id=str(turn_row["dispatch_group_id"] or ""),
                member_id=str(turn_row["member_id"] or ""),
                task_id=turn_row["task_id"],
                task_revision=turn_row["task_revision"],
                owner_epoch=int(turn_row["owner_epoch"]),
                fencing_token=str(turn_row["fencing_token"]),
            )
            conn_obj = next(c for c in sync_driver._connections.values() if c.runtime_sid == child_sid)
            handle = contracts.RuntimeHandle(
                runtime_sid=child_sid,
                runtime_instance_id=conn_obj.runtime_instance_id,
                owner_connection_id=conn_obj.owner_connection_id,
                snapshot_revision=conn_obj.revision,
                canonical_workspace=conn_obj.canonical_workspace,
                process_identity={"pid": conn_obj.pid, "process_started_at": conn_obj.process_started_at},
            )

            runner._deliver_queued_via_mailbox(assignment, handle)
            unread_dir = mbox_root / child_sid / "unread"
            read_dir = mbox_root / child_sid / "read"
            env_files = sorted(unread_dir.glob("*.json"))
            self.assertEqual(len(env_files), 2)
            # Ensure no .tmp-* files match *.json
            self.assertTrue(all(not f.name.startswith(".tmp-") for f in env_files))

            env1 = json.loads(env_files[0].read_text(encoding="utf-8"))
            self.assertEqual(env1["version"], 1)
            self.assertEqual(env1["messageId"], m1_res["message_id"])
            self.assertEqual(env1["fromSessionId"], self.parent_caller.runtime_sid)
            self.assertEqual(env1["toSessionId"], child_sid)
            self.assertEqual(env1["content"], "First mid-turn steer message")
            self.assertNotIn("fencing_token", json.dumps(env1))
            self.assertNotIn("owner_token", json.dumps(env1))

            # Simulate ZCode CLI draining the first envelope into read/
            os.replace(env_files[0], read_dir / env_files[0].name)
            runner._deliver_queued_via_mailbox(assignment, handle)

            d1 = self.store.conn.execute(
                "SELECT state FROM inbox_deliveries WHERE target_node_id = ? AND message_id = ? AND channel = 'mailbox'",
                (child_id, m1_res["message_id"]),
            ).fetchone()
            im1 = self.store.conn.execute(
                "SELECT state FROM inbox_messages WHERE target_node_id = ? AND message_id = ?",
                (child_id, m1_res["message_id"]),
            ).fetchone()
            self.assertEqual(d1["state"], "read")
            self.assertEqual(im1["state"], "completed")

            # Now write an assistant message with reasoning + text parts into the fake host DB
            sync_driver.seed_source_session(
                child_sid,
                messages=[
                    {
                        "id": "msg-asst-1",
                        "role": "assistant",
                        "turn_id": "t-mbox-1",
                        "parts": [
                            {"type": "reasoning", "text": "INTERNAL_REASONING_MUST_BE_FILTERED"},
                            {"type": "text", "text": "Extracted assistant final answer from CLI DB."},
                        ],
                    }
                ],
                directory=str(self.workspace_dir),
                parent_id=self.parent_caller.runtime_sid,
            )
            sync_driver.queue_event(
                child_sid,
                {"kind": "turn.terminal", "runtime_turn_id": "t-mbox-1", "outcome": "success"},
            )
            rcpt = runner.run_turn(assignment)
            self.assertTrue(rcpt.exit_confirmed)

            # Second unread envelope should have been rolled back to fallback / queued
            d2 = self.store.conn.execute(
                "SELECT state FROM inbox_deliveries WHERE target_node_id = ? AND message_id = ? AND channel = 'mailbox'",
                (child_id, m2_res["message_id"]),
            ).fetchone()
            im2 = self.store.conn.execute(
                "SELECT state FROM inbox_messages WHERE target_node_id = ? AND message_id = ?",
                (child_id, m2_res["message_id"]),
            ).fetchone()
            self.assertEqual(d2["state"], "fallback")
            self.assertEqual(im2["state"], "queued")
            self.assertFalse(env_files[1].exists())

            # Fallback report recap must match the assistant text part and exclude reasoning
            rep_row = self.store.conn.execute(
                "SELECT canonical_json FROM reports WHERE node_id = ? AND turn_seq = 1 AND phase = 'final'",
                (child_id,),
            ).fetchone()
            self.assertIsNotNone(rep_row)
            rep_data = json.loads(rep_row["canonical_json"])
            self.assertEqual(rep_data["recap"], "Extracted assistant final answer from CLI DB.")
            self.assertIn("Extracted assistant final answer from CLI DB.", rep_data["full_report"])
            self.assertNotIn("INTERNAL_REASONING_MUST_BE_FILTERED", rep_data["recap"])
            self.assertNotIn("INTERNAL_REASONING_MUST_BE_FILTERED", rep_data["full_report"])
        finally:
            os.environ.pop("ZCODE_MAILBOX_ROOT", None)

    def test_desktop_bridge_comm_projection_and_ack_signature_transition(self) -> None:
        """6. desktop_bridge.py comm projection, recapPreview truncation, forbidden field filtering, and ack_events."""
        from contextlib import closing
        import sqlite3
        from desktop_bridge import FORBIDDEN_EXPORT_KEYS, ProjectionReader

        tasks_index_db = self.tmp_path / "tasks-index.sqlite"
        with closing(sqlite3.connect(tasks_index_db)) as c, c:
            c.execute(
                """
                CREATE TABLE tasks (
                    task_id TEXT,
                    workspace_path TEXT,
                    project_id TEXT,
                    cli_created_at INTEGER,
                    archived INTEGER DEFAULT 0,
                    deleted INTEGER DEFAULT 0,
                    PRIMARY KEY (workspace_path, task_id)
                )
                """
            )

        st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Bridge projection child",
                "prompt": "Verify desktop bridge comm projection.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "bridge-child",
            },
        )
        child_id = st["node_id"]
        child_sid = st["runtime_session_id"]

        with closing(sqlite3.connect(tasks_index_db)) as c, c:
            c.execute(
                "INSERT INTO tasks VALUES (?, ?, 'proj-1', 1700000000000, 0, 0)",
                (child_sid, os.path.realpath(self.workspace_dir)),
            )

        child_caller = CallerContext(
            runtime_sid=child_sid,
            workspace_path=str(self.workspace_dir),
        )
        rep = self.engine.report_child_turn(
            child_caller,
            {
                "request_id": str(uuid.uuid4()),
                "run_id": st["run_id"],
                "turn_seq": st["turn_seq"],
                "worker_turn_id": st["worker_turn_id"],
                "phase": "final",
                "report_revision": None,
                "outcome": "success",
                "recap": "R" * 180,
                "full_report": "SENSITIVE_FULL_REPORT_DO_NOT_LEAK",
                "blocked": False,
                "block_reason": None,
                "artifacts": [],
            },
        )
        self._close_child_run(st)

        reader = ProjectionReader(
            self.state_root,
            cli_db_path=self.host_db_path,
            tasks_index_path=tasks_index_db,
            persist_export=True,
        )
        try:
            snap1 = reader.snapshot()
            nodes1 = {n["nodeId"]: n for n in snap1["nodes"]}
            c1 = nodes1[child_id]
            p1 = nodes1[c1["parentNodeId"]]

            self.assertEqual(c1["indexState"], "indexed")
            self.assertEqual(c1["comm"]["toParentUnread"], 1)
            self.assertTrue(c1["reportPendingAck"])
            self.assertTrue(c1["comm"]["idleParentHint"])
            self.assertEqual(len(c1["comm"]["lastToParent"]["recapPreview"]), 120)
            self.assertEqual(p1["childrenUnreadTotal"], 1)
            sig1 = c1["comm"]["commSignature"]
            rev1 = snap1["projectionRevision"]

            dumped = json.dumps(snap1, ensure_ascii=False)
            for k in FORBIDDEN_EXPORT_KEYS:
                self.assertNotIn(f'"{k}"', dumped)
            self.assertNotIn("SENSITIVE_FULL_REPORT_DO_NOT_LEAK", dumped)

            # Present and ack event on parent
            self.engine.handle_hook(
                HookContext(
                    event="UserPromptSubmit",
                    invocation_id=str(uuid.uuid4()),
                    runtime_sid=self.parent_caller.runtime_sid,
                    cwd=str(self.workspace_dir),
                    runtime_turn_id="turn-parent-ack-1",
                )
            )
            self.engine.ack_events(
                CallerContext(
                    runtime_sid=self.parent_caller.runtime_sid,
                    runtime_turn_id="turn-parent-ack-1",
                    workspace_path=str(self.workspace_dir),
                ),
                {"request_id": str(uuid.uuid4()), "event_ids": [rep["event_id"]]},
            )

            snap2 = reader.snapshot()
            nodes2 = {n["nodeId"]: n for n in snap2["nodes"]}
            c2 = nodes2[child_id]
            p2 = nodes2[c2["parentNodeId"]]
            self.assertEqual(c2["comm"]["toParentUnread"], 0)
            self.assertFalse(c2["reportPendingAck"])
            self.assertFalse(c2["comm"]["idleParentHint"])
            self.assertEqual(p2["childrenUnreadTotal"], 0)
            self.assertNotEqual(c2["comm"]["commSignature"], sig1)
            self.assertGreater(snap2["projectionRevision"], rev1)
        finally:
            reader.close()

    def test_sidebar_js_adapter_fixpoint_and_tree_bundle_in_node(self) -> None:
        """7. Node.js syntax check and core logic verification for zcode-3.17.2.js and sidebar_tree_bundle.js."""
        import shutil

        node_bin = shutil.which("node") or "/opt/homebrew/opt/node@22/bin/node"
        self.assertTrue(Path(node_bin).is_file(), f"node binary not found at {node_bin}")

        adapter_js = PLUGIN_ROOT / "ui" / "adapters" / "zcode-3.17.2.js"
        bundle_js = PLUGIN_ROOT / "ui" / "sidebar_tree_bundle.js"
        fixpoint_mjs = PLUGIN_ROOT / "tests" / "sidebar-ui" / "fixpoint.test.mjs"

        for js_file in (adapter_js, bundle_js):
            chk = subprocess.run([node_bin, "--check", str(js_file)], capture_output=True, text=True)
            self.assertEqual(chk.returncode, 0, f"node --check failed for {js_file}: {chk.stderr}")

        fp_run = subprocess.run([node_bin, str(fixpoint_mjs)], capture_output=True, text=True)
        self.assertEqual(fp_run.returncode, 0, f"fixpoint.test.mjs failed: {fp_run.stderr}")
        self.assertIn("only children left", fp_run.stdout)
        self.assertIn("showMore= false", fp_run.stdout)

        # Execute adapter + bundle pure functions & controller lifecycle in Node VM
        node_test_script = """
        const assert = require('node:assert/strict');
        const fs = require('node:fs');
        const [adapterPath, bundlePath] = process.argv.slice(1);

        class FakeElement {
          constructor(tag = 'div') {
            this.tagName = tag.toUpperCase();
            this.nodeType = 1;
            this.className = '';
            this.id = '';
            this.hidden = false;
            this.draggable = false;
            this.textContent = '';
            this.title = '';
            this.attributes = new Map();
            this.children = [];
            this.parentElement = null;
            this.isConnected = true;
            this. listeners = {};
            this.style = { props: {}, setProperty(k, v) { this.props[k] = v; } };
            this.classList = {
              contains: (c) => this.className.split(/\\s+/).includes(c),
            };
          }
          setAttribute(k, v) { this.attributes.set(k, String(v)); }
          getAttribute(k) { return this.attributes.has(k) ? this.attributes.get(k) : null; }
          hasAttribute(k) { return this.attributes.has(k); }
          removeAttribute(k) { this.attributes.delete(k); }
          append(...nodes) {
            for (const n of nodes) {
              if (typeof n === 'object' && n) { n.parentElement = this; this.children.push(n); }
            }
          }
          appendChild(n) { this.append(n); return n; }
          replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
          replaceWith(other) {
            if (this.parentElement && other) {
              const idx = this.parentElement.children.indexOf(this);
              if (idx !== -1) {
                other.parentElement = this.parentElement;
                this.parentElement.children[idx] = other;
                this.parentElement = null;
              }
            }
          }
          remove() {
            if (this.parentElement) {
              this.parentElement.children = this.parentElement.children.filter(x => x !== this);
              this.parentElement = null;
            }
          }
          get lastElementChild() { return this.children[this.children.length - 1] || null; }
          contains(other) {
            if (other === this) return true;
            return this.children.some(c => c.contains && c.contains(other));
          }
          closest(sel) {
            if (sel === '[data-testid="virtual-project-tasks"]') return this;
            return null;
          }
          querySelector(sel) {
            if (sel === 'ul') return this.children.find(c => c.tagName === 'UL') || null;
            if (sel === '.ss-sr') return this.children.find(c => c.className === 'ss-sr') || null;
            if (sel === ':scope > .ss-tree-chevron') return this.children.find(c => c.classList && c.classList.contains('ss-tree-chevron')) || null;
            if (sel.includes('.ss-comm-badge--parent')) {
              return this.children.find(c => (c.classList && c.classList.contains('ss-comm-badge--parent')) || (c.hasAttribute && c.hasAttribute('data-ss-parent-badge'))) || null;
            }
            return null;
          }
          querySelectorAll(sel) {
            if (sel === ':scope > .ss-tree-chevron') {
              return this.children.filter(c => c.classList && c.classList.contains('ss-tree-chevron'));
            }
            if (sel && sel.includes('.ss-tree-chevron') && sel.includes('.ss-comm-badge--parent')) {
              return this.children.filter(c => (c.classList && (c.classList.contains('ss-tree-chevron') || c.classList.contains('ss-comm-badge--parent'))) || (c.hasAttribute && c.hasAttribute('data-ss-parent-badge')));
            }
            return [];
          }
          addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
          removeEventListener(ev, fn) {
            if (this.listeners[ev]) {
              this.listeners[ev] = this.listeners[ev].filter(f => f !== fn);
            }
          }
          getBoundingClientRect() { return { left: 40 }; }
        }

        global.Element = FakeElement;
        global.window = global;
        global.addEventListener = () => {};
        global.removeEventListener = () => {};
        global.localStorage = {
          _m: new Map(),
          getItem(k) { return this._m.has(k) ? this._m.get(k) : null; },
          setItem(k, v) { this._m.set(k, String(v)); },
          removeItem(k) { this._m.delete(k); },
        };
        global.MutationObserver = class { observe() {} disconnect() {} };
        global.requestAnimationFrame = (fn) => { fn(); return 1; };
        global.cancelAnimationFrame = () => {};
        const headEl = new FakeElement('head');
        const navRoot = new FakeElement('aside');
        global.document = {
          hidden: false,
          readyState: 'complete',
          head: headEl,
          documentElement: headEl,
          activeElement: null,
          createElement: (t) => new FakeElement(t),
          createTextNode: (t) => ({ nodeType: 3, textContent: String(t) }),
          getElementById: (id) => headEl.children.find(c => c.id === id) || null,
          querySelector: (sel) => sel === '[data-project-sidebar-panel="navigation"]' ? navRoot : null,
          querySelectorAll: () => [],
          addEventListener: () => {},
          removeEventListener: () => {},
        };

        eval(fs.readFileSync(adapterPath, 'utf8'));
        const A = global.__SS_ZCODE_ADAPTER__;
        assert.ok(A, 'adapter must register on global');
        assert.equal(A.id, 'zcode-3.17.2');

        // Verify liveFiber alternate selection
        const el = new FakeElement('li');
        const curProps = { a: 2 };
        const altFiber = { memoizedProps: curProps, tag: 5 };
        const staleFiber = { memoizedProps: { a: 1 }, alternate: altFiber, tag: 5 };
        el['__reactFiber$xyz'] = staleFiber;
        el['__reactProps$xyz'] = curProps;
        assert.equal(A.liveFiber(el), altFiber);

        // Verify buildRootOf + suppressDuplicates
        const tasks = [{ taskId: 'c1' }, { taskId: 'c2' }, { taskId: 'a' }, { taskId: 'b' }, { taskId: 'P' }, { taskId: 'd' }, { taskId: 'e' }];
        let dispatchedL = 5;
        const q = { dispatch(v) { dispatchedL = v; } };
        const h2 = { memoizedState: [tasks], next: null };
        const h1 = { memoizedState: false, next: h2 };
        const h0 = { memoizedState: 5, queue: q, next: h1 };
        const onSelect = () => {};
        const trHost = new FakeElement('div');
        const trHostFiber = { tag: 5, stateNode: trHost, memoizedProps: {}, child: null, sibling: null };
        let prev = null;
        for (let i = 0; i < 5; i++) {
          const oct = { memoizedProps: { task: tasks[i], onSelect }, child: null, sibling: null };
          if (!trHostFiber.child) trHostFiber.child = oct;
          else prev.sibling = oct;
          prev = oct;
        }
        const trFiber = { memoizedProps: { tasks, onSelect, kind: 'project' }, memoizedState: h0, child: trHostFiber };
        const mounts = tasks.slice(0, 5).map(t => ({
          taskId: t.taskId,
          wrapper: new FakeElement('div'),
          row: new FakeElement('li'),
          titleSlot: new FakeElement('div'),
          titleText: new FakeElement('span'),
          trFiber,
          octFiber: { memoizedProps: { task: t, onSelect }, child: { child: { memoizedProps: { activeTaskId: 'P' } } } },
          hostId: 'local',
          projectId: 'p1',
          instanceKey: `proj:p1:${t.taskId}`,
        }));

        const pNode = { nodeId: 'nP', parentNodeId: null, sessionId: 'P', name: 'main', title: 'Main', hostId: 'local', workspacePath: '/w', createdAt: '1', comm: {} };
        const c1Node = { nodeId: 'n1', parentNodeId: 'nP', sessionId: 'c1', name: 'sub-1', title: 'Sub 1', hostId: 'local', workspacePath: '/w', createdAt: '2', indexState: 'indexed', comm: { toParentUnread: 2 } };
        const c2Node = { nodeId: 'n2', parentNodeId: 'nP', sessionId: 'c2', name: 'sub-2', title: 'Sub 2', hostId: 'local', workspacePath: '/w', createdAt: '3', indexState: 'indexed', comm: { toParentUnread: 0 } };
        const bySid = new Map([['P', pNode], ['c1', c1Node], ['c2', c2Node]]);
        const byNodeId = new Map([['nP', pNode], ['n1', c1Node], ['n2', c2Node]]);

        const dedupRes = A.suppressDuplicates(mounts, bySid, byNodeId);
        assert.equal(dedupRes.state, 'active');
        assert.equal(dedupRes.L, 7);
        assert.equal(dispatchedL, 7);
        assert.equal(mounts[0].wrapper.getAttribute('data-ss-suppressed'), '1');
        assert.equal(mounts[1].wrapper.getAttribute('data-ss-suppressed'), '1');
        assert.equal(mounts[4].wrapper.getAttribute('data-ss-suppressed'), null);

        // Stub findTaskMounts to return mounts and load sidebar_tree_bundle.js
        A.findTaskMounts = () => mounts;
        eval(fs.readFileSync(bundlePath, 'utf8'));
        const T = global.__SS_SIDEBAR_TREE__;
        assert.ok(T && T.alive);
        const upd = T.update({ schemaVersion: 1, storeInstanceId: 'store-1', projectionRevision: 1, nodes: [pNode, c1Node, c2Node] });
        assert.equal(upd.ok, true);
        const st = T.getStatus();
        assert.equal(st.mountedParentCount, 1);
        assert.equal(st.childCount, 2);
        assert.equal(st.lastError, null);
        assert.equal(mounts[4].row.getAttribute('data-ss-has-children'), 'true');
        assert.ok(mounts[4].titleSlot.querySelector(':scope > .ss-tree-chevron'));
        assert.ok(mounts[4].titleSlot.querySelector(':scope > .ss-comm-badge--parent'));

        // S12: archived intermediate node stops buildRootOf so grandchild is not suppressed
        const archMid = { nodeId: 'nArch', parentNodeId: 'nP', sessionId: 'c1', archived: true, hostId: 'local' };
        const grandChild = { nodeId: 'nGC', parentNodeId: 'nArch', sessionId: 'c2', archived: false, hostId: 'local' };
        const rootMapArch = A.buildRootOf(
          ['P', 'c1', 'c2'],
          new Map([['P', pNode], ['c1', archMid], ['c2', grandChild]]),
          new Map([['nP', pNode], ['nArch', archMid], ['nGC', grandChild]])
        );
        assert.equal(rootMapArch.has('c2'), false);

        // S18: removing children cleans up parent row attribute, chevron, and parent badge
        T.update({ schemaVersion: 1, storeInstanceId: 'store-1', projectionRevision: 2, nodes: [pNode] });
        assert.equal(mounts[4].row.getAttribute('data-ss-has-children'), null);
        assert.equal(mounts[4].titleSlot.querySelector(':scope > .ss-tree-chevron'), null);
        assert.equal(mounts[4].titleSlot.querySelector(':scope > .ss-comm-badge--parent'), null);

        T.destroy();
        assert.equal((trHost.listeners['click'] || []).length, 0);
        assert.equal(global.__SS_SIDEBAR_TREE__, undefined);
        """
        vm_run = subprocess.run(
            [node_bin, "-e", node_test_script, str(adapter_js), str(bundle_js)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(vm_run.returncode, 0, f"Node VM adapter/bundle test failed: {vm_run.stderr}")

    def test_sidebar_ui_ctl_and_asar_cdp_patch_roundtrip_on_synthetic_asar(self) -> None:
        """8. Verify asar_cdp_patch equal-length patch + byte-for-byte restore on synthetic ASAR, plus sidebar_ui_ctl."""
        import sqlite3
        import struct
        from unittest.mock import patch
        import asar_cdp_patch
        import sidebar_ui_ctl
        from zcode_proc import AppGen

        fake_app = self.tmp_path / "FakeZCode.app"
        res_dir = fake_app / "Contents" / "Resources"
        fw_dir = fake_app / "Contents" / "Frameworks" / "Electron Framework.framework"
        cs_dir = fake_app / "Contents" / "_CodeSignature"
        res_dir.mkdir(parents=True, exist_ok=True)
        fw_dir.mkdir(parents=True, exist_ok=True)
        cs_dir.mkdir(parents=True, exist_ok=True)

        # Write Info.plist
        info_plist = fake_app / "Contents" / "Info.plist"
        info_plist.write_bytes(plistlib.dumps({"CFBundleShortVersionString": "3.17.2"}))

        # Write synthetic Electron Framework binary with Fuse wire at offset 64 (bit 3='1', bit 4='0')
        fw_bin = fw_dir / "Electron Framework"
        wire_bytes = b"\x01\x09101100011"  # version=1, len=9, wire[3]='1', wire[4]='0'
        fw_bin.write_bytes((b"\x00" * 64) + wire_bytes + (b"\x00" * 64))

        # Build synthetic app.asar containing out/main/index.js with exact target pattern
        target_branch = (
            b'console.log("init");'
            b'!X.isPackaged&&process.env.ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT!=="1"&&'
            b'X.commandLine.appendSwitch("remote-debugging-port","9229");'
            b'console.log("ready");'
        )
        body_sha = sha256_hex(target_branch)
        header_obj = {
            "files": {
                "out": {
                    "files": {
                        "main": {
                            "files": {
                                "index.js": {
                                    "size": len(target_branch),
                                    "offset": "0",
                                    "integrity": {"hash": body_sha},
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
        fake_asar = res_dir / "app.asar"
        orig_asar_bytes = asar_header + target_branch
        fake_asar.write_bytes(orig_asar_bytes)
        orig_asar_sha = sha256_hex(orig_asar_bytes)

        # Write CodeResources with hash2 matching orig_asar_bytes
        code_resources = cs_dir / "CodeResources"
        code_resources.write_bytes(
            plistlib.dumps(
                {
                    "files2": {
                        "Resources/app.asar": {
                            "hash2": bytes.fromhex(orig_asar_sha),
                        }
                    }
                }
            )
        )

        loc = asar_cdp_patch.locate(asar_path=fake_asar)
        self.assertTrue(loc["ok"])
        self.assertTrue(loc["fileShaOk"])
        self.assertEqual(len(loc["orig"]), len(loc["new"]))
        self.assertEqual(len(loc["orig"]), 134)

        manifest_path = self.state_root / "sidebar-ui" / "backups" / "asar_patch.json"
        entry = {"fuseWireOffset": 64, "fuseSentinel": ""}
        with patch.object(asar_cdp_patch, "codesign_ok", side_effect=[False, True]):
            apply_res = asar_cdp_patch.apply(entry, manifest_path, app_path=fake_app)
            self.assertTrue(apply_res["ok"])
            self.assertEqual(apply_res["origSha"], orig_asar_sha)
            self.assertNotEqual(apply_res["patchedSha"], orig_asar_sha)
            self.assertEqual(len(fake_asar.read_bytes()), len(orig_asar_bytes))
            self.assertTrue(manifest_path.is_file())

            with patch.object(asar_cdp_patch, "DEFAULT_FUSE_WIRE_OFFSET", 64):
                st_applied = asar_cdp_patch.status(manifest_path, app_path=fake_app)
                self.assertEqual(st_applied["state"], "applied")
                self.assertTrue(st_applied["locate"]["alreadyPatched"])

        with patch.object(asar_cdp_patch, "codesign_ok", return_value=True):
            rest_res = asar_cdp_patch.restore(manifest_path, app_path=fake_app)
            self.assertTrue(rest_res["ok"])
            self.assertEqual(rest_res["sha"], orig_asar_sha)
            self.assertEqual(fake_asar.read_bytes(), orig_asar_bytes)
            self.assertFalse(manifest_path.is_file())

        # Verify LaunchGuard gate (stale running task before lstart does NOT block; newer pending update blocks)
        from contextlib import closing

        tasks_idx = self.tmp_path / "lg-tasks-index.sqlite"
        cli_db = self.tmp_path / "lg-cli-db.sqlite"
        with closing(sqlite3.connect(tasks_idx)) as c, c:
            c.execute(
                "CREATE TABLE tasks (task_id TEXT, task_status TEXT, deleted INT, archived INT, updated_at INT)"
            )
            # Stale running row from before process launch (lstart=2000s -> proc_ms=2_000_000)
            c.execute("INSERT INTO tasks VALUES ('old-t', 'running', 0, 0, 1000000)")
        with closing(sqlite3.connect(cli_db)) as c, c:
            c.execute("CREATE TABLE message (id TEXT, time_created INT)")

        pending_upd = self.tmp_path / "update-info.json"
        pending_upd.write_text(json.dumps({"fileName": "ZCode-3.17.2-mac-arm64.zip"}), encoding="utf-8")

        lg = sidebar_ui_ctl.LaunchGuard(
            self.state_root,
            tasks_index_path=tasks_idx,
            cli_db_path=cli_db,
            pending_update_path=pending_upd,
            info_plist_path=info_plist,
            asar_path=fake_asar,
        )
        fake_gen = AppGen(pid=99999, lstart=2000.0, checkin=2005.0)
        self.assertEqual(lg.step(fake_gen)["state"], "NOTIFY")
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value.returncode = 1  # pgrep ShipIt -> not running
            self.assertEqual(lg.gate(fake_gen), [])
            pending_upd.write_text(json.dumps({"fileName": "ZCode-3.18.0-mac-arm64.zip"}), encoding="utf-8")
            self.assertIn("pending_update", lg.gate(fake_gen))

        # Verify sidebar_ui_ctl install -> doctor -> uninstall in isolated state_root without touching user LaunchAgents
        fake_plist = self.tmp_path / "com.zcode.side-sessions.plist"
        inst_res = sidebar_ui_ctl.install(
            self.state_root,
            plugin_root=PLUGIN_ROOT,
            launch_guard_mode="notify",
            enable_cdp_patch=False,
            manage_launchctl=False,
            plist_dest=fake_plist,
        )
        self.assertTrue(inst_res["ok"])
        self.assertTrue(fake_plist.is_file())
        self.assertTrue((self.state_root / "sidebar-ui" / "current.json").is_file())
        self.assertTrue((self.state_root / "sidebar-ui" / "launcher" / "side_sessions_agent.py").is_file())

        uninst_res = sidebar_ui_ctl.uninstall(
            self.state_root,
            keep_data=True,
            manage_launchctl=False,
            plist_dest=fake_plist,
        )
        self.assertTrue(uninst_res["ok"])
        self.assertFalse(fake_plist.is_file())
        self.assertFalse((self.state_root / "sidebar-ui" / "current.json").exists())
        self.assertTrue((self.state_root / "state.sqlite3").is_file())

    def test_synthetic_rturn_upgrade_on_get_current_task_and_report_child_turn(self) -> None:
        """9. Synthetic rturn: binding upgrades atomically on child get_current_task, report_child_turn, and deferred worker startup (G01/G03/S01/S02)."""
        from contracts import SendReceipt

        # Case A: Child calls get_current_task with real host turn_... when initial send had no turnId (rturn:...)
        self.driver.inject_fault(
            "send",
            lambda handle, inp: SendReceipt(
                input_id=inp.input_id,
                status="accepted",
                runtime_turn_id=None,
                response_revision=2,
                evidence_ref=f"send-no-turn:{handle.runtime_instance_id}:{inp.input_id}",
            ),
        )
        st1 = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Child rturn upgrade via get_current_task",
                "prompt": "Call get_current_task with real host turn id.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "rturn-get-task",
            },
        )
        c1_id = st1["node_id"]
        c1_sid = st1["runtime_session_id"]
        c1_run = st1["run_id"]
        expected_synth_1 = f"rturn:{c1_run[:8]}"

        t1_before = self.store.conn.execute("SELECT runtime_turn_id FROM turns WHERE run_id = ?", (c1_run,)).fetchone()
        b1_before = self.store.conn.execute(
            "SELECT runtime_turn_id FROM task_turn_bindings WHERE node_id = ? AND state = 'active'",
            (c1_id,),
        ).fetchone()
        self.assertEqual(t1_before["runtime_turn_id"], expected_synth_1)
        self.assertEqual(b1_before["runtime_turn_id"], expected_synth_1)

        real_turn_1 = "turn_real_host_101"
        c1_caller = CallerContext(
            runtime_sid=c1_sid,
            runtime_turn_id=real_turn_1,
            workspace_path=str(self.workspace_dir),
        )
        cur_task = self.engine.get_current_task(c1_caller, {})
        self.assertEqual(cur_task["task_id"], st1["task_id"])

        t1_after = self.store.conn.execute("SELECT runtime_turn_id FROM turns WHERE run_id = ?", (c1_run,)).fetchone()
        b1_after = self.store.conn.execute(
            "SELECT runtime_turn_id FROM task_turn_bindings WHERE node_id = ? AND state = 'active'",
            (c1_id,),
        ).fetchone()
        bind1_after = self.store.conn.execute("SELECT last_turn_id FROM bindings WHERE node_id = ?", (c1_id,)).fetchone()
        self.assertEqual(t1_after["runtime_turn_id"], real_turn_1)
        self.assertEqual(b1_after["runtime_turn_id"], real_turn_1)
        self.assertEqual(bind1_after["last_turn_id"], real_turn_1)

        # Subsequent report_child_turn on the upgraded turn succeeds without REPORT_TURN_UNBOUND
        rep1 = self.engine.report_child_turn(
            c1_caller,
            {
                "request_id": str(uuid.uuid4()),
                "run_id": c1_run,
                "turn_seq": st1["turn_seq"],
                "worker_turn_id": st1["worker_turn_id"],
                "phase": "final",
                "report_revision": None,
                "outcome": "success",
                "recap": "Completed after get_current_task rturn upgrade.",
                "full_report": "# Report 1\nUpgraded turn binding verified.",
                "blocked": False,
                "block_reason": None,
                "artifacts": [],
            },
        )
        self.assertTrue(rep1["ok"])
        self._close_child_run(st1)

        # Case B: Child directly calls report_child_turn with real host turn_... while DB still has rturn:...
        self.driver.inject_fault(
            "send",
            lambda handle, inp: SendReceipt(
                input_id=inp.input_id,
                status="accepted",
                runtime_turn_id=None,
                response_revision=2,
                evidence_ref=f"send-no-turn:{handle.runtime_instance_id}:{inp.input_id}",
            ),
        )
        st2 = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Child rturn upgrade via report_child_turn",
                "prompt": "Call report_child_turn directly with real host turn id.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "rturn-direct-report",
            },
        )
        c2_id = st2["node_id"]
        c2_sid = st2["runtime_session_id"]
        c2_run = st2["run_id"]
        self.assertEqual(
            self.store.conn.execute("SELECT runtime_turn_id FROM turns WHERE run_id = ?", (c2_run,)).fetchone()[0],
            f"rturn:{c2_run[:8]}",
        )

        real_turn_2 = "turn_real_host_202"
        c2_caller = CallerContext(
            runtime_sid=c2_sid,
            runtime_turn_id=real_turn_2,
            workspace_path=str(self.workspace_dir),
        )
        rep2 = self.engine.report_child_turn(
            c2_caller,
            {
                "request_id": str(uuid.uuid4()),
                "run_id": c2_run,
                "turn_seq": st2["turn_seq"],
                "worker_turn_id": st2["worker_turn_id"],
                "phase": "final",
                "report_revision": None,
                "outcome": "success",
                "recap": "Direct report_child_turn upgraded rturn binding.",
                "full_report": "# Report 2\nDirect report upgrade verified.",
                "blocked": False,
                "block_reason": None,
                "artifacts": [],
            },
        )
        self.assertTrue(rep2["ok"])
        t2_after = self.store.conn.execute("SELECT runtime_turn_id FROM turns WHERE run_id = ?", (c2_run,)).fetchone()
        b2_after = self.store.conn.execute(
            "SELECT runtime_turn_id FROM task_turn_bindings WHERE node_id = ? AND state = 'active'",
            (c2_id,),
        ).fetchone()
        self.assertEqual(t2_after["runtime_turn_id"], real_turn_2)
        self.assertEqual(b2_after["runtime_turn_id"], real_turn_2)
        self._close_child_run(st2)

        # Case C: Deferred startup where driver.send returns runtime_turn_id=None avoids NOT NULL IntegrityError
        # and upgrades to turn_real_host_303 upon receiving turn.terminal
        deferred_eng = Engine(
            self.store,
            clock=lambda: self.clock_now,
            host_adapter=self.host_adapter,
            driver=self.driver,
            worktrees_home=self.state_root / "worktrees",
            runtime_execution="deferred",
        )
        st3 = deferred_eng.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Deferred child with null send turnId",
                "prompt": "Deferred startup without immediate turnId.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "rturn-deferred",
            },
        )
        self.driver.inject_fault(
            "send",
            lambda handle, inp: SendReceipt(
                input_id=inp.input_id,
                status="accepted",
                runtime_turn_id=None,
                response_revision=2,
                evidence_ref=f"send-no-turn:{handle.runtime_instance_id}:{inp.input_id}",
            ),
        )
        self.driver.queue_event(
            st3["runtime_session_id"],
            {"kind": "turn.terminal", "runtime_turn_id": "turn_real_host_303", "outcome": "success"},
        )
        runner = WorkerRunner(self.store, engine=deferred_eng, driver=self.driver, host_adapter=self.host_adapter)
        drain_res = runner.drain_node(st3["node_id"])
        self.assertTrue(drain_res["ok"])
        t3_after = self.store.conn.execute(
            "SELECT runtime_turn_id FROM turns WHERE run_id = ?",
            (st3["run_id"],),
        ).fetchone()
        self.assertEqual(t3_after["runtime_turn_id"], "turn_real_host_303")

    def test_read_only_dual_prefix_allowlist_and_report_child_turn_rejects_unauthorized_exit_confirmed(self) -> None:
        """10. read_only allowlist has both mcp__side_sessions__* and mcp__plugin_side-sessions_side_sessions__*, and public report_child_turn rejects exit_confirmed (G02/S03/S04/G06/G07/S06/S07/G09)."""
        from contracts import (
            MCP_PLUGIN_TOOL_PREFIX,
            MCP_TOOL_PREFIX,
            READ_ONLY_CONTROL_ALLOWLIST,
            RuntimeCreateSpec,
            RuntimeResumeSpec,
            runtime_profile_for_task_kind,
        )
        from driver import ZCodeDriver, build_resume_payload

        # 1. Verify read_only profile includes both MCP prefixes for all allowed control tools
        ro_prof = runtime_profile_for_task_kind("read_only")
        self.assertEqual(ro_prof.mode, "plan")
        self.assertIsNotNone(ro_prof.tool_allowlist)
        allow_set = set(ro_prof.tool_allowlist or ())
        self.assertEqual(MCP_TOOL_PREFIX, "mcp__side_sessions__")
        self.assertEqual(MCP_PLUGIN_TOOL_PREFIX, "mcp__plugin_side-sessions_side_sessions__")
        for tool_name in READ_ONLY_CONTROL_ALLOWLIST:
            self.assertIn(f"mcp__side_sessions__{tool_name}", allow_set)
            self.assertIn(f"mcp__plugin_side-sessions_side_sessions__{tool_name}", allow_set)

        asgn = self._make_sample_assignment()
        create_payload = build_create_payload(
            RuntimeCreateSpec(
                assignment=asgn,
                workspace_path=str(self.workspace_dir),
                parent_runtime_sid="sess_parent",
                mode=ro_prof.mode,
                model={},
                tool_allowlist=list(ro_prof.tool_allowlist or ()),
                tool_denylist=list(ro_prof.tool_denylist),
            )
        )
        resume_payload = build_resume_payload(
            RuntimeResumeSpec(
                assignment=asgn,
                expected_workspace=str(self.workspace_dir),
                expected_parent_runtime_sid="sess_parent",
                mode=ro_prof.mode,
                model={},
                tool_allowlist=list(ro_prof.tool_allowlist or ()),
                tool_denylist=list(ro_prof.tool_denylist),
            )
        )
        self.assertEqual(create_payload["mode"], "plan")
        self.assertEqual(create_payload["toolAllowlist"], resume_payload["toolAllowlist"])
        self.assertIn("mcp__side_sessions__get_current_task", create_payload["toolAllowlist"])
        self.assertIn("mcp__plugin_side-sessions_side_sessions__get_current_task", create_payload["toolAllowlist"])

        # 2. Public report_child_turn must reject unauthorized exit_confirmed with UNKNOWN_FIELD
        st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Reject spoofed exit_confirmed",
                "prompt": "Attempt to pass exit_confirmed via public report_child_turn.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "reject-exit-confirmed",
            },
        )
        child_caller = CallerContext(
            runtime_sid=st["runtime_session_id"],
            workspace_path=str(self.workspace_dir),
        )
        for spoof_val in ("confirmed", True):
            with self.assertRaises(SideSessionError) as exc_ctx:
                self.engine.report_child_turn(
                    child_caller,
                    {
                        "request_id": str(uuid.uuid4()),
                        "run_id": st["run_id"],
                        "turn_seq": st["turn_seq"],
                        "worker_turn_id": st["worker_turn_id"],
                        "phase": "final",
                        "report_revision": None,
                        "outcome": "success",
                        "recap": "Spoofed exit_confirmed attempt",
                        "full_report": "# Spoof attempt",
                        "blocked": False,
                        "block_reason": None,
                        "artifacts": [],
                        "exit_confirmed": spoof_val,
                    },
                )
            self.assertEqual(exc_ctx.exception.code, ErrorCode.UNKNOWN_FIELD)

        slot_row = self.store.conn.execute(
            "SELECT state FROM parent_slots WHERE node_id = ?",
            (st["node_id"],),
        ).fetchone()
        member_row = self.store.conn.execute(
            "SELECT state, exit_confirmed FROM dispatch_group_members WHERE node_id = ?",
            (st["node_id"],),
        ).fetchone()
        self.assertEqual(slot_row["state"], "running")
        self.assertEqual(member_row["state"], "running")
        self.assertNotEqual(member_row["exit_confirmed"], "confirmed")

        # 3. Unverified child UserPromptSubmit must NOT write interactive_leases (G06)
        self.engine.handle_hook(
            HookContext(
                event="UserPromptSubmit",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=st["runtime_session_id"],
                cwd=str(self.workspace_dir),
                runtime_turn_id="turn-system-unverified",
                raw_input={"origin": "system_dispatch"},
            )
        )
        lease_cnt = self.store.conn.execute(
            "SELECT COUNT(*) FROM interactive_leases WHERE node_id = ?",
            (st["node_id"],),
        ).fetchone()[0]
        self.assertEqual(lease_cnt, 0)

        # 4. PreToolUse hook blocks tool execution when task_turn_binding is frozen (G07/S06)
        with self.store.transaction("IMMEDIATE") as txn:
            txn.execute(
                "UPDATE task_turn_bindings SET state = 'frozen' WHERE node_id = ?",
                (st["node_id"],),
            )
        pre_out = self.engine.handle_hook(
            HookContext(
                event="PreToolUse",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=st["runtime_session_id"],
                cwd=str(self.workspace_dir),
                raw_input={"tool_name": "Read", "tool_use_id": "tu-frozen-check"},
            )
        )
        self.assertIsNotNone(pre_out)
        assert pre_out is not None
        self.assertIs(pre_out["continue"], False)
        self.assertIn(ErrorCode.TASK_OWNER_CHANGED.value, pre_out["additionalContext"])

        # 5. ZCodeDriver._parse_notification unwraps session/event notifications and idx_wait_requests_node_state exists (S07/G09)
        zdrv = ZCodeDriver()
        ev_started = zdrv._parse_notification(
            {
                "method": "session/event",
                "params": {
                    "sessionId": st["runtime_session_id"],
                    "type": "turn.started",
                    "payload": {"turnId": "turn-wrapped-1", "inputId": "inp-w-1"},
                },
            },
            runtime_sid=st["runtime_session_id"],
        )
        self.assertIsNotNone(ev_started)
        assert ev_started is not None
        self.assertEqual(ev_started.kind, "turn.started")
        self.assertEqual(ev_started.runtime_turn_id, "turn-wrapped-1")

        ev_term = zdrv._parse_notification(
            {
                "method": "session/event",
                "params": {
                    "sessionId": st["runtime_session_id"],
                    "type": "turn.completed",
                    "payload": {"turnId": "turn-wrapped-1", "status": "completed"},
                },
            },
            runtime_sid=st["runtime_session_id"],
        )
        self.assertIsNotNone(ev_term)
        assert ev_term is not None
        self.assertEqual(ev_term.kind, "turn.terminal")
        self.assertEqual(ev_term.outcome, "success")

        idx_row = self.store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_wait_requests_node_state'"
        ).fetchone()
        self.assertIsNotNone(idx_row)
        self._close_child_run(st)

    def test_asar_cdp_patch_refuses_restore_after_external_upgrade_and_cdp_ws_half_frame_poll(self) -> None:
        """11. asar_cdp_patch refuses blind restore after external ASAR upgrade (S05) and cdp_ws preserves frame state across non-blocking half-frame reads (S08)."""
        from collections import deque
        import socket
        import struct
        from unittest.mock import patch
        import asar_cdp_patch
        from cdp_ws import CdpError, CdpSocket

        # --- Part 1: asar_cdp_patch refuses blind restore when ASAR was modified by external app upgrade (S05) ---
        fake_app = self.tmp_path / "UpgradeZCode.app"
        res_dir = fake_app / "Contents" / "Resources"
        fw_dir = fake_app / "Contents" / "Frameworks" / "Electron Framework.framework"
        cs_dir = fake_app / "Contents" / "_CodeSignature"
        res_dir.mkdir(parents=True, exist_ok=True)
        fw_dir.mkdir(parents=True, exist_ok=True)
        cs_dir.mkdir(parents=True, exist_ok=True)

        fw_bin = fw_dir / "Electron Framework"
        fw_bin.write_bytes((b"\x00" * 64) + b"\x01\x09101100011" + (b"\x00" * 64))

        target_branch = (
            b'console.log("boot");'
            b'!X.isPackaged&&process.env.ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT!=="1"&&'
            b'X.commandLine.appendSwitch("remote-debugging-port","9229");'
            b'console.log("done");'
        )
        header_obj = {
            "files": {
                "out": {
                    "files": {
                        "main": {
                            "files": {
                                "index.js": {
                                    "size": len(target_branch),
                                    "offset": "0",
                                    "integrity": {"hash": sha256_hex(target_branch)},
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
        fake_asar = res_dir / "app.asar"
        orig_asar_bytes = asar_header + target_branch
        fake_asar.write_bytes(orig_asar_bytes)
        orig_asar_sha = sha256_hex(orig_asar_bytes)

        (cs_dir / "CodeResources").write_bytes(
            plistlib.dumps({"files2": {"Resources/app.asar": {"hash2": bytes.fromhex(orig_asar_sha)}}})
        )

        manifest_path = self.state_root / "sidebar-ui" / "backups" / "asar_patch_upgrade.json"
        entry = {"fuseWireOffset": 64, "fuseSentinel": ""}
        with patch.object(asar_cdp_patch, "codesign_ok", return_value=False):
            apply_res = asar_cdp_patch.apply(entry, manifest_path, app_path=fake_app)
            self.assertTrue(apply_res["ok"])
            patched_sha = apply_res["patchedSha"]
            self.assertTrue(manifest_path.is_file())

        # Simulate external ZCode upgrade replacing app.asar with new build bytes
        upgraded_asar_bytes = orig_asar_bytes + b"\n// ZCode 3.18.0 upgraded bundle\n"
        fake_asar.write_bytes(upgraded_asar_bytes)
        upgraded_sha = sha256_hex(upgraded_asar_bytes)

        with patch.object(asar_cdp_patch, "codesign_ok", return_value=True):
            conflict_res = asar_cdp_patch.restore(manifest_path, app_path=fake_app)
            self.assertFalse(conflict_res["ok"])
            self.assertEqual(conflict_res["code"], "ASAR_VERSION_CONFLICT")
            self.assertEqual(conflict_res["sha"], upgraded_sha)
            self.assertEqual(conflict_res["origSha"], orig_asar_sha)
            self.assertEqual(conflict_res["patchedSha"], patched_sha)
            # Upgraded ASAR must remain 100% untouched and manifest preserved
            self.assertEqual(fake_asar.read_bytes(), upgraded_asar_bytes)
            self.assertTrue(manifest_path.is_file())

            # If app.asar is already restored to orig_asar_bytes externally, restore succeeds without rewriting
            fake_asar.write_bytes(orig_asar_bytes)
            already_res = asar_cdp_patch.restore(manifest_path, app_path=fake_app)
            self.assertTrue(already_res["ok"])
            self.assertTrue(already_res.get("alreadyRestored"))
            self.assertFalse(manifest_path.is_file())

        # --- Part 2: cdp_ws CdpSocket preserves frame state across non-blocking half-frame reads (S08) ---
        class ScriptedChunkSocket:
            def __init__(self, steps: list[bytes | Exception]) -> None:
                self.steps = deque(steps)
                self.timeout: float | None = 5.0

            def settimeout(self, t: float | None) -> None:
                self.timeout = t

            def recv(self, _bufsize: int) -> bytes:
                if not self.steps:
                    raise BlockingIOError("no more data currently available")
                step = self.steps.popleft()
                if isinstance(step, Exception):
                    raise step
                return step

            def sendall(self, _data: bytes) -> None:
                pass

            def close(self) -> None:
                pass

        msg1_obj = {
            "method": "Runtime.executionContextCreated",
            "params": {"context": {"id": 1, "name": "x" * 180}},
        }
        msg1_bytes = json.dumps(msg1_obj, separators=(",", ":")).encode("utf-8")
        self.assertGreaterEqual(len(msg1_bytes), 126)
        frame1 = b"\x81\x7e" + struct.pack("!H", len(msg1_bytes)) + msg1_bytes

        msg2_obj = {"method": "Target.targetCreated", "params": {"targetInfo": {"targetId": "t-frag-2"}}}
        msg2_bytes = json.dumps(msg2_obj, separators=(",", ":")).encode("utf-8")
        split_idx = len(msg2_bytes) // 2
        part_a, part_b = msg2_bytes[:split_idx], msg2_bytes[split_idx:]
        # Fragment 1: fin=0, opcode=0x1 (text); Fragment 2: fin=1, opcode=0x0 (continuation)
        frag_frame_a = bytes([0x01, len(part_a)]) + part_a
        frag_frame_b = bytes([0x80, len(part_b)]) + part_b

        ws = CdpSocket.__new__(CdpSocket)
        ws.ws_url = "ws://127.0.0.1:9222/devtools/page/1"
        ws.buf = b""
        ws._id = 0
        ws.events = deque()
        ws._frag_parts = []
        ws.sock = ScriptedChunkSocket(
            [
                # Poll 1: only 1 byte of the 2-byte header arrives, then BlockingIOError
                frame1[:1],
                BlockingIOError("half 2-byte header"),
                # Poll 2: 2nd header byte + 1 byte of 16-bit extended length arrive, then socket.timeout
                frame1[1:3],
                socket.timeout("half extended length"),
                # Poll 3: remaining extended length byte + first 40 payload bytes arrive, then BlockingIOError
                frame1[3:44],
                BlockingIOError("partial payload"),
                # Poll 4: rest of frame1 payload + first fragment of msg2 arrive, then BlockingIOError
                frame1[44:] + frag_frame_a,
                BlockingIOError("between websocket fragments"),
                # Poll 5: continuation fragment of msg2 arrives
                frag_frame_b,
            ]
        )

        # Polls 1..3 should yield no completed messages and preserve unconsumed header bytes in ws.buf
        self.assertEqual(ws.poll_events(0.0), [])
        self.assertEqual(ws.buf, frame1[:1])
        self.assertEqual(ws.poll_events(0.0), [])
        self.assertEqual(ws.buf, frame1[:3])
        self.assertEqual(ws.poll_events(0.0), [])
        self.assertEqual(ws.buf, frame1[:44])

        # Poll 4 completes frame1 and buffers frag_frame_a in ws._frag_parts
        events_poll_4 = ws.poll_events(0.0)
        self.assertEqual(events_poll_4, [msg1_obj])
        self.assertEqual(len(ws._frag_parts), 1)
        self.assertEqual(ws._frag_parts[0], part_a)

        # Poll 5 completes fragmented msg2 and clears ws._frag_parts
        events_poll_5 = ws.poll_events(0.0)
        self.assertEqual(events_poll_5, [msg2_obj])
        self.assertEqual(ws._frag_parts, [])
        self.assertEqual(ws.buf, b"")

        # Invalid JSON payload in a complete frame must raise CdpError
        bad_payload = b"{not-valid-json"
        ws.sock = ScriptedChunkSocket([bytes([0x81, len(bad_payload)]) + bad_payload])
        with self.assertRaises(CdpError):
            ws.recv_message()

    def test_real_host_turn_id_replaces_synthetic_rturn_and_allows_report(self) -> None:
        """12. Verify real host turn_id replaces synthetic rturn: across turns, task_turn_bindings, wait_requests, and report_child_turn."""
        self.test_synthetic_rturn_upgrade_on_get_current_task_and_report_child_turn()

    def test_read_only_profile_allows_both_mcp_prefixes(self) -> None:
        """13. Verify runtime_profile_for_task_kind('read_only') and create/resume payloads allow both MCP prefixes."""
        self.test_read_only_dual_prefix_allowlist_and_report_child_turn_rejects_unauthorized_exit_confirmed()

    def test_child_get_current_task_fallback(self) -> None:
        """14. Verify child get_current_task fallback when caller turn_id differs from synthetic rturn: or is omitted."""
        st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Child get_current_task fallback check",
                "prompt": "Check get_current_task fallback.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "child-task-fallback",
            },
        )
        child_sid = st["runtime_session_id"]
        # 1. Omitted runtime_turn_id falls back to active binding on child node
        res_no_turn = self.engine.get_current_task(
            CallerContext(runtime_sid=child_sid, runtime_turn_id=None, workspace_path=str(self.workspace_dir)),
            {},
        )
        self.assertEqual(res_no_turn["task_id"], st["task_id"])
        # 2. Real host turn_id falls back to active child binding and returns the task
        res_real_turn = self.engine.get_current_task(
            CallerContext(runtime_sid=child_sid, runtime_turn_id="turn_host_fallback_999", workspace_path=str(self.workspace_dir)),
            {},
        )
        self.assertEqual(res_real_turn["task_id"], st["task_id"])
        self._close_child_run(st)


# ==============================================================================
# Phase 2 (S0-S5) & Fable 5.2 Review Optimization Acceptance Tests
# ==============================================================================
class TestPhase2FullIntegrationAndFableInvariants(IsolatedSideSessionsTestCase):
    """Comprehensive unit tests for Phase 2 S0-S5 and FABLE-01..23 invariants."""

    def test_s0a_hook_no_db_fail_open_and_1_1_migration_and_newer_version_pretooluse_fail_closed(self) -> None:
        """S0-A / FABLE-01, 02, 06: No DB -> fail-open; 1.1 DB -> additive migration; newer DB / LOCK_BUSY -> PreToolUse fail-closed for write tools only."""
        empty_root = self.tmp_path / "uninitialized-state-root"
        env = {"ZCODE_SIDE_SESSIONS_HOME": str(empty_root), "CLAUDE_SESSION_ID": "sid-fresh-install"}

        # 1. open_store(initialize=False) on missing DB raises RETRY_LATER without creating state.sqlite3
        with self.assertRaises(SideSessionError) as no_db_ctx:
            open_store(empty_root, writable=True, initialize=False)
        self.assertEqual(no_db_ctx.exception.code, ErrorCode.RETRY_LATER)
        self.assertFalse((empty_root / "state.sqlite3").exists())

        # 2. PreToolUse on non-read-only tool (Bash) when DB does NOT exist must fail-open (rc=0, empty stdout)
        out_no_db = io.StringIO()
        err_no_db = io.StringIO()
        rc_no_db = hook_main(
            stdin=json.dumps(
                {
                    "session_id": "sid-fresh-install",
                    "hook_event_name": "PreToolUse",
                    "cwd": str(self.workspace_dir),
                    "tool_name": "Bash",
                }
            ),
            stdout=out_no_db,
            stderr=err_no_db,
            environ=env,
        )
        self.assertEqual(rc_no_db, 0)
        self.assertEqual(out_no_db.getvalue(), "")
        self.assertFalse((empty_root / "state.sqlite3").exists())

        # 3. SessionStart initializes the DB via initialize=True
        out_ss = io.StringIO()
        rc_ss = hook_main(
            stdin=json.dumps(
                {
                    "session_id": "sid-fresh-install",
                    "hook_event_name": "SessionStart",
                    "cwd": str(self.workspace_dir),
                }
            ),
            stdout=out_ss,
            stderr=io.StringIO(),
            environ=env,
        )
        self.assertEqual(rc_ss, 0)
        self.assertTrue((empty_root / "state.sqlite3").exists())

        # 4. Simulate a legacy 1.1 database -> Hook with >=1.0s budget migrates in-place to 1.2
        with open_store(empty_root, writable=True) as st_mig:
            st_mig.conn.execute("UPDATE schema_meta SET engine_schema_version = '1.1' WHERE id = 1")
        out_mig = io.StringIO()
        rc_mig = hook_main(
            stdin=json.dumps(
                {
                    "session_id": "sid-fresh-install",
                    "hook_event_name": "PreToolUse",
                    "cwd": str(self.workspace_dir),
                    "tool_name": "Bash",
                }
            ),
            stdout=out_mig,
            stderr=io.StringIO(),
            environ=env,
        )
        self.assertEqual(rc_mig, 0)
        self.assertEqual(out_mig.getvalue(), "")
        with open_store(empty_root, writable=False, initialize=False) as st_after:
            ver_row = st_after.conn.execute("SELECT engine_schema_version FROM schema_meta WHERE id = 1").fetchone()
            self.assertEqual(ver_row["engine_schema_version"], "1.2")
            u_ver = st_after.conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(u_ver, 2)

        # 5. Simulate newer DB version ('9.9') -> PreToolUse blocks Bash with continue:False, but allows Read & diff_worktree
        with open_store(empty_root, writable=True) as st_new:
            st_new.conn.execute("UPDATE schema_meta SET engine_schema_version = '9.9' WHERE id = 1")
            st_new.conn.execute("UPDATE store_meta SET engine_schema_version = '9.9' WHERE id = 1")

        out_block = io.StringIO()
        rc_block = hook_main(
            stdin=json.dumps(
                {
                    "session_id": "sid-fresh-install",
                    "hook_event_name": "PreToolUse",
                    "cwd": str(self.workspace_dir),
                    "tool_name": "Bash",
                }
            ),
            stdout=out_block,
            stderr=io.StringIO(),
            environ=env,
        )
        self.assertEqual(rc_block, 0)
        blocked_payload = json.loads(out_block.getvalue().strip())
        self.assertIs(blocked_payload["continue"], False)
        self.assertIn("VERSION_MISMATCH", blocked_payload["additionalContext"])

        for ro_tool in ("Read", "mcp__side_sessions__diff_worktree", "mcp__plugin_side-sessions_side_sessions__read_brief"):
            out_ro = io.StringIO()
            rc_ro = hook_main(
                stdin=json.dumps(
                    {
                        "session_id": "sid-fresh-install",
                        "hook_event_name": "PreToolUse",
                        "cwd": str(self.workspace_dir),
                        "tool_name": ro_tool,
                    }
                ),
                stdout=out_ro,
                stderr=io.StringIO(),
                environ=env,
            )
            self.assertEqual(rc_ro, 0)
            self.assertEqual(out_ro.getvalue(), "")

    def test_s0a_lock_order_repo_merge_and_deferred_emit_confirm_auto_ack(self) -> None:
        """S0-A / FABLE-04, 05: Verify session -> repo_merge -> maintenance lock order and inbox_deliveries emitted_at confirmation."""
        from state import LOCK_ORDER

        self.assertEqual(LOCK_ORDER, ("session", "repo_merge", "maintenance"))
        nid = str(uuid.uuid4())
        rkey = sha256_hex("repo-common-dir-1")

        with self.store.session_lock(nid, blocking=True, timeout_ms=500):
            with self.store.repo_merge_lock(rkey, blocking=True, timeout_ms=500):
                with self.store.transaction("IMMEDIATE"):
                    pass

        # Acquiring session lock while holding repo_merge lock must raise INVALID_REQUEST
        with self.store.repo_merge_lock(rkey, blocking=True, timeout_ms=500):
            with self.assertRaises(SideSessionError) as order_err:
                with self.store.session_lock(nid, blocking=False):
                    pass
            self.assertEqual(order_err.exception.code, ErrorCode.INVALID_REQUEST)
            self.assertIn("session -> repo_merge -> maintenance", order_err.exception.message)

        # Deferred emit confirmation: unconfirmed delivery (emitted_at IS NULL) is reset to queued and re-delivered on next turn
        st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Emit confirm child",
                "prompt": "Test emit confirm.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "emit-child",
            },
        )
        self._close_child_run(st)
        child_id = st["node_id"]
        child_sid = st["runtime_session_id"]

        msg_res = self.engine.send_message_to_session(
            self.parent_caller,
            {
                "request_id": str(uuid.uuid4()),
                "session_id": child_id,
                "message_id": str(uuid.uuid4()),
                "message": "Must not be lost if stdout flush fails",
                "resume_policy": "explicit",
            },
        )
        mid = msg_res["message_id"]

        self.host_adapter.record_human_input(
            runtime_sid=child_sid,
            input_id="inp-child-emit-1",
            origin="human_prompt",
            runtime_turn_id="turn-emit-1",
        )
        out1 = self.engine.handle_hook(
            HookContext(
                event="UserPromptSubmit",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=child_sid,
                cwd=str(self.workspace_dir),
                runtime_turn_id="turn-emit-1",
                raw_input={"input_id": "inp-child-emit-1", "origin": "human_prompt"},
            ),
            defer_emit_confirm=True,
        )
        self.assertIsNotNone(out1)
        self.assertIn(mid, out1["additionalContext"])
        d_row_unconfirmed = self.store.conn.execute(
            "SELECT state, emitted_at FROM inbox_deliveries WHERE target_node_id = ? AND message_id = ?",
            (child_id, mid),
        ).fetchone()
        self.assertEqual(d_row_unconfirmed["state"], "presented")
        self.assertIsNone(d_row_unconfirmed["emitted_at"])

        # Next turn WITHOUT confirm_emitted() -> must NOT ack; must re-present mid!
        out2 = self.engine.handle_hook(
            HookContext(
                event="PostToolUse",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=child_sid,
                cwd=str(self.workspace_dir),
                runtime_turn_id="turn-emit-2",
            ),
            defer_emit_confirm=True,
        )
        self.assertIsNotNone(out2)
        self.assertIn(mid, out2["additionalContext"])
        # Now confirm emission!
        self.assertEqual(self.engine.confirm_emitted(), 1)

        # Turn 3 now auto-acks mid because emitted_at IS NOT NULL
        self.engine.handle_hook(
            HookContext(
                event="PostToolUse",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=child_sid,
                cwd=str(self.workspace_dir),
                runtime_turn_id="turn-emit-3",
            ),
            defer_emit_confirm=True,
        )
        d_row_acked = self.store.conn.execute(
            "SELECT state, emitted_at FROM inbox_deliveries WHERE target_node_id = ? AND message_id = ?",
            (child_id, mid),
        ).fetchone()
        self.assertEqual(d_row_acked["state"], "acked")
        self.assertIsNotNone(d_row_acked["emitted_at"])

    def test_s0b_asar_resolve_build_entry_patched_sha_slice_and_injector_destroy(self) -> None:
        """S0-B / FABLE-03: Verify resolve_build_entry same-fd checks, locate offset formula, and Injector destroy before drop_all."""
        import struct
        from unittest.mock import patch
        import asar_cdp_patch
        from zcode_sidebar_injector import Injector

        fake_app = self.tmp_path / "PatchCheckZCode.app"
        res_dir = fake_app / "Contents" / "Resources"
        fw_dir = fake_app / "Contents" / "Frameworks" / "Electron Framework.framework"
        cs_dir = fake_app / "Contents" / "_CodeSignature"
        res_dir.mkdir(parents=True, exist_ok=True)
        fw_dir.mkdir(parents=True, exist_ok=True)
        cs_dir.mkdir(parents=True, exist_ok=True)
        (fw_dir / "Electron Framework").write_bytes((b"\x00" * 64) + b"\x01\x09101100011" + (b"\x00" * 64))

        padding_prefix = b"/* leading-file-bytes */" * 4
        target_branch = (
            b'console.log("init");'
            b'!app.isPackaged&&process.env.ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT!=="1"&&'
            b'app.commandLine.appendSwitch("remote-debugging-port","9229");'
        )
        header_obj = {
            "files": {
                "out": {
                    "files": {
                        "main": {
                            "files": {
                                "index.js": {
                                    "size": len(target_branch),
                                    "offset": str(len(padding_prefix)),
                                    "integrity": {"hash": sha256_hex(target_branch)},
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
        fake_asar = res_dir / "app.asar"
        orig_bytes = asar_header + padding_prefix + target_branch
        fake_asar.write_bytes(orig_bytes)
        orig_sha = sha256_hex(orig_bytes)
        builds = {orig_sha: {"version": "3.17.2", "adapter": "zcode-3.17.2", "fuseWireOffset": 64}}

        manifest_p = self.state_root / "sidebar-ui" / "backups" / "asar_patch.json"
        with patch.object(asar_cdp_patch, "codesign_ok", return_value=False):
            app_res = asar_cdp_patch.apply(builds[orig_sha], manifest_p, app_path=fake_app)
            self.assertTrue(app_res["ok"])

        loc_after = asar_cdp_patch.locate(fake_asar)
        self.assertFalse(loc_after["ok"])
        self.assertTrue(loc_after["alreadyPatched"])
        self.assertEqual(loc_after["patchedAbs"], app_res["abs"])

        # Valid patched ASAR resolves to builds[orig_sha]
        cache: dict[str, Any] = {}
        resolved, cur_sha, err = asar_cdp_patch.resolve_build_entry(fake_asar, manifest_p, builds, cache=cache)
        self.assertIsNotNone(resolved)
        self.assertIsNone(err)
        self.assertEqual(cur_sha, app_res["patchedSha"])

        # Unrecoverable incomplete manifest (patchedSha=None and missing orig) -> rejected with PATCH_MANIFEST_INCOMPLETE
        m_data = json.loads(manifest_p.read_text(encoding="utf-8"))
        m_data["patchedSha"] = None
        m_data.pop("orig", None)
        manifest_p.write_text(json.dumps(m_data), encoding="utf-8")
        os.chmod(manifest_p, 0o600)
        resolved_inc, _, err_inc = asar_cdp_patch.resolve_build_entry(fake_asar, manifest_p, builds)
        self.assertIsNone(resolved_inc)
        self.assertEqual(err_inc, "PATCH_MANIFEST_INCOMPLETE")

        # Injector._destroy_and_drop_all invokes Runtime.evaluate destroy before closing sockets
        inj = Injector(self.state_root)
        called_exprs: list[str] = []

        class DummyWs:
            def __init__(self) -> None:
                self.closed = False

            def call(self, method: str, params: dict | None = None) -> dict:
                if method == "Runtime.evaluate" and params:
                    called_exprs.append(str(params.get("expression") or ""))
                return {}

            def close(self) -> None:
                self.closed = True

        dws = DummyWs()
        inj.sessions["t1"] = dws  # type: ignore[assignment]
        inj.script_ids["t1"] = "script-1"
        inj._destroy_and_drop_all()
        self.assertTrue(any("__SS_SIDEBAR_TREE__.destroy()" in e for e in called_exprs))
        self.assertTrue(dws.closed)
        self.assertEqual(len(inj.sessions), 0)

    def test_s0c_transactional_approval_consumption_anti_forge_and_slash_command_hook(self) -> None:
        """S0-C / FABLE-07, 08, 09, 10: Verify verify_and_consume_approval_in_txn, anti-forgery, slash command hook, and worker guard."""
        from contracts import ApprovalEvidence

        prop1 = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "own_initiative",
                "request_id": str(uuid.uuid4()),
                "title": "Proposal 1",
                "prompt": "Task 1.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
            },
        )
        prop2 = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "own_initiative",
                "request_id": str(uuid.uuid4()),
                "title": "Proposal 2",
                "prompt": "Task 2.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
            },
        )
        pid1 = prop1["proposal_id"]
        pid2 = prop2["proposal_id"]

        # 1. Forged ApprovalEvidence (not in approval_consumptions) must be rejected
        forged_ev = ApprovalEvidence(
            approval_id=str(uuid.uuid4()),
            parent_node_id=str(uuid.uuid4()),
            real_input_id="forged-inp",
            purpose="proposal",
            task_hash="deadbeef",
            approved_at=self.clock_now.isoformat().replace("+00:00", "Z"),
            expires_at=(self.clock_now + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
            verifier="forged",
            evidence_ref="forged",
        )
        with self.assertRaises(SideSessionError) as forge_ctx:
            self.engine.approve_proposal(self.parent_caller, {"proposal_id": pid1, "evidence": forged_ev})
        self.assertEqual(forge_ctx.exception.code, ErrorCode.USER_APPROVAL_UNAVAILABLE)

        # 2. UserPromptSubmit with ZCode-expanded `/side-sessions:approve <pid1>` approves pid1 and queues proposal_claim_jobs
        expanded_approve_prompt = (
            "Run custom command /side-sessions:approve.\n"
            "Command source: plugin/side-sessions.\n\n"
            "# /side-sessions:approve\n\n"
            f"User arguments:\n{pid1}"
        )
        hook_out = self.engine.handle_hook(
            HookContext(
                event="UserPromptSubmit",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=self.parent_caller.runtime_sid,
                cwd=str(self.workspace_dir),
                runtime_turn_id="turn-slash-approve-1",
                raw_input={"prompt": expanded_approve_prompt, "input_id": "inp-slash-app-1"},
            )
        )
        self.assertIsNotNone(hook_out)
        self.assertIn("proposal_claim_jobs", hook_out["additionalContext"])

        # Replaying the same input_id 'inp-slash-app-1' on pid2 must raise APPROVAL_REPLAYED
        with self.assertRaises(SideSessionError) as replay_ctx:
            self.engine.approve_proposal(
                self.parent_caller,
                {"proposal_id": pid2, "real_input_id": "inp-slash-app-1", "command_id": "/side-sessions:approve"},
            )
        self.assertEqual(replay_ctx.exception.code, ErrorCode.APPROVAL_REPLAYED)

        # WorkerRunner._process_proposal_claim_jobs() claims pid1 and starts the child session
        runner = WorkerRunner(self.store, engine=self.engine, driver=self.driver, host_adapter=self.host_adapter)
        claimed = runner._process_proposal_claim_jobs()
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["proposal_id"], pid1)
        self.assertEqual(claimed[0]["status"], "completed")
        child_nid = claimed[0]["node_id"]
        self.assertIsNotNone(child_nid)

        # 3. Worker-driven turn with prompt `/side-sessions:dismiss <pid2>` must NOT intercept or dismiss pid2 (FABLE-09)
        child_row = self.store.conn.execute("SELECT * FROM nodes WHERE node_id = ?", (child_nid,)).fetchone()
        self.engine.handle_hook(
            HookContext(
                event="UserPromptSubmit",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=str(child_row["runtime_session_id"]),
                cwd=str(self.workspace_dir),
                runtime_turn_id="turn-worker-active",
                raw_input={"prompt": f"/side-sessions:dismiss {pid2}", "input_id": "inp-worker-spoof"},
            )
        )
        p2_after = self.store.conn.execute("SELECT state FROM proposals WHERE proposal_id = ?", (pid2,)).fetchone()
        self.assertEqual(p2_after["state"], "waiting_user")

        # 4. Real human `/side-sessions:dismiss <pid2>` on idle parent dismisses pid2
        dis_out = self.engine.handle_hook(
            HookContext(
                event="UserPromptSubmit",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=self.parent_caller.runtime_sid,
                cwd=str(self.workspace_dir),
                runtime_turn_id="turn-slash-dismiss-2",
                raw_input={"prompt": f"/side-sessions:dismiss {pid2}", "input_id": "inp-slash-dis-2"},
            )
        )
        self.assertIsNotNone(dis_out)
        self.assertIn("[side-sessions:dismiss]", dis_out["additionalContext"])
        p2_final = self.store.conn.execute("SELECT state FROM proposals WHERE proposal_id = ?", (pid2,)).fetchone()
        self.assertEqual(p2_final["state"], "dismissed")

    def test_s1_zero_host_sqlite_writes_and_realtime_index_state_and_can_resume_for_index(self) -> None:
        """S1 / FABLE-11, 12: Verify worker_runner has zero host DB writes and desktop_bridge computes indexState/canResumeForIndex."""
        from contextlib import closing
        import sqlite3
        from desktop_bridge import ProjectionReader

        wr_src = (SCRIPTS_DIR / "worker_runner.py").read_text(encoding="utf-8")
        self.assertNotIn("_sync_child_to_desktop_tasks_index", wr_src)
        self.assertNotIn("UPDATE session SET title", wr_src)
        self.assertNotIn("INSERT INTO tasks", wr_src)

        tasks_idx = self.tmp_path / "s1-tasks-index.sqlite"
        with closing(sqlite3.connect(self.host_db_path)) as c, c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS session (id TEXT PRIMARY KEY, parent_id TEXT, title TEXT, time_archived INTEGER, time_deleted INTEGER)"
            )
        with closing(sqlite3.connect(tasks_idx)) as c, c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS tasks (task_id TEXT, workspace_path TEXT, project_id TEXT, cli_created_at INTEGER, archived INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0)"
            )

        st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "S1 Index Child",
                "prompt": "Check index state.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "s1-child",
            },
        )
        cid = st["node_id"]
        csid = st["runtime_session_id"]

        # Even if desktop_index_probe says 'indexed', if cliExists=True and not in tasks-index.sqlite -> indexState must be 'pending'
        with closing(sqlite3.connect(self.host_db_path)) as c, c:
            c.execute("INSERT INTO session VALUES (?, ?, ?, NULL, NULL)", (csid, self.parent_caller.runtime_sid, "S1 Index Child"))
        with self.store.transaction("IMMEDIATE") as txn:
            txn.execute("INSERT OR REPLACE INTO desktop_index_probe VALUES (?, 'indexed', ?)", (cid, "2026-07-13T12:00:00Z"))

        reader = ProjectionReader(self.state_root, cli_db_path=self.host_db_path, tasks_index_path=tasks_idx, persist_export=False)
        try:
            snap_running = reader.snapshot()
            c_running = {n["nodeId"]: n for n in snap_running["nodes"]}[cid]
            self.assertEqual(c_running["indexState"], "pending")
            # Active turn is running -> canResumeForIndex must be False!
            self.assertFalse(c_running["canResumeForIndex"])
            self.assertTrue(c_running["canCancel"])
            self.assertFalse(c_running["canArchive"])

            # Close run -> child becomes idle -> canResumeForIndex becomes True, canArchive becomes True
            self._close_child_run(st)
            snap_idle = reader.snapshot()
            c_idle = {n["nodeId"]: n for n in snap_idle["nodes"]}[cid]
            self.assertEqual(c_idle["indexState"], "pending")
            self.assertTrue(c_idle["canResumeForIndex"])
            self.assertTrue(c_idle["canArchive"])
            self.assertFalse(c_idle["canCancel"])
        finally:
            reader.close()

    def test_s2_agent_clean_env_consistency_fd_cloexec_and_agent_control_json(self) -> None:
        """S2 / FABLE-13, 14: Verify side_sessions_agent._clean_env matches driver.sanitize_subprocess_env, FD_CLOEXEC, and agent-control.json."""
        import fcntl
        import agent_ctl
        from driver import sanitize_subprocess_env
        import side_sessions_agent
        import sidebar_ui_ctl

        agent_src = (SCRIPTS_DIR / "side_sessions_agent.py").read_text(encoding="utf-8")
        self.assertNotIn("import driver", agent_src)
        self.assertNotIn("from driver", agent_src)

        sample_env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.tmp_path),
            "CLAUDE_SESSION_ID": "drop-1",
            "CLAUDE_CODE_SESSION_ID": "drop-2",
            "CLAUDE_TURN_ID": "drop-3",
            "ZCODE_SESSION_ID": "drop-4",
            "ZCODE_SESSION_EXTRA": "drop-5",
            "ZCODE_TURN_ID": "drop-6",
            "ZCODE_TRACE_ID": "drop-7",
            "ZCODE_REQUEST_ID": "drop-8",
            "ZCODE_SIDE_SESSIONS_HOME": str(self.state_root),
            "ZCODE_SIDE_SESSIONS_ZCODE_BIN": "/usr/local/bin/zcode",
        }
        cleaned_agent = side_sessions_agent._clean_env(sample_env)
        cleaned_driver = sanitize_subprocess_env(sample_env)
        self.assertEqual(cleaned_agent, cleaned_driver)
        self.assertEqual(cleaned_agent["ZCODE_SIDE_SESSIONS_HOME"], str(self.state_root))
        self.assertEqual(cleaned_agent["ZCODE_SIDE_SESSIONS_ZCODE_BIN"], "/usr/local/bin/zcode")
        for dropped in (
            "CLAUDE_SESSION_ID",
            "CLAUDE_CODE_SESSION_ID",
            "CLAUDE_TURN_ID",
            "ZCODE_SESSION_ID",
            "ZCODE_SESSION_EXTRA",
            "ZCODE_TURN_ID",
            "ZCODE_TRACE_ID",
            "ZCODE_REQUEST_ID",
        ):
            self.assertNotIn(dropped, cleaned_agent)

        # Verify uninstall writes agent-control.json with autostartFromHook=False and prevents Hook kick
        sidebar_ui_ctl.uninstall(self.state_root, manage_launchctl=False, plist_dest=self.tmp_path / "dummy.plist")
        ctrl_file = self.state_root / "agent-control.json"
        self.assertTrue(ctrl_file.is_file())
        ctrl_data = json.loads(ctrl_file.read_text(encoding="utf-8"))
        self.assertFalse(ctrl_data["installed"])
        self.assertFalse(ctrl_data["autostartFromHook"])
        kick_disabled = agent_ctl.probe_and_kick_nonblocking(self.state_root)
        self.assertEqual(kick_disabled["status"], "disabled")

        # Enable agent-control.json and verify first probe kicks, second within 15s hits cooldown, and held lock returns alive
        ctrl_file.write_text(json.dumps({"installed": True, "autostartFromHook": True, "mode": "agent"}), encoding="utf-8")
        os.environ["ZCODE_SIDE_SESSIONS_DISABLE_LAUNCHCTL"] = "1"
        try:
            res1 = agent_ctl.probe_and_kick_nonblocking(self.state_root)
            self.assertEqual(res1["status"], "kicked")
            res2 = agent_ctl.probe_and_kick_nonblocking(self.state_root)
            self.assertEqual(res2["status"], "cooldown")

            lock_p = self.state_root / "locks" / "agent.lock"
            fd = os.open(str(lock_p), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.fcntl(fd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
                flags = fcntl.fcntl(fd, fcntl.F_GETFD)
                self.assertTrue(bool(flags & fcntl.FD_CLOEXEC))
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                res_alive = agent_ctl.probe_and_kick_nonblocking(self.state_root)
                self.assertEqual(res_alive["status"], "alive")
            finally:
                os.close(fd)
        finally:
            os.environ.pop("ZCODE_SIDE_SESSIONS_DISABLE_LAUNCHCTL", None)

    def test_s3_worktree_diff_merge_modes_conflict_reconciliation_and_cleanup(self) -> None:
        """S3 / FABLE-15, 16, 17, 18: Verify diff_worktree, merge_worktree (merge/squash/conflict), maintenance fence, and cleanup_worktree."""
        from contracts import READ_ONLY_CONTROL_ALLOWLIST

        self.assertIn("diff_worktree", ALLOWED_ENGINE_TOOLS)
        self.assertIn("diff_worktree", READ_ONLY_CONTROL_ALLOWLIST)
        self.assertNotIn("merge_worktree", ALLOWED_ENGINE_TOOLS)
        self.assertNotIn("cleanup_worktree", ALLOWED_ENGINE_TOOLS)
        self.assertNotIn("merge_worktree", READ_ONLY_CONTROL_ALLOWLIST)
        self.assertNotIn("cleanup_worktree", READ_ONLY_CONTROL_ALLOWLIST)

        repo_dir = self.tmp_path / "s3-git-repo"
        base_head = _init_temp_git_repo(repo_dir)
        git_caller = CallerContext(
            runtime_sid="sid-parent-git",
            runtime_turn_id="turn-git-1",
            workspace_path=str(repo_dir),
            connection_id="stdio:git",
        )

        # 1. Start write_code child with branch worktree, commit change, diff, merge (squash), and cleanup
        st1 = self.engine.start_session(
            git_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Feature Child 1",
                "prompt": "Add feature_a.py",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "write_code",
                "use_worktree": True,
                "name": "feat-one",
            },
        )
        self._close_child_run(st1)
        c1_id = st1["node_id"]
        c1_wt = Path(
            self.store.conn.execute(
                "SELECT canonical_worktree_path FROM worktrees WHERE node_id = ?",
                (c1_id,),
            ).fetchone()["canonical_worktree_path"]
        )
        (c1_wt / "feature_a.py").write_text("FEATURE_A = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(c1_wt), "add", "feature_a.py"], check=True)
        subprocess.run(["git", "-C", str(c1_wt), "commit", "-m", "Add feature_a"], check=True, capture_output=True)

        diff1 = self.engine.diff_worktree(git_caller, {"session_id": c1_id})
        self.assertTrue(diff1["ok"])
        self.assertTrue(diff1["merge_eligible"])
        self.assertEqual(diff1["commits_ahead"], 1)
        self.assertIn("feature_a.py", diff1["patch"])
        prev_hash_1 = diff1["preview_hash"]

        # Queue merge job via UserPromptSubmit slash command (/side-sessions:merge feat-one <hash> squash --cleanup)
        merge_hook_out = self.engine.handle_hook(
            HookContext(
                event="UserPromptSubmit",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=git_caller.runtime_sid,
                cwd=str(repo_dir),
                runtime_turn_id="turn-git-merge-1",
                raw_input={
                    "prompt": f"/side-sessions:merge feat-one {prev_hash_1} squash --cleanup",
                    "input_id": "inp-merge-1",
                },
            )
        )
        self.assertIsNotNone(merge_hook_out)
        self.assertIn("[side-sessions:merge]", merge_hook_out["additionalContext"])

        # Maintenance fence: while job is queued, send_message_to_session must fail with SESSION_BUSY
        with self.assertRaises(SideSessionError) as fence_err:
            self.engine.send_message_to_session(
                git_caller,
                {
                    "request_id": str(uuid.uuid4()),
                    "message_id": str(uuid.uuid4()),
                    "session_id": c1_id,
                    "message": "Blocked by worktree job fence",
                    "resume_policy": "explicit",
                },
            )
        self.assertEqual(fence_err.exception.code, ErrorCode.SESSION_BUSY)

        # Execute queued worktree job via WorkerRunner
        runner = WorkerRunner(self.store, engine=self.engine, driver=self.driver, host_adapter=self.host_adapter)
        wt_results = runner._process_worktree_jobs()
        self.assertEqual(len(wt_results), 1)
        self.assertTrue(wt_results[0]["ok"])
        self.assertEqual(wt_results[0]["status"], "merged")
        self.assertTrue(wt_results[0]["cleanup"]["cleaned"])
        # Squash mode retains branch reference while removing worktree directory and archiving node
        self.assertTrue(wt_results[0]["cleanup"]["branch_retained"])
        self.assertFalse(c1_wt.exists())
        self.assertTrue((repo_dir / "feature_a.py").is_file())
        c1_node_after = self.store.conn.execute("SELECT node_status FROM nodes WHERE node_id = ?", (c1_id,)).fetchone()
        self.assertEqual(c1_node_after["node_status"], "archived")

        # 2. Conflict test: child and parent modify same line -> merge-tree rc=1 -> reconciliation, parent working tree untouched
        st2 = self.engine.start_session(
            git_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Conflict Child 2",
                "prompt": "Modify app.py",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "write_code",
                "use_worktree": True,
                "name": "feat-conflict",
            },
        )
        self._close_child_run(st2)
        c2_id = st2["node_id"]
        c2_wt = Path(
            self.store.conn.execute(
                "SELECT canonical_worktree_path FROM worktrees WHERE node_id = ?",
                (c2_id,),
            ).fetchone()["canonical_worktree_path"]
        )
        (c2_wt / "app.py").write_text("def greet() -> str:\n    return 'from-child'\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(c2_wt), "commit", "-am", "Child edit app.py"], check=True, capture_output=True)

        # Parent also commits a conflicting change on app.py
        (repo_dir / "app.py").write_text("def greet() -> str:\n    return 'from-parent'\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo_dir), "commit", "-am", "Parent edit app.py"], check=True, capture_output=True)

        diff2 = self.engine.diff_worktree(git_caller, {"session_id": c2_id})
        self._trust_human("inp-merge-conflict-2", command_id="/side-sessions:merge", runtime_sid=git_caller.runtime_sid)
        merge_conf_res = self.engine.merge_worktree(
            git_caller,
            {
                "session_id": c2_id,
                "preview_hash": diff2["preview_hash"],
                "mode": "merge",
                "real_input_id": "inp-merge-conflict-2",
                "command_id": "/side-sessions:merge",
            },
            execute_now=True,
        )
        self.assertFalse(merge_conf_res["ok"])
        self.assertEqual(merge_conf_res["state"], "reconciliation")
        self.assertIn("app.py", merge_conf_res["conflict_files"])
        # Parent working tree must remain 100% clean
        p_st = subprocess.run(["git", "-C", str(repo_dir), "status", "--porcelain=v1"], check=True, capture_output=True)
        self.assertEqual(p_st.stdout.strip(), b"")
        _ = base_head

    def test_s4_public_projection_validator_ui_actions_overlay_banner_and_pinned_unique_ids(self) -> None:
        """S4 / FABLE-19, 20, 21: Verify validate_public_projection, execute_ui_action, and Node VM UI actions/banner/pinned."""
        import shutil
        from desktop_bridge import validate_public_projection

        # 1. validate_public_projection catches both snake_case and camelCase forbidden keys at any depth
        for bad_key in ("nonce", "promptNonce", "approval_token", "realInputId", "taskHash", "ownerToken", "fullReport"):
            with self.assertRaises(ValueError):
                validate_public_projection({"nodes": [{"comm": {bad_key: "secret"}}]})

        # 2. execute_ui_action idempotency via requests table, mandatory expectedRevision on archive, strict_node on cancel_run
        st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "UI Action Child",
                "prompt": "Test UI actions.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "ui-child",
            },
        )
        cid = st["node_id"]
        rid = st["run_id"]

        # cancel_run with wrong nodeId must not fall back to another node when strict_node=True
        other_st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Other Child",
                "prompt": "Other.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "ui-other",
            },
        )
        self._close_child_run(other_st)
        bad_cancel = self.engine.execute_ui_action(
            "cancel_run",
            {"actionId": str(uuid.uuid4()), "nodeId": other_st["node_id"], "runId": rid},
        )
        self.assertFalse(bad_cancel["ok"])
        self.assertEqual(bad_cancel["code"], ErrorCode.NOT_FOUND.value)

        # Valid cancel_run UI action and idempotent repeat
        cancel_aid = str(uuid.uuid4())
        ok_cancel_1 = self.engine.execute_ui_action(
            "cancel_run",
            {"actionId": cancel_aid, "nodeId": cid, "runId": rid},
        )
        ok_cancel_2 = self.engine.execute_ui_action(
            "cancel_run",
            {"actionId": cancel_aid, "nodeId": cid, "runId": rid},
        )
        self.assertTrue(ok_cancel_1["ok"])
        self.assertTrue(ok_cancel_2["ok"])
        self.assertEqual(ok_cancel_1["result"]["control_id"], ok_cancel_2["result"]["control_id"])
        self._close_child_run(st)

        # archive_session without expectedRevision must fail with VALIDATION_ERROR
        no_rev_arch = self.engine.execute_ui_action(
            "archive_session",
            {"actionId": str(uuid.uuid4()), "nodeId": cid},
        )
        self.assertFalse(no_rev_arch["ok"])
        self.assertEqual(no_rev_arch["code"], ErrorCode.VALIDATION_ERROR.value)

        cur_rev = int(self.store.conn.execute("SELECT revision FROM nodes WHERE node_id = ?", (cid,)).fetchone()["revision"])
        ok_arch = self.engine.execute_ui_action(
            "archive_session",
            {"actionId": str(uuid.uuid4()), "nodeId": cid, "expectedRevision": cur_rev},
        )
        self.assertTrue(ok_arch["ok"])

        # 3. Node VM test for Pinned + Projects unique ss-sub-* IDs, drainActions/ackActions, and #ss-overlay-root Banner
        node_bin = shutil.which("node") or "/opt/homebrew/opt/node@22/bin/node"
        adapter_js = PLUGIN_ROOT / "ui" / "adapters" / "zcode-3.17.2.js"
        bundle_js = PLUGIN_ROOT / "ui" / "sidebar_tree_bundle.js"
        vm_script = """
        const assert = require('node:assert/strict');
        const fs = require('node:fs');
        const [adapterPath, bundlePath] = process.argv.slice(1);

        class FakeEl {
          constructor(tag = 'div') {
            this.tagName = tag.toUpperCase();
            this.nodeType = 1;
            this.className = '';
            this.id = '';
            this.hidden = false;
            this.disabled = false;
            this.draggable = false;
            this.textContent = '';
            this.title = '';
            this.attributes = new Map();
            this.children = [];
            this.parentElement = null;
            this.isConnected = true;
            this.listeners = {};
            this.style = { props: {}, setProperty(k, v) { this.props[k] = v; } };
            this.classList = { contains: (c) => this.className.split(/\\s+/).includes(c) };
          }
          setAttribute(k, v) { this.attributes.set(k, String(v)); }
          getAttribute(k) { return this.attributes.has(k) ? this.attributes.get(k) : null; }
          hasAttribute(k) { return this.attributes.has(k); }
          removeAttribute(k) { this.attributes.delete(k); }
          append(...nodes) {
            for (const n of nodes) {
              if (typeof n === 'object' && n) { n.parentElement = this; this.children.push(n); }
            }
          }
          appendChild(n) { this.append(n); return n; }
          replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
          replaceWith(other) {
            if (this.parentElement && other) {
              const i = this.parentElement.children.indexOf(this);
              if (i !== -1) { other.parentElement = this.parentElement; this.parentElement.children[i] = other; this.parentElement = null; }
            }
          }
          remove() {
            if (this.parentElement) {
              this.parentElement.children = this.parentElement.children.filter(x => x !== this);
              this.parentElement = null;
            }
          }
          get lastElementChild() { return this.children[this.children.length - 1] || null; }
          contains(other) { return other === this || this.children.some(c => c.contains && c.contains(other)); }
          closest() { return null; }
          querySelector(sel) {
            if (sel === 'ul') return this.children.find(c => c.tagName === 'UL') || null;
            if (sel === '.ss-sr') return this.children.find(c => c.className === 'ss-sr') || null;
            if (sel === ':scope > .ss-tree-chevron') return this.children.find(c => c.classList.contains('ss-tree-chevron')) || null;
            if (sel.includes('.ss-comm-badge--parent')) return this.children.find(c => c.classList.contains('ss-comm-badge--parent')) || null;
            return null;
          }
          querySelectorAll(sel) {
            if (sel === ':scope > .ss-tree-chevron') return this.children.filter(c => c.classList.contains('ss-tree-chevron'));
            return [];
          }
          addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
          removeEventListener() {}
          getBoundingClientRect() { return { top: 20, left: 260, width: 800 }; }
        }

        const headEl = new FakeEl('head');
        const bodyEl = new FakeEl('body');
        const navRoot = new FakeEl('aside');
        const chatView = new FakeEl('main');
        function walkAll(root, out = []) {
          for (const c of root.children || []) {
            if (c.nodeType === 1) { out.push(c); walkAll(c, out); }
          }
          return out;
        }
        global.Element = FakeEl;
        global.window = global;
        global.addEventListener = () => {};
        global.removeEventListener = () => {};
        global.localStorage = { getItem() { return null; }, setItem() {}, removeItem() {} };
        global.MutationObserver = class { observe() {} disconnect() {} };
        global.ResizeObserver = class { observe() {} disconnect() {} };
        global.requestAnimationFrame = (fn) => { fn(); return 1; };
        global.cancelAnimationFrame = () => {};
        global.document = {
          hidden: false,
          readyState: 'complete',
          head: headEl,
          body: bodyEl,
          documentElement: headEl,
          activeElement: null,
          createElement: (t) => new FakeEl(t),
          createTextNode: (t) => ({ nodeType: 3, textContent: String(t) }),
          getElementById: (id) => [...walkAll(headEl), ...walkAll(bodyEl), ...walkAll(navRoot)].find(e => e.id === id) || null,
          querySelector: (sel) => sel === '[data-project-sidebar-panel="navigation"]' ? navRoot : (sel === '[data-testid="chat-view"]' ? chatView : null),
          querySelectorAll: (sel) => sel === '[data-ss-owned]' ? [...walkAll(headEl), ...walkAll(bodyEl), ...walkAll(navRoot)].filter(e => e.hasAttribute('data-ss-owned')) : [],
          addEventListener: () => {},
          removeEventListener: () => {},
        };

        eval(fs.readFileSync(adapterPath, 'utf8'));
        const A = global.__SS_ZCODE_ADAPTER__;
        // Verify suppressDuplicates skips pinned
        assert.equal(A.suppressDuplicates([{ kind: 'pinned', trFiber: { memoizedProps: { kind: 'pinned' } } }]).state, 'skipped:pinned');

        const trProj = { memoizedProps: { kind: 'project', tasks: [], onSelect: () => {} } };
        const trPin = { memoizedProps: { kind: 'pinned', tasks: [], onSelect: () => {} } };
        const wProj = new FakeEl('div');
        const wPin = new FakeEl('div');
        navRoot.append(wProj, wPin);
        const mounts = [
          {
            taskId: 'sid-P', wrapper: wProj, row: new FakeEl('li'), titleSlot: new FakeEl('div'), titleText: new FakeEl('span'),
            trFiber: trProj, octFiber: { memoizedProps: {}, child: { child: { memoizedProps: { activeTaskId: 'sid-C1', isWorkspaceActive: true } } } },
            hostId: 'local', projectId: 'p1', kind: 'project', instanceKey: 'proj:p1:sid-P'
          },
          {
            taskId: 'sid-P', wrapper: wPin, row: new FakeEl('li'), titleSlot: new FakeEl('div'), titleText: new FakeEl('span'),
            trFiber: trPin, octFiber: { memoizedProps: {}, child: { child: { memoizedProps: { activeTaskId: 'sid-C1', isWorkspaceActive: true } } } },
            hostId: 'local', projectId: 'p1', kind: 'pinned', instanceKey: 'pinned:p1:sid-P'
          },
        ];
        A.findTaskMounts = () => mounts;
        eval(fs.readFileSync(bundlePath, 'utf8'));
        const T = global.__SS_SIDEBAR_TREE__;

        const nodes = [
          { nodeId: 'nP', parentNodeId: null, sessionId: 'sid-P', name: 'root', title: 'Mother Task', hostId: 'local', workspacePath: '/w', createdAt: '1', revision: 1, childrenUnreadTotal: 0, comm: { childrenUnreadTotal: 0 } },
          { nodeId: 'nC1', parentNodeId: 'nP', sessionId: 'sid-C1', name: 'child-1', title: 'Child 1', hostId: 'local', workspacePath: '/w', createdAt: '2', revision: 3, activeRunId: 'run-99', canCancel: true, canArchive: false, branchName: 'side/nC1', indexState: 'indexed', comm: { toParentUnread: 0 } },
          { nodeId: 'nGC1', parentNodeId: 'nC1', sessionId: 'sid-GC1', name: 'grand-1', title: 'Grandchild 1', hostId: 'local', workspacePath: '/w', createdAt: '3', revision: 2, canCancel: false, canArchive: true, indexState: 'indexed', comm: { toParentUnread: 0 } },
        ];
        T.update({ schemaVersion: 1, storeInstanceId: 'st-1', projectionRevision: 1, nodes });

        // Check unique IDs across Project and Pinned mounts
        const allIds = walkAll(navRoot).filter(e => e.id).map(e => e.id);
        const uniqueIds = new Set(allIds);
        assert.equal(allIds.length, uniqueIds.size, 'All DOM IDs must be globally unique across Pinned and Projects');
        assert.ok(allIds.some(id => id.startsWith('ss-sub-')), 'Nested sub-list IDs must start with ss-sub-');

        // Check #ss-overlay-root banner exists and does NOT show "0 条未读汇报"
        const overlay = global.document.getElementById('ss-overlay-root');
        assert.ok(overlay && !overlay.hidden, 'Overlay banner must be visible when child is active');
        assert.ok(overlay.children[0].textContent.includes('Mother Task'));
        assert.ok(overlay.children[0].textContent.includes('side/nC1'));
        assert.ok(!overlay.children[0].textContent.includes('0 条未读汇报'));

        // Check enqueueAction / drainActions / ackActions and cancel_run stripping expectedRevision
        const actCancel = T.enqueueAction('cancel_run', 'nC1');
        assert.ok(actCancel);
        assert.equal('expectedRevision' in actCancel, false, 'cancel_run must strip expectedRevision');
        const drained1 = T.drainActions();
        const drained2 = T.drainActions();
        assert.equal(drained1.length, 1);
        assert.equal(drained2.length, 1, 'drainActions must not destructively clear before ackActions');
        T.ackActions([{ actionId: actCancel.actionId, ok: true }]);
        assert.equal(T.drainActions().length, 0);

        T.destroy();
        assert.equal(global.document.querySelectorAll('[data-ss-owned]').length, 0, 'destroy() must leave zero owned nodes');
        """
        vm_run = subprocess.run([node_bin, "-e", vm_script, str(adapter_js), str(bundle_js)], capture_output=True, text=True)
        self.assertEqual(vm_run.returncode, 0, f"S4 Node VM check failed: {vm_run.stderr}")

    def test_s5_zcode_driver_fork_idle_explicitly_disabled(self) -> None:
        """S5 / FABLE-22: Verify ZCodeDriver.fork_idle preserves precondition errors then unconditionally raises CAPABILITY_UNAVAILABLE."""
        from unittest.mock import patch
        from contracts import CapabilityStatus, DriverCapabilities
        from driver import ZCodeDriver

        zdrv = ZCodeDriver()
        # 1. Precondition 1: branch workspace_mode still raises UNSUPPORTED_CONTEXT_WORKSPACE
        with self.assertRaises(SideSessionError) as ws_err:
            zdrv.fork_idle({"workspace_mode": "branch"})
        self.assertEqual(ws_err.exception.code, ErrorCode.UNSUPPORTED_CONTEXT_WORKSPACE)

        # 2. Precondition 2: parent_busy still raises UNSUPPORTED_LIVE_FORK
        with self.assertRaises(SideSessionError) as live_err:
            zdrv.fork_idle({"workspace_mode": "inherit", "parent_busy": True})
        self.assertEqual(live_err.exception.code, ErrorCode.UNSUPPORTED_LIVE_FORK)

        # 3. Even if supports_native_fork capability is forcibly enabled, ZCodeDriver.fork_idle raises CAPABILITY_UNAVAILABLE
        enabled_caps = DriverCapabilities(supports_native_fork=CapabilityStatus(True, True))
        with patch.object(zdrv, "probe", return_value=enabled_caps):
            with self.assertRaises(SideSessionError) as cap_err:
                zdrv.fork_idle({"workspace_mode": "inherit", "parent_busy": False})
            self.assertEqual(cap_err.exception.code, ErrorCode.CAPABILITY_UNAVAILABLE)
            self.assertIn("summary_copy", cap_err.exception.message)


class TestPostPhase2ComprehensiveReviewFixes(IsolatedSideSessionsTestCase):
    """Post-Phase-2 comprehensive review regression suite covering all 5 critical invariants."""

    def test_1_high_version_db_no_pollution_and_1_1_tight_budget_pretooluse_fail_closed(self) -> None:
        """1. High-version DB (9.9) open_store(initialize=True) raises VERSION_MISMATCH without mutating user_version/schema; 1.1 DB with <0.5s budget fails closed on write PreToolUse."""
        import sqlite3
        import time

        # Part A: High-version (9.9) SQLite store must not be polluted by open_store(..., initialize=True)
        high_root = self.tmp_path / "high-ver-root"
        ensure_safe_dir(high_root)
        high_db = high_root / "state.sqlite3"
        raw_conn = sqlite3.connect(str(high_db))
        try:
            raw_conn.execute("PRAGMA user_version = 99;")
            raw_conn.execute(
                """
                CREATE TABLE schema_meta (
                    id INTEGER PRIMARY KEY CHECK (id = 1) DEFAULT 1,
                    store_instance_id TEXT NOT NULL,
                    engine_schema_version TEXT NOT NULL,
                    driver_api_version TEXT NOT NULL,
                    export_version TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    maintenance_state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            raw_conn.execute(
                """
                INSERT INTO schema_meta (
                    id, store_instance_id, engine_schema_version, driver_api_version,
                    export_version, revision, maintenance_state, created_at, updated_at
                ) VALUES (1, 'inst-9-9', '9.9', '1.1', '1.1', 7, 'normal', '2026-11-10T00:00:00Z', '2026-11-10T00:00:00Z')
                """
            )
            raw_conn.commit()
        finally:
            raw_conn.close()
        os.chmod(high_db, 0o600)

        with self.assertRaises(SideSessionError) as ver_err:
            open_store(high_root, writable=True, initialize=True)
        self.assertEqual(ver_err.exception.code, ErrorCode.VERSION_MISMATCH)
        self.assertEqual(ver_err.exception.details.get("db_engine_schema_version"), "9.9")

        verify_conn = sqlite3.connect(str(high_db))
        try:
            user_ver = verify_conn.execute("PRAGMA user_version;").fetchone()[0]
            self.assertEqual(user_ver, 99, "open_store(initialize=True) must not alter PRAGMA user_version on 9.9 DB")
            tables = {
                r[0]
                for r in verify_conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            self.assertEqual(tables, {"schema_meta"}, "open_store(initialize=True) must not create/alter tables on 9.9 DB")
            meta_ver = verify_conn.execute("SELECT engine_schema_version FROM schema_meta WHERE id = 1").fetchone()[0]
            self.assertEqual(meta_ver, "9.9")
        finally:
            verify_conn.close()

        # Part B: 1.1 legacy store with tight remaining budget (<0.5s) fails closed on non-read-only PreToolUse
        legacy_root = self.tmp_path / "legacy-tight-budget-root"
        with open_store(legacy_root, writable=True, initialize=True) as st_11:
            st_11.conn.execute("UPDATE schema_meta SET engine_schema_version = '1.1' WHERE id = 1")
            st_11.conn.execute("UPDATE store_meta SET engine_schema_version = '1.1' WHERE id = 1")
            st_11.conn.execute("PRAGMA user_version = 1;")

        env = {
            **os.environ,
            "ZCODE_SIDE_SESSIONS_HOME": str(legacy_root),
            "ZCODE_HOST_DB_PATH": str(self.host_db_path),
        }
        out_tight = io.StringIO()
        err_tight = io.StringIO()
        rc_tight = hook_main(
            stdin=json.dumps(
                {
                    "session_id": "sid-tight-budget-11",
                    "hook_event_name": "PreToolUse",
                    "cwd": str(self.workspace_dir),
                    "tool_name": "Bash",
                }
            ),
            stdout=out_tight,
            stderr=err_tight,
            environ=env,
            deadline_monotonic=time.monotonic() + 0.3,
        )
        self.assertEqual(rc_tight, 0, f"Hook stderr: {err_tight.getvalue()}")
        raw_line = out_tight.getvalue().strip()
        self.assertTrue(raw_line, "Tight-budget 1.1 PreToolUse for Bash must emit fail-closed JSON")
        parsed_out = json.loads(raw_line)
        validated_out = validate_hook_output("PreToolUse", parsed_out)
        self.assertIs(validated_out["continue"], False)
        self.assertIn("VERSION_MISMATCH", validated_out["additionalContext"])

        # Confirm DB remained 1.1 (did not attempt migration under <0.5s budget)
        chk_conn = sqlite3.connect(str(legacy_root / "state.sqlite3"))
        try:
            self.assertEqual(
                chk_conn.execute("SELECT engine_schema_version FROM schema_meta WHERE id = 1").fetchone()[0],
                "1.1",
            )
        finally:
            chk_conn.close()

    def test_2_ordinary_chat_prompt_cannot_self_approve_permission_wait(self) -> None:
        """2. Ordinary human_prompt cannot approve permission wait (with or without input_id); /side-sessions:respond Hook succeeds."""
        st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Permission Guard Child",
                "prompt": "Run task needing permission.",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "perm-guard-child",
            },
        )
        child_id = st["node_id"]
        run_id = st["run_id"]
        child_sid = st["runtime_session_id"]

        self.driver.queue_event(
            child_sid,
            {
                "kind": "wait_request",
                "runtime_turn_id": f"rturn:{run_id[:8]}",
                "wait_request": {
                    "host_request_id": "host-perm-guard-1",
                    "kind": "permission",
                    "nonce": "nonce-perm-guard-1",
                    "question": "Allow privileged command?",
                    "options": ["allow", "deny"],
                    "required_authority": "human",
                },
            },
        )

        runner = WorkerRunner(
            self.store,
            engine=self.engine,
            driver=self.driver,
            host_adapter=self.host_adapter,
            wait_poll_timeout_ms=250,
        )

        def _on_wait(_assignment: Any, _handle: Any) -> None:
            waits_res = self.engine.list_waits(self.parent_caller, {"session_id": child_id})
            self.assertEqual(len(waits_res["waits"]), 1)
            wait_id = waits_res["waits"][0]["wait_id"]

            # Simulate an ordinary user chat prompt in parent session (origin='human_prompt', no slash command_id / action_binding)
            chat_turn_id = "turn-ordinary-chat-1"
            self.engine.handle_hook(
                HookContext(
                    event="UserPromptSubmit",
                    invocation_id=str(uuid.uuid4()),
                    runtime_sid=self.parent_caller.runtime_sid,
                    cwd=str(self.workspace_dir),
                    runtime_turn_id=chat_turn_id,
                    raw_input={
                        "prompt": "子会话怎么停住了？帮我看看情况",
                        "input_id": chat_turn_id,
                        "origin": "human_prompt",
                    },
                )
            )
            prov_row = self.store.conn.execute(
                "SELECT origin, command_id, action_binding_json, verified FROM input_provenance WHERE input_id = ?",
                (chat_turn_id,),
            ).fetchone()
            self.assertIsNotNone(prov_row)
            self.assertEqual(prov_row["origin"], "human_prompt")
            self.assertIsNone(prov_row["command_id"])
            self.assertFalse(prov_row["action_binding_json"])

            chat_caller = CallerContext(
                runtime_sid=self.parent_caller.runtime_sid,
                runtime_turn_id=chat_turn_id,
                workspace_path=str(self.workspace_dir),
                connection_id="stdio:test-main",
            )

            # (a) Calling respond_to_wait in the same turn WITHOUT input_id -> blocked by USER_APPROVAL_REQUIRED
            with self.assertRaises(SideSessionError) as no_inp_err:
                self.engine.respond_to_wait(
                    chat_caller,
                    {
                        "request_id": str(uuid.uuid4()),
                        "wait_id": wait_id,
                        "nonce": "nonce-perm-guard-1",
                        "response": {"kind": "permission", "option_id": "allow", "decision": "allow"},
                    },
                )
            self.assertEqual(str(no_inp_err.exception.code), "USER_APPROVAL_REQUIRED")

            # (b) Calling respond_to_wait explicitly passing ordinary chat's input_id -> still blocked by USER_APPROVAL_REQUIRED
            with self.assertRaises(SideSessionError) as with_inp_err:
                self.engine.respond_to_wait(
                    chat_caller,
                    {
                        "request_id": str(uuid.uuid4()),
                        "wait_id": wait_id,
                        "nonce": "nonce-perm-guard-1",
                        "response": {"kind": "permission", "option_id": "allow", "decision": "allow"},
                        "input_id": chat_turn_id,
                        "real_input_id": chat_turn_id,
                    },
                )
            self.assertEqual(str(with_inp_err.exception.code), "USER_APPROVAL_REQUIRED")

            # (c) Approving via `/side-sessions:respond <wait_id> allow` Hook path succeeds
            slash_hook_out = self.engine.handle_hook(
                HookContext(
                    event="UserPromptSubmit",
                    invocation_id=str(uuid.uuid4()),
                    runtime_sid=self.parent_caller.runtime_sid,
                    cwd=str(self.workspace_dir),
                    runtime_turn_id="turn-slash-respond-ok",
                    raw_input={
                        "prompt": f"/side-sessions:respond {wait_id} allow",
                        "input_id": "inp-slash-respond-ok",
                    },
                )
            )
            self.assertIsNotNone(slash_hook_out)
            self.assertIn("[side-sessions:respond]", slash_hook_out["additionalContext"])

            self.driver.queue_event(
                child_sid,
                {
                    "kind": "turn.terminal",
                    "runtime_turn_id": f"rturn:{run_id[:8]}",
                    "outcome": "success",
                },
            )

        runner.on_wait = _on_wait
        run_out = runner.run_node(child_id, once=True)
        self.assertTrue(run_out["ok"])
        self.assertEqual(len(self.driver.wait_responses), 1)
        self.assertEqual(self.driver.wait_responses[0]["response"]["decision"], "allow")

    def test_3_worktree_fallback_identity_and_ignored_prefix_collision_guard(self) -> None:
        """3. merge_worktree (merge/squash) succeeds with fallback identity when global git user.name/email are stripped; ignored path prefix collisions are blocked."""
        from unittest.mock import patch

        repo_dir = self.tmp_path / "fallback-id-and-ignore-repo"
        _init_temp_git_repo(repo_dir)
        # Commit .gitignore rules up front so parent baseline stays clean when ignored artifacts exist
        (repo_dir / ".gitignore").write_text("build/out.bin\ndist\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo_dir), "add", ".gitignore"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "Add gitignore"], check=True, capture_output=True)

        git_caller = CallerContext(
            runtime_sid="sid-parent-wt-review",
            runtime_turn_id="turn-wt-review-1",
            workspace_path=str(repo_dir),
            connection_id="stdio:wt-review",
        )

        # --- Part A: Fallback git identity on merge & squash when local + global git identity are completely absent ---
        st_merge = self.engine.start_session(
            git_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Fallback Merge Child",
                "prompt": "Add mod_merge.py",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "write_code",
                "use_worktree": True,
                "name": "fb-merge",
            },
        )
        self._close_child_run(st_merge)
        wt_merge = Path(
            self.store.conn.execute(
                "SELECT canonical_worktree_path FROM worktrees WHERE node_id = ?",
                (st_merge["node_id"],),
            ).fetchone()["canonical_worktree_path"]
        )
        (wt_merge / "mod_merge.py").write_text("M = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(wt_merge), "add", "mod_merge.py"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(wt_merge), "commit", "-m", "Child mod_merge"], check=True, capture_output=True)

        # Advance parent so `merge` mode creates a real 2-parent merge commit via commit-tree
        (repo_dir / "parent_advance.txt").write_text("parent\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo_dir), "add", "parent_advance.txt"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "Parent advance"], check=True, capture_output=True)

        st_squash = self.engine.start_session(
            git_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Fallback Squash Child",
                "prompt": "Add mod_squash.py",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "write_code",
                "use_worktree": True,
                "name": "fb-squash",
            },
        )
        self._close_child_run(st_squash)
        wt_squash = Path(
            self.store.conn.execute(
                "SELECT canonical_worktree_path FROM worktrees WHERE node_id = ?",
                (st_squash["node_id"],),
            ).fetchone()["canonical_worktree_path"]
        )
        (wt_squash / "mod_squash.py").write_text("S = 2\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(wt_squash), "add", "mod_squash.py"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(wt_squash), "commit", "-m", "Child mod_squash"], check=True, capture_output=True)

        # Strip local repo user.name / user.email and isolate HOME + XDG_CONFIG_HOME + GIT_AUTHOR_*/GIT_COMMITTER_*
        subprocess.run(["git", "-C", str(repo_dir), "config", "--unset-all", "user.name"], check=False, capture_output=True)
        subprocess.run(["git", "-C", str(repo_dir), "config", "--unset-all", "user.email"], check=False, capture_output=True)
        empty_home = self.tmp_path / "empty-git-home"
        empty_home.mkdir(parents=True, exist_ok=True)
        stripped_env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL")
        }
        stripped_env["HOME"] = str(empty_home)
        stripped_env["XDG_CONFIG_HOME"] = str(empty_home)

        with patch.dict(os.environ, stripped_env, clear=True):
            # Confirm git indeed has no configured user.name or user.email
            chk_name = worktree._run_git(repo_dir, ["config", "--get", "user.name"], isolated=True)
            self.assertNotEqual(chk_name.returncode, 0)

            diff_m = self.engine.diff_worktree(git_caller, {"session_id": st_merge["node_id"]})
            self.assertTrue(diff_m["merge_eligible"])
            self._trust_human("inp-fb-merge-1", command_id="/side-sessions:merge", runtime_sid=git_caller.runtime_sid)
            res_m = self.engine.merge_worktree(
                git_caller,
                {
                    "session_id": st_merge["node_id"],
                    "preview_hash": diff_m["preview_hash"],
                    "mode": "merge",
                    "real_input_id": "inp-fb-merge-1",
                    "command_id": "/side-sessions:merge",
                },
                execute_now=True,
            )
            self.assertTrue(res_m["ok"])
            self.assertEqual(res_m["status"], "merged")
            log_m = subprocess.run(
                ["git", "-C", str(repo_dir), "log", "-1", "--format=%an <%ae>"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertEqual(log_m, "side-sessions <side-sessions@localhost>")

            diff_s = self.engine.diff_worktree(git_caller, {"session_id": st_squash["node_id"]})
            self.assertTrue(diff_s["merge_eligible"])
            self._trust_human("inp-fb-squash-1", command_id="/side-sessions:merge", runtime_sid=git_caller.runtime_sid)
            res_s = self.engine.merge_worktree(
                git_caller,
                {
                    "session_id": st_squash["node_id"],
                    "preview_hash": diff_s["preview_hash"],
                    "mode": "squash",
                    "real_input_id": "inp-fb-squash-1",
                    "command_id": "/side-sessions:merge",
                },
                execute_now=True,
            )
            self.assertTrue(res_s["ok"])
            self.assertEqual(res_s["status"], "merged")
            log_s = subprocess.run(
                ["git", "-C", str(repo_dir), "log", "-1", "--format=%an <%ae>"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertEqual(log_s, "side-sessions <side-sessions@localhost>")

        # Restore repo-local git identity for preparing collision child commits cleanly
        subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "Test"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "test@local"], check=True, capture_output=True)

        # --- Part B1: Parent has ignored file `build/out.bin` while child branch adds file `build` ---
        st_col1 = self.engine.start_session(
            git_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Prefix Collision Child 1",
                "prompt": "Add file build",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "write_code",
                "use_worktree": True,
                "name": "col-build-file",
            },
        )
        self._close_child_run(st_col1)
        wt_col1 = Path(
            self.store.conn.execute(
                "SELECT canonical_worktree_path FROM worktrees WHERE node_id = ?",
                (st_col1["node_id"],),
            ).fetchone()["canonical_worktree_path"]
        )
        (wt_col1 / "build").write_text("file-replacing-dir\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(wt_col1), "add", "build"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(wt_col1), "commit", "-m", "Add build as regular file"], check=True, capture_output=True)

        (repo_dir / "build").mkdir(parents=True, exist_ok=True)
        (repo_dir / "build" / "out.bin").write_bytes(b"\x89BIN")

        diff_col1 = self.engine.diff_worktree(git_caller, {"session_id": st_col1["node_id"]})
        self.assertFalse(diff_col1["merge_eligible"])
        self.assertEqual(diff_col1["merge_block_reason"], ErrorCode.DIRTY_SOURCE.value)

        self._trust_human("inp-col-1", command_id="/side-sessions:merge", runtime_sid=git_caller.runtime_sid)
        with self.assertRaises(SideSessionError) as col1_err:
            self.engine.merge_worktree(
                git_caller,
                {
                    "session_id": st_col1["node_id"],
                    "preview_hash": diff_col1["preview_hash"],
                    "mode": "merge",
                    "real_input_id": "inp-col-1",
                    "command_id": "/side-sessions:merge",
                },
                execute_now=True,
            )
        self.assertEqual(col1_err.exception.code, ErrorCode.DIRTY_SOURCE)
        self.assertIn("build/out.bin", col1_err.exception.details.get("conflicting_ignored", []))
        self.assertTrue((repo_dir / "build" / "out.bin").is_file())
        # Clean up build/out.bin before testing reverse direction
        (repo_dir / "build" / "out.bin").unlink()
        (repo_dir / "build").rmdir()

        # --- Part B2: Parent has ignored regular file `dist` while child branch adds `dist/app.js` ---
        st_col2 = self.engine.start_session(
            git_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Prefix Collision Child 2",
                "prompt": "Add dist/app.js",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "write_code",
                "use_worktree": True,
                "name": "col-dist-dir",
            },
        )
        self._close_child_run(st_col2)
        wt_col2 = Path(
            self.store.conn.execute(
                "SELECT canonical_worktree_path FROM worktrees WHERE node_id = ?",
                (st_col2["node_id"],),
            ).fetchone()["canonical_worktree_path"]
        )
        (wt_col2 / "dist").mkdir(parents=True, exist_ok=True)
        (wt_col2 / "dist" / "app.js").write_text("console.log(1);\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(wt_col2), "add", "-f", "dist/app.js"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(wt_col2), "commit", "-m", "Add dist/app.js"], check=True, capture_output=True)

        (repo_dir / "dist").write_text("ignored-regular-file\n", encoding="utf-8")

        diff_col2 = self.engine.diff_worktree(git_caller, {"session_id": st_col2["node_id"]})
        self.assertFalse(diff_col2["merge_eligible"])
        self.assertEqual(diff_col2["merge_block_reason"], ErrorCode.DIRTY_SOURCE.value)

        self._trust_human("inp-col-2", command_id="/side-sessions:merge", runtime_sid=git_caller.runtime_sid)
        with self.assertRaises(SideSessionError) as col2_err:
            self.engine.merge_worktree(
                git_caller,
                {
                    "session_id": st_col2["node_id"],
                    "preview_hash": diff_col2["preview_hash"],
                    "mode": "squash",
                    "real_input_id": "inp-col-2",
                    "command_id": "/side-sessions:merge",
                },
                execute_now=True,
            )
        self.assertEqual(col2_err.exception.code, ErrorCode.DIRTY_SOURCE)
        self.assertIn("dist", col2_err.exception.details.get("conflicting_ignored", []))
        self.assertTrue((repo_dir / "dist").is_file())

    def test_4_legacy_asar_patch_manifest_self_healing_migration(self) -> None:
        """4. Legacy asar_patch.json with only origSha/abs/orig self-heals patchedSha/patchLen/patched (mode 0600) in resolve_build_entry."""
        import struct
        from unittest.mock import patch
        import asar_cdp_patch

        fake_app = self.tmp_path / "LegacyHealZCode.app"
        res_dir = fake_app / "Contents" / "Resources"
        fw_dir = fake_app / "Contents" / "Frameworks" / "Electron Framework.framework"
        res_dir.mkdir(parents=True, exist_ok=True)
        fw_dir.mkdir(parents=True, exist_ok=True)
        (fw_dir / "Electron Framework").write_bytes((b"\x00" * 64) + b"\x01\x09101100011" + (b"\x00" * 64))

        lead = b"/* header-pad */" * 3
        js_body = (
            b'"use strict";'
            b'!app.isPackaged&&process.env.ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT!=="1"&&'
            b'app.commandLine.appendSwitch("remote-debugging-port","9229");'
        )
        hdr_obj = {
            "files": {
                "out": {
                    "files": {
                        "main": {
                            "files": {
                                "index.js": {
                                    "size": len(js_body),
                                    "offset": str(len(lead)),
                                    "integrity": {"hash": sha256_hex(js_body)},
                                }
                            }
                        }
                    }
                }
            }
        }
        hdr_json = json.dumps(hdr_obj, separators=(",", ":")).encode("utf-8")
        jlen = len(hdr_json)
        pad = (4 - (jlen % 4)) % 4
        payload_sz = 4 + jlen + pad
        hdr_sz = payload_sz + 4
        asar_hdr = struct.pack("<4I", 4, hdr_sz, payload_sz, jlen) + hdr_json + (b"\x00" * pad)

        fake_asar = res_dir / "app.asar"
        orig_asar_bytes = asar_hdr + lead + js_body
        fake_asar.write_bytes(orig_asar_bytes)
        orig_sha = sha256_hex(orig_asar_bytes)
        builds = {orig_sha: {"version": "3.17.2", "adapter": "zcode-3.17.2", "fuseWireOffset": 64}}

        manifest_p = self.state_root / "sidebar-ui" / "backups" / "asar_patch.json"
        with patch.object(asar_cdp_patch, "codesign_ok", return_value=False):
            app_res = asar_cdp_patch.apply(builds[orig_sha], manifest_p, app_path=fake_app, builds=builds)
            self.assertTrue(app_res["ok"])

        full_manifest = json.loads(manifest_p.read_text(encoding="utf-8"))
        expected_patched_sha = app_res["patchedSha"]
        expected_patched_str = full_manifest["patched"]

        # Rewrite manifest_p to legacy format: ONLY origSha, abs, orig (missing patchedSha, patchLen, patched)
        legacy_manifest = {
            "origSha": orig_sha,
            "abs": int(full_manifest["abs"]),
            "orig": str(full_manifest["orig"]),
        }
        manifest_p.write_text(json.dumps(legacy_manifest, indent=2), encoding="utf-8")
        os.chmod(manifest_p, 0o600)

        resolved, cur_sha, err = asar_cdp_patch.resolve_build_entry(fake_asar, manifest_p, builds)
        self.assertIsNone(err)
        self.assertEqual(cur_sha, expected_patched_sha)
        self.assertEqual(resolved, builds[orig_sha])

        st_mode = stat.S_IMODE(manifest_p.stat().st_mode)
        self.assertEqual(st_mode, 0o600)
        healed = json.loads(manifest_p.read_text(encoding="utf-8"))
        self.assertEqual(healed["origSha"], orig_sha)
        self.assertEqual(healed["patchedSha"], expected_patched_sha)
        self.assertEqual(healed["patchLen"], len(legacy_manifest["orig"].encode("latin-1")))
        self.assertEqual(healed["patched"], expected_patched_str)
        self.assertEqual(healed["patchedSliceSha"], sha256_hex(expected_patched_str.encode("latin-1")))

        # Verify sidebar_ui_ctl._launchctl_bootout_wait waits until launchctl print returns non-zero before bootstrap
        import sidebar_ui_ctl

        calls: list[list[str]] = []
        print_rcs = [0, 0, 113]

        def _fake_lc_run(cmd: list[str], **_kw: Any) -> subprocess.CompletedProcess[str]:
            calls.append(list(cmd))
            if len(cmd) >= 2 and cmd[1] == "print":
                rc = print_rcs.pop(0) if print_rcs else 113
                return subprocess.CompletedProcess(cmd, rc, "", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.object(sidebar_ui_ctl.subprocess, "run", side_effect=_fake_lc_run):
            with patch.object(sidebar_ui_ctl.time, "sleep"):
                sidebar_ui_ctl._launchctl_bootout_wait(502, "com.zcode.side-sessions")
        self.assertEqual(calls[0][:2], ["/bin/launchctl", "bootout"])
        self.assertEqual(sum(1 for c in calls if c[1] == "print"), 3)

    def test_5_real_zcode_3_17_2_conversation_frame_dom_and_ui_interaction_robustness(self) -> None:
        """5. Node VM verification of conversation-frame + 48px header Banner offset (56px), hidden on non-chat view, ackActions error unlock, and external copy_respond sibling button."""
        import shutil

        node_bin = shutil.which("node") or "/opt/homebrew/opt/node@22/bin/node"
        adapter_js = PLUGIN_ROOT / "ui" / "adapters" / "zcode-3.17.2.js"
        bundle_js = PLUGIN_ROOT / "ui" / "sidebar_tree_bundle.js"

        vm_script = """
        const assert = require('node:assert/strict');
        const fs = require('node:fs');
        const [adapterPath, bundlePath] = process.argv.slice(1);

        function walkAll(root, out = []) {
          for (const c of root.children || []) {
            if (c && c.nodeType === 1) {
              out.push(c);
              walkAll(c, out);
            }
          }
          return out;
        }

        class FakeEl {
          constructor(tag = 'div', rect = { top: 0, bottom: 720, left: 260, right: 1160, width: 900, height: 720 }) {
            this.tagName = tag.toUpperCase();
            this.nodeType = 1;
            this.className = '';
            this.id = '';
            this.hidden = false;
            this.disabled = false;
            this.draggable = false;
            this.textContent = '';
            this.title = '';
            this.value = '';
            this._rect = rect;
            this.attributes = new Map();
            this.children = [];
            this.parentElement = null;
            this.isConnected = true;
            this.listeners = {};
            this.style = { props: {}, setProperty(k, v) { this.props[k] = v; this[k] = v; } };
            this.classList = { contains: (c) => this.className.split(/\\s+/).filter(Boolean).includes(c) };
          }
          setAttribute(k, v) { this.attributes.set(k, String(v)); }
          getAttribute(k) { return this.attributes.has(k) ? this.attributes.get(k) : null; }
          hasAttribute(k) { return this.attributes.has(k); }
          removeAttribute(k) { this.attributes.delete(k); }
          append(...nodes) {
            for (const n of nodes) {
              if (typeof n === 'object' && n) { n.parentElement = this; this.children.push(n); }
            }
          }
          appendChild(n) { this.append(n); return n; }
          replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
          replaceWith(other) {
            if (this.parentElement && other) {
              const i = this.parentElement.children.indexOf(this);
              if (i !== -1) { other.parentElement = this.parentElement; this.parentElement.children[i] = other; this.parentElement = null; }
            }
          }
          remove() {
            if (this.parentElement) {
              this.parentElement.children = this.parentElement.children.filter(x => x !== this);
              this.parentElement = null;
            }
          }
          get lastElementChild() { return this.children[this.children.length - 1] || null; }
          contains(other) { return other === this || this.children.some(c => c.contains && c.contains(other)); }
          closest() { return null; }
          querySelector(sel) {
            if (sel === ':scope > header' || sel === 'header') {
              return this.children.find(c => c.tagName === 'HEADER') || null;
            }
            if (sel === 'ul') return this.children.find(c => c.tagName === 'UL') || null;
            if (sel === '.ss-sr') return this.children.find(c => c.className === 'ss-sr') || null;
            if (sel === ':scope > .ss-tree-chevron') return this.children.find(c => c.classList.contains('ss-tree-chevron')) || null;
            if (sel.includes('.ss-comm-badge--parent')) return this.children.find(c => c.classList.contains('ss-comm-badge--parent')) || null;
            return null;
          }
          querySelectorAll(sel) {
            if (sel === ':scope > .ss-tree-chevron') return this.children.filter(c => c.classList.contains('ss-tree-chevron'));
            return [];
          }
          addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
          removeEventListener() {}
          dispatchClick() {
            const ev = { stopPropagation() {}, preventDefault() {} };
            for (const fn of (this.listeners.click || [])) fn(ev);
          }
          getBoundingClientRect() { return this._rect; }
        }

        const headEl = new FakeEl('head');
        const bodyEl = new FakeEl('body');
        const navRoot = new FakeEl('aside', { top: 0, bottom: 720, left: 0, right: 260, width: 260, height: 720 });
        const convSection = new FakeEl('section', { top: 0, bottom: 720, left: 260, right: 1160, width: 900, height: 720 });
        convSection.setAttribute('data-workspace-conversation-frame', 'true');
        const convHeader = new FakeEl('header', { top: 0, bottom: 48, left: 260, right: 1160, width: 900, height: 48 });
        convSection.append(convHeader);
        bodyEl.append(navRoot, convSection);

        const winListeners = {};
        let clipboardText = null;
        global.Element = FakeEl;
        global.window = global;
        Object.defineProperty(global, 'navigator', {
          value: {
            clipboard: {
              writeText: async (txt) => { clipboardText = txt; },
            },
          },
          configurable: true,
          writable: true,
        });
        global.addEventListener = (ev, fn) => { (winListeners[ev] = winListeners[ev] || []).push(fn); };
        global.removeEventListener = () => {};
        global.localStorage = { getItem() { return null; }, setItem() {}, removeItem() {} };
        global.MutationObserver = class { observe() {} disconnect() {} };
        global.ResizeObserver = class { observe() {} disconnect() {} };
        global.requestAnimationFrame = (fn) => { fn(); return 1; };
        global.cancelAnimationFrame = () => {};
        global.document = {
          hidden: false,
          readyState: 'complete',
          head: headEl,
          body: bodyEl,
          documentElement: headEl,
          activeElement: null,
          createElement: (t) => new FakeEl(t),
          createTextNode: (t) => ({ nodeType: 3, textContent: String(t) }),
          getElementById: (id) => [...walkAll(headEl), ...walkAll(bodyEl)].find(e => e.id === id) || null,
          querySelector: (sel) => {
            if (sel === '[data-project-sidebar-panel="navigation"]') return navRoot;
            if (sel === 'section[data-workspace-conversation-frame="true"]') return convSection;
            return null;
          },
          querySelectorAll: (sel) => {
            if (sel === 'section[data-workspace-conversation-frame="true"]') return [convSection];
            if (sel === '[data-ss-owned]') return [...walkAll(headEl), ...walkAll(bodyEl)].filter(e => e.hasAttribute('data-ss-owned'));
            return [];
          },
          addEventListener: () => {},
          removeEventListener: () => {},
        };

        eval(fs.readFileSync(adapterPath, 'utf8'));
        const A = global.__SS_ZCODE_ADAPTER__;
        const trProj = { memoizedProps: { kind: 'project', tasks: [], onSelect: () => {} } };
        const wProj = new FakeEl('div', { top: 60, bottom: 90, left: 12, right: 248, width: 236, height: 30 });
        navRoot.append(wProj);
        A.findTaskMounts = () => [
          {
            taskId: 'sid-P', wrapper: wProj, row: new FakeEl('li'), titleSlot: new FakeEl('div'),
            titleText: new FakeEl('span', { top: 60, bottom: 80, left: 38, right: 200, width: 162, height: 20 }),
            trFiber: trProj,
            octFiber: { memoizedProps: {}, child: { child: { memoizedProps: { activeTaskId: 'sid-C1', isWorkspaceActive: true } } } },
            hostId: 'local', projectId: 'p1', kind: 'project', instanceKey: 'proj:p1:sid-P',
          },
        ];

        eval(fs.readFileSync(bundlePath, 'utf8'));
        const T = global.__SS_SIDEBAR_TREE__;

        const nodes = [
          { nodeId: 'nP', parentNodeId: null, sessionId: 'sid-P', name: 'root', title: 'Mother Session', hostId: 'local', workspacePath: '/w', createdAt: '1', revision: 1, childrenUnreadTotal: 0, comm: { childrenUnreadTotal: 0 } },
          {
            nodeId: 'nC1', parentNodeId: 'nP', sessionId: 'sid-C1', name: 'worker-1', title: 'Child Worker',
            hostId: 'local', workspacePath: '/w', createdAt: '2', revision: 4,
            activeRunId: 'run-77', canCancel: true, canArchive: false,
            waitingInput: true, activeWaitId: 'wait-perm-999', waitingInputKind: 'permission',
            indexState: 'indexed', comm: { toParentUnread: 0, waitingInput: true },
          },
        ];
        T.update({ schemaVersion: 1, storeInstanceId: 'st-review', projectionRevision: 1, nodes });

        // (1) Verify Parent Banner top = headerRect.bottom + 8 = 48 + 8 = 56px (does not cover 48px header)
        const overlay = global.document.getElementById('ss-overlay-root');
        assert.ok(overlay, 'Overlay root must be created');
        assert.equal(overlay.hidden, false, 'Overlay must be visible on active child conversation frame');
        assert.equal(overlay.style.top, '56px', 'Parent Banner must sit at headerRect.bottom (48) + 8 = 56px');

        // (2) Hide conversation section (simulating switch to plugin-store) -> overlay.hidden === true
        convSection.hidden = true;
        for (const fn of (winListeners.resize || [])) fn();
        assert.equal(overlay.hidden, true, 'Overlay must hide when conversation frame section is hidden');

        // Restore conversation section visibility -> overlay becomes visible again at 56px
        convSection.hidden = false;
        for (const fn of (winListeners.resize || [])) fn();
        assert.equal(overlay.hidden, false);
        assert.equal(overlay.style.top, '56px');

        // (3) Verify waitingInput && activeWaitId renders external sibling copy button (not nested inside .ss-child-link)
        const allNavEls = walkAll(wProj);
        const childRow = allNavEls.find(e => e.classList.contains('ss-child-row'));
        const childLink = allNavEls.find(e => e.classList.contains('ss-child-link'));
        const copyBtn = allNavEls.find(e => e.getAttribute('data-ss-action') === 'copy_respond');
        assert.ok(childRow && childLink && copyBtn, 'Child row, child link, and copy_respond button must exist');
        assert.equal( childLink.contains(copyBtn), false, 'copy_respond button must NOT be nested inside .ss-child-link');
        assert.equal(copyBtn.parentElement.parentElement, childRow, 'copy_respond action group must be an external sibling in .ss-child-row');
        assert.equal(copyBtn.textContent, '批权限');
        copyBtn.dispatchClick();
        // Wait for async copyTextWithFallback promise chain to settle
        (async () => {
          await new Promise(r => setTimeout(r, 20));
          assert.equal(clipboardText, '/side-sessions:respond wait-perm-999 ');
          assert.equal(copyBtn.textContent, '已复制 ✓');

          // (4) Verify ackActions([{actionId, ok: false, code: 'SESSION_BUSY', message: 'busy'}]) records error tip and unlocks button
          const cancelBtnBefore = walkAll(wProj).find(e => e.getAttribute('data-ss-action') === 'cancel_run');
          assert.ok(cancelBtnBefore && !cancelBtnBefore.disabled);
          const queuedAct = T.enqueueAction('cancel_run', 'nC1');
          assert.ok(queuedAct);
          const cancelBtnLocked = walkAll(wProj).find(e => e.getAttribute('data-ss-action') === 'cancel_run');
          assert.equal(cancelBtnLocked.disabled, true, 'Button must lock while action is in flight');

          const ackRes = T.ackActions([{ actionId: queuedAct.actionId, ok: false, code: 'SESSION_BUSY', message: 'busy' }]);
          assert.equal(ackRes.acked, 1);
          assert.equal(ackRes.remaining, 0);

          const cancelBtnUnlocked = walkAll(wProj).find(e => e.getAttribute('data-ss-action') === 'cancel_run');
          assert.equal(cancelBtnUnlocked.disabled, false, 'Button must unlock after failed ackActions');
          assert.ok(cancelBtnUnlocked.title.includes('SESSION_BUSY') && cancelBtnUnlocked.title.includes('busy'));
          const errPill = walkAll(wProj).find(e => e.classList.contains('ss-action-err-pill'));
          assert.ok(errPill, 'Error pill must render after failed ackActions');
          assert.equal(errPill.textContent, 'SESSION_BUSY');
          assert.ok(errPill.title.includes('busy'));

          T.destroy();
          assert.equal(global.document.querySelectorAll('[data-ss-owned]').length, 0);
        })().catch(err => {
          console.error(err);
          process.exit(1);
        });
        """
        vm_proc = subprocess.run([node_bin, "-e", vm_script, str(adapter_js), str(bundle_js)], capture_output=True, text=True)
        self.assertEqual(vm_proc.returncode, 0, f"Post-Phase-2 Node VM check failed: {vm_proc.stderr}")


class TestClaudeDesktop365562AlignmentAndPortability(IsolatedSideSessionsTestCase):
    """Regression suite for A1 (/side-sessions:cleanup), A2 (sidebar branch/state badges), A3 (SKILL.md rules), PORT-1 (run_py311.sh), and PORT-2 (path portability)."""

    def test_a1_slash_cleanup_merged_unmerged_branch_retained_and_dirty_rejected(self) -> None:
        """Verify /side-sessions:cleanup for merged follow-up, unmerged clean branch-retention, and dirty retained_dirty."""
        from contracts import READ_ONLY_CONTROL_ALLOWLIST

        self.assertNotIn("enqueue_cleanup_worktree_job", ALLOWED_ENGINE_TOOLS)
        self.assertNotIn("enqueue_cleanup_worktree_job", READ_ONLY_CONTROL_ALLOWLIST)

        repo_dir = self.tmp_path / "a1-cleanup-repo"
        _init_temp_git_repo(repo_dir)
        git_caller = CallerContext(
            runtime_sid="sid-parent-cleanup",
            runtime_turn_id="turn-cleanup-0",
            workspace_path=str(repo_dir),
            connection_id="stdio:cleanup",
        )

        kicked_events: list[dict[str, Any]] = []

        class _FakeKicker:
            def wake(self, payload: Any = None) -> None:
                kicked_events.append(dict(payload or {}))

        self.engine.supervisor_port = _FakeKicker()

        # 0. Arity validation: 0 args or 2 args must fail with INVALID_REQUEST in Hook feedback
        for idx, bad_prompt in enumerate(("/side-sessions:cleanup", "/side-sessions:cleanup s1 s2")):
            bad_out = self.engine.handle_hook(
                HookContext(
                    event="UserPromptSubmit",
                    invocation_id=str(uuid.uuid4()),
                    runtime_sid=git_caller.runtime_sid,
                    cwd=str(repo_dir),
                    runtime_turn_id=f"turn-bad-{idx}",
                    raw_input={"prompt": bad_prompt, "input_id": f"inp-bad-{idx}"},
                )
            )
            self.assertIsNotNone(bad_out)
            self.assertIn("[side-sessions:cleanup:error] [INVALID_REQUEST]", bad_out["additionalContext"])

        # 1. Merged child (merge without --cleanup) -> standalone /side-sessions:cleanup <short-name> removes worktree & branch
        st_merged = self.engine.start_session(
            git_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Merged Child",
                "prompt": "Add merged_mod.py",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "write_code",
                "use_worktree": True,
                "name": "clean-merged",
            },
        )
        self._close_child_run(st_merged)
        m_id = st_merged["node_id"]
        m_row = self.store.conn.execute("SELECT * FROM worktrees WHERE node_id = ?", (m_id,)).fetchone()
        m_wt = Path(m_row["canonical_worktree_path"])
        m_branch = str(m_row["branch"])
        (m_wt / "merged_mod.py").write_text("MERGED = True\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(m_wt), "add", "merged_mod.py"], check=True)
        subprocess.run(["git", "-C", str(m_wt), "commit", "-m", "Add merged_mod"], check=True, capture_output=True)

        diff_m = self.engine.diff_worktree(git_caller, {"session_id": m_id})
        self._trust_human("inp-pre-merge", command_id="/side-sessions:merge", runtime_sid=git_caller.runtime_sid)
        merge_res = self.engine.merge_worktree(
            git_caller,
            {
                "session_id": m_id,
                "preview_hash": diff_m["preview_hash"],
                "mode": "merge",
                "cleanup_after": False,
                "real_input_id": "inp-pre-merge",
                "command_id": "/side-sessions:merge",
            },
            execute_now=True,
        )
        self.assertTrue(merge_res["ok"])
        self.assertTrue(m_wt.exists())

        # Verify ProjectionReader preserves 'retained_dirty' even when merged_commit is non-empty
        from desktop_bridge import ProjectionReader

        (m_wt / "post_merge_dirty.tmp").write_text("untracked after merge\n", encoding="utf-8")
        hook_m_dirty = self.engine.handle_hook(
            HookContext(
                event="UserPromptSubmit",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=git_caller.runtime_sid,
                cwd=str(repo_dir),
                runtime_turn_id="turn-clean-merged-dirty",
                raw_input={"prompt": "/side-sessions:cleanup clean-merged", "input_id": "inp-clean-merged-dirty"},
            )
        )
        self.assertIsNotNone(hook_m_dirty)
        runner = WorkerRunner(self.store, engine=self.engine, driver=self.driver, host_adapter=self.host_adapter)
        res_m_dirty_list = runner._process_worktree_jobs()
        self.assertEqual(len(res_m_dirty_list), 1)
        self.assertFalse(res_m_dirty_list[0]["cleaned"])
        self.assertEqual(res_m_dirty_list[0]["state"], "retained_dirty")

        proj_reader = ProjectionReader(
            self.state_root,
            cli_db_path=self.host_db_path,
            tasks_index_path=self.tmp_path / "tasks-index.sqlite",
            persist_export=False,
        )
        try:
            proj_snap = proj_reader.snapshot()
        finally:
            proj_reader.close()
        m_proj_node = next(n for n in proj_snap["nodes"] if n["nodeId"] == m_id)
        self.assertEqual(m_proj_node["worktreeState"], "retained_dirty")

        (m_wt / "post_merge_dirty.tmp").unlink()

        hook_m = self.engine.handle_hook(
            HookContext(
                event="UserPromptSubmit",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=git_caller.runtime_sid,
                cwd=str(repo_dir),
                runtime_turn_id="turn-clean-merged",
                raw_input={"prompt": "/side-sessions:cleanup clean-merged", "input_id": "inp-clean-merged"},
            )
        )
        self.assertIsNotNone(hook_m)
        self.assertIn("[side-sessions:cleanup]", hook_m["additionalContext"])
        self.assertTrue(any(ev.get("kind") == "cleanup" and ev.get("node_id") == m_id for ev in kicked_events))

        res_m_list = runner._process_worktree_jobs()
        self.assertEqual(len(res_m_list), 1)
        self.assertTrue(res_m_list[0]["ok"])
        self.assertTrue(res_m_list[0]["cleaned"])
        self.assertTrue(res_m_list[0]["branch_removed"])
        self.assertFalse(m_wt.exists())
        self.assertEqual(
            self.store.conn.execute("SELECT state FROM worktrees WHERE node_id = ?", (m_id,)).fetchone()["state"],
            "cleaned",
        )
        self.assertEqual(
            self.store.conn.execute("SELECT node_status FROM nodes WHERE node_id = ?", (m_id,)).fetchone()["node_status"],
            "archived",
        )
        br_chk_m = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "--verify", f"refs/heads/{m_branch}"], capture_output=True)
        self.assertNotEqual(br_chk_m.returncode, 0)

        # 2. Unmerged clean child with new commit -> resolved by runtime_session_id -> directory removed, side/<hex> branch RETAINED!
        st_unmerged = self.engine.start_session(
            git_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Unmerged Clean Child",
                "prompt": "Add unmerged_feature.py",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "write_code",
                "use_worktree": True,
                "name": "clean-unmerged",
            },
        )
        self._close_child_run(st_unmerged)
        u_id = st_unmerged["node_id"]
        u_runtime_sid = str(
            self.store.conn.execute("SELECT runtime_session_id FROM nodes WHERE node_id = ?", (u_id,)).fetchone()[
                "runtime_session_id"
            ]
        )
        u_row = self.store.conn.execute("SELECT * FROM worktrees WHERE node_id = ?", (u_id,)).fetchone()
        u_wt = Path(u_row["canonical_worktree_path"])
        u_branch = str(u_row["branch"])
        (u_wt / "unmerged_feature.py").write_text("KEEP_CODE = 42\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(u_wt), "add", "unmerged_feature.py"], check=True)
        subprocess.run(["git", "-C", str(u_wt), "commit", "-m", "Unmerged commit"], check=True, capture_output=True)
        u_commit = subprocess.run(
            ["git", "-C", str(u_wt), "rev-parse", "--verify", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()

        hook_u = self.engine.handle_hook(
            HookContext(
                event="UserPromptSubmit",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=git_caller.runtime_sid,
                cwd=str(repo_dir),
                runtime_turn_id="turn-clean-unmerged",
                raw_input={"prompt": f"/side-sessions:cleanup {u_runtime_sid}", "input_id": "inp-clean-unmerged"},
            )
        )
        self.assertIsNotNone(hook_u)
        self.assertIn("[side-sessions:cleanup]", hook_u["additionalContext"])

        res_u_list = runner._process_worktree_jobs()
        self.assertEqual(len(res_u_list), 1)
        self.assertTrue(res_u_list[0]["ok"])
        self.assertTrue(res_u_list[0]["cleaned"])
        self.assertFalse(res_u_list[0]["branch_removed"])
        self.assertTrue(res_u_list[0]["branch_retained"])
        self.assertFalse(u_wt.exists())
        self.assertEqual(
            self.store.conn.execute("SELECT state FROM worktrees WHERE node_id = ?", (u_id,)).fetchone()["state"],
            "cleaned",
        )
        self.assertEqual(
            self.store.conn.execute("SELECT node_status FROM nodes WHERE node_id = ?", (u_id,)).fetchone()["node_status"],
            "archived",
        )
        # Verify side/<hex> branch ref and commit contents are 100% preserved in parent repository!
        br_chk_u = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "--verify", f"refs/heads/{u_branch}"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(br_chk_u.stdout.strip(), u_commit)

        # 3. Dirty child worktree (untracked + ignored file) -> resolved by node_id -> refused & state='retained_dirty'
        st_dirty = self.engine.start_session(
            git_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Dirty Child",
                "prompt": "Leave uncommitted work",
                "context": "fresh",
                "background": VALID_BACKGROUND_80,
                "task_kind": "write_code",
                "use_worktree": True,
                "name": "clean-dirty",
            },
        )
        self._close_child_run(st_dirty)
        d_id = st_dirty["node_id"]
        d_wt = Path(
            self.store.conn.execute("SELECT canonical_worktree_path FROM worktrees WHERE node_id = ?", (d_id,)).fetchone()[
                "canonical_worktree_path"
            ]
        )
        (d_wt / ".gitignore").write_text("*.local.secret\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(d_wt), "add", ".gitignore"], check=True)
        subprocess.run(["git", "-C", str(d_wt), "commit", "-m", "Add gitignore"], check=True, capture_output=True)
        (d_wt / "creds.local.secret").write_text("TOKEN=123\n", encoding="utf-8")
        (d_wt / "draft.txt").write_text("untracked\n", encoding="utf-8")

        hook_d = self.engine.handle_hook(
            HookContext(
                event="UserPromptSubmit",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=git_caller.runtime_sid,
                cwd=str(repo_dir),
                runtime_turn_id="turn-clean-dirty",
                raw_input={"prompt": f"/side-sessions:cleanup {d_id}", "input_id": "inp-clean-dirty"},
            )
        )
        self.assertIsNotNone(hook_d)
        self.assertIn("[side-sessions:cleanup]", hook_d["additionalContext"])

        res_d_list = runner._process_worktree_jobs()
        self.assertEqual(len(res_d_list), 1)
        self.assertFalse(res_d_list[0]["ok"])
        self.assertFalse(res_d_list[0]["cleaned"])
        self.assertEqual(res_d_list[0]["state"], "retained_dirty")
        self.assertIn("dirty worktree", str(res_d_list[0]["reason"]).lower())
        self.assertTrue(d_wt.exists())
        self.assertEqual(
            self.store.conn.execute("SELECT state FROM worktrees WHERE node_id = ?", (d_id,)).fetchone()["state"],
            "retained_dirty",
        )
        self.assertNotEqual(
            self.store.conn.execute("SELECT node_status FROM nodes WHERE node_id = ?", (d_id,)).fetchone()["node_status"],
            "archived",
        )

        # 4. Verify action_binding={'cmd': 'cleanup', 'node_id': d_id} blocks cross-node / cross-command replay,
        #    and cleaning up the dirty files allows subsequent /side-sessions:cleanup to succeed
        self.host_adapter.record_human_input(
            runtime_sid=git_caller.runtime_sid,
            input_id="inp-bound-cleanup-only",
            origin="slash_command",
            command_id="/side-sessions:cleanup",
            action_binding={"cmd": "cleanup", "node_id": d_id},
        )
        diff_d_clean_probe = sha256_hex("dummy-preview-hash")
        with self.assertRaises(SideSessionError) as cross_cmd_err:
            self.engine.enqueue_merge_worktree_job(
                git_caller,
                session_ref=d_id,
                preview_hash=diff_d_clean_probe,
                real_input_id="inp-bound-cleanup-only",
                command_id="/side-sessions:merge",
            )
        self.assertEqual(cross_cmd_err.exception.code, ErrorCode.APPROVAL_REPLAYED)

        (d_wt / "creds.local.secret").unlink()
        (d_wt / "draft.txt").unlink()
        enq_d_retry = self.engine.enqueue_cleanup_worktree_job(
            git_caller,
            {"session_id": d_id, "real_input_id": "inp-bound-cleanup-only", "command_id": "/side-sessions:cleanup"},
        )
        self.assertEqual(enq_d_retry["state"], "queued")
        res_d_retry = self.engine.execute_worktree_job(enq_d_retry["job_id"])
        self.assertTrue(res_d_retry["ok"])
        self.assertTrue(res_d_retry["cleaned"])
        self.assertTrue(res_d_retry["branch_retained"])
        self.assertFalse(d_wt.exists())
        self.assertEqual(
            self.store.conn.execute("SELECT state FROM worktrees WHERE node_id = ?", (d_id,)).fetchone()["state"],
            "cleaned",
        )
        self.assertEqual(
            self.store.conn.execute("SELECT node_status FROM nodes WHERE node_id = ?", (d_id,)).fetchone()["node_status"],
            "archived",
        )

    def test_a2_sidebar_child_row_branch_tooltip_and_worktree_state_badges(self) -> None:
        """Verify sidebar_tree_bundle.js renders link.title branch tooltip and 已合并 / 脏目录保留 badges."""
        import shutil
        import sidebar_ui_ctl

        node_bin = shutil.which("node") or str(Path(sidebar_ui_ctl._resolve_default_node_dir()) / "node")
        adapter_js = PLUGIN_ROOT / "ui" / "adapters" / "zcode-3.17.2.js"
        bundle_js = PLUGIN_ROOT / "ui" / "sidebar_tree_bundle.js"

        vm_script = """
        const assert = require('node:assert/strict');
        const fs = require('node:fs');
        const [adapterPath, bundlePath] = process.argv.slice(1);

        function walkAll(root, out = []) {
          for (const c of root.children || []) {
            if (c && c.nodeType === 1) { out.push(c); walkAll(c, out); }
          }
          return out;
        }

        class FakeEl {
          constructor(tag = 'div', rect = { top: 0, bottom: 720, left: 0, right: 260, width: 260, height: 720 }) {
            this.tagName = tag.toUpperCase();
            this.nodeType = 1;
            this.className = '';
            this.id = '';
            this.hidden = false;
            this.textContent = '';
            this.title = '';
            this._rect = rect;
            this.attributes = new Map();
            this.children = [];
            this.parentElement = null;
            this.isConnected = true;
            this.listeners = {};
            this.style = { props: {}, setProperty(k, v) { this.props[k] = v; this[k] = v; } };
            this.classList = { contains: (c) => this.className.split(/\\s+/).filter(Boolean).includes(c) };
          }
          setAttribute(k, v) { this.attributes.set(k, String(v)); }
          getAttribute(k) { return this.attributes.has(k) ? this.attributes.get(k) : null; }
          hasAttribute(k) { return this.attributes.has(k); }
          removeAttribute(k) { this.attributes.delete(k); }
          append(...nodes) { for (const n of nodes) { if (typeof n === 'object' && n) { n.parentElement = this; this.children.push(n); } } }
          appendChild(n) { this.append(n); return n; }
          replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
          replaceWith(other) {
            if (this.parentElement && other) {
              const i = this.parentElement.children.indexOf(this);
              if (i !== -1) { other.parentElement = this.parentElement; this.parentElement.children[i] = other; this.parentElement = null; }
            }
          }
          remove() { if (this.parentElement) { this.parentElement.children = this.parentElement.children.filter(x => x !== this); this.parentElement = null; } }
          get lastElementChild() { return this.children[this.children.length - 1] || null; }
          contains(other) { return other === this || this.children.some(c => c.contains && c.contains(other)); }
          closest() { return null; }
          querySelector(sel) {
            if (sel === 'ul') return this.children.find(c => c.tagName === 'UL') || null;
            if (sel === '.ss-sr') return this.children.find(c => c.className === 'ss-sr') || null;
            if (sel === ':scope > .ss-tree-chevron') return this.children.find(c => c.classList.contains('ss-tree-chevron')) || null;
            if (sel.includes('.ss-comm-badge--parent')) return this.children.find(c => c.classList.contains('ss-comm-badge--parent')) || null;
            return null;
          }
          querySelectorAll(sel) {
            if (sel === ':scope > .ss-tree-chevron') return this.children.filter(c => c.classList.contains('ss-tree-chevron'));
            return [];
          }
          addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
          removeEventListener() {}
          getBoundingClientRect() { return this._rect; }
        }

        const headEl = new FakeEl('head');
        const bodyEl = new FakeEl('body');
        const navRoot = new FakeEl('aside');
        bodyEl.append(navRoot);
        global.Element = FakeEl;
        global.window = global;
        global.addEventListener = () => {};
        global.removeEventListener = () => {};
        global.localStorage = { getItem() { return null; }, setItem() {}, removeItem() {} };
        global.MutationObserver = class { observe() {} disconnect() {} };
        global.ResizeObserver = class { observe() {} disconnect() {} };
        global.requestAnimationFrame = (fn) => { fn(); return 1; };
        global.cancelAnimationFrame = () => {};
        global.document = {
          hidden: false,
          readyState: 'complete',
          head: headEl,
          body: bodyEl,
          documentElement: headEl,
          activeElement: null,
          createElement: (t) => new FakeEl(t),
          createTextNode: (t) => ({ nodeType: 3, textContent: String(t) }),
          getElementById: (id) => [...walkAll(headEl), ...walkAll(bodyEl)].find(e => e.id === id) || null,
          querySelector: (sel) => sel === '[data-project-sidebar-panel="navigation"]' ? navRoot : null,
          querySelectorAll: (sel) => sel === '[data-ss-owned]' ? [...walkAll(headEl), ...walkAll(bodyEl)].filter(e => e.hasAttribute('data-ss-owned')) : [],
          addEventListener: () => {},
          removeEventListener: () => {},
        };

        eval(fs.readFileSync(adapterPath, 'utf8'));
        const A = global.__SS_ZCODE_ADAPTER__;
        const trProj = { memoizedProps: { kind: 'project', tasks: [], onSelect: () => {} } };
        const wProj = new FakeEl('div');
        navRoot.append(wProj);
        A.findTaskMounts = () => [{
          taskId: 'sid-P', wrapper: wProj, row: new FakeEl('li'), titleSlot: new FakeEl('div'),
          titleText: new FakeEl('span', { top: 0, bottom: 20, left: 26, right: 200, width: 174, height: 20 }),
          trFiber: trProj,
          octFiber: { memoizedProps: {}, child: { child: { memoizedProps: { activeTaskId: 'sid-P', isWorkspaceActive: true } } } },
          hostId: 'local', projectId: 'p1', kind: 'project', instanceKey: 'proj:p1:sid-P',
        }];

        eval(fs.readFileSync(bundlePath, 'utf8'));
        const T = global.__SS_SIDEBAR_TREE__;

        T.update({
          schemaVersion: 1,
          storeInstanceId: 'st-a2',
          projectionRevision: 1,
          nodes: [
            { nodeId: 'nP', parentNodeId: null, sessionId: 'sid-P', name: 'root', title: 'Parent', hostId: 'local', workspacePath: '/w', createdAt: '1', revision: 1, comm: {} },
            { nodeId: 'nMerged', parentNodeId: 'nP', sessionId: 'sid-M', name: 'feat-m', title: 'Merged Task', hostId: 'local', workspacePath: '/wt1', createdAt: '2', revision: 1, indexState: 'indexed', branchName: 'side/aaa111', worktreeState: 'merged', comm: {} },
            { nodeId: 'nDirty', parentNodeId: 'nP', sessionId: 'sid-D', name: 'feat-d', title: 'Dirty Task', hostId: 'local', workspacePath: '/wt2', createdAt: '3', revision: 1, indexState: 'indexed', branchName: 'side/bbb222', worktreeState: 'retained_dirty', comm: {} },
            { nodeId: 'nPlain', parentNodeId: 'nP', sessionId: 'sid-R', name: 'read-o', title: 'Read Only', hostId: 'local', workspacePath: '/w', createdAt: '4', revision: 1, indexState: 'indexed', branchName: null, worktreeState: null, comm: {} },
          ],
        });

        const items = walkAll(wProj).filter(e => e.classList.contains('ss-child-item'));
        assert.equal(items.length, 3);

        const linkM = walkAll(items[0]).find(e => e.classList.contains('ss-child-link'));
        const badgeM = walkAll(linkM).find(e => e.classList.contains('ss-wt-badge--merged'));
        assert.equal(linkM.title, 'Merged Task (feat-m) | 分支: side/aaa111 (merged)');
        assert.ok(badgeM, 'Merged worktree badge must render');
        assert.equal(badgeM.textContent, '已合并');

        const linkD = walkAll(items[1]).find(e => e.classList.contains('ss-child-link'));
        const badgeD = walkAll(linkD).find(e => e.classList.contains('ss-wt-badge--dirty'));
        assert.equal(linkD.title, 'Dirty Task (feat-d) | 分支: side/bbb222 (retained_dirty)');
        assert.ok(badgeD, 'Dirty worktree badge must render');
        assert.equal(badgeD.textContent, '脏目录保留');

        const linkR = walkAll(items[2]).find(e => e.classList.contains('ss-child-link'));
        assert.equal(linkR.title, 'Read Only (read-o)');
        assert.equal(walkAll(linkR).filter(e => e.classList.contains('ss-wt-badge')).length, 0);

        // Update worktreeState on nDirty -> sig() must trigger re-render and clear badge
        T.update({
          schemaVersion: 1,
          storeInstanceId: 'st-a2',
          projectionRevision: 2,
          nodes: [
            { nodeId: 'nP', parentNodeId: null, sessionId: 'sid-P', name: 'root', title: 'Parent', hostId: 'local', workspacePath: '/w', createdAt: '1', revision: 1, comm: {} },
            { nodeId: 'nDirty', parentNodeId: 'nP', sessionId: 'sid-D', name: 'feat-d', title: 'Dirty Task', hostId: 'local', workspacePath: '/wt2', createdAt: '3', revision: 1, indexState: 'indexed', branchName: 'side/bbb222', worktreeState: 'in_use', comm: {} },
          ],
        });
        const itemsAfter = walkAll(wProj).filter(e => e.classList.contains('ss-child-item'));
        const linkDAfter = walkAll(itemsAfter[0]).find(e => e.classList.contains('ss-child-link'));
        assert.equal(linkDAfter.title, 'Dirty Task (feat-d) | 分支: side/bbb222 (in_use)');
        assert.equal(walkAll(linkDAfter).filter(e => e.classList.contains('ss-wt-badge')).length, 0);

        T.destroy();
        """
        vm_proc = subprocess.run([node_bin, "-e", vm_script, str(adapter_js), str(bundle_js)], capture_output=True, text=True)
        self.assertEqual(vm_proc.returncode, 0, f"A2 sidebar branch/worktree badge check failed: {vm_proc.stderr}")

    def test_port1_port2_a3_run_py311_bootstrap_portability_and_skill_rules(self) -> None:
        """Verify run_py311.sh probe/exec/failure, PORT-2 dynamic Python/Node resolution + plist placeholders, and A3 SKILL.md rules."""
        import side_sessions_agent
        import sidebar_ui_ctl

        # 1. PORT-1: run_py311.sh executable permissions, ZCODE_SIDE_SESSIONS_PYTHON priority, <3.11 skip, and >=3.11 failure exit
        runner_sh = PLUGIN_ROOT / "scripts" / "run_py311.sh"
        self.assertTrue(runner_sh.is_file())
        self.assertTrue(os.access(runner_sh, os.X_OK))

        direct_proc = subprocess.run(
            [
                "/bin/sh",
                str(runner_sh),
                "-c",
                "import sys; print(sys.flags.isolated, sys.flags.dont_write_bytecode, sys.version_info >= (3, 11))",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(direct_proc.stdout.strip(), "1 1 True")

        # Fake Python 3.9 in ZCODE_SIDE_SESSIONS_PYTHON must be skipped in favor of valid >=3.11 interpreter
        fake_bin_dir = self.tmp_path / "fake-py-bin"
        fake_bin_dir.mkdir(parents=True, exist_ok=True)
        fake_py39 = fake_bin_dir / "python3"
        fake_py39.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        fake_py39.chmod(0o755)

        env_skip = dict(os.environ)
        env_skip["ZCODE_SIDE_SESSIONS_PYTHON"] = str(fake_py39)
        skip_proc = subprocess.run(
            ["/bin/sh", str(runner_sh), "-c", "import sys; print(sys.version_info >= (3, 11))"],
            env=env_skip,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(skip_proc.stdout.strip(), "True")

        # Fake Python >=3.11 wrapper in ZCODE_SIDE_SESSIONS_PYTHON must be selected first and receive -I -B "$@"
        fake_py312 = fake_bin_dir / "py312-wrapper"
        fake_py312.write_text(
            '#!/bin/sh\nif [ "$2" = "-c" ]; then exit 0; fi\nprintf "%s|%s|%s\\n" "$1" "$2" "$3"\n',
            encoding="utf-8",
        )
        fake_py312.chmod(0o755)
        env_hit = dict(os.environ)
        env_hit["ZCODE_SIDE_SESSIONS_PYTHON"] = str(fake_py312)
        hit_proc = subprocess.run(
            ["/bin/sh", str(runner_sh), "target_script.py"],
            env=env_hit,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(hit_proc.stdout.strip(), "-I|-B|target_script.py")

        # Isolated copy where fixed Homebrew paths do not exist and PATH only has fake 3.9 -> exit 1 with clear stderr
        sandbox_sh = self.tmp_path / "run_py311_no_brew.sh"
        sh_src = runner_sh.read_text(encoding="utf-8")
        sandbox_sh.write_text(
            sh_src.replace("/opt/homebrew/bin/python3", str(self.tmp_path / "missing-opt-py3")).replace(
                "/usr/local/bin/python3", str(self.tmp_path / "missing-local-py3")
            ),
            encoding="utf-8",
        )
        sandbox_sh.chmod(0o755)
        fail_proc = subprocess.run(
            ["/bin/sh", str(sandbox_sh), "noop.py"],
            env={"PATH": str(fake_bin_dir)},
            capture_output=True,
            text=True,
        )
        self.assertEqual(fail_proc.returncode, 1)
        self.assertIn("side-sessions requires Python >= 3.11", fail_proc.stderr)

        # 2. PORT-2: plist.example placeholders & dynamic Python/Node resolution
        plist_path = PLUGIN_ROOT / "service" / "com.zcode.side-sessions.plist.example"
        plist_raw = plist_path.read_text(encoding="utf-8")
        self.assertNotIn("/opt/homebrew/bin/python3", plist_raw)
        self.assertNotIn("/opt/homebrew/opt/node@22/bin", plist_raw)
        plist_data = plistlib.loads(plist_raw.encode("utf-8"))
        self.assertEqual(plist_data["ProgramArguments"][0], "__PYTHON3_PATH__")
        self.assertIn("__NODE_BIN_DIR__", plist_data["EnvironmentVariables"]["PATH"])

        self.assertEqual(
            sidebar_ui_ctl._resolve_default_node_dir({"ZCODE_SIDE_SESSIONS_NODE_DIR": "/custom/node/bin", "PATH": ""}),
            "/custom/node/bin",
        )
        self.assertEqual(
            side_sessions_agent._resolve_node_dir({"ZCODE_SIDE_SESSIONS_NODE_DIR": "/custom/node/bin", "PATH": ""}),
            "/custom/node/bin",
        )
        fake_node_dir = self.tmp_path / "node-bin"
        fake_node_dir.mkdir(parents=True, exist_ok=True)
        fake_node = fake_node_dir / "node"
        fake_node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_node.chmod(0o755)
        self.assertEqual(sidebar_ui_ctl._resolve_default_node_dir({"PATH": str(fake_node_dir)}), str(fake_node_dir))
        self.assertEqual(side_sessions_agent._resolve_node_dir({"PATH": str(fake_node_dir)}), str(fake_node_dir))
        self.assertEqual(sidebar_ui_ctl._select_python3(), str(Path(sys.executable).absolute()))
        self.assertEqual(side_sessions_agent._select_python3(), str(Path(sys.executable).absolute()))

        # 3. A3: SKILL.md contains /side-sessions:cleanup and both Claude Desktop 3.6556.2 coordination rules
        skill_text = (PLUGIN_ROOT / "skills" / "side-sessions" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("/side-sessions:cleanup <session>", skill_text)
        self.assertIn("结果核验铁律", skill_text)
        self.assertIn("diff_worktree", skill_text)
        self.assertIn("摘要置首规范", skill_text)


if __name__ == "__main__":
    unittest.main()

