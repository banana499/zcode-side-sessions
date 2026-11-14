"""Protocol & ownership tests for ZCode 3.18.2 M5, M6, M7, and M8 in side-sessions."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import uuid

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR = _PLUGIN_ROOT / "scripts"
_HOOKS_DIR = _PLUGIN_ROOT / "hooks"
for p in (str(_SCRIPTS_DIR), str(_HOOKS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from contracts import (  # noqa: E402
    MAX_HOOK_CONTEXT_BYTES,
    BoundWait,
    CallerContext,
    ErrorCode,
    HookContext,
    RunAssignment,
    RuntimeCreateSpec,
    RuntimeInput,
    RuntimeResumeSpec,
    SideSessionError,
    canonical_json_sha256,
    sha256_hex,
)
from driver import RuntimeEvent, WaitResponse, ZCodeDriver  # noqa: E402
from engine import Engine, normalize_human_wait_answer  # noqa: E402
from host_adapter import HostAdapter  # noqa: E402
from side_sessions_hook import main as hook_main  # noqa: E402
from state import open_store  # noqa: E402
from worker_runner import WorkerRunner  # noqa: E402


VALID_BG_80 = (
    "总体目标：在隔离工作区完成协议与门禁测试，确保端到端真实链路行为严格满足规范要求。\n"
    "已有决策：采用真实 stdio app-server 协议夹具与独立状态目录验证所有交互。\n"
    "约束：严禁跳过授权链、绕过人类审批或使用伪造响应。"
)


def _write_fake_zcode_bin(tmp_dir: Path, script_body: str) -> Path:
    """Create an executable fake `zcode` CLI script handling `app-server` over stdio NDJSON."""
    bin_path = tmp_dir / "fake-zcode"
    content = f"#!{sys.executable}\n{script_body}\n"
    bin_path.write_text(content, encoding="utf-8")
    bin_path.chmod(bin_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return bin_path


class ProtocolV3182TestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)
        self.state_root = self.tmp_path / "state"
        self.workspace_dir = self.tmp_path / "workspace"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.host_db_path = self.tmp_path / "host.sqlite"
        self.store = open_store(self.state_root, writable=True)
        self.host_adapter = HostAdapter(host_db_path=self.host_db_path, store=self.store)
        self.parent_sid = f"sid-parent-{uuid.uuid4().hex[:8]}"
        self.parent_caller = CallerContext(
            runtime_sid=self.parent_sid,
            runtime_turn_id="turn-parent-1",
            workspace_path=str(self.workspace_dir),
            connection_id="stdio:test",
        )
        self.engine = Engine(
            self.store,
            host_adapter=self.host_adapter,
            driver=ZCodeDriver(host_db_path=self.host_db_path),
            runtime_execution="deferred",
        )
        self.parent_node = self.engine.ensure_caller_node(self.parent_caller)

    def tearDown(self) -> None:
        try:
            self.store.close()
        except Exception:
            pass
        self._tmp.cleanup()

    def _start_child(self, *, name: str = "child-a", engine: Engine | None = None) -> dict:
        eng = engine or self.engine
        self.host_adapter.record_human_input(
            runtime_sid=self.parent_sid,
            input_id=f"inp-start-{name}-{uuid.uuid4().hex[:6]}",
            origin="human_prompt",
            runtime_turn_id="turn-parent-1",
        )
        return eng.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": f"Child {name}",
                "prompt": "Run test task",
                "context": "fresh",
                "background": VALID_BG_80,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": name,
            },
        )


# ==============================================================================
# M5: Native Session Tool Ownership Guard + SessionStart + RuntimePreferences
# ==============================================================================


class TestM5NativeOwnershipGuard(ProtocolV3182TestCase):
    def test_session_start_empty_outbox_always_injects_routing_within_budget(self) -> None:
        fresh_root = self.tmp_path / "fresh-m5-state"
        env = {"ZCODE_SIDE_SESSIONS_HOME": str(fresh_root), "CLAUDE_SESSION_ID": "sid-m5-root"}
        out = io.StringIO()
        err = io.StringIO()
        rc = hook_main(
            stdin=json.dumps(
                {
                    "session_id": "sid-m5-root",
                    "hook_event_name": "SessionStart",
                    "cwd": str(self.workspace_dir),
                }
            ),
            stdout=out,
            stderr=err,
            environ=env,
        )
        self.assertEqual(rc, 0, err.getvalue())
        raw = out.getvalue().strip()
        self.assertTrue(raw, "SessionStart with empty outbox must still emit routing context")
        payload = json.loads(raw)
        ctx = payload["additionalContext"]
        self.assertLessEqual(len(ctx.encode("utf-8")), MAX_HOOK_CONTEXT_BYTES)
        self.assertIn("start_session", ctx)
        self.assertIn("CreateSession", ctx)
        self.assertIn("SendToSession", ctx)

    def test_create_and_fork_blocked_on_initial_turn_and_ignores_independent_flag(self) -> None:
        for tool in ("CreateSession", "ForkSession", "mcp__zcode__CreateSession"):
            out = self.engine.handle_hook(
                HookContext(
                    event="PreToolUse",
                    invocation_id=str(uuid.uuid4()),
                    runtime_sid=self.parent_sid,
                    cwd=str(self.workspace_dir),
                    runtime_turn_id="turn-1",
                    raw_input={
                        "tool_name": tool,
                        "tool_input": {"independent": True, "title": "Bypass attempt"},
                    },
                )
            )
            self.assertIsNotNone(out, f"{tool} must be blocked on initial turn")
            self.assertIs(out["continue"], False)
            self.assertIn("OWNERSHIP_CONFLICT", out["additionalContext"])

        # Loose suffix matching must NOT match non-native custom tools
        non_native = self.engine.native_session_guard(
            self.parent_caller,
            "my_custom_CreateSession",
            {"independent": True},
        )
        self.assertIsNone(non_native)

    def test_managed_target_blocks_send_interrupt_archive_rename_and_allows_unmanaged(self) -> None:
        child = self._start_child(name="managed-one")
        child_nid = child["node_id"]
        child_rsid = child["runtime_session_id"]

        # Unmanaged bare native root in DB (e.g., auto-registered by SessionStart without any children/tasks/runs)
        unmanaged_sid = "sid-unmanaged-native-root"
        self.engine.ensure_caller_node(
            CallerContext(runtime_sid=unmanaged_sid, workspace_path=str(self.workspace_dir))
        )

        for tool in ("SendToSession", "InterruptSession", "SetSessionArchived", "RenameSession"):
            # Blocked by runtime_session_id via top-level sessionId
            out_top = self.engine.handle_hook(
                HookContext(
                    event="PreToolUse",
                    invocation_id=str(uuid.uuid4()),
                    runtime_sid=self.parent_sid,
                    cwd=str(self.workspace_dir),
                    raw_input={"tool_name": tool, "tool_input": {"sessionId": child_rsid}},
                )
            )
            self.assertIsNotNone(out_top, f"{tool} must block managed sessionId")
            self.assertIs(out_top["continue"], False)

            # Blocked by node_id via nested session.sessionId
            out_nested = self.engine.handle_hook(
                HookContext(
                    event="PreToolUse",
                    invocation_id=str(uuid.uuid4()),
                    runtime_sid=self.parent_sid,
                    cwd=str(self.workspace_dir),
                    raw_input={"tool_name": tool, "tool_input": {"session": {"sessionId": child_nid}}},
                )
            )
            self.assertIsNotNone(out_nested, f"{tool} must block nested session.sessionId")
            self.assertIs(out_nested["continue"], False)

            # Conflicting top-level sessionId vs session.sessionId -> blocked
            out_conflict = self.engine.handle_hook(
                HookContext(
                    event="PreToolUse",
                    invocation_id=str(uuid.uuid4()),
                    runtime_sid=self.parent_sid,
                    cwd=str(self.workspace_dir),
                    raw_input={
                        "tool_name": tool,
                        "tool_input": {
                            "sessionId": "sid-a",
                            "session": {"sessionId": "sid-b"},
                        },
                    },
                )
            )
            self.assertIsNotNone(out_conflict)
            self.assertIs(out_conflict["continue"], False)

            # Allowed on genuinely unmanaged SID (never in DB)
            out_unm1 = self.engine.handle_hook(
                HookContext(
                    event="PreToolUse",
                    invocation_id=str(uuid.uuid4()),
                    runtime_sid=self.parent_sid,
                    cwd=str(self.workspace_dir),
                    raw_input={"tool_name": tool, "tool_input": {"sessionId": "sid-never-seen"}},
                )
            )
            self.assertIsNone(out_unm1)

            # Allowed on bare auto-registered native root (not auto-adopted!)
            out_unm2 = self.engine.handle_hook(
                HookContext(
                    event="PreToolUse",
                    invocation_id=str(uuid.uuid4()),
                    runtime_sid=self.parent_sid,
                    cwd=str(self.workspace_dir),
                    raw_input={"tool_name": tool, "tool_input": {"sessionId": unmanaged_sid}},
                )
            )
            self.assertIsNone(out_unm2)

    def test_allowed_read_nav_pin_and_task_freeze_coexistence_and_db_busy_fail_closed(self) -> None:
        for tool in ("ListProjects", "ListSessions", "ReadSession", "OpenSession", "SetSessionPinned"):
            out = self.engine.handle_hook(
                HookContext(
                    event="PreToolUse",
                    invocation_id=str(uuid.uuid4()),
                    runtime_sid=self.parent_sid,
                    cwd=str(self.workspace_dir),
                    runtime_turn_id="turn-ro-1",
                    raw_input={"tool_name": tool, "tool_input": {"sessionId": "sid-any"}},
                )
            )
            self.assertIsNone(out)

        # Register a task and freeze its turn binding -> allowed native tool is still blocked by task freeze
        reg = self.engine.register_task(
            self.parent_caller,
            {
                "request_id": str(uuid.uuid4()),
                "title": "Frozen Task",
                "remaining_plan": "step 1",
                "task_kind": "read_only",
                "scope": {"resource_keys": ["src/"], "write_path_roots": [], "artifact_source_roots": []},
            },
        )
        with self.store.transaction("IMMEDIATE") as txn:
            txn.execute(
                "UPDATE task_turn_bindings SET state = 'frozen' WHERE task_id = ?",
                (reg["task_id"],),
            )
        frozen_out = self.engine.handle_hook(
            HookContext(
                event="PreToolUse",
                invocation_id=str(uuid.uuid4()),
                runtime_sid=self.parent_sid,
                cwd=str(self.workspace_dir),
                runtime_turn_id=self.parent_caller.runtime_turn_id,
                raw_input={"tool_name": "OpenSession", "tool_input": {"sessionId": "sid-any"}},
            )
        )
        self.assertIsNotNone(frozen_out)
        self.assertIs(frozen_out["continue"], False)
        self.assertIn("TASK_OWNER_CHANGED", frozen_out["additionalContext"])

        # DB version mismatch / busy fail-closed for native write tools via hook_main
        root2 = self.tmp_path / "busy-db-root"
        env2 = {"ZCODE_SIDE_SESSIONS_HOME": str(root2), "CLAUDE_SESSION_ID": "sid-busy-check"}
        with open_store(root2, writable=True) as st2:
            st2.conn.execute("UPDATE schema_meta SET engine_schema_version = '9.9' WHERE id = 1")
            st2.conn.execute("UPDATE store_meta SET engine_schema_version = '9.9' WHERE id = 1")

        out_busy = io.StringIO()
        rc_busy = hook_main(
            stdin=json.dumps(
                {
                    "session_id": "sid-busy-check",
                    "hook_event_name": "PreToolUse",
                    "cwd": str(self.workspace_dir),
                    "tool_name": "CreateSession",
                    "tool_input": {},
                }
            ),
            stdout=out_busy,
            stderr=io.StringIO(),
            environ=env2,
        )
        self.assertEqual(rc_busy, 0)
        blocked_busy = json.loads(out_busy.getvalue().strip())
        self.assertIs(blocked_busy["continue"], False)
        self.assertIn("VERSION_MISMATCH", blocked_busy["additionalContext"])


# ==============================================================================
# M6: Reverse Interaction Request Parking + Re-announcement + Auth/Unknown RPC
# ==============================================================================


class TestM6ReverseRequestParking(ProtocolV3182TestCase):
    def _make_create_spec(self, sid: str) -> RuntimeCreateSpec:
        return RuntimeCreateSpec(
            assignment=RunAssignment(
                node_id=str(uuid.uuid4()),
                runtime_sid=sid,
                turn_seq=1,
                run_id=str(uuid.uuid4()),
                worker_turn_id=str(uuid.uuid4()),
                input_id=str(uuid.uuid4()),
                message_id=str(uuid.uuid4()),
                parent_node_id=self.parent_node["node_id"],
                dispatch_group_id="",
                member_id="",
                task_id=None,
                task_revision=None,
                owner_epoch=1,
                fencing_token="fence-1",
            ),
            workspace_path=str(self.workspace_dir),
            parent_runtime_sid=self.parent_sid,
            mode="plan",
            model={},
            tool_allowlist=["Read"],
            tool_denylist=["Bash"],
        )

    def test_reverse_init_state_prefs_auth_unknown_reannounce_conflict_and_wrong_sid(self) -> None:
        log_path = self.tmp_path / "wire-log.jsonl"
        sid = "sid-m6-init"
        fake_bin = _write_fake_zcode_bin(
            self.tmp_path,
            f"""
import json, sys

log_path = {str(log_path)!r}
def record(obj):
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(obj) + '\\n')

def send(obj):
    sys.stdout.write(json.dumps(obj) + '\\n')
    sys.stdout.flush()

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    msg = json.loads(raw)
    record(msg)
    method = msg.get('method')
    if method == 'session/create':
        p = msg['params']
        # 1. Runtime preferences
        send({{"id": "server-1", "method": "session/requestRuntimePreferences", "params": {{}}}})
        # 2. Provider headers + Official MCP auth + Unknown method
        send({{"id": "server-2", "method": "interaction/requestProviderRuntimeHeaders", "params": {{"requestId": "prh-1"}}}})
        send({{"id": "server-3", "method": "interaction/requestOfficialMcpAuthHeaders", "params": {{"requestId": "mcp-1"}}}})
        send({{"id": "server-4", "method": "interaction/unknownFutureMethod", "params": {{}}}})
        # 3. Permission request arriving DURING session/create init
        perm_params = {{
            "requestId": "req-init-perm-1",
            "sessionId": p["sessionId"],
            "turnId": "turn-init-1",
            "toolCallId": "tc-init-1",
            "toolName": "Bash",
            "reason": "Run diagnostic command",
            "riskLevel": "medium",
            "input": {{"command": "echo hi", "hugeBlob": "x" * 100}},
            "options": [
                {{"optionId": "allowOnce", "kind": "allow_once", "name": "Allow once", "response": {{"decision": "allow", "reason": "Once"}}}},
                {{"optionId": "deny", "kind": "deny", "name": "Deny", "response": {{"decision": "deny", "reason": "No"}}}},
            ],
        }}
        send({{"id": "server-5", "method": "interaction/requestPermission", "params": perm_params}})
        # 4. Re-announcement of same requestId with new server-N
        send({{"id": "server-6", "method": "interaction/requestPermission", "params": perm_params}})
        # 5. Conflicting params for same requestId
        bad_params = dict(perm_params, reason="Mutated reason")
        send({{"id": "server-7", "method": "interaction/requestPermission", "params": bad_params}})
        # 6. Wrong sessionId
        wrong_sid = dict(perm_params, requestId="req-wrong-sid", sessionId="sid-other-session")
        send({{"id": "server-8", "method": "interaction/requestPermission", "params": wrong_sid}})
        # Now finish session/create response
        send({{
            "id": msg["id"],
            "result": {{
                "session": {{
                    "id": p["sessionId"],
                    "parentSessionId": p["parentSessionId"],
                    "mode": p["mode"],
                    "toolAllowlist": p.get("toolAllowlist", []),
                    "toolDenylist": p.get("toolDenylist", []),
                    "workspace": {{"workspacePath": p["workspace"]["workspacePath"]}},
                    "revision": 1,
                }}
            }},
        }})
    elif method == 'session/send':
        p = msg['params']
        send({{"id": msg["id"], "result": {{"status": "accepted", "turnId": "turn-send-1", "revision": 2}}}})
        # UserInput during events() stream + re-announce
        ask_params = {{
            "requestId": "req-ask-events-1",
            "sessionId": p["sessionId"],
            "turnId": "turn-send-1",
            "toolCallId": "tc-ask-1",
            "toolName": "AskUserQuestion",
            "questions": [{{
                "question": "Pick target environment?",
                "header": "Env",
                "options": [{{"label": "prod", "value": "prod"}}, {{"label": "staging", "value": "staging"}}],
                "multiSelect": False,
            }}],
        }}
        send({{"id": "server-9", "method": "interaction/requestUserInput", "params": ask_params}})
        send({{"id": "server-10", "method": "interaction/requestUserInput", "params": ask_params}})
    elif method == 'session/stop':
        sys.exit(0)
""",
        )

        driver = ZCodeDriver(zcode_bin=fake_bin, host_db_path=self.host_db_path, rpc_timeout_sec=5.0)
        handle = driver.create(self._make_create_spec(sid))

        # Init permission wait retained on connection with aliases ['server-5', 'server-6'] and latestRpcId == 'server-6'
        conn = driver._connections[handle.runtime_instance_id]
        self.assertIn("req-init-perm-1", conn.pending_waits)
        self.assertNotIn("req-wrong-sid", conn.pending_waits)
        p_entry = conn.pending_waits["req-init-perm-1"]
        self.assertEqual(p_entry["aliases"], ["server-5", "server-6"])
        self.assertEqual(p_entry["latestRpcId"], "server-6")
        self.assertIsNone(p_entry["sentResult"])

        # Init event queue has EXACTLY 1 wait_request (no duplicate on re-announcement!)
        init_evs = driver.events(handle).drain_available(200)
        self.assertEqual(len(init_evs), 1)
        ev0 = init_evs[0]
        self.assertEqual(ev0.kind, "wait_request")
        self.assertEqual(ev0.wait_request["host_request_id"], "req-init-perm-1")
        self.assertEqual(ev0.wait_request["required_authority"], "human")
        self.assertNotIn("hugeBlob", json.dumps(ev0.wait_request))

        # Now send() and pump UserInput + re-announcement via events()
        driver.send(handle, RuntimeInput(input_id="inp-1", content="go"))
        stream_evs = driver.events(handle).drain_available(400)
        wait_evs = [e for e in stream_evs if e.kind == "wait_request"]
        self.assertEqual(len(wait_evs), 1, "Re-announced UserInput must emit only 1 wait_request")
        self.assertEqual(wait_evs[0].wait_request["host_request_id"], "req-ask-events-1")
        self.assertEqual(wait_evs[0].wait_request["required_authority"], "human")
        ask_entry = conn.pending_waits["req-ask-events-1"]
        self.assertEqual(ask_entry["aliases"], ["server-9", "server-10"])
        self.assertEqual(ask_entry["latestRpcId"], "server-10")

        driver.stop_and_wait(handle, deadline_ms=2000)

        # Inspect wire log: verify NO interaction response written before human approval,
        # and verify exact replies for preferences, provider headers, MCP auth, unknown, conflicts, wrong sid.
        wire_msgs = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        by_id = {m.get("id"): m for m in wire_msgs if m.get("id") is not None}

        self.assertEqual(
            by_id["server-1"]["result"],
            {
                "nativeSearchEnhancementsEnabled": False,
                "memoryEnabled": False,
                "askUserQuestionAutoResolutionEnabled": False,
                "appControlEnabled": False,
            },
        )
        self.assertEqual(
            by_id["server-2"]["result"],
            {"headersApplied": False, "errorMessage": "provider_auth_delegation_unsupported"},
        )
        self.assertNotIn("headers", by_id["server-2"]["result"])
        self.assertEqual(
            by_id["server-3"]["result"],
            {"ok": False, "reason": "official_auth_unavailable"},
        )
        self.assertEqual(by_id["server-4"]["error"]["code"], -32601)
        self.assertEqual(by_id["server-7"]["error"]["code"], -32602)
        self.assertEqual(by_id["server-8"]["error"]["code"], -32602)
        for parked_id in ("server-5", "server-6", "server-9", "server-10"):
            self.assertNotIn(parked_id, by_id, f"Parked request {parked_id} must NOT be replied to before approval")


# ==============================================================================
# M7 + M8: Normalization, Strict Wire Responses, Unknown -> Resolved Convergence
# ==============================================================================


class TestM7M8NormalizationAndResolution(ProtocolV3182TestCase):
    def test_m7_normalization_unit_rules_across_permission_ask_plan_mcp(self) -> None:
        # 1. Permission with multiple allow options: bare 'allow' must NOT broaden privileges!
        perm_wait = {
            "kind": "permission",
            "options": [
                {
                    "optionId": "allowOnce",
                    "kind": "allow_once",
                    "name": "Allow once",
                    "response": {"decision": "allow", "reason": "Approved once"},
                },
                {
                    "optionId": "allowAlways",
                    "kind": "allow_always",
                    "name": "Allow always",
                    "response": {"decision": "allow", "permissionUpdates": [{"scope": "session"}]},
                },
                {
                    "optionId": "deny",
                    "kind": "deny",
                    "name": "Deny",
                    "response": {"decision": "deny", "reason": "Denied"},
                },
            ],
        }
        with self.assertRaises(SideSessionError):
            normalize_human_wait_answer(perm_wait, "allow")
        with self.assertRaises(SideSessionError):
            normalize_human_wait_answer(perm_wait, {"optionId": "allowOnce", "decision": "deny"})
        norm_once = normalize_human_wait_answer(perm_wait, "allowOnce")
        self.assertEqual(norm_once, {"kind": "permission", "option_id": "allowOnce", "decision": "allow"})

        # 2. Multi-question AskUserQuestion: reject short header key, accept full question key & answer_i
        multi_ask_wait = {
            "kind": "elicitation",
            "options": [
                {
                    "kind": "question",
                    "subtype": "ask_user_question",
                    "question": "Which target environment should we deploy?",
                    "header": "Env",
                    "multiSelect": False,
                    "options": [{"value": "staging", "label": "staging"}, {"value": "prod", "label": "prod"}],
                },
                {
                    "kind": "question",
                    "subtype": "ask_user_question",
                    "question": "Which post-deploy checks should run?",
                    "header": "Checks",
                    "multiSelect": True,
                    "options": [{"value": "smoke", "label": "smoke"}, {"value": "e2e", "label": "e2e"}],
                },
            ],
        }
        # Reject plain text on multi-question
        with self.assertRaises(SideSessionError):
            normalize_human_wait_answer(multi_ask_wait, "prod")
        # Reject short header key
        with self.assertRaises(SideSessionError):
            normalize_human_wait_answer(
                multi_ask_wait,
                json.dumps({"action": "accept", "content": {"answers": {"Env": "prod", "Checks": ["smoke"]}}}),
            )
        # Reject bare string content
        with self.assertRaises(SideSessionError):
            normalize_human_wait_answer(
                multi_ask_wait,
                json.dumps({"action": "accept", "content": "raw string"}),
            )
        # Reject list on single-select question
        with self.assertRaises(SideSessionError):
            normalize_human_wait_answer(
                multi_ask_wait,
                json.dumps(
                    {
                        "action": "accept",
                        "content": {
                            "answers": {
                                "Which target environment should we deploy?": ["prod"],
                                "Which post-deploy checks should run?": ["smoke"],
                            }
                        },
                    }
                ),
            )
        # Accept valid full-question keys
        norm_multi = normalize_human_wait_answer(
            multi_ask_wait,
            json.dumps(
                {
                    "action": "accept",
                    "content": {
                        "answers": {
                            "Which target environment should we deploy?": "prod",
                            "Which post-deploy checks should run?": ["smoke", "e2e"],
                        }
                    },
                }
            ),
        )
        self.assertEqual(norm_multi["action"], "accept")
        self.assertEqual(
            norm_multi["content"]["answers"]["Which target environment should we deploy?"],
            "prod",
        )

        # 3. plan_approval: reject empty accept / bare 'accept' / invalid value; accept valid option.value
        plan_wait = {
            "kind": "elicitation",
            "options": [
                {
                    "kind": "plan_option",
                    "subtype": "plan_approval",
                    "value": "approve",
                    "label": "Approve",
                    "question": "Review this implementation plan.",
                }
            ],
        }
        for bad_plan in ("accept", json.dumps({"action": "accept", "content": {}}), "bogus"):
            with self.assertRaises(SideSessionError):
                normalize_human_wait_answer(plan_wait, bad_plan)
        norm_plan_ok = normalize_human_wait_answer(plan_wait, "approve")
        self.assertEqual(norm_plan_ok, {"kind": "elicitation", "action": "accept", "content": {"answer": "approve"}})
        norm_plan_refine = normalize_human_wait_answer(plan_wait, "refine: Add unit tests")
        self.assertEqual(
            norm_plan_refine,
            {"kind": "elicitation", "action": "decline", "content": None, "reason": "Add unit tests"},
        )

        # 4. McpElicitation requestedSchema coercion & validation
        mcp_wait = {
            "kind": "elicitation",
            "options": [
                {
                    "kind": "schema",
                    "subtype": "mcp_elicitation",
                    "requestedSchema": {
                        "type": "object",
                        "properties": {
                            "retries": {"type": "integer"},
                            "confirm": {"type": "boolean"},
                            "region": {"type": "string", "enum": ["us", "eu"]},
                        },
                        "required": ["retries", "confirm"],
                    },
                    "questions": [
                        {"question": "Retries", "header": "Retries"},
                        {"question": "Confirm", "header": "Confirm"},
                        {"question": "Region", "header": "Region"},
                    ],
                }
            ],
        }
        with self.assertRaises(SideSessionError):
            normalize_human_wait_answer(
                mcp_wait,
                json.dumps({"action": "accept", "content": {"answer_0": "not-an-int", "answer_1": "true"}}),
            )
        with self.assertRaises(SideSessionError):
            normalize_human_wait_answer(
                mcp_wait,
                json.dumps({"action": "accept", "content": {"answer_0": "3", "answer_1": "true", "answer_2": "ap"}}),
            )
        norm_mcp = normalize_human_wait_answer(
            mcp_wait,
            json.dumps({"action": "accept", "content": {"answer_0": 3, "answer_1": True, "answer_2": "eu"}}),
        )
        self.assertEqual(norm_mcp["content"]["answer_0"], "3")
        self.assertEqual(norm_mcp["content"]["answer_1"], "true")
        self.assertEqual(norm_mcp["content"]["answer_2"], "eu")

    def test_m7_m8_human_slash_to_stdin_flush_unknown_then_permission_resolved_convergence(self) -> None:
        """End-to-end: Permission (with permissionUpdates) + AskUserQuestion via real ZCodeDriver + WorkerRunner."""
        wire_log = self.tmp_path / "e2e-wire.jsonl"
        fake_bin = _write_fake_zcode_bin(
            self.tmp_path,
            f"""
import json, sys, time

wire_log = {str(wire_log)!r}
def record(obj):
    with open(wire_log, 'a', encoding='utf-8') as f:
        f.write(json.dumps(obj) + '\\n')

def send(obj):
    sys.stdout.write(json.dumps(obj) + '\\n')
    sys.stdout.flush()

sid = None
for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    msg = json.loads(raw)
    record(msg)
    method = msg.get('method')
    if method == 'session/create':
        p = msg['params']
        sid = p['sessionId']
        send({{"id": "server-1", "method": "session/requestRuntimePreferences", "params": {{}}}})
        send({{
            "id": msg["id"],
            "result": {{
                "session": {{
                    "id": sid,
                    "parentSessionId": p["parentSessionId"],
                    "mode": p["mode"],
                    "toolAllowlist": p.get("toolAllowlist", []),
                    "toolDenylist": p.get("toolDenylist", []),
                    "workspace": {{"workspacePath": p["workspace"]["workspacePath"]}},
                    "revision": 1,
                }}
            }},
        }})
    elif method == 'session/send':
        send({{"id": msg["id"], "result": {{"status": "accepted", "turnId": "turn-e2e-1", "revision": 2}}}})
        send({{
            "id": "server-20",
            "method": "interaction/requestPermission",
            "params": {{
                "requestId": "req-perm-e2e",
                "sessionId": sid,
                "turnId": "turn-e2e-1",
                "toolCallId": "tc-perm-1",
                "toolName": "Write",
                "reason": "Write config",
                "riskLevel": "high",
                "input": {{"file": "a.txt"}},
                "options": [
                    {{
                        "optionId": "allowOnce",
                        "kind": "allow_once",
                        "name": "Allow once",
                        "response": {{"decision": "allow", "reason": "Once", "permissionUpdates": [{{"path": "a.txt"}}]}},
                    }},
                    {{
                        "optionId": "allowAlways",
                        "kind": "allow_always",
                        "name": "Allow always",
                        "response": {{"decision": "allow", "permissionUpdates": [{{"scope": "global"}}]}},
                    }},
                ],
            }},
        }})
    elif msg.get('id') == 'server-20':
        # Delay resolution slightly so WorkerRunner definitely observes unknown first,
        # then resolve via permission.resolved and immediately issue AskUserQuestion.
        time.sleep(0.15)
        send({{
            "method": "session/event",
            "params": {{
                "type": "permission.resolved",
                "sessionId": sid,
                "payload": {{
                    "eventId": "ev-perm-resolved-1",
                    "requestId": "req-perm-e2e",
                    "toolCallId": "tc-perm-1",
                    "turnId": "turn-e2e-1",
                    "decision": "allow",
                }},
            }},
        }})
        send({{
            "id": "server-21",
            "method": "interaction/requestUserInput",
            "params": {{
                "requestId": "req-ask-e2e",
                "sessionId": sid,
                "turnId": "turn-e2e-1",
                "toolCallId": "tc-ask-1",
                "toolName": "AskUserQuestion",
                "questions": [{{
                    "question": "Which branch name?",
                    "header": "Branch",
                    "options": [{{"label": "main", "value": "main"}}],
                    "multiSelect": False,
                }}],
            }},
        }})
    elif msg.get('id') == 'server-21':
        time.sleep(0.15)
        # Confirm UserInput lifecycle via permission.resolved (real zcode.cjs mapping!)
        send({{
            "method": "session/event",
            "params": {{
                "type": "permission.resolved",
                "sessionId": sid,
                "payload": {{
                    "eventId": "ev-ask-resolved-1",
                    "requestId": "req-ask-e2e",
                    "toolCallId": "tc-ask-1",
                    "turnId": "turn-e2e-1",
                    "decision": "modify",
                }},
            }},
        }})
        send({{
            "method": "session/event",
            "params": {{
                "type": "turn.terminal",
                "sessionId": sid,
                "payload": {{"turnId": "turn-e2e-1", "outcome": "success"}},
            }},
        }})
    elif method == 'session/stop':
        sys.exit(0)
""",
        )

        driver = ZCodeDriver(zcode_bin=fake_bin, host_db_path=self.host_db_path, rpc_timeout_sec=5.0)
        eng = Engine(self.store, host_adapter=self.host_adapter, driver=driver, runtime_execution="deferred")
        start_res = self._start_child(name="m7m8-e2e", engine=eng)
        child_id = start_res["node_id"]

        runner = WorkerRunner(
            self.store,
            engine=eng,
            driver=driver,
            host_adapter=self.host_adapter,
            poll_interval_ms=20,
            wait_poll_timeout_ms=2000,
        )

        seen_unknown_states: list[str] = []
        control_ids: list[str] = []

        def _on_wait(_assignment: RunAssignment, _handle: Any) -> None:
            waits = eng.list_waits(self.parent_caller, {"session_id": child_id})["waits"]
            open_w = [w for w in waits if w["state"] == "open"]
            self.assertEqual(len(open_w), 1)
            w = open_w[0]
            wid = w["wait_id"]
            if w["kind"] == "permission":
                answer = "allowOnce"
            else:
                answer = "feature-x"

            hook_out = eng.handle_hook(
                HookContext(
                    event="UserPromptSubmit",
                    invocation_id=str(uuid.uuid4()),
                    runtime_sid=self.parent_sid,
                    cwd=str(self.workspace_dir),
                    runtime_turn_id=f"turn-slash-{wid[:8]}",
                    raw_input={
                        "prompt": f"/side-sessions:respond {wid} {answer}",
                        "input_id": f"inp-{wid[:8]}",
                    },
                )
            )
            self.assertIn("[side-sessions:respond]", hook_out["additionalContext"])
            c_row = self.store.conn.execute(
                "SELECT control_id FROM control_commands WHERE wait_id = ?",
                (wid,),
            ).fetchone()
            control_ids.append(str(c_row["control_id"]))

        runner.on_wait = _on_wait

        # Intercept _poll_and_apply_control_commands to verify unknown state immediately after flush
        orig_poll = runner._poll_and_apply_control_commands

        def _wrapped_poll(assignment: RunAssignment, handle: Any):
            rcpt, resolved = orig_poll(assignment, handle)
            for cid in control_ids:
                c_row = self.store.conn.execute(
                    "SELECT state, receipt_ref FROM control_commands WHERE control_id = ?",
                    (cid,),
                ).fetchone()
                if c_row and c_row["state"] == "unknown":
                    seen_unknown_states.append(cid)
                    w_row = self.store.conn.execute(
                        "SELECT wait_id, state, nonce FROM wait_requests WHERE wait_id = (SELECT wait_id FROM control_commands WHERE control_id = ?)",
                        (cid,),
                    ).fetchone()
                    self.assertEqual(w_row["state"], "unknown")
                    # unknown must be visible in default list_waits, yet NOT re-submittable
                    vis_waits = eng.list_waits(self.parent_caller, {"session_id": child_id})["waits"]
                    self.assertTrue(any(vw["wait_id"] == w_row["wait_id"] and vw["state"] == "unknown" for vw in vis_waits))
                    with self.assertRaises(SideSessionError) as re_err:
                        eng.respond_to_wait(
                            self.parent_caller,
                            {
                                "request_id": str(uuid.uuid4()),
                                "wait_id": w_row["wait_id"],
                                "nonce": w_row["nonce"],
                                "response": {"kind": "input", "text": "dup"},
                            },
                        )
                    self.assertEqual(re_err.exception.code, ErrorCode.WAIT_ALREADY_RESPONDED)
            return rcpt, resolved

        runner._poll_and_apply_control_commands = _wrapped_poll  # type: ignore[method-assign]
        res = runner.run_node(child_id, once=True)
        self.assertTrue(res["ok"])
        self.assertEqual(len(control_ids), 2)
        self.assertEqual(len(set(seen_unknown_states)), 2, "Both waits must pass through 'unknown' before event confirmation")

        # After completion, both controls must be 'applied' with real event receipts and both waits 'resolved'
        for cid, expected_ev in zip(control_ids, ("ev-perm-resolved-1", "ev-ask-resolved-1")):
            ctrl = eng.get_control(self.parent_caller, {"control_id": cid})
            self.assertEqual(ctrl["status"], "applied")
            self.assertEqual(ctrl["receipt_ref"], expected_ev)

        all_waits = eng.list_waits(self.parent_caller, {"session_id": child_id, "include_resolved": True})["waits"]
        self.assertEqual(len(all_waits), 2)
        for aw in all_waits:
            self.assertEqual(aw["state"], "resolved")

        # Inspect wire NDJSON: strict schemas, exact server-N IDs, zero forbidden respond_* RPCs
        wire_msgs = [json.loads(line) for line in wire_log.read_text(encoding="utf-8").splitlines() if line.strip()]
        methods_sent = [m.get("method") for m in wire_msgs if "method" in m]
        for forbidden in ("respond_permission", "respond_elicitation", "session/respond_input"):
            self.assertNotIn(forbidden, methods_sent)

        by_id = {m.get("id"): m for m in wire_msgs if m.get("id") is not None}
        self.assertEqual(
            by_id["server-20"]["result"],
            {"decision": "allow", "reason": "Once", "permissionUpdates": [{"path": "a.txt"}]},
        )
        self.assertEqual(
            by_id["server-21"]["result"],
            {"action": "accept", "content": {"answer": "feature-x"}},
        )

        # Verify human approval target_hash bound to normalized WaitResponse
        perm_w = next(aw for aw in all_waits if aw["kind"] == "permission")
        expected_perm_hash = canonical_json_sha256({"kind": "permission", "option_id": "allowOnce", "decision": "allow"})
        self.assertEqual(perm_w["response_hash"], expected_perm_hash)
        expected_target_hash = sha256_hex(f"{perm_w['nonce']}:{expected_perm_hash}")
        cons = self.store.conn.execute(
            "SELECT target_hash FROM approval_consumptions WHERE target_id = ?",
            (perm_w["wait_id"],),
        ).fetchone()
        self.assertEqual(cons["target_hash"], expected_target_hash)

    def test_m8_flush_without_resolution_not_applied(self) -> None:
        fake_bin = _write_fake_zcode_bin(
            self.tmp_path,
            """
import json, sys
for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    msg = json.loads(raw)
    if msg.get('method') == 'session/create':
        p = msg['params']
        sys.stdout.write(json.dumps({
            "id": msg["id"],
            "result": {
                "session": {
                    "id": p["sessionId"],
                    "parentSessionId": p["parentSessionId"],
                    "mode": p["mode"],
                    "toolAllowlist": p.get("toolAllowlist", []),
                    "toolDenylist": p.get("toolDenylist", []),
                    "workspace": {"workspacePath": p["workspace"]["workspacePath"]},
                    "revision": 1,
                }
            }
        }) + '\\n')
        sys.stdout.flush()
    elif msg.get('method') == 'session/send':
        sys.stdout.write(json.dumps({"id": msg["id"], "result": {"status": "accepted", "turnId": "t-1"}}) + '\\n')
        sys.stdout.write(json.dumps({
            "id": "server-99",
            "method": "interaction/requestPermission",
            "params": {
                "requestId": "req-no-res-1",
                "sessionId": msg['params']['sessionId'],
                "turnId": "t-1",
                "toolCallId": "tc-1",
                "toolName": "Bash",
                "reason": "Run cmd",
                "riskLevel": "low",
                "input": {},
                "options": [{"optionId": "allowOnce", "kind": "allow_once", "name": "Allow", "response": {"decision": "allow"}}],
            }
        }) + '\\n')
        sys.stdout.flush()
    elif msg.get('method') == 'session/stop':
        sys.exit(0)
""",
        )
        driver = ZCodeDriver(zcode_bin=fake_bin, host_db_path=self.host_db_path, rpc_timeout_sec=5.0)
        assignment = RunAssignment(
            node_id=str(uuid.uuid4()),
            runtime_sid="sid-m8-nores",
            turn_seq=1,
            run_id=str(uuid.uuid4()),
            worker_turn_id=str(uuid.uuid4()),
            input_id=str(uuid.uuid4()),
            message_id=str(uuid.uuid4()),
            parent_node_id=self.parent_node["node_id"],
            dispatch_group_id="",
            member_id="",
            task_id=None,
            task_revision=None,
            owner_epoch=1,
            fencing_token="f-1",
        )
        spec = RuntimeCreateSpec(
            assignment=assignment,
            workspace_path=str(self.workspace_dir),
            parent_runtime_sid=self.parent_sid,
            mode="plan",
            model={},
            tool_allowlist=["Read"],
            tool_denylist=["Bash"],
        )
        handle = driver.create(spec)
        driver.send(handle, RuntimeInput(input_id="i-1", content="run"))
        evs = driver.events(handle).drain_available(300)
        self.assertEqual(len(evs), 1)
        bw = BoundWait(
            wait_id=str(uuid.uuid4()),
            node_id=assignment.node_id,
            run_id=assignment.run_id,
            runtime_turn_id="t-1",
            runtime_instance_id=handle.runtime_instance_id,
            owner_epoch=1,
            host_request_id="req-no-res-1",
            kind="permission",
            nonce="n-1",
            question="Run cmd",
            options=evs[0].wait_request["options"],
            required_authority="human",
            deadline_at=None,
            state="responding",
        )
        rcpt = driver.respond_wait(handle, bw, {"kind": "permission", "option_id": "allowOnce", "decision": "allow"}, "ctrl-1")
        self.assertEqual(rcpt.status, "unknown")
        self.assertEqual(rcpt.observed_wait_state, "unknown")
        self.assertIsNone(rcpt.host_receipt_id)
        driver.stop_and_wait(handle, deadline_ms=2000)

    def test_m8_external_resolution_ambiguous_match_multi_wait_late_event_and_disconnect_cleanup(self) -> None:
        # Setup child node + run via WorkerRunner helpers directly with fake ZCodeDriver
        start_res = self._start_child(name="m8-matrix")
        child_id = start_res["node_id"]
        run_id = start_res["run_id"]
        child_sid = start_res["runtime_session_id"]

        # Create a controllable handle in ZCodeDriver backed by a minimal sleeping subprocess
        sleeper_bin = _write_fake_zcode_bin(
            self.tmp_path,
            "import sys, time\nfor line in sys.stdin:\n    if 'session/stop' in line: sys.exit(0)\n",
        )
        driver = ZCodeDriver(zcode_bin=sleeper_bin, host_db_path=self.host_db_path)
        proc = driver._spawn_app_server(str(self.workspace_dir))
        inst_id = str(uuid.uuid4())
        from driver import _AppServerConnection  # noqa: E402
        from contracts import RuntimeHandle  # noqa: E402

        conn = _AppServerConnection(
            runtime_sid=child_sid,
            runtime_instance_id=inst_id,
            owner_connection_id=f"conn:{inst_id}",
            canonical_workspace=str(self.workspace_dir),
            parent_runtime_sid=self.parent_sid,
            mode="plan",
            model={},
            tool_allowlist=["Read"],
            tool_denylist=["Bash"],
            additional_directories=[],
            proc=proc,
            pid=proc.pid,
            process_started_at=None,
            process_group=proc.pid,
            status="running",
        )
        driver._connections[inst_id] = conn
        handle = RuntimeHandle(
            runtime_sid=child_sid,
            runtime_instance_id=inst_id,
            owner_connection_id=conn.owner_connection_id,
            snapshot_revision=1,
            canonical_workspace=str(self.workspace_dir),
        )
        assignment = RunAssignment(
            node_id=child_id,
            runtime_sid=child_sid,
            turn_seq=1,
            run_id=run_id,
            worker_turn_id=str(uuid.uuid4()),
            input_id=str(uuid.uuid4()),
            message_id=str(uuid.uuid4()),
            parent_node_id=self.parent_node["node_id"],
            dispatch_group_id="",
            member_id="",
            task_id=None,
            task_revision=None,
            owner_epoch=1,
            fencing_token="fence-m8",
        )
        runner = WorkerRunner(self.store, engine=self.engine, driver=driver, host_adapter=self.host_adapter)
        with self.store.transaction("IMMEDIATE") as txn:
            runner._register_owner_in_txn(
                txn,
                node_id=child_id,
                run_id=run_id,
                owner_epoch=1,
                fencing_token="fence-m8",
                runtime_instance_id=inst_id,
            )
            txn.execute("UPDATE turns SET execution_state = 'running' WHERE run_id = ?", (run_id,))

        # Record 2 waits sharing the SAME toolCallId ('tc-shared') to test ambiguous match & multi-wait
        w1 = runner._record_wait_event(
            assignment,
            handle,
            RuntimeEvent(
                event_id="req-w1",
                runtime_sid=child_sid,
                kind="wait_request",
                runtime_turn_id="turn-m8",
                wait_request={
                    "host_request_id": "req-w1",
                    "kind": "permission",
                    "nonce": "n-w1",
                    "question": "Allow 1?",
                    "options": ["allow"],
                    "tool_call_id": "tc-shared",
                    "turn_id": "turn-m8",
                },
            ),
        )
        w2 = runner._record_wait_event(
            assignment,
            handle,
            RuntimeEvent(
                event_id="req-w2",
                runtime_sid=child_sid,
                kind="wait_request",
                runtime_turn_id="turn-m8",
                wait_request={
                    "host_request_id": "req-w2",
                    "kind": "permission",
                    "nonce": "n-w2",
                    "question": "Allow 2?",
                    "options": ["allow"],
                    "tool_call_id": "tc-shared",
                    "turn_id": "turn-m8",
                },
            ),
        )

        # Insert an unsent local control ('queued') on w1
        unsent_cid = str(uuid.uuid4())
        with self.store.transaction("IMMEDIATE") as txn:
            txn.execute(
                """
                INSERT INTO control_commands (
                    control_id, request_id, node_id, run_id, owner_epoch,
                    kind, wait_id, payload_hash, payload, state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 1, 'respond_wait', ?, 'h', '{}', 'queued', '', '')
                """,
                (unsent_cid, str(uuid.uuid4()), child_id, run_id, w1),
            )

        # 1. Ambiguous match (missing request_id, shared tool_call_id 'tc-shared') -> must NOT confirm either!
        resumed = runner._resolve_wait_from_event(
            assignment,
            handle,
            RuntimeEvent(
                event_id="ev-ambig",
                runtime_sid=child_sid,
                kind="wait_resolved",
                runtime_turn_id="turn-m8",
                payload={"request_id": None, "tool_call_id": "tc-shared", "turn_id": "turn-m8", "event_id": "ev-ambig"},
            ),
        )
        self.assertFalse(resumed)
        self.assertEqual(
            self.store.conn.execute("SELECT state FROM wait_requests WHERE wait_id = ?", (w1,)).fetchone()["state"],
            "open",
        )
        self.assertEqual(
            self.store.conn.execute("SELECT state FROM wait_requests WHERE wait_id = ?", (w2,)).fetchone()["state"],
            "open",
        )

        # 2. External resolution of w1 by request_id:
        # - w1 becomes 'resolved'
        # - unsent local control becomes 'rejected' ('resolved_externally'), NOT 'applied'!
        # - w2 is still open, so run must NOT resume early!
        resumed_after_w1 = runner._resolve_wait_from_event(
            assignment,
            handle,
            RuntimeEvent(
                event_id="ev-ext-w1",
                runtime_sid=child_sid,
                kind="wait_resolved",
                runtime_turn_id="turn-m8",
                payload={"request_id": "req-w1", "tool_call_id": "tc-shared", "turn_id": "turn-m8", "event_id": "ev-ext-w1"},
            ),
        )
        self.assertFalse(resumed_after_w1, "Run must NOT resume while w2 is still unresolved")
        self.assertEqual(
            self.store.conn.execute("SELECT state FROM wait_requests WHERE wait_id = ?", (w1,)).fetchone()["state"],
            "resolved",
        )
        c_row = self.store.conn.execute(
            "SELECT state, receipt_ref FROM control_commands WHERE control_id = ?",
            (unsent_cid,),
        ).fetchone()
        self.assertEqual(c_row["state"], "rejected")
        self.assertEqual(c_row["receipt_ref"], "resolved_externally")
        self.assertEqual(
            self.store.conn.execute("SELECT execution_state FROM turns WHERE run_id = ?", (run_id,)).fetchone()["execution_state"],
            "waiting_input",
        )

        # 3. Now put w2 into 'unknown' with a sent 'unknown' control, then disconnect/close_run -> cleans 'unknown'!
        sent_cid = str(uuid.uuid4())
        with self.store.transaction("IMMEDIATE") as txn:
            txn.execute("UPDATE wait_requests SET state = 'unknown' WHERE wait_id = ?", (w2,))
            txn.execute(
                """
                INSERT INTO control_commands (
                    control_id, request_id, node_id, run_id, owner_epoch,
                    kind, wait_id, payload_hash, payload, state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 1, 'respond_wait', ?, 'h2', '{}', 'unknown', '', '')
                """,
                (sent_cid, str(uuid.uuid4()), child_id, run_id, w2),
            )
        exit_rcpt = driver.stop_and_wait(handle, deadline_ms=1000)
        self.assertTrue(exit_rcpt.exit_confirmed)
        from worker_runner import OwnerContext  # noqa: E402
        from contracts import ExitReceipt  # noqa: E402

        owner_ctx = OwnerContext(
            node_id=child_id,
            run_id=run_id,
            worker_id=runner.worker_id,
            owner_epoch=1,
            fencing_token="fence-m8",
        )
        cancelled_rcpt = ExitReceipt(
            runtime_instance_id=inst_id,
            process_identity={},
            exit_confirmed=True,
            runtime_outcome="cancelled",
            ended_at=exit_rcpt.ended_at,
            exit_code=0,
            evidence_ref="disconnect-cancel",
        )
        self.engine.close_run(owner_ctx, cancelled_rcpt, run_id=run_id)
        self.assertEqual(
            self.store.conn.execute("SELECT state FROM wait_requests WHERE wait_id = ?", (w2,)).fetchone()["state"],
            "cancelled",
        )
        # Uncertain control fact preserved as 'unknown'
        self.assertEqual(
            self.store.conn.execute("SELECT state FROM control_commands WHERE control_id = ?", (sent_cid,)).fetchone()["state"],
            "unknown",
        )

        # 4. Late event after run terminated must NOT revive run!
        late_res = runner._resolve_wait_from_event(
            assignment,
            handle,
            RuntimeEvent(
                event_id="ev-late",
                runtime_sid=child_sid,
                kind="wait_resolved",
                runtime_turn_id="turn-m8",
                payload={"request_id": "req-w2", "tool_call_id": "tc-shared", "turn_id": "turn-m8", "event_id": "ev-late"},
            ),
        )
        self.assertFalse(late_res)
        self.assertEqual(
            self.store.conn.execute("SELECT execution_state FROM turns WHERE run_id = ?", (run_id,)).fetchone()["execution_state"],
            "cancelled",
        )

    def test_m6_resume_retains_init_wait_and_m7_m8_plan_userinput_resolved_and_eof_cleanup(self) -> None:
        # Part A: session/resume retains reverse request during initialization
        sid = "sid-m6-resume-init"
        resume_bin = _write_fake_zcode_bin(
            self.tmp_path,
            """
import json, sys
for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    msg = json.loads(raw)
    if msg.get('method') == 'session/resume':
        p = msg['params']
        sys.stdout.write(json.dumps({
            "id": "server-30",
            "method": "interaction/requestUserInput",
            "params": {
                "requestId": "req-resume-plan-1",
                "sessionId": p["sessionId"],
                "turnId": "turn-res-1",
                "toolCallId": "tc-plan-1",
                "toolName": "ExitPlanMode",
                "schema": {"interaction": "plan_approval", "toolName": "ExitPlanMode"},
                "questions": [{
                    "question": "Review this implementation plan.",
                    "header": "Plan",
                    "options": [{"label": "Approve", "value": "approve", "description": "Start"}],
                    "multiSelect": False,
                }],
            },
        }) + '\\n')
        sys.stdout.write(json.dumps({
            "id": msg["id"],
            "result": {
                "snapshot": {
                    "revision": 3,
                    "session": {
                        "id": p["sessionId"],
                        "mode": "plan",
                        "toolAllowlist": p.get("toolAllowlist", []),
                        "toolDenylist": p.get("toolDenylist", []),
                        "workspace": {"workspacePath": """
            + repr(str(self.workspace_dir.resolve()))
            + """},
                    },
                }
            },
        }) + '\\n')
        sys.stdout.flush()
    elif msg.get('method') == 'session/stop':
        sys.exit(0)
""",
        )
        drv_res = ZCodeDriver(zcode_bin=resume_bin, host_db_path=self.host_db_path, rpc_timeout_sec=5.0)
        res_spec = RuntimeResumeSpec(
            assignment=RunAssignment(
                node_id=str(uuid.uuid4()),
                runtime_sid=sid,
                turn_seq=2,
                run_id=str(uuid.uuid4()),
                worker_turn_id=str(uuid.uuid4()),
                input_id=str(uuid.uuid4()),
                message_id=str(uuid.uuid4()),
                parent_node_id=self.parent_node["node_id"],
                dispatch_group_id="",
                member_id="",
                task_id=None,
                task_revision=None,
                owner_epoch=1,
                fencing_token="f-res",
            ),
            expected_workspace=str(self.workspace_dir),
            expected_parent_runtime_sid=self.parent_sid,
            mode="plan",
            model={},
            tool_allowlist=["Read"],
            tool_denylist=["Bash"],
        )
        res_handle = drv_res.resume(res_spec)
        res_conn = drv_res._connections[res_handle.runtime_instance_id]
        self.assertIn("req-resume-plan-1", res_conn.pending_waits)
        res_evs = drv_res.events(res_handle).drain_available(200)
        self.assertEqual(len(res_evs), 1)
        self.assertEqual(res_evs[0].wait_request["subtype"], "plan_approval")
        self.assertEqual(res_evs[0].wait_request["required_authority"], "human")
        drv_res.stop_and_wait(res_handle, deadline_ms=1000)

        # Calling respond_wait on closed handle raises WAIT_RESPONSE_UNAVAILABLE
        bw_closed = BoundWait(
            wait_id=str(uuid.uuid4()),
            node_id=res_spec.assignment.node_id,
            run_id=res_spec.assignment.run_id,
            runtime_turn_id="turn-res-1",
            runtime_instance_id=res_handle.runtime_instance_id,
            owner_epoch=1,
            host_request_id="req-resume-plan-1",
            kind="elicitation",
            nonce="n-res",
            question="Review this implementation plan.",
            options=res_evs[0].wait_request["options"],
            required_authority="human",
            deadline_at=None,
            state="open",
        )
        with self.assertRaises(SideSessionError) as unavail_err:
            drv_res.respond_wait(
                res_handle,
                bw_closed,
                {"kind": "elicitation", "action": "accept", "content": {"answer": "approve"}},
                "ctrl-closed",
            )
        self.assertEqual(unavail_err.exception.code, ErrorCode.WAIT_RESPONSE_UNAVAILABLE)

        # Part B: userInput.resolved confirms plan_approval; and subprocess EOF while unknown cleans wait
        eof_wire = self.tmp_path / "eof-wire.jsonl"
        eof_bin = _write_fake_zcode_bin(
            self.tmp_path,
            f"""
import json, sys, time
eof_wire = {str(eof_wire)!r}
sid = None
for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    msg = json.loads(raw)
    with open(eof_wire, 'a', encoding='utf-8') as f:
        f.write(json.dumps(msg) + '\\n')
    m = msg.get('method')
    if m == 'session/create':
        p = msg['params']
        sid = p['sessionId']
        sys.stdout.write(json.dumps({{
            "id": msg["id"],
            "result": {{
                "session": {{
                    "id": sid,
                    "parentSessionId": p["parentSessionId"],
                    "mode": p["mode"],
                    "toolAllowlist": p.get("toolAllowlist", []),
                    "toolDenylist": p.get("toolDenylist", []),
                    "workspace": {{"workspacePath": p["workspace"]["workspacePath"]}},
                    "revision": 1,
                }}
            }}
        }}) + '\\n')
        sys.stdout.flush()
    elif m == 'session/send':
        sys.stdout.write(json.dumps({{"id": msg["id"], "result": {{"status": "accepted", "turnId": "t-eof-1"}}}}) + '\\n')
        sys.stdout.write(json.dumps({{
            "id": "server-40",
            "method": "interaction/requestUserInput",
            "params": {{
                "requestId": "req-plan-ui-1",
                "sessionId": sid,
                "turnId": "t-eof-1",
                "toolCallId": "tc-plan-ui",
                "toolName": "ExitPlanMode",
                "schema": {{"interaction": "plan_approval"}},
                "questions": [{{
                    "question": "Review this implementation plan.",
                    "header": "Plan",
                    "options": [{{"label": "Approve", "value": "approve"}}],
                }}],
            }},
        }}) + '\\n')
        sys.stdout.flush()
    elif msg.get('id') == 'server-40':
        sys.stdout.write(json.dumps({{
            "method": "session/event",
            "params": {{
                "type": "userInput.resolved",
                "sessionId": sid,
                "payload": {{"eventId": "ev-ui-res-1", "requestId": "req-plan-ui-1", "cancelled": False}},
            }},
        }}) + '\\n')
        sys.stdout.write(json.dumps({{
            "id": "server-41",
            "method": "interaction/requestPermission",
            "params": {{
                "requestId": "req-eof-perm-1",
                "sessionId": sid,
                "turnId": "t-eof-1",
                "toolCallId": "tc-eof-perm",
                "toolName": "Bash",
                "reason": "Crash before resolve",
                "riskLevel": "low",
                "input": {{}},
                "options": [{{"optionId": "allowOnce", "kind": "allow_once", "name": "Allow", "response": {{"decision": "allow"}}}}],
            }},
        }}) + '\\n')
        sys.stdout.flush()
    elif msg.get('id') == 'server-41':
        # Crash/exit immediately after receiving reply without sending permission.resolved!
        time.sleep(0.05)
        sys.exit(1)
""",
        )
        drv_eof = ZCodeDriver(zcode_bin=eof_bin, host_db_path=self.host_db_path, rpc_timeout_sec=5.0)
        eng_eof = Engine(self.store, host_adapter=self.host_adapter, driver=drv_eof, runtime_execution="deferred")
        child = self._start_child(name="m8-eof-child", engine=eng_eof)
        cid_node = child["node_id"]
        runner_eof = WorkerRunner(
            self.store,
            engine=eng_eof,
            driver=drv_eof,
            host_adapter=self.host_adapter,
            poll_interval_ms=20,
        )

        def _on_wait_eof(_a: RunAssignment, _h: Any) -> None:
            waits = eng_eof.list_waits(self.parent_caller, {"session_id": cid_node})["waits"]
            for w in waits:
                if w["state"] != "open":
                    continue
                ans = "approve" if w["kind"] == "elicitation" else "allowOnce"
                eng_eof.handle_hook(
                    HookContext(
                        event="UserPromptSubmit",
                        invocation_id=str(uuid.uuid4()),
                        runtime_sid=self.parent_sid,
                        cwd=str(self.workspace_dir),
                        runtime_turn_id=f"t-slash-{w['wait_id'][:8]}",
                        raw_input={"prompt": f"/side-sessions:respond {w['wait_id']} {ans}", "input_id": f"inp-{w['wait_id'][:8]}"},
                    )
                )

        runner_eof.on_wait = _on_wait_eof
        eof_res = runner_eof.run_node(cid_node, once=True)
        self.assertTrue(eof_res["ok"])
        waits_after = eng_eof.list_waits(self.parent_caller, {"session_id": cid_node, "include_resolved": True})["waits"]
        by_req = {w["host_request_id"]: w for w in waits_after}
        self.assertEqual(by_req["req-plan-ui-1"]["state"], "resolved")
        self.assertEqual(by_req["req-eof-perm-1"]["state"], "cancelled")
        # Default list_waits must now be empty
        self.assertEqual(eng_eof.list_waits(self.parent_caller, {"session_id": cid_node})["waits"], [])


if __name__ == "__main__":
    unittest.main()
