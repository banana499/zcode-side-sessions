#!/usr/bin/env python3
"""Unit tests for desktop_bridge.py read-only sidebar projection and comm state."""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import uuid

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PLUGIN_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from contracts import CallerContext, HookContext  # type: ignore  # noqa: E402
from desktop_bridge import FORBIDDEN_EXPORT_KEYS, ProjectionReader, build_projection_snapshot  # type: ignore  # noqa: E402
from driver import ScriptedFakeDriver  # type: ignore  # noqa: E402
from engine import Engine  # type: ignore  # noqa: E402
from host_adapter import HostAdapter  # type: ignore  # noqa: E402
from state import open_store  # type: ignore  # noqa: E402

VALID_BG = (
    "总体目标：验证 desktop_bridge.py 三库只读联查、comm 投影字段、commSignature 与敏感字段过滤。\n"
    "已有决策：使用完全隔离的 tempfile.TemporaryDirectory 构建 state.sqlite3、db.sqlite 与 tasks-index.sqlite。\n"
    "约束：严禁导出 brief/full_report/fencing_token/owner_token 等内部敏感字段。"
)


class TestDesktopBridgeProjection(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="ss-desktop-bridge-test-")
        self.tmp_path = Path(self._tmp.name).resolve()
        self.state_root = self.tmp_path / "state"
        self.workspace_dir = self.tmp_path / "workspace"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.cli_db_path = self.tmp_path / "cli-db.sqlite"
        self.tasks_index_path = self.tmp_path / "tasks-index.sqlite"

        self._init_cli_and_index_dbs()

        self.store = open_store(self.state_root, writable=True)
        self.driver = ScriptedFakeDriver(host_db_path=self.cli_db_path, sync_to_host_db=False)
        self.host_adapter = HostAdapter(
            store=self.store,
            state_root=self.state_root,
            host_db_path=self.cli_db_path,
        )
        self.engine = Engine(
            self.store,
            clock=lambda: datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc),
            host_adapter=self.host_adapter,
            driver=self.driver,
            worktrees_home=self.state_root / "worktrees",
        )
        self.parent_caller = CallerContext(
            runtime_sid="sess_parent_main",
            runtime_turn_id="turn-p-1",
            workspace_path=str(self.workspace_dir),
            connection_id="stdio:test",
        )

    def tearDown(self) -> None:
        try:
            self.store.close()
        except Exception:
            pass
        self._tmp.cleanup()

    def _init_cli_and_index_dbs(self) -> None:
        with closing(sqlite3.connect(self.cli_db_path)) as c, c:
            c.execute(
                """
                CREATE TABLE session (
                    id TEXT PRIMARY KEY,
                    parent_id TEXT,
                    title TEXT,
                    time_archived INTEGER,
                    time_deleted INTEGER
                )
                """
            )
            c.execute(
                "INSERT INTO session (id, parent_id, title, time_archived, time_deleted) VALUES (?, NULL, ?, NULL, NULL)",
                ("sess_parent_main", "Parent Main Title"),
            )

        with closing(sqlite3.connect(self.tasks_index_path)) as c, c:
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
            c.execute(
                "INSERT INTO tasks (task_id, workspace_path, project_id, cli_created_at, archived, deleted) VALUES (?, ?, ?, ?, 0, 0)",
                ("sess_parent_main", os.path.realpath(self.workspace_dir), "proj-local-1", 1700000000000),
            )

    def test_projection_comm_counts_signature_ack_and_forbidden_keys(self) -> None:
        st = self.engine.start_session(
            self.parent_caller,
            {
                "initiation": "user_asked",
                "request_id": str(uuid.uuid4()),
                "title": "Child Research Node",
                "prompt": "Check database schema.",
                "context": "fresh",
                "background": VALID_BG,
                "task_kind": "read_only",
                "use_worktree": False,
                "name": "research-one",
            },
        )
        child_sid = st["runtime_session_id"]
        child_node_id = st["node_id"]

        with closing(sqlite3.connect(self.cli_db_path)) as c, c:
            c.execute(
                "INSERT INTO session (id, parent_id, title, time_archived, time_deleted) VALUES (?, ?, ?, NULL, NULL)",
                (child_sid, "sess_parent_main", "Child Research Node"),
            )
        with closing(sqlite3.connect(self.tasks_index_path)) as c, c:
            c.execute(
                "INSERT INTO tasks (task_id, workspace_path, project_id, cli_created_at, archived, deleted) VALUES (?, ?, ?, ?, 0, 0)",
                (child_sid, os.path.realpath(self.workspace_dir), "proj-local-1", 1700000001000),
            )

        child_caller = CallerContext(
            runtime_sid=child_sid,
            workspace_path=str(self.workspace_dir),
        )
        long_recap = "A" * 200
        rep_res = self.engine.report_child_turn(
            child_caller,
            {
                "request_id": str(uuid.uuid4()),
                "run_id": st["run_id"],
                "turn_seq": st["turn_seq"],
                "worker_turn_id": st["worker_turn_id"],
                "phase": "final",
                "report_revision": None,
                "outcome": "success",
                "recap": long_recap,
                "full_report": "SECRET_FULL_REPORT_BODY_NEVER_EXPORT",
                "blocked": False,
                "block_reason": None,
                "artifacts": [],
            },
        )
        event_id = rep_res["event_id"]

        reader = ProjectionReader(
            self.state_root,
            cli_db_path=self.cli_db_path,
            tasks_index_path=self.tasks_index_path,
            persist_export=True,
        )
        try:
            snap1 = reader.snapshot()
            by_id1 = {n["nodeId"]: n for n in snap1["nodes"]}
            c1 = by_id1[child_node_id]
            p1 = by_id1[c1["parentNodeId"]]

            self.assertEqual(c1["indexState"], "indexed")
            self.assertEqual(c1["comm"]["toParentUnread"], 1)
            self.assertTrue(c1["reportPendingAck"])
            self.assertTrue(c1["comm"]["idleParentHint"])
            self.assertEqual(len(c1["comm"]["lastToParent"]["recapPreview"]), 120)
            self.assertEqual(p1["childrenUnreadTotal"], 1)
            sig_before = c1["comm"]["commSignature"]
            rev_before = snap1["projectionRevision"]

            raw_json = json.dumps(snap1, ensure_ascii=False)
            for forbidden in FORBIDDEN_EXPORT_KEYS:
                self.assertNotIn(f'"{forbidden}"', raw_json)
            self.assertNotIn("SECRET_FULL_REPORT_BODY_NEVER_EXPORT", raw_json)
            self.assertNotIn(VALID_BG[:30], raw_json)

            # Parent presents and acknowledges the event
            self.engine.handle_hook(
                HookContext(
                    event="UserPromptSubmit",
                    invocation_id=str(uuid.uuid4()),
                    runtime_sid="sess_parent_main",
                    cwd=str(self.workspace_dir),
                    runtime_turn_id="turn-p-2",
                )
            )
            self.engine.ack_events(
                CallerContext(
                    runtime_sid="sess_parent_main",
                    runtime_turn_id="turn-p-2",
                    workspace_path=str(self.workspace_dir),
                ),
                {"request_id": str(uuid.uuid4()), "event_ids": [event_id]},
            )

            snap2 = reader.snapshot()
            by_id2 = {n["nodeId"]: n for n in snap2["nodes"]}
            c2 = by_id2[child_node_id]
            p2 = by_id2[c2["parentNodeId"]]

            self.assertEqual(c2["comm"]["toParentUnread"], 0)
            self.assertFalse(c2["reportPendingAck"])
            self.assertEqual(p2["childrenUnreadTotal"], 0)
            self.assertNotEqual(c2["comm"]["commSignature"], sig_before)
            self.assertGreater(snap2["projectionRevision"], rev_before)
        finally:
            reader.close()


if __name__ == "__main__":
    unittest.main()
