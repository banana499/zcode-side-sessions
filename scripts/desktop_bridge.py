from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from state import atomic_export, resolve_state_root, utc_now_iso  # noqa: E402

NODES_SQL = """
SELECT n.node_id, n.parent_node_id, n.runtime_session_id, n.name, n.title, n.node_status, n.canonical_workspace,
       n.created_at, n.revision, p.runtime_session_id AS parent_sid
FROM nodes n LEFT JOIN nodes p ON p.node_id = n.parent_node_id
"""

LAST_TURN_SQL = "SELECT run_id, execution_state, outcome FROM turns WHERE node_id=? ORDER BY turn_seq DESC LIMIT 1"

COMM_SQL = {
    "toParentUnread": "SELECT COUNT(*) FROM outbox_events WHERE child_node_id=? AND state IN ('pending','presented')",
    "toChildQueued": "SELECT COUNT(*) FROM inbox_messages WHERE target_node_id=? AND state IN ('queued','claimed')",
    "waitingInput": (
        "SELECT EXISTS(SELECT 1 FROM turns WHERE node_id=? AND execution_state='waiting_input') "
        "OR EXISTS(SELECT 1 FROM wait_requests WHERE node_id=? AND state IN ('open','responding'))"
    ),
    "reportPendingAck": (
        "SELECT EXISTS(SELECT 1 FROM outbox_events WHERE child_node_id=? AND kind='terminal' AND state!='acked')"
    ),
    "lastToParent": (
        "SELECT event_id, kind, created_at, payload FROM outbox_events "
        "WHERE child_node_id=? ORDER BY event_seq DESC LIMIT 1"
    ),
    "lastOutboxAt": "SELECT MAX(created_at) FROM outbox_events WHERE child_node_id=?",
    "lastInboxAt": "SELECT MAX(created_at) FROM inbox_messages WHERE target_node_id=?",
    "parentNullChildUnread": (
        "SELECT COUNT(*) FROM outbox_events "
        "WHERE parent_node_id=? AND child_node_id IS NULL AND state IN ('pending','presented')"
    ),
    "sigParts": (
        "SELECT (SELECT MAX(event_seq) FROM outbox_events WHERE child_node_id=:n), "
        "(SELECT MAX(acked_at) FROM outbox_events WHERE child_node_id=:n), "
        "(SELECT MAX(updated_at) FROM inbox_messages WHERE target_node_id=:n), "
        "(SELECT MAX(created_at) FROM inbox_messages WHERE target_node_id=:n), "
        "(SELECT MAX(updated_at) FROM wait_requests WHERE node_id=:n), "
        "(SELECT MAX(event_seq) FROM outbox_events WHERE parent_node_id=:n AND child_node_id IS NULL), "
        "(SELECT MAX(acked_at) FROM outbox_events WHERE parent_node_id=:n AND child_node_id IS NULL)"
    ),
}

FORBIDDEN_EXPORT_KEYS = frozenset(
    {
        "brief",
        "brief_content",
        "full_report",
        "report_ref",
        "linked_sessions_now",
        "formatted_event",
        "owner_token",
        "fencing_token",
        "nonce",
        "prompt_nonce",
        "approval_token",
        "real_input_id",
        "task_hash",
    }
)
_NORMALIZED_FORBIDDEN_EXPORT_KEYS = frozenset(k.replace("_", "").lower() for k in FORBIDDEN_EXPORT_KEYS)


def validate_public_projection(obj: Any) -> None:
    """Recursively verify that no forbidden secret or full-text keys exist in a public projection."""
    stack: list[Any] = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, Mapping):
            for k, v in cur.items():
                norm_k = str(k).replace("_", "").lower()
                if norm_k in _NORMALIZED_FORBIDDEN_EXPORT_KEYS:
                    raise ValueError(f"Forbidden key in public projection: {k!r}")
                stack.append(v)
        elif isinstance(cur, (list, tuple)):
            stack.extend(cur)


def _ro_connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


class _ReadOnlyDbHandle:
    """Maintains a persistent read-only SQLite connection that reopens on inode replacement."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._conn: sqlite3.Connection | None = None
        self._ident: tuple[int, int] | None = None
        self._last_data_version: int | None = None
        self._last_file_sig: tuple[int, int, tuple[int, int]] | None = None
        self._cols_cache: dict[str, set[str]] = {}

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None
            self._ident = None
            self._last_data_version = None
            self._last_file_sig = None
            self._cols_cache.clear()

    def get_conn(self) -> tuple[sqlite3.Connection | None, bool]:
        """Return (conn, changed_since_last_call)."""
        try:
            st = os.stat(self.path)
        except OSError:
            had_conn = self._conn is not None or self._ident is not None
            self.close()
            return None, had_conn

        wal_sig: tuple[int, int] = (0, 0)
        try:
            wst = os.stat(f"{self.path}-wal")
            wal_sig = (wst.st_mtime_ns, wst.st_size)
        except OSError:
            pass

        ident = (st.st_dev, st.st_ino)
        file_sig = (st.st_mtime_ns, st.st_size, wal_sig)
        reopened = False
        if self._conn is None or self._ident != ident:
            self.close()
            try:
                self._conn = _ro_connect(self.path)
                self._ident = ident
                reopened = True
            except sqlite3.Error:
                self.close()
                return None, True

        try:
            row = self._conn.execute("PRAGMA data_version").fetchone()
            dv = int(row[0]) if row is not None else 0
        except sqlite3.Error:
            self.close()
            return None, True

        changed = reopened or (self._last_data_version != dv) or (self._last_file_sig != file_sig)
        if changed:
            self._cols_cache.clear()
        self._last_data_version = dv
        self._last_file_sig = file_sig
        return self._conn, changed

    def table_columns(self, table_name: str) -> set[str]:
        if self._conn is None:
            return set()
        if table_name not in self._cols_cache:
            self._cols_cache[table_name] = _table_columns(self._conn, table_name)
        return self._cols_cache[table_name]


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
        (table_name,),
    ).fetchone()
    return row is not None


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    if not _table_exists(conn, table_name):
        return set()
    return {str(r["name"]) for r in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}


def _non_empty_ts(val: Any) -> bool:
    return val not in (None, 0, "", "0", False)


def _extract_recap_preview(raw_payload: Any, max_codepoints: int = 120) -> str:
    if not isinstance(raw_payload, str) or not raw_payload.strip():
        return ""
    try:
        data = json.loads(raw_payload)
    except Exception:
        return ""
    if not isinstance(data, Mapping):
        return ""
    recap = data.get("recap")
    if not isinstance(recap, str):
        recap = data.get("summary") if isinstance(data.get("summary"), str) else ""
    text = " ".join(recap.split())
    return text[:max_codepoints]


class ProjectionReader:
    """Read-only bridge across state.sqlite3, CLI db.sqlite, and tasks-index.sqlite."""

    EXPORT_REL_PATH = "exports/sidebar-tree-v1.json"

    def __init__(
        self,
        state_root: Path | str | None = None,
        *,
        cli_db_path: Path | str | None = None,
        tasks_index_path: Path | str | None = None,
        persist_export: bool = True,
    ) -> None:
        self.state_root = Path(state_root).expanduser().resolve() if state_root else resolve_state_root()
        if cli_db_path is not None:
            self.cli_db_path = Path(cli_db_path).expanduser().resolve()
        else:
            env_cli = os.environ.get("ZCODE_HOST_DB_PATH") or os.environ.get("ZCODE_CLI_DB_PATH")
            self.cli_db_path = (
                Path(env_cli).expanduser().resolve()
                if env_cli
                else (Path.home() / ".zcode" / "cli" / "db" / "db.sqlite")
            )
        if tasks_index_path is not None:
            self.tasks_index_path = Path(tasks_index_path).expanduser().resolve()
        else:
            env_idx = os.environ.get("ZCODE_TASKS_INDEX_PATH") or os.environ.get("ZCODE_TASKS_INDEX_DB_PATH")
            self.tasks_index_path = (
                Path(env_idx).expanduser().resolve()
                if env_idx
                else (Path.home() / ".zcode" / "v2" / "tasks-index.sqlite")
            )
        self.persist_export = bool(persist_export)

        self._state_db = _ReadOnlyDbHandle(self.state_root / "state.sqlite3")
        self._cli_db = _ReadOnlyDbHandle(self.cli_db_path)
        self._idx_db = _ReadOnlyDbHandle(self.tasks_index_path)

        self._projection_revision: int = 0
        self._last_digest: str | None = None
        self._last_snapshot: dict[str, Any] | None = None
        self._has_live_snapshot: bool = False
        self._load_persisted_baseline()

    def close(self) -> None:
        self._state_db.close()
        self._cli_db.close()
        self._idx_db.close()

    def _load_persisted_baseline(self) -> None:
        export_file = self.state_root / self.EXPORT_REL_PATH
        if not export_file.is_file() or export_file.is_symlink():
            return
        try:
            data = json.loads(export_file.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("schemaVersion") == 1:
                validate_public_projection(data)
                self._projection_revision = int(data.get("projectionRevision") or 0)
                self._last_digest = self._compute_snapshot_digest(
                    str(data.get("storeInstanceId") or ""),
                    list(data.get("nodes") or []),
                )
                self._last_snapshot = data
        except Exception:
            pass

    @staticmethod
    def _compute_snapshot_digest(store_instance_id: str, nodes: list[dict[str, Any]]) -> str:
        canonical = json.dumps(
            {"storeInstanceId": store_instance_id, "nodes": nodes},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _read_cli_session(self, conn: sqlite3.Connection | None, sid: str | None) -> dict[str, Any]:
        info = {
            "cliExists": False,
            "cliArchived": False,
            "cliDeleted": False,
            "parentId": None,
            "title": None,
        }
        if conn is None or not sid:
            return info
        try:
            cols = self._cli_db.table_columns("session") if conn is self._cli_db._conn else _table_columns(conn, "session")
            if "id" not in cols:
                return info
            row = conn.execute("SELECT * FROM session WHERE id=? LIMIT 1", (sid,)).fetchone()
            if row is None:
                return info
            d = dict(row)
            info["cliExists"] = True
            info["cliArchived"] = _non_empty_ts(d.get("time_archived")) or _non_empty_ts(d.get("archived"))
            info["cliDeleted"] = _non_empty_ts(d.get("time_deleted")) or _non_empty_ts(d.get("deleted"))
            info["parentId"] = d.get("parent_id") or d.get("parentId")
            info["title"] = d.get("title")
        except sqlite3.Error:
            pass
        return info

    def _read_tasks_index(
        self,
        conn: sqlite3.Connection | None,
        sid: str | None,
        workspace_path: str | None,
    ) -> dict[str, Any]:
        res = {
            "indexed": False,
            "projectId": None,
            "archived": False,
            "deleted": False,
        }
        if conn is None or not sid:
            return res
        try:
            cols = self._idx_db.table_columns("tasks") if conn is self._idx_db._conn else _table_columns(conn, "tasks")
            if "task_id" not in cols:
                return res
            row = None
            if workspace_path and "workspace_path" in cols:
                row = conn.execute(
                    "SELECT * FROM tasks WHERE task_id=? AND workspace_path=? LIMIT 1",
                    (sid, workspace_path),
                ).fetchone()
            if row is None:
                row = conn.execute("SELECT * FROM tasks WHERE task_id=? LIMIT 1", (sid,)).fetchone()
            if row is None:
                return res
            d = dict(row)
            has_cli_created = ("cli_created_at" not in cols) or (d.get("cli_created_at") is not None)
            res["indexed"] = bool(has_cli_created)
            res["projectId"] = d.get("project_id")
            res["archived"] = _non_empty_ts(d.get("archived"))
            res["deleted"] = _non_empty_ts(d.get("deleted"))
        except sqlite3.Error:
            pass
        return res

    def snapshot(self) -> dict[str, Any]:
        state_conn, state_changed = self._state_db.get_conn()
        cli_conn, cli_changed = self._cli_db.get_conn()
        idx_conn, idx_changed = self._idx_db.get_conn()

        if (
            self._has_live_snapshot
            and self._last_snapshot is not None
            and not (state_changed or cli_changed or idx_changed)
        ):
            return self._last_snapshot

        if state_conn is None:
            empty_nodes: list[dict[str, Any]] = []
            digest = self._compute_snapshot_digest("", empty_nodes)
            if digest != self._last_digest or self._projection_revision == 0:
                self._projection_revision += 1
                self._last_digest = digest
            snap_empty = {
                "schemaVersion": 1,
                "storeInstanceId": "",
                "stateRevision": 0,
                "projectionRevision": self._projection_revision,
                "nodes": empty_nodes,
            }
            self._last_snapshot = snap_empty
            self._has_live_snapshot = True
            return snap_empty

        store_instance_id = ""
        state_revision = 0
        try:
            meta_table = "schema_meta" if _table_exists(state_conn, "schema_meta") else "store_meta"
            if _table_exists(state_conn, meta_table):
                meta_row = state_conn.execute(
                    f"SELECT store_instance_id, revision FROM {meta_table} WHERE id=1"
                ).fetchone()
                if meta_row is not None:
                    store_instance_id = str(meta_row["store_instance_id"] or "")
                    state_revision = int(meta_row["revision"] or 0)
        except sqlite3.Error:
            pass

        has_probe_table = _table_exists(state_conn, "desktop_index_probe")
        has_turns_table = _table_exists(state_conn, "turns")
        has_outbox_table = _table_exists(state_conn, "outbox_events")
        has_inbox_table = _table_exists(state_conn, "inbox_messages")
        has_wait_table = _table_exists(state_conn, "wait_requests")
        has_owners_table = _table_exists(state_conn, "owners")
        has_ops_table = _table_exists(state_conn, "operations")
        has_leases_table = _table_exists(state_conn, "interactive_leases")
        has_wt_jobs_table = _table_exists(state_conn, "worktree_jobs")
        has_worktrees_table = _table_exists(state_conn, "worktrees")
        now_iso = utc_now_iso()

        raw_nodes = state_conn.execute(NODES_SQL).fetchall() if _table_exists(state_conn, "nodes") else []

        nodes_by_id: dict[str, dict[str, Any]] = {}
        parent_null_unread: dict[str, int] = {}
        sig_parts_by_id: dict[str, list[Any]] = {}

        for r in raw_nodes:
            node_id = str(r["node_id"])
            parent_node_id = str(r["parent_node_id"]) if r["parent_node_id"] else None
            sid = str(r["runtime_session_id"]) if r["runtime_session_id"] else None
            parent_sid = str(r["parent_sid"]) if r["parent_sid"] else None
            workspace_path = str(r["canonical_workspace"] or "")
            node_status = str(r["node_status"] or "active")

            exec_state: str | None = None
            last_outcome: str | None = None
            active_run_id: str | None = None
            if has_turns_table:
                t_row = state_conn.execute(LAST_TURN_SQL, (node_id,)).fetchone()
                if t_row is not None:
                    exec_state = str(t_row["execution_state"]) if t_row["execution_state"] else None
                    last_outcome = str(t_row["outcome"]) if t_row["outcome"] else None
                    if exec_state in ("queued", "starting", "running", "waiting_input", "stopping") and t_row["run_id"]:
                        active_run_id = str(t_row["run_id"])

            probe_state: str | None = None
            probe_checked_at: str | None = None
            if has_probe_table:
                p_row = state_conn.execute(
                    "SELECT state, checked_at FROM desktop_index_probe WHERE node_id=?",
                    (node_id,),
                ).fetchone()
                if p_row is not None:
                    probe_state = str(p_row["state"]) if p_row["state"] else None
                    probe_checked_at = str(p_row["checked_at"]) if p_row["checked_at"] else None

            cli_info = self._read_cli_session(cli_conn, sid)
            idx_info = self._read_tasks_index(idx_conn, sid, workspace_path or None)

            if idx_info["indexed"]:
                index_state = "indexed"
            elif cli_info["cliExists"]:
                index_state = "pending"
            else:
                index_state = "absent"

            archived = bool(
                node_status == "archived"
                or cli_info["cliArchived"]
                or cli_info["cliDeleted"]
                or idx_info["archived"]
                or idx_info["deleted"]
            )

            lineage_mismatch = False
            if parent_node_id and cli_info["cliExists"] and parent_sid:
                cli_parent = str(cli_info["parentId"] or "")
                if cli_parent != parent_sid:
                    lineage_mismatch = True

            to_parent_unread = 0
            to_child_queued = 0
            waiting_input = False
            report_pending_ack = False
            last_to_parent: dict[str, Any] | None = None
            last_outbox_at: str | None = None
            last_inbox_at: str | None = None
            null_child_unread = 0
            sig_parts: list[Any] = [None, None, None, None, None, None, None]

            if has_outbox_table:
                to_parent_unread = int(
                    state_conn.execute(COMM_SQL["toParentUnread"], (node_id,)).fetchone()[0]
                )
                report_pending_ack = bool(
                    state_conn.execute(COMM_SQL["reportPendingAck"], (node_id,)).fetchone()[0]
                )
                ltp_row = state_conn.execute(COMM_SQL["lastToParent"], (node_id,)).fetchone()
                if ltp_row is not None:
                    last_to_parent = {
                        "eventId": str(ltp_row["event_id"]),
                        "kind": str(ltp_row["kind"]),
                        "at": str(ltp_row["created_at"] or ""),
                        "recapPreview": _extract_recap_preview(ltp_row["payload"], 120),
                    }
                lo_row = state_conn.execute(COMM_SQL["lastOutboxAt"], (node_id,)).fetchone()
                if lo_row is not None and lo_row[0]:
                    last_outbox_at = str(lo_row[0])
                null_child_unread = int(
                    state_conn.execute(COMM_SQL["parentNullChildUnread"], (node_id,)).fetchone()[0]
                )

            if has_inbox_table:
                to_child_queued = int(
                    state_conn.execute(COMM_SQL["toChildQueued"], (node_id,)).fetchone()[0]
                )
                li_row = state_conn.execute(COMM_SQL["lastInboxAt"], (node_id,)).fetchone()
                if li_row is not None and li_row[0]:
                    last_inbox_at = str(li_row[0])

            if has_turns_table and has_wait_table:
                waiting_input = bool(
                    state_conn.execute(COMM_SQL["waitingInput"], (node_id, node_id)).fetchone()[0]
                )
            elif has_turns_table:
                waiting_input = exec_state == "waiting_input"

            active_wait_id: str | None = None
            waiting_input_kind: str | None = None
            if has_wait_table:
                w_open = state_conn.execute(
                    "SELECT wait_id, kind FROM wait_requests WHERE node_id=? AND state IN ('open','responding') ORDER BY created_at DESC LIMIT 1",
                    (node_id,),
                ).fetchone()
                if w_open is not None:
                    active_wait_id = str(w_open["wait_id"]) if w_open["wait_id"] else None
                    waiting_input_kind = str(w_open["kind"]) if w_open["kind"] else None

            branch_name: str | None = None
            worktree_state: str | None = None
            if has_worktrees_table:
                wt_cols = self._state_db.table_columns("worktrees")
                has_merged_col = "merged_commit" in wt_cols
                wt_sql = (
                    "SELECT branch, state, merged_commit FROM worktrees WHERE node_id=? ORDER BY created_at DESC LIMIT 1"
                    if has_merged_col
                    else "SELECT branch, state, NULL AS merged_commit FROM worktrees WHERE node_id=? ORDER BY created_at DESC LIMIT 1"
                )
                wt_row = state_conn.execute(wt_sql, (node_id,)).fetchone()
                if wt_row is not None:
                    branch_name = str(wt_row["branch"]) if wt_row["branch"] else None
                    raw_wt_st = str(wt_row["state"]) if wt_row["state"] else None
                    if wt_row["merged_commit"] and raw_wt_st not in ("cleaned", "retained_dirty", "reconciliation"):
                        worktree_state = "merged"
                    else:
                        worktree_state = raw_wt_st

            has_active_turn = bool(active_run_id is not None or exec_state == "reconciliation")
            if has_turns_table and not has_active_turn:
                any_act_turn = state_conn.execute(
                    "SELECT 1 FROM turns WHERE node_id=? AND execution_state IN ('queued','starting','running','waiting_input','stopping','reconciliation') LIMIT 1",
                    (node_id,),
                ).fetchone()
                has_active_turn = any_act_turn is not None

            has_live_owner = False
            if has_owners_table:
                ow_row = state_conn.execute(
                    "SELECT 1 FROM owners WHERE node_id=? AND state='active' AND current_run_id IS NOT NULL LIMIT 1",
                    (node_id,),
                ).fetchone()
                has_live_owner = ow_row is not None

            has_pending_op = False
            if has_ops_table:
                op_row = state_conn.execute(
                    """
                    SELECT 1 FROM operations
                    WHERE node_id=?
                      AND stage IN ('preparing_context','awaiting_context_acceptance','ready_for_admission',
                                    'reserved','worktree_created','session_created','brief_accepted','running','reconciliation')
                    LIMIT 1
                    """,
                    (node_id,),
                ).fetchone()
                has_pending_op = op_row is not None

            has_active_lease = False
            if has_leases_table:
                lease_cols = self._state_db.table_columns("interactive_leases")
                exp_col = (
                    "expires_at"
                    if "expires_at" in lease_cols
                    else ("lease_until" if "lease_until" in lease_cols else None)
                )
                if exp_col is not None:
                    ls_row = state_conn.execute(
                        f"SELECT 1 FROM interactive_leases WHERE node_id=? AND {exp_col} > ? LIMIT 1",
                        (node_id, now_iso),
                    ).fetchone()
                    has_active_lease = ls_row is not None

            has_active_wt_job = False
            if has_wt_jobs_table:
                wj_row = state_conn.execute(
                    "SELECT 1 FROM worktree_jobs WHERE node_id=? AND state IN ('queued','running','prepared') LIMIT 1",
                    (node_id,),
                ).fetchone()
                has_active_wt_job = wj_row is not None

            can_resume_for_index = bool(
                cli_info["cliExists"]
                and not archived
                and not has_active_turn
                and not has_live_owner
                and to_child_queued == 0
                and not has_pending_op
                and not has_active_lease
                and not has_active_wt_job
            )
            can_cancel = bool(
                parent_node_id
                and not archived
                and active_run_id is not None
                and exec_state in ("queued", "starting", "running", "waiting_input")
            )
            can_archive = bool(
                parent_node_id
                and not archived
                and not has_active_turn
                and not has_live_owner
                and to_child_queued == 0
                and not has_pending_op
                and not has_active_lease
                and not has_active_wt_job
            )

            if has_outbox_table and has_inbox_table and has_wait_table:
                sp_row = state_conn.execute(COMM_SQL["sigParts"], {"n": node_id}).fetchone()
                if sp_row is not None:
                    sig_parts = list(sp_row)

            if last_outbox_at and last_inbox_at:
                last_direction: str | None = (
                    "child_to_parent" if last_outbox_at >= last_inbox_at else "parent_to_child"
                )
            elif last_outbox_at:
                last_direction = "child_to_parent"
            elif last_inbox_at:
                last_direction = "parent_to_child"
            else:
                last_direction = None

            title = str(r["title"] or "").strip() or str(cli_info["title"] or "").strip() or str(r["name"] or "")
            navigation_state = "ready" if (index_state == "indexed" and not archived) else "pending"

            parent_null_unread[node_id] = null_child_unread
            sig_parts_by_id[node_id] = sig_parts

            nodes_by_id[node_id] = {
                "nodeId": node_id,
                "parentNodeId": parent_node_id,
                "parentSessionId": parent_sid,
                "sessionId": sid,
                "name": str(r["name"] or ""),
                "title": title,
                "hostId": "local",
                "projectId": idx_info["projectId"],
                "workspacePath": workspace_path,
                "workspaceIdentity": None,
                "sessionKind": "interactive",
                "createdAt": str(r["created_at"] or ""),
                "revision": int(r["revision"] or 0),
                "nodeStatus": node_status,
                "archived": archived,
                "executionState": exec_state,
                "lastOutcome": last_outcome,
                "activeRunId": active_run_id,
                "waitingInput": waiting_input,
                "activeWaitId": active_wait_id,
                "waitingInputKind": waiting_input_kind,
                "canArchive": can_archive,
                "canCancel": can_cancel,
                "branchName": branch_name,
                "worktreeState": worktree_state,
                "canResumeForIndex": can_resume_for_index,
                "indexState": index_state,
                "desktopIndexProbe": (
                    {"state": probe_state, "checkedAt": probe_checked_at}
                    if probe_state is not None
                    else None
                ),
                "cliExists": bool(cli_info["cliExists"]),
                "cliArchived": bool(cli_info["cliArchived"]),
                "cliDeleted": bool(cli_info["cliDeleted"]),
                "lineageMismatch": lineage_mismatch,
                "taskMetaReady": index_state == "indexed",
                "navigationState": navigation_state,
                "reportPendingAck": report_pending_ack,
                "childrenUnreadTotal": 0,
                "comm": {
                    "toParentUnread": to_parent_unread,
                    "lastToParent": last_to_parent,
                    "toChildQueued": to_child_queued,
                    "waitingInput": waiting_input,
                    "lastDirection": last_direction,
                    "idleParentHint": False,
                    "childrenUnreadTotal": 0,
                    "commSignature": "",
                },
            }

        children_map: dict[str, list[str]] = {}
        for nid, nd in nodes_by_id.items():
            pid = nd["parentNodeId"]
            if pid and pid in nodes_by_id and not nd["archived"]:
                children_map.setdefault(pid, []).append(nid)

        memo_unread: dict[str, int] = {}

        def _compute_children_unread(nid: str, visiting: set[str]) -> int:
            if nid in memo_unread:
                return memo_unread[nid]
            if nid in visiting:
                return 0
            visiting.add(nid)
            total = int(parent_null_unread.get(nid, 0))
            for cid in children_map.get(nid, []):
                cnode = nodes_by_id[cid]
                total += int(cnode["comm"]["toParentUnread"]) + _compute_children_unread(cid, visiting)
            visiting.remove(nid)
            memo_unread[nid] = total
            return total

        for nid, nd in nodes_by_id.items():
            pid = nd["parentNodeId"]
            parent_node = nodes_by_id.get(pid) if pid else None
            nd["parentWorkspacePath"] = (
                str(parent_node.get("workspacePath") or "") or None
                if parent_node is not None
                else None
            )
            parent_busy = bool(
                parent_node and parent_node.get("executionState") in ("running", "waiting_input")
            )
            idle_parent_hint = bool(pid and nd["comm"]["toParentUnread"] > 0 and not parent_busy)
            children_unread = _compute_children_unread(nid, set())
            has_unread_while_idle = bool(
                children_unread > 0 and nd.get("executionState") not in ("running", "waiting_input")
            )

            nd["childrenUnreadTotal"] = children_unread
            nd["comm"]["idleParentHint"] = idle_parent_hint
            nd["comm"]["childrenUnreadTotal"] = children_unread
            nd["comm"]["hasUnreadWhileIdle"] = has_unread_while_idle

            sig_payload = {
                "toParentUnread": nd["comm"]["toParentUnread"],
                "toChildQueued": nd["comm"]["toChildQueued"],
                "waitingInput": nd["comm"]["waitingInput"],
                "reportPendingAck": nd["reportPendingAck"],
                "lastDirection": nd["comm"]["lastDirection"],
                "idleParentHint": idle_parent_hint,
                "childrenUnreadTotal": children_unread,
                "lastToParent": nd["comm"]["lastToParent"],
                "sigParts": sig_parts_by_id.get(nid, []),
            }
            nd["comm"]["commSignature"] = hashlib.sha256(
                json.dumps(sig_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()

        sorted_nodes = sorted(
            nodes_by_id.values(),
            key=lambda item: (str(item.get("createdAt") or ""), str(item.get("nodeId") or "")),
        )

        digest = self._compute_snapshot_digest(store_instance_id, sorted_nodes)
        if digest != self._last_digest or self._projection_revision == 0:
            self._projection_revision += 1
            self._last_digest = digest
            snap = {
                "schemaVersion": 1,
                "storeInstanceId": store_instance_id,
                "stateRevision": state_revision,
                "projectionRevision": self._projection_revision,
                "nodes": sorted_nodes,
            }
            self._last_snapshot = snap
            validate_public_projection(snap)
            if self.persist_export and self.state_root.exists():
                try:
                    raw = json.dumps(snap, ensure_ascii=False, indent=2).encode("utf-8")
                    atomic_export(
                        self.EXPORT_REL_PATH,
                        raw,
                        root=self.state_root,
                        revision=self._projection_revision,
                    )
                except Exception:
                    pass
        else:
            assert self._last_snapshot is not None
            snap = {
                "schemaVersion": 1,
                "storeInstanceId": store_instance_id,
                "stateRevision": state_revision,
                "projectionRevision": self._projection_revision,
                "nodes": sorted_nodes,
            }
            self._last_snapshot = snap

        self._has_live_snapshot = True
        return snap


def build_projection_snapshot(
    state_root: Path | str | None = None,
    *,
    cli_db_path: Path | str | None = None,
    tasks_index_path: Path | str | None = None,
    persist_export: bool = True,
) -> dict[str, Any]:
    reader = ProjectionReader(
        state_root,
        cli_db_path=cli_db_path,
        tasks_index_path=tasks_index_path,
        persist_export=persist_export,
    )
    try:
        return reader.snapshot()
    finally:
        reader.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only desktop sidebar projection bridge")
    sub = parser.add_subparsers(dest="cmd")

    p_snap = sub.add_parser("snapshot", help="Export current sidebar tree projection snapshot")
    p_snap.add_argument("--state-home", default=None, help="Override state root directory")
    p_snap.add_argument("--no-persist", action="store_true", help="Do not write exports/sidebar-tree-v1.json")
    p_snap.add_argument("--json", action="store_true", help="Output JSON")

    args = parser.parse_args(argv)
    state_home = getattr(args, "state_home", None)
    persist = not bool(getattr(args, "no_persist", False))
    snap = build_projection_snapshot(state_home, persist_export=persist)
    print(json.dumps(snap, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
