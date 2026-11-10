"""Supervisor and single-owner worker runner for side-sessions."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Mapping
import uuid

try:
    from . import worktree as _worktree_mod
    from .contracts import (
        DRIVER_API_VERSION,
        ENGINE_SCHEMA_VERSION,
        EXPORT_SCHEMA_VERSION,
        MAX_FALLBACK_LAST_TEXT_CHARS,
        MAX_FULL_REPORT_CHARS,
        BoundWait,
        CallerContext,
        CanonicalReport,
        ErrorCode,
        ExitReceipt,
        RunAssignment,
        RuntimeCreateSpec,
        RuntimeHandle,
        RuntimeInput,
        RuntimeProfile,
        RuntimeResumeSpec,
        SideSessionError,
        WorkspaceSpec,
        WorktreeRecord,
        canonical_json,
        format_recap_400,
        runtime_profile_for_task_kind,
        sha256_hex,
        utc_now_iso,
    )
    from .driver import (
        BaseDriver,
        RuntimeEvent,
        ScriptedFakeDriver,
        ZCodeDriver,
        get_default_driver,
    )
    from .host_adapter import (
        HostAdapter,
        get_default_host_adapter,
        get_process_lstart,
        verify_process_identity,
    )
    from .state import (
        FileLock,
        Store,
        _get_held_locks,
        open_store,
        resolve_state_root,
    )
except ImportError:  # pragma: no cover
    _script_dir = str(Path(__file__).resolve().parent)
    if _script_dir not in sys.path:
        sys.path.insert(0, _script_dir)
    import worktree as _worktree_mod  # type: ignore
    from contracts import (  # type: ignore
        DRIVER_API_VERSION,
        ENGINE_SCHEMA_VERSION,
        EXPORT_SCHEMA_VERSION,
        MAX_FALLBACK_LAST_TEXT_CHARS,
        MAX_FULL_REPORT_CHARS,
        BoundWait,
        CallerContext,
        CanonicalReport,
        ErrorCode,
        ExitReceipt,
        RunAssignment,
        RuntimeCreateSpec,
        RuntimeHandle,
        RuntimeInput,
        RuntimeProfile,
        RuntimeResumeSpec,
        SideSessionError,
        WorkspaceSpec,
        WorktreeRecord,
        canonical_json,
        format_recap_400,
        runtime_profile_for_task_kind,
        sha256_hex,
        utc_now_iso,
    )
    from driver import (  # type: ignore
        BaseDriver,
        RuntimeEvent,
        ScriptedFakeDriver,
        ZCodeDriver,
        get_default_driver,
    )
    from host_adapter import (  # type: ignore
        HostAdapter,
        get_default_host_adapter,
        get_process_lstart,
        verify_process_identity,
    )
    from state import (  # type: ignore
        FileLock,
        Store,
        _get_held_locks,
        open_store,
        resolve_state_root,
    )


VALID_VERIFY_PROFILES: frozenset[str] = frozenset(
    {
        "builtin",
        "default",
        "self-check",
        "host-contract",
        "plugin-load",
        "supervisor-survival",
        "gui-wake",
        "recovery",
    }
)


class _CompatRow(dict):
    """SQLite row factory supporting dict `.get()`, key lookup, and positional index lookup."""

    def __init__(self, cursor: Any, row: tuple[Any, ...]) -> None:
        cols = [col[0] for col in (cursor.description or ())]
        super().__init__(zip(cols, row))
        self._values = row

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


def _ensure_compat_row_factory(store_or_engine: Any) -> None:
    conn = getattr(store_or_engine, "conn", None)
    if conn is None and hasattr(store_or_engine, "store"):
        conn = getattr(store_or_engine.store, "conn", None)
    if conn is not None:
        try:
            conn.row_factory = _CompatRow
        except Exception:
            pass


_orig_store_init = Store.__init__


def _patched_store_init(self: Store, *args: Any, **kwargs: Any) -> None:
    _orig_store_init(self, *args, **kwargs)
    _ensure_compat_row_factory(self)


if getattr(Store.__init__, "__name__", "") != "_patched_store_init":
    Store.__init__ = _patched_store_init  # type: ignore[method-assign]


@dataclass(frozen=True)
class OwnerContext:
    """Internal worker ownership credentials for `finalize_from_owner` and `close_run`."""

    node_id: str
    run_id: str
    worker_id: str
    owner_epoch: int
    fencing_token: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "run_id": self.run_id,
            "worker_id": self.worker_id,
            "owner_epoch": self.owner_epoch,
            "fencing_token": self.fencing_token,
        }


def _is_session_lock_held_on_thread(node_id: str) -> bool:
    lock_name = f"session-{node_id}.lock"
    return any(kind == "session" and key == lock_name for _, kind, key in _get_held_locks())


def _is_supervisor_lock_held_on_thread() -> bool:
    return any(kind == "supervisor" and key == "supervisor.lock" for _, kind, key in _get_held_locks())


def _safe_pgid(pid: int) -> int:
    try:
        return os.getpgid(pid)
    except OSError:
        return pid


class WorkerRunner:
    """Single-node owner runner, control loop, crash recovery, and health/contract verifier."""

    def __init__(
        self,
        store: Store | None = None,
        *,
        engine: Any = None,
        driver: BaseDriver | Any = None,
        host_adapter: HostAdapter | Any = None,
        state_root: Path | str | None = None,
        worker_id: str | None = None,
        poll_interval_ms: int = 50,
        wait_poll_timeout_ms: int = 2500,
    ) -> None:
        self._owns_store = False
        if store is not None:
            self.store = store
        elif engine is not None and hasattr(engine, "store"):
            self.store = engine.store
        else:
            resolved_root = resolve_state_root() if state_root is None else Path(state_root).expanduser().absolute()
            self.store = open_store(resolved_root, writable=True)
            self._owns_store = True
        _ensure_compat_row_factory(self.store)

        if host_adapter is not None:
            self.host_adapter = host_adapter
        elif engine is not None and getattr(engine, "_host_adapter", None) is not None:
            self.host_adapter = engine.host_adapter
        else:
            self.host_adapter = HostAdapter(store=self.store)
        if hasattr(self.host_adapter, "bind_store"):
            try:
                self.host_adapter.bind_store(self.store)
            except Exception:
                pass

        if driver is not None:
            self.driver = driver
        elif engine is not None and getattr(engine, "_driver", None) is not None:
            self.driver = engine.driver
        else:
            self.driver = ZCodeDriver(
                zcode_bin=os.environ.get("ZCODE_SIDE_SESSIONS_ZCODE_BIN") or "zcode"
            )

        if engine is not None:
            self.engine = engine
        else:
            try:
                from .engine import Engine
            except ImportError:  # pragma: no cover
                from engine import Engine  # type: ignore
            self.engine = Engine(
                self.store,
                host_adapter=self.host_adapter,
                driver=self.driver,
                runtime_execution="deferred",
            )

        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:12]}"
        self.poll_interval_ms = max(10, int(poll_interval_ms))
        self.wait_poll_timeout_ms = max(0, int(wait_poll_timeout_ms))
        self.on_wait: Callable[..., Any] | None = None

    def close(self) -> None:
        if self._owns_store and self.store is not None:
            self.store.close()

    def __enter__(self) -> WorkerRunner:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal Helpers for Owner Registration, Operations & Handles
    # ------------------------------------------------------------------

    def _check_existing_live_processes(self, owner_row: Mapping[str, Any] | None) -> tuple[bool, bool, str | None]:
        """Return `(worker_alive, model_alive, reason)` for an `owners` row."""
        if owner_row is None:
            return False, False, None

        w_pid = owner_row.get("pid")
        w_lstart = owner_row.get("process_started_at")
        worker_alive = False
        if isinstance(w_pid, int) and w_pid > 0:
            # If another process (or explicitly stamped current process with matching lstart) is alive
            if verify_process_identity(w_pid, w_lstart):
                if w_pid != os.getpid() or str(owner_row.get("worker_id") or "") != self.worker_id:
                    worker_alive = True

        m_pid = owner_row.get("model_pid")
        m_lstart = owner_row.get("model_started_at")
        model_alive = False
        same_worker = str(owner_row.get("worker_id") or "") == self.worker_id
        same_process = isinstance(w_pid, int) and w_pid == os.getpid()
        if isinstance(m_pid, int) and m_pid > 0:
            if verify_process_identity(m_pid, m_lstart):
                if not (same_worker and same_process):
                    model_alive = True

        if worker_alive:
            return True, model_alive, "worker_process_alive"
        if model_alive:
            return False, True, "model_process_alive"
        return False, False, None

    def _find_open_driver_handle(
        self,
        runtime_sid: str,
        runtime_instance_id: str | None,
        canonical_workspace: str,
    ) -> RuntimeHandle | None:
        """Look up an already-open connection handle on `self.driver` if `start_session` created it."""
        conns = getattr(self.driver, "_connections", None)
        if not isinstance(conns, Mapping):
            return None
        if runtime_instance_id and runtime_instance_id in conns:
            conn = conns[runtime_instance_id]
            if not getattr(conn, "closed", False):
                return RuntimeHandle(
                    runtime_sid=getattr(conn, "runtime_sid", runtime_sid),
                    runtime_instance_id=runtime_instance_id,
                    owner_connection_id=getattr(conn, "owner_connection_id", f"conn:{runtime_instance_id}"),
                    snapshot_revision=int(getattr(conn, "revision", 1)),
                    canonical_workspace=getattr(conn, "canonical_workspace", canonical_workspace),
                    process_identity={
                        "pid": getattr(conn, "pid", None),
                        "process_started_at": getattr(conn, "process_started_at", None),
                        "process_group": getattr(conn, "process_group", None),
                    },
                )
        for inst_id, conn in conns.items():
            if getattr(conn, "runtime_sid", None) == runtime_sid and not getattr(conn, "closed", False):
                return RuntimeHandle(
                    runtime_sid=runtime_sid,
                    runtime_instance_id=str(inst_id),
                    owner_connection_id=getattr(conn, "owner_connection_id", f"conn:{inst_id}"),
                    snapshot_revision=int(getattr(conn, "revision", 1)),
                    canonical_workspace=getattr(conn, "canonical_workspace", canonical_workspace),
                    process_identity={
                        "pid": getattr(conn, "pid", None),
                        "process_started_at": getattr(conn, "process_started_at", None),
                        "process_group": getattr(conn, "process_group", None),
                    },
                )
        return None

    def _register_owner_in_txn(
        self,
        txn: Any,
        *,
        node_id: str,
        run_id: str,
        owner_epoch: int,
        fencing_token: str,
        runtime_instance_id: str | None = None,
        model_pid: int | None = None,
        model_started_at: str | None = None,
    ) -> None:
        now = utc_now_iso()
        pid = os.getpid()
        lstart = get_process_lstart(pid) or f"test:{pid}"
        pgid = _safe_pgid(pid)
        owner_token = f"tok:{uuid.uuid4().hex}"

        txn.execute(
            """
            INSERT INTO owners (
                node_id, worker_id, owner_token, owner_epoch, fencing_token,
                pid, process_started_at, process_group, model_pid, model_started_at,
                runtime_instance_id, current_run_id, heartbeat, state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
            ON CONFLICT(node_id) DO UPDATE SET
                worker_id = excluded.worker_id,
                owner_token = excluded.owner_token,
                owner_epoch = excluded.owner_epoch,
                fencing_token = excluded.fencing_token,
                pid = excluded.pid,
                process_started_at = excluded.process_started_at,
                process_group = excluded.process_group,
                model_pid = COALESCE(excluded.model_pid, owners.model_pid),
                model_started_at = COALESCE(excluded.model_started_at, owners.model_started_at),
                runtime_instance_id = COALESCE(excluded.runtime_instance_id, owners.runtime_instance_id),
                current_run_id = excluded.current_run_id,
                heartbeat = excluded.heartbeat,
                state = 'active'
            """,
            (
                node_id,
                self.worker_id,
                owner_token,
                owner_epoch,
                fencing_token,
                pid,
                lstart,
                pgid,
                model_pid,
                model_started_at,
                runtime_instance_id,
                run_id,
                now,
            ),
        )
        txn.execute(
            """
            UPDATE turns
            SET owner_epoch = ?, fencing_token = ?
            WHERE run_id = ?
            """,
            (owner_epoch, fencing_token, run_id),
        )

    def _update_heartbeat(self, node_id: str, owner_epoch: int, fencing_token: str) -> None:
        now = utc_now_iso()
        with self.store.transaction("IMMEDIATE") as txn:
            txn.execute(
                """
                UPDATE owners
                SET heartbeat = ?
                WHERE node_id = ? AND owner_epoch = ? AND fencing_token = ?
                """,
                (now, node_id, owner_epoch, fencing_token),
            )

    def _has_pending_cancel_command(self, node_id: str, run_id: str) -> dict[str, Any] | None:
        t_row = self.store.conn.execute(
            "SELECT cancel_requested_at, cancel_reason FROM turns WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        c_row = self.store.conn.execute(
            """
            SELECT * FROM control_commands
            WHERE node_id = ? AND (run_id = ? OR run_id IS NULL)
              AND kind = 'cancel_run' AND state IN ('queued', 'claimed')
            ORDER BY created_at ASC
            LIMIT 1
            """,
            (node_id, run_id),
        ).fetchone()
        if c_row is not None:
            return dict(c_row)
        if t_row is not None and t_row["cancel_requested_at"]:
            return {
                "control_id": None,
                "reason": t_row["cancel_reason"] or "Cancel requested on turn",
            }
        return None

    def _advance_startup_operation(
        self,
        node_id: str,
        assignment: RunAssignment,
        *,
        message_content: str,
    ) -> tuple[RuntimeHandle, str | None]:
        """Advance an operation through `reserved -> worktree_created -> session_created -> brief_accepted -> running`
        or resume an existing session and send the turn input on the same handle.
        """
        node_row = self.store.conn.execute("SELECT * FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
        if node_row is None:
            raise SideSessionError(ErrorCode.NOT_FOUND, f"Node not found: {node_id}")

        parent_id = str(node_row["parent_node_id"] or assignment.parent_node_id or "")
        parent_row = (
            self.store.conn.execute("SELECT * FROM nodes WHERE node_id = ?", (parent_id,)).fetchone()
            if parent_id
            else None
        )
        parent_sid = str(
            (parent_row["runtime_session_id"] if parent_row and parent_row["runtime_session_id"] else None)
            or f"parent:{parent_id}"
        )
        task_kind = str(node_row["task_kind"] or "read_only")
        workspace_mode = str(node_row["workspace_mode"] or "inherit")
        context_applied = str(node_row["context_applied"] or "fresh")
        canonical_ws = str(node_row["canonical_workspace"] or "")

        op_row = self.store.conn.execute(
            """
            SELECT * FROM operations
            WHERE node_id = ? AND stage IN ('reserved', 'worktree_created', 'session_created', 'brief_accepted', 'running')
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (node_id,),
        ).fetchone()

        # Check if an open handle already exists (e.g. created by Engine.start_session)
        o_row = self.store.conn.execute("SELECT * FROM owners WHERE node_id = ?", (node_id,)).fetchone()
        existing_inst_id = str(o_row["runtime_instance_id"]) if o_row and o_row["runtime_instance_id"] else None
        t_row = self.store.conn.execute("SELECT * FROM turns WHERE run_id = ?", (assignment.run_id,)).fetchone()

        if t_row is not None and t_row["execution_state"] in ("running", "waiting_input", "exited") and existing_inst_id:
            open_handle = self._find_open_driver_handle(
                assignment.runtime_sid,
                existing_inst_id,
                canonical_ws or str(self.store.root),
            )
            if open_handle is not None:
                return open_handle, t_row["runtime_turn_id"]

        # Stage: reserved -> worktree_created (if operation is at 'reserved' or workspace is not yet prepared)
        if op_row is not None and str(op_row["stage"]) == "reserved":
            operation_id = str(op_row["operation_id"])
            source_cwd = canonical_ws or (
                str(parent_row["canonical_workspace"]) if parent_row and parent_row["canonical_workspace"] else str(self.store.root)
            )
            if not canonical_ws or (workspace_mode == "branch" and not Path(canonical_ws).exists()):
                ws_spec = WorkspaceSpec(
                    node_id=node_id,
                    workspace_mode=workspace_mode,
                    source_cwd=source_cwd,
                    name=str(node_row["name"]),
                )
                wt_rec = _worktree_mod.prepare(
                    ws_spec,
                    operation_id=operation_id,
                    worktrees_home=getattr(self.engine, "worktrees_home", self.store.root / "worktrees"),
                )
                canonical_ws = wt_rec.canonical_worktree_path
                with self.store.transaction("IMMEDIATE") as txn:
                    now = utc_now_iso()
                    txn.execute(
                        "UPDATE nodes SET canonical_workspace = ?, repo_root = ?, base_commit = ?, updated_at = ? WHERE node_id = ?",
                        (canonical_ws, wt_rec.repo_root, wt_rec.base_commit, now, node_id),
                    )
                    if workspace_mode == "branch":
                        txn.execute(
                            """
                            INSERT OR IGNORE INTO worktrees (
                                worktree_id, node_id, operation_id, canonical_worktree_path,
                                worktrees_home, workspace_mode, repo_key, repo_root, base_commit,
                                branch, source_patch_hash, ownership_marker, state, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, 'branch', ?, ?, ?, ?, ?, ?, 'in_use', ?, ?)
                            """,
                            (
                                wt_rec.worktree_id,
                                node_id,
                                operation_id,
                                wt_rec.canonical_worktree_path,
                                wt_rec.worktrees_home,
                                wt_rec.repo_key,
                                wt_rec.repo_root,
                                wt_rec.base_commit,
                                wt_rec.branch,
                                wt_rec.source_patch_hash,
                                wt_rec.ownership_marker,
                                now,
                                now,
                            ),
                        )
                    txn.execute(
                        """
                        UPDATE operations
                        SET stage = 'worktree_created',
                            expected_paths = ?,
                            revision = revision + 1,
                            updated_at = ?
                        WHERE operation_id = ?
                        """,
                        (canonical_json({"workspace": canonical_ws, "branch": wt_rec.branch}), now, operation_id),
                    )
            else:
                with self.store.transaction("IMMEDIATE") as txn:
                    txn.execute(
                        "UPDATE operations SET stage = 'worktree_created', revision = revision + 1, updated_at = ? WHERE operation_id = ?",
                        (utc_now_iso(), operation_id),
                    )
            op_row = self.store.conn.execute("SELECT * FROM operations WHERE operation_id = ?", (operation_id,)).fetchone()

        if not canonical_ws:
            canonical_ws = str(self.store.root)

        # Check cancellation before driver.create / driver.resume
        if self._has_pending_cancel_command(node_id, assignment.run_id) is not None:
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "CANCEL_BEFORE_START")

        is_first_create = (
            assignment.turn_seq == 1
            and not bool(node_row["host_link_verified"])
            and (op_row is None or str(op_row["stage"]) in ("reserved", "worktree_created"))
        )

        prof = runtime_profile_for_task_kind(task_kind)
        mode_str = prof.mode
        model_cfg: dict[str, Any] = {}
        allowlist = list(prof.tool_allowlist or [])
        denylist = list(prof.tool_denylist)

        if is_first_create:
            create_spec = RuntimeCreateSpec(
                assignment=assignment,
                workspace_path=canonical_ws,
                parent_runtime_sid=parent_sid,
                mode=mode_str,
                model=model_cfg,
                tool_allowlist=allowlist,
                tool_denylist=denylist,
                additional_directories=[],
                persistence="immediate",
                preallocated_session_id=assignment.runtime_sid,
                brief_ref=f"side-session-notes/{parent_id}/{node_id}-brief.md" if parent_id else "",
                context_applied=context_applied,
            )
            handle = self.driver.create(create_spec)
        else:
            open_handle = self._find_open_driver_handle(
                assignment.runtime_sid,
                existing_inst_id,
                canonical_ws,
            )
            if open_handle is not None and op_row is not None and str(op_row["stage"]) in ("session_created", "brief_accepted"):
                handle = open_handle
            else:
                resume_spec = RuntimeResumeSpec(
                    assignment=assignment,
                    expected_workspace=canonical_ws,
                    expected_parent_runtime_sid=parent_sid,
                    mode=mode_str,
                    model=model_cfg,
                    tool_allowlist=allowlist,
                    tool_denylist=denylist,
                    additional_directories=[],
                )
                handle = self.driver.resume(resume_spec)

        # Record model process identity (only if distinct child process, e.g. ZCodeDriver subprocess)
        proc_id = handle.process_identity if isinstance(handle.process_identity, Mapping) else {}
        raw_mpid = proc_id.get("pid")
        mpid = int(raw_mpid) if isinstance(raw_mpid, int) and raw_mpid != os.getpid() else None
        mlstart = str(proc_id.get("process_started_at") or "") or None if mpid is not None else None

        with self.store.transaction("IMMEDIATE") as txn:
            now = utc_now_iso()
            if handle.runtime_sid != assignment.runtime_sid:
                txn.execute("UPDATE nodes SET runtime_session_id = ? WHERE node_id = ?", (handle.runtime_sid, node_id))
                txn.execute("UPDATE bindings SET runtime_sid = ? WHERE node_id = ?", (handle.runtime_sid, node_id))
            txn.execute(
                """
                UPDATE owners
                SET runtime_instance_id = ?,
                    model_pid = COALESCE(?, model_pid),
                    model_started_at = COALESCE(?, model_started_at),
                    heartbeat = ?
                WHERE node_id = ?
                """,
                (handle.runtime_instance_id, mpid, mlstart, now, node_id),
            )
            if op_row is not None and str(op_row["stage"]) in ("reserved", "worktree_created"):
                txn.execute(
                    "UPDATE operations SET stage = 'session_created', revision = revision + 1, updated_at = ? WHERE operation_id = ?",
                    (now, op_row["operation_id"]),
                )
                txn.execute(
                    "UPDATE operations SET stage = 'brief_accepted', revision = revision + 1, updated_at = ? WHERE operation_id = ?",
                    (now, op_row["operation_id"]),
                )

        if t_row is not None and str(t_row["execution_state"]) in ("running", "waiting_input", "exited"):
            return handle, t_row["runtime_turn_id"]

        # Check cancellation before driver.send
        if self._has_pending_cancel_command(node_id, assignment.run_id) is not None:
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "CANCEL_BEFORE_SEND")

        # Record system input provenance so it never advances user_epoch
        if hasattr(self.host_adapter, "record_system_input"):
            try:
                self.host_adapter.record_system_input(
                    runtime_sid=handle.runtime_sid,
                    input_id=assignment.input_id,
                    origin="system/side_sessions",
                )
            except Exception:
                pass

        send_rcpt = self.driver.send(
            handle,
            RuntimeInput(
                input_id=assignment.input_id,
                content=message_content,
                origin="system/side_sessions",
            ),
        )
        if send_rcpt.status == "rejected":
            raise SideSessionError(
                ErrorCode.REVISION_CONFLICT,
                f"driver.send rejected input {assignment.input_id}",
                {"input_id": assignment.input_id, "status": send_rcpt.status},
            )

        runtime_turn_id = send_rcpt.runtime_turn_id
        binding_turn_id = runtime_turn_id or f"rturn:{assignment.run_id[:8]}"

        verified = False
        reader = getattr(self.driver, "_read_source_session_from_sqlite", None)
        if callable(reader):
            try:
                s, _m, reason = reader(handle.runtime_sid)
                if s is None and getattr(self.driver, "driver_kind", None) == "zcode":
                    for _ in range(15):
                        time.sleep(0.1)
                        s, _m, reason = reader(handle.runtime_sid)
                        if s is not None:
                            break
                verified = (
                    s is not None
                    and reason is None
                    and str(s.get("parent_id") or s.get("parent_session_id") or "") == parent_sid
                )
            except Exception:
                verified = False

        with self.store.transaction("IMMEDIATE") as txn:
            now = utc_now_iso()
            if handle.runtime_sid != assignment.runtime_sid:
                txn.execute("UPDATE nodes SET runtime_session_id = ? WHERE node_id = ?", (handle.runtime_sid, node_id))
                txn.execute("UPDATE bindings SET runtime_sid = ? WHERE node_id = ?", (handle.runtime_sid, node_id))
            if verified:
                txn.execute(
                    """
                    UPDATE nodes
                    SET host_link_verified = 1,
                        recovery_status = 'runtime_resumable',
                        revision = revision + 1,
                        updated_at = ?
                    WHERE node_id = ?
                    """,
                    (now, node_id),
                )
                txn.execute(
                    "UPDATE bindings SET last_turn_id = ?, db_check_state = 'verified', last_seen_at = ? WHERE node_id = ?",
                    (runtime_turn_id, now, node_id),
                )
            else:
                txn.execute(
                    "UPDATE bindings SET last_turn_id = ?, db_check_state = 'pending', last_seen_at = ? WHERE node_id = ?",
                    (runtime_turn_id, now, node_id),
                )
            txn.execute(
                "UPDATE turns SET runtime_turn_id = ?, execution_state = 'running' WHERE run_id = ?",
                (runtime_turn_id, assignment.run_id),
            )
            if assignment.task_id:
                txn.execute(
                    """
                    UPDATE task_turn_bindings
                    SET state = 'released'
                    WHERE runtime_sid = ?
                      AND (runtime_turn_id = ? OR runtime_turn_id LIKE 'rturn:%')
                      AND state = 'active'
                    """,
                    (handle.runtime_sid, binding_turn_id),
                )
                txn.execute(
                    """
                    INSERT INTO task_turn_bindings (
                        binding_id, task_id, node_id, runtime_sid, runtime_turn_id,
                        task_revision, state, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        assignment.task_id,
                        node_id,
                        handle.runtime_sid,
                        binding_turn_id,
                        int(assignment.task_revision or 1),
                        now,
                    ),
                )
            txn.execute(
                "UPDATE inbox_messages SET state = 'running', updated_at = ? WHERE target_node_id = ? AND message_id = ?",
                (now, node_id, assignment.message_id),
            )
            txn.execute(
                "UPDATE parent_slots SET state = 'running', updated_at = ? WHERE node_id = ? AND state != 'released'",
                (now, node_id),
            )
            if assignment.member_id:
                txn.execute(
                    "UPDATE dispatch_group_members SET state = 'running', updated_at = ? WHERE member_id = ?",
                    (now, assignment.member_id),
                )
            if op_row is not None:
                txn.execute(
                    "UPDATE operations SET stage = 'running', result_state = 'running', revision = revision + 1, updated_at = ? WHERE operation_id = ?",
                    (now, op_row["operation_id"]),
                )

        if is_first_create:
            if hasattr(self.engine, "complete_handoff_transfer"):
                try:
                    self.engine.complete_handoff_transfer(node_id)
                except Exception:
                    pass
            self._update_desktop_index_probe(node_id, handle.runtime_sid, canonical_ws)

        return handle, runtime_turn_id

    def _query_tasks_index_ro(self, runtime_sid: str, canonical_ws: str) -> bool:
        idx_path_env = os.environ.get("ZCODE_TASKS_INDEX_PATH") or os.environ.get("ZCODE_TASKS_INDEX_DB_PATH")
        idx_path = (
            Path(idx_path_env).expanduser().absolute()
            if idx_path_env
            else (Path.home() / ".zcode" / "v2" / "tasks-index.sqlite")
        )
        if not idx_path.exists() or idx_path.is_symlink() or not idx_path.is_file():
            return False
        try:
            conn = sqlite3.connect(f"file:{idx_path}?mode=ro", uri=True, timeout=1.5)
        except sqlite3.Error:
            return False
        try:
            conn.execute("PRAGMA query_only=ON")
            row = conn.execute(
                "SELECT cli_created_at FROM tasks WHERE task_id = ? AND workspace_path = ?",
                (runtime_sid, canonical_ws),
            ).fetchone()
            return row is not None and row[0] is not None
        except sqlite3.Error:
            return False
        finally:
            conn.close()

    def _update_desktop_index_probe(
        self,
        node_id: str,
        runtime_sid: str,
        canonical_ws: str,
        *,
        poll_timeout_sec: float = 0.0,
    ) -> str:
        indexed = self._query_tasks_index_ro(runtime_sid, canonical_ws)
        state = "indexed" if indexed else "pending"
        now = utc_now_iso()
        with self.store.transaction("IMMEDIATE") as txn:
            txn.execute(
                "INSERT OR REPLACE INTO desktop_index_probe (node_id, state, checked_at) VALUES (?, ?, ?)",
                (node_id, state, now),
            )
        if state == "indexed":
            return state

        if poll_timeout_sec > 0:
            deadline = time.monotonic() + poll_timeout_sec
            delay = 0.05
            while time.monotonic() < deadline:
                time.sleep(min(delay, max(0.01, deadline - time.monotonic())))
                if self._query_tasks_index_ro(runtime_sid, canonical_ws):
                    state = "indexed"
                    break
                delay = min(delay * 2.0, 1.0)
            else:
                state = "timeout"
            now = utc_now_iso()
            with self.store.transaction("IMMEDIATE") as txn:
                txn.execute(
                    "INSERT OR REPLACE INTO desktop_index_probe (node_id, state, checked_at) VALUES (?, ?, ?)",
                    (node_id, state, now),
                )
            return state

        if getattr(self.driver, "driver_kind", None) == "zcode":
            state_root = self.store.root

            def _bg_probe() -> None:
                deadline = time.monotonic() + 60.0
                for step_sec in (1.0, 2.0, 4.0, 8.0, 8.0, 8.0, 8.0, 8.0, 8.0, 8.0):
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(min(step_sec, max(0.1, deadline - time.monotonic())))
                    if self._query_tasks_index_ro(runtime_sid, canonical_ws):
                        final_state = "indexed"
                        break
                else:
                    final_state = "indexed" if self._query_tasks_index_ro(runtime_sid, canonical_ws) else "timeout"
                try:
                    with open_store(state_root, writable=True) as bg_store:
                        with bg_store.transaction("IMMEDIATE") as bg_txn:
                            bg_txn.execute(
                                "INSERT OR REPLACE INTO desktop_index_probe (node_id, state, checked_at) VALUES (?, ?, ?)",
                                (node_id, final_state, utc_now_iso()),
                            )
                except Exception:
                    pass

            threading.Thread(target=_bg_probe, daemon=True).start()
        return state

    def _record_wait_event(
        self,
        assignment: RunAssignment,
        handle: RuntimeHandle,
        ev: RuntimeEvent,
    ) -> str:
        w_req = dict(ev.wait_request or {})
        host_req_id = str(w_req.get("host_request_id") or w_req.get("requestId") or ev.event_id or uuid.uuid4())
        kind = str(w_req.get("kind") or "permission")
        if kind not in ("input", "elicitation", "permission"):
            kind = "input"
        nonce = str(w_req.get("nonce") or f"nonce-{uuid.uuid4().hex[:12]}")
        question = str(w_req.get("question") or "Waiting for input")
        options = list(w_req.get("options") or [])
        req_auth = "human" if kind == "permission" or w_req.get("required_authority") == "human" else "parent_agent_allowed"
        deadline_at = w_req.get("deadline_at")
        wait_id = str(w_req.get("wait_id") or uuid.uuid4())

        with self.store.transaction("IMMEDIATE") as txn:
            now = utc_now_iso()
            existing = txn.execute(
                "SELECT wait_id FROM wait_requests WHERE host_request_id = ? AND runtime_instance_id = ?",
                (host_req_id, handle.runtime_instance_id),
            ).fetchone()
            if existing is not None:
                wait_id = str(existing["wait_id"])
            else:
                txn.execute(
                    """
                    INSERT INTO wait_requests (
                        wait_id, node_id, run_id, runtime_turn_id, runtime_instance_id,
                        owner_epoch, host_request_id, kind, nonce, question, options,
                        required_authority, deadline_at, state, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
                    """,
                    (
                        wait_id,
                        assignment.node_id,
                        assignment.run_id,
                        ev.runtime_turn_id,
                        handle.runtime_instance_id,
                        assignment.owner_epoch,
                        host_req_id,
                        kind,
                        nonce,
                        question,
                        canonical_json(options),
                        req_auth,
                        deadline_at,
                        now,
                        now,
                    ),
                )
            txn.execute(
                "UPDATE turns SET execution_state = 'waiting_input' WHERE run_id = ?",
                (assignment.run_id,),
            )
            txn.execute(
                "UPDATE parent_slots SET state = 'waiting_input', updated_at = ? WHERE node_id = ? AND state != 'released'",
                (now, assignment.node_id),
            )
            if assignment.member_id:
                txn.execute(
                    "UPDATE dispatch_group_members SET state = 'waiting_input', updated_at = ? WHERE member_id = ?",
                    (now, assignment.member_id),
                )
        return wait_id

    def _poll_and_apply_control_commands(
        self,
        assignment: RunAssignment,
        handle: RuntimeHandle,
    ) -> tuple[ExitReceipt | None, bool]:
        """Poll `control_commands` for `assignment.node_id` and apply `cancel_run` / `respond_wait`.

        Returns `(exit_receipt_if_stopped, any_wait_resolved)`.
        """
        rows = self.store.conn.execute(
            """
            SELECT * FROM control_commands
            WHERE node_id = ? AND state IN ('queued', 'claimed')
            ORDER BY CASE WHEN kind = 'cancel_run' THEN 0 ELSE 1 END ASC, created_at ASC
            """,
            (assignment.node_id,),
        ).fetchall()

        # Also check if turns.cancel_requested_at was set directly without a queued control_commands row
        t_row = self.store.conn.execute(
            "SELECT cancel_requested_at, execution_state FROM turns WHERE run_id = ?",
            (assignment.run_id,),
        ).fetchone()

        if not rows and not (t_row and t_row["cancel_requested_at"] and t_row["execution_state"] != "cancelled"):
            return None, False

        any_wait_resolved = False

        for cmd in rows:
            control_id = str(cmd["control_id"])
            kind = str(cmd["kind"])

            if kind in ("cancel_run", "stop_run"):
                with self.store.transaction("IMMEDIATE") as txn:
                    now = utc_now_iso()
                    txn.execute(
                        "UPDATE control_commands SET state = 'claimed', updated_at = ? WHERE control_id = ?",
                        (now, control_id),
                    )
                    txn.execute(
                        """
                        UPDATE control_commands
                        SET state = 'rejected', updated_at = ?
                        WHERE node_id = ? AND kind = 'respond_wait' AND state IN ('queued', 'claimed')
                        """,
                        (now, assignment.node_id),
                    )
                    txn.execute(
                        "UPDATE turns SET execution_state = 'stopping', cancel_requested_at = COALESCE(cancel_requested_at, ?) WHERE run_id = ?",
                        (now, assignment.run_id),
                    )
                    txn.execute(
                        "UPDATE parent_slots SET state = 'stopping', updated_at = ? WHERE node_id = ? AND state != 'released'",
                        (now, assignment.node_id),
                    )

                exit_rcpt = self.driver.stop_and_wait(handle, deadline_ms=5000)
                with self.store.transaction("IMMEDIATE") as txn:
                    now = utc_now_iso()
                    if exit_rcpt.exit_confirmed:
                        txn.execute(
                            "UPDATE control_commands SET state = 'applied', receipt_ref = ?, updated_at = ? WHERE control_id = ?",
                            (exit_rcpt.evidence_ref, now, control_id),
                        )
                    else:
                        txn.execute(
                            "UPDATE control_commands SET state = 'unknown', receipt_ref = ?, updated_at = ? WHERE control_id = ?",
                            (exit_rcpt.evidence_ref, now, control_id),
                        )
                        txn.execute(
                            "UPDATE turns SET execution_state = 'reconciliation' WHERE run_id = ?",
                            (assignment.run_id,),
                        )
                        txn.execute(
                            "UPDATE parent_slots SET state = 'reconciliation', updated_at = ? WHERE node_id = ? AND state != 'released'",
                            (now, assignment.node_id),
                        )
                return exit_rcpt, False

            if kind == "respond_wait":
                wait_id = str(cmd["wait_id"] or "")
                w_row = self.store.conn.execute(
                    "SELECT * FROM wait_requests WHERE wait_id = ?",
                    (wait_id,),
                ).fetchone()
                if w_row is None or str(w_row["state"]) not in ("open", "responding"):
                    with self.store.transaction("IMMEDIATE") as txn:
                        txn.execute(
                            "UPDATE control_commands SET state = 'rejected', updated_at = ? WHERE control_id = ?",
                            (utc_now_iso(), control_id),
                        )
                    continue

                if (
                    int(w_row["owner_epoch"]) != int(assignment.owner_epoch)
                    or str(w_row["runtime_instance_id"]) != handle.runtime_instance_id
                ):
                    with self.store.transaction("IMMEDIATE") as txn:
                        now = utc_now_iso()
                        txn.execute(
                            "UPDATE control_commands SET state = 'rejected', updated_at = ? WHERE control_id = ?",
                            (now, control_id),
                        )
                        txn.execute(
                            "UPDATE wait_requests SET state = 'expired', updated_at = ? WHERE wait_id = ?",
                            (now, wait_id),
                        )
                    continue

                with self.store.transaction("IMMEDIATE") as txn:
                    now = utc_now_iso()
                    txn.execute(
                        "UPDATE control_commands SET state = 'claimed', updated_at = ? WHERE control_id = ?",
                        (now, control_id),
                    )
                    txn.execute(
                        "UPDATE wait_requests SET state = 'responding', updated_at = ? WHERE wait_id = ?",
                        (now, wait_id),
                    )

                raw_payload = json.loads(cmd["payload"] or "{}")
                resp_obj = (
                    raw_payload["response"]
                    if isinstance(raw_payload, Mapping) and isinstance(raw_payload.get("response"), Mapping)
                    else raw_payload
                )
                bound_wait = BoundWait(
                    wait_id=str(w_row["wait_id"]),
                    node_id=str(w_row["node_id"]),
                    run_id=str(w_row["run_id"]),
                    runtime_turn_id=w_row["runtime_turn_id"],
                    runtime_instance_id=str(w_row["runtime_instance_id"]),
                    owner_epoch=int(w_row["owner_epoch"]),
                    host_request_id=str(w_row["host_request_id"]),
                    kind=str(w_row["kind"]),
                    nonce=str(w_row["nonce"]),
                    question=str(w_row["question"]),
                    options=json.loads(w_row["options"] or "[]"),
                    required_authority=str(w_row["required_authority"]),
                    deadline_at=w_row["deadline_at"],
                    state="responding",
                )
                try:
                    ctrl_rcpt = self.driver.respond_wait(handle, bound_wait, resp_obj, control_id)
                except SideSessionError as exc:
                    with self.store.transaction("IMMEDIATE") as txn:
                        now = utc_now_iso()
                        next_cmd_state = "rejected" if exc.code != ErrorCode.WAIT_RESPONSE_UNAVAILABLE.value else "rejected"
                        txn.execute(
                            "UPDATE control_commands SET state = ?, receipt_ref = ?, updated_at = ? WHERE control_id = ?",
                            (next_cmd_state, f"error:{exc.code}", now, control_id),
                        )
                        if exc.code == ErrorCode.WAIT_RESPONSE_UNAVAILABLE.value:
                            txn.execute(
                                "UPDATE wait_requests SET state = 'open', updated_at = ? WHERE wait_id = ?",
                                (now, wait_id),
                            )
                    continue

                with self.store.transaction("IMMEDIATE") as txn:
                    now = utc_now_iso()
                    applied = ctrl_rcpt.status == "applied"
                    txn.execute(
                        "UPDATE control_commands SET state = ?, receipt_ref = ?, updated_at = ? WHERE control_id = ?",
                        (ctrl_rcpt.status, ctrl_rcpt.host_receipt_id, now, control_id),
                    )
                    txn.execute(
                        "UPDATE wait_requests SET state = ?, receipt_ref = ?, updated_at = ? WHERE wait_id = ?",
                        ("resolved" if applied else "unknown", ctrl_rcpt.host_receipt_id, now, wait_id),
                    )
                    if applied:
                        txn.execute(
                            "UPDATE turns SET execution_state = 'running' WHERE run_id = ?",
                            (assignment.run_id,),
                        )
                        txn.execute(
                            "UPDATE parent_slots SET state = 'running', updated_at = ? WHERE node_id = ? AND state != 'released'",
                            (now, assignment.node_id),
                        )
                        if assignment.member_id:
                            txn.execute(
                                "UPDATE dispatch_group_members SET state = 'running', updated_at = ? WHERE member_id = ?",
                                (now, assignment.member_id),
                            )
                        any_wait_resolved = True

        # Handle direct cancel_requested_at on turns if no control_commands row existed
        if t_row and t_row["cancel_requested_at"]:
            exit_rcpt = self.driver.stop_and_wait(handle, deadline_ms=5000)
            return exit_rcpt, False

        return None, any_wait_resolved

    # ------------------------------------------------------------------
    # Public Turn & Node Execution Methods
    # ------------------------------------------------------------------

    def run_turn(
        self,
        assignment: RunAssignment,
        *,
        handle: RuntimeHandle | None = None,
        message_content: str | None = None,
    ) -> ExitReceipt:
        """Drive a single child turn under the node's fixed session lock, consume events and control
        commands, submit the idempotent fallback report, and call `engine.close_run`.
        """
        node_id = assignment.node_id
        acquired_lock: FileLock | None = None
        if not _is_session_lock_held_on_thread(node_id):
            acquired_lock = self.store.session_lock(node_id, blocking=False, timeout_ms=0)
            acquired_lock.acquire()

        owner_ctx = OwnerContext(
            node_id=node_id,
            run_id=assignment.run_id,
            worker_id=self.worker_id,
            owner_epoch=assignment.owner_epoch,
            fencing_token=assignment.fencing_token,
        )

        try:
            with self.store.transaction("IMMEDIATE") as txn:
                self._register_owner_in_txn(
                    txn,
                    node_id=node_id,
                    run_id=assignment.run_id,
                    owner_epoch=assignment.owner_epoch,
                    fencing_token=assignment.fencing_token,
                    runtime_instance_id=handle.runtime_instance_id if handle else None,
                )

            if message_content is None:
                m_row = self.store.conn.execute(
                    "SELECT payload FROM inbox_messages WHERE target_node_id = ? AND message_id = ?",
                    (node_id, assignment.message_id),
                ).fetchone()
                if m_row is not None:
                    message_content = str(m_row["payload"])
                else:
                    n_row = self.store.conn.execute(
                        "SELECT brief_content FROM nodes WHERE node_id = ?",
                        (node_id,),
                    ).fetchone()
                    message_content = str(n_row["brief_content"]) if n_row else "Execute assigned turn"

            # Check pre-start cancellation
            pre_cancel = self._has_pending_cancel_command(node_id, assignment.run_id)
            if pre_cancel is not None and handle is None:
                exit_rcpt = ExitReceipt(
                    runtime_instance_id="not_started",
                    process_identity={},
                    exit_confirmed=True,
                    runtime_outcome="cancelled",
                    ended_at=utc_now_iso(),
                    exit_code=0,
                    evidence_ref="not_started_proven",
                )
                fallback_rep = CanonicalReport(
                    node_id=node_id,
                    run_id=assignment.run_id,
                    turn_seq=assignment.turn_seq,
                    worker_turn_id=assignment.worker_turn_id,
                    runtime_turn_id=None,
                    phase="final",
                    report_revision=None,
                    outcome="cancelled",
                    blocked=False,
                    block_reason=None,
                    recap="Turn cancelled before runtime start",
                    full_report="Turn was cancelled before runtime session startup or send.",
                    artifacts=[],
                )
                self.engine.finalize_from_owner(owner_ctx, assignment.run_id, fallback_rep, exit_receipt=exit_rcpt)
                self.engine.close_run(owner_ctx, exit_rcpt, run_id=assignment.run_id)
                return exit_rcpt

            runtime_turn_id: str | None = None
            if handle is None:
                try:
                    handle, runtime_turn_id = self._advance_startup_operation(
                        node_id,
                        assignment,
                        message_content=message_content,
                    )
                except SideSessionError as exc:
                    if exc.message in ("CANCEL_BEFORE_START", "CANCEL_BEFORE_SEND"):
                        exit_rcpt = ExitReceipt(
                            runtime_instance_id="not_started",
                            process_identity={},
                            exit_confirmed=True,
                            runtime_outcome="cancelled",
                            ended_at=utc_now_iso(),
                            exit_code=0,
                            evidence_ref="not_started_proven",
                        )
                        fallback_rep = CanonicalReport(
                            node_id=node_id,
                            run_id=assignment.run_id,
                            turn_seq=assignment.turn_seq,
                            worker_turn_id=assignment.worker_turn_id,
                            runtime_turn_id=None,
                            phase="final",
                            report_revision=None,
                            outcome="cancelled",
                            blocked=False,
                            block_reason=None,
                            recap="Turn cancelled during startup",
                            full_report="Turn was cancelled during startup before runtime execution began.",
                            artifacts=[],
                        )
                        self.engine.finalize_from_owner(owner_ctx, assignment.run_id, fallback_rep, exit_receipt=exit_rcpt)
                        self.engine.close_run(owner_ctx, exit_rcpt, run_id=assignment.run_id)
                        return exit_rcpt
                    raise

            assert handle is not None
            terminal_outcome = "success"
            stopped_receipt: ExitReceipt | None = None
            turn_terminal_seen = False
            in_wait = False
            wait_deadline = time.monotonic() + (self.wait_poll_timeout_ms / 1000.0)
            last_hb = time.monotonic()

            while True:
                if time.monotonic() - last_hb >= 1.0:
                    self._update_heartbeat(node_id, assignment.owner_epoch, assignment.fencing_token)
                    last_hb = time.monotonic()

                # Poll control_commands first (cancel_run has priority over respond_wait)
                stop_rcpt, wait_resolved = self._poll_and_apply_control_commands(assignment, handle)
                if stop_rcpt is not None:
                    stopped_receipt = stop_rcpt
                    terminal_outcome = "cancelled" if stop_rcpt.exit_confirmed else "cancel_unknown"
                    break
                if wait_resolved:
                    in_wait = False

                if not in_wait:
                    self._deliver_queued_via_mailbox(assignment, handle)

                ev_stream = self.driver.events(handle)
                drain_fn = getattr(ev_stream, "drain_available", None)
                events = drain_fn(250) if callable(drain_fn) else list(ev_stream)
                for ev in events:
                    if ev.runtime_turn_id and not str(ev.runtime_turn_id).startswith("rturn:"):
                        if not runtime_turn_id or str(runtime_turn_id).startswith("rturn:"):
                            runtime_turn_id = str(ev.runtime_turn_id)
                            upgrade_fn = getattr(self.engine, "_upgrade_synthetic_turn_binding", None)
                            if callable(upgrade_fn):
                                upgrade_fn(
                                    node_id,
                                    handle.runtime_sid,
                                    runtime_turn_id,
                                    run_id=assignment.run_id,
                                )
                            else:
                                with self.store.transaction("IMMEDIATE") as txn:
                                    now_up = utc_now_iso()
                                    txn.execute(
                                        """
                                        UPDATE turns
                                        SET runtime_turn_id = ?
                                        WHERE run_id = ?
                                          AND (runtime_turn_id IS NULL OR runtime_turn_id = '' OR runtime_turn_id LIKE 'rturn:%')
                                        """,
                                        (runtime_turn_id, assignment.run_id),
                                    )
                                    txn.execute(
                                        """
                                        UPDATE bindings
                                        SET last_turn_id = ?, last_seen_at = ?
                                        WHERE (runtime_sid = ? OR node_id = ?)
                                          AND (last_turn_id IS NULL OR last_turn_id = '' OR last_turn_id LIKE 'rturn:%')
                                        """,
                                        (runtime_turn_id, now_up, handle.runtime_sid, node_id),
                                    )
                                    txn.execute(
                                        """
                                        UPDATE task_turn_bindings
                                        SET runtime_turn_id = ?
                                        WHERE (node_id = ? OR runtime_sid = ?)
                                          AND state = 'active'
                                          AND (runtime_turn_id IS NULL OR runtime_turn_id = '' OR runtime_turn_id LIKE 'rturn:%')
                                        """,
                                        (runtime_turn_id, node_id, handle.runtime_sid),
                                    )

                    if ev.kind == "wait_request" and ev.wait_request:
                        self._record_wait_event(assignment, handle, ev)
                        in_wait = True
                        if callable(self.on_wait):
                            self.on_wait(assignment, handle)
                    elif ev.kind == "turn.terminal":
                        if ev.outcome:
                            terminal_outcome = str(ev.outcome)
                        turn_terminal_seen = True
                        in_wait = False

                # Re-check control commands if any were queued while draining events
                stop_rcpt, wait_resolved = self._poll_and_apply_control_commands(assignment, handle)
                if stop_rcpt is not None:
                    stopped_receipt = stop_rcpt
                    terminal_outcome = "cancelled" if stop_rcpt.exit_confirmed else "cancel_unknown"
                    break
                if wait_resolved:
                    in_wait = False
                    continue

                if turn_terminal_seen and not in_wait:
                    break

                if in_wait:
                    time.sleep(min(0.025, self.poll_interval_ms / 1000.0))
                    continue

                time.sleep(min(0.025, self.poll_interval_ms / 1000.0))

            self._rollback_unread_mailbox_deliveries(assignment, handle)

            if stopped_receipt is not None:
                exit_receipt = stopped_receipt
            else:
                try:
                    stop_rcpt = self.driver.stop_and_wait(handle, deadline_ms=5000)
                except Exception:
                    stop_rcpt = ExitReceipt(
                        runtime_instance_id=handle.runtime_instance_id,
                        process_identity=dict(handle.process_identity),
                        exit_confirmed=False,
                        runtime_outcome="cancel_unknown",
                        ended_at=utc_now_iso(),
                        exit_code=None,
                        evidence_ref=f"exit:{handle.runtime_instance_id}:stop_failed",
                    )
                outcome = terminal_outcome if turn_terminal_seen else stop_rcpt.runtime_outcome
                norm_exit_code = 0 if (turn_terminal_seen and outcome == "success") else stop_rcpt.exit_code
                exit_receipt = ExitReceipt(
                    runtime_instance_id=stop_rcpt.runtime_instance_id,
                    process_identity=dict(stop_rcpt.process_identity or handle.process_identity),
                    exit_confirmed=bool(stop_rcpt.exit_confirmed),
                    runtime_outcome=outcome,
                    ended_at=stop_rcpt.ended_at or utc_now_iso(),
                    exit_code=norm_exit_code,
                    evidence_ref=stop_rcpt.evidence_ref,
                )

            if not exit_receipt.exit_confirmed:
                return exit_receipt

            # Check if child already submitted a final report for this turn_seq
            existing_final = self.store.conn.execute(
                "SELECT * FROM reports WHERE node_id = ? AND turn_seq = ? AND phase = 'final'",
                (node_id, assignment.turn_seq),
            ).fetchone()
            if existing_final is not None and terminal_outcome == "success":
                rep_outcome = str(existing_final["outcome"])
            else:
                rep_outcome = (
                    "cancelled"
                    if terminal_outcome == "cancelled"
                    else ("failed" if terminal_outcome in ("failed", "error") else "success")
                )

            last_text = ""
            if existing_final is None:
                reader = getattr(self.driver, "_read_source_session_from_sqlite", None)
                if callable(reader):
                    try:
                        _s, msgs, _r = reader(handle.runtime_sid)
                        for m in reversed(msgs or []):
                            if m.get("role") == "assistant":
                                parts = m.get("parts")
                                if isinstance(parts, list) and parts:
                                    last_text = "\n".join(
                                        str(p.get("text") or "")
                                        for p in parts
                                        if isinstance(p, Mapping) and p.get("type") == "text"
                                    ).strip()
                                elif m.get("content") and m.get("type") in (None, "text"):
                                    last_text = str(m.get("content") or "").strip()
                                if last_text:
                                    break
                    except Exception:
                        last_text = ""

            fallback_report = CanonicalReport(
                node_id=node_id,
                run_id=assignment.run_id,
                turn_seq=assignment.turn_seq,
                worker_turn_id=assignment.worker_turn_id,
                runtime_turn_id=runtime_turn_id,
                phase="final",
                report_revision=None,
                outcome=rep_outcome,
                blocked=(rep_outcome == "blocked"),
                block_reason="Blocked on child turn" if rep_outcome == "blocked" else None,
                recap=last_text or f"Turn {assignment.turn_seq} completed with outcome={rep_outcome}",
                full_report=(
                    f"# Worker Fallback Turn Report\n\n"
                    f"- Node ID: {node_id}\n"
                    f"- Run ID: {assignment.run_id}\n"
                    f"- Turn Seq: {assignment.turn_seq}\n"
                    f"- Outcome: {rep_outcome}\n"
                    + (
                        f"\n## Last assistant message\n\n{last_text[:MAX_FALLBACK_LAST_TEXT_CHARS]}\n"
                        if last_text
                        else ""
                    )
                ),
                artifacts=[],
            )

            # Submit idempotent fallback report (reuses child's final report & event_id if already reported)
            self.engine.finalize_from_owner(
                owner_ctx,
                assignment.run_id,
                fallback_report,
                exit_receipt=exit_receipt,
            )
            # Release parent slot and finalize turn/member/group state
            self.engine.close_run(
                owner_ctx,
                exit_receipt,
                run_id=assignment.run_id,
            )
            if getattr(self.driver, "driver_kind", None) == "zcode":
                try:
                    self._update_desktop_index_probe(node_id, handle.runtime_sid, handle.canonical_workspace)
                except Exception:
                    pass
            return exit_receipt

        except Exception:
            # Stop any spawned model process and clear PID on unhandled exception so crash recovery can detect termination
            try:
                if handle is not None:
                    self.driver.stop_and_wait(handle, deadline_ms=2000)
            except Exception:
                pass
            try:
                with self.store.transaction("IMMEDIATE") as err_txn:
                    err_txn.execute(
                        "UPDATE owners SET pid = NULL, model_pid = NULL, state = 'crashed' WHERE node_id = ? AND worker_id = ?",
                        (node_id, self.worker_id),
                    )
            except Exception:
                pass
            raise
        finally:
            if acquired_lock is not None:
                acquired_lock.release()

    def _resolve_mailbox_root(self) -> Path:
        env_root = os.environ.get("ZCODE_MAILBOX_ROOT")
        if env_root:
            return Path(env_root).expanduser().absolute()
        if getattr(self.driver, "driver_kind", None) == "zcode":
            return Path.home() / ".zcode" / "mailbox"
        return self.store.root / "mailbox"

    def _deliver_queued_via_mailbox(self, assignment: RunAssignment, handle: RuntimeHandle) -> None:
        root = self._resolve_mailbox_root()
        sdir = root / handle.runtime_sid
        unread, read = sdir / "unread", sdir / "read"
        unread.mkdir(mode=0o700, parents=True, exist_ok=True)
        read.mkdir(mode=0o700, parents=True, exist_ok=True)

        parent_row = (
            self.store.conn.execute(
                "SELECT runtime_session_id FROM nodes WHERE node_id = ?",
                (assignment.parent_node_id,),
            ).fetchone()
            if assignment.parent_node_id
            else None
        )
        parent_runtime_sid = str(
            (parent_row["runtime_session_id"] if parent_row and parent_row["runtime_session_id"] else None)
            or getattr(assignment, "parent_runtime_sid", None)
            or f"sess_{assignment.parent_node_id}"
        )

        rows = self.store.conn.execute(
            "SELECT * FROM inbox_messages WHERE target_node_id = ? AND state = 'queued' AND run_id IS NULL ORDER BY seq",
            (assignment.node_id,),
        ).fetchall()
        base_ms = int(time.time() * 1000)
        for idx, r in enumerate(rows):
            name = f"{base_ms + idx:013d}-{r['message_id']}.json"
            extract_fn = getattr(self.engine, "_extract_inbox_message_text", None)
            content_text = extract_fn(str(r["payload"])) if callable(extract_fn) else str(r["payload"])
            env = {
                "version": 1,
                "messageId": str(r["message_id"]),
                "fromSessionId": parent_runtime_sid,
                "toSessionId": handle.runtime_sid,
                "content": content_text,
                "createdAt": utc_now_iso(),
            }
            tmp = unread / f".tmp-{r['message_id']}"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(env, f, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            now = utc_now_iso()
            claimed = False
            try:
                with self.store.transaction("IMMEDIATE") as txn:
                    cur = txn.execute(
                        "UPDATE inbox_messages SET state = 'claimed', updated_at = ? WHERE target_node_id = ? AND message_id = ? AND state = 'queued'",
                        (now, assignment.node_id, r["message_id"]),
                    )
                    if cur.rowcount == 1:
                        txn.execute(
                            """
                            INSERT OR REPLACE INTO inbox_deliveries (
                                message_id, target_node_id, channel, state,
                                envelope_name, presented_in_turn, emitted_at, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (r["message_id"], assignment.node_id, "mailbox", "written", name, None, now, now, now),
                        )
                        claimed = True
                if claimed:
                    os.replace(tmp, unread / name)
                else:
                    tmp.unlink(missing_ok=True)
            except Exception:
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass
                raise

        for d in self.store.conn.execute(
            "SELECT * FROM inbox_deliveries WHERE target_node_id = ? AND channel = 'mailbox' AND state = 'written'",
            (assignment.node_id,),
        ).fetchall():
            if (read / str(d["envelope_name"])).exists():
                now = utc_now_iso()
                with self.store.transaction("IMMEDIATE") as txn:
                    txn.execute(
                        "UPDATE inbox_deliveries SET state = 'read', updated_at = ? WHERE target_node_id = ? AND message_id = ? AND channel = 'mailbox'",
                        (now, assignment.node_id, d["message_id"]),
                    )
                    txn.execute(
                        "UPDATE inbox_messages SET state = 'completed', updated_at = ? WHERE target_node_id = ? AND message_id = ?",
                        (now, assignment.node_id, d["message_id"]),
                    )

    def _rollback_unread_mailbox_deliveries(self, assignment: RunAssignment, handle: RuntimeHandle) -> None:
        self._deliver_queued_via_mailbox(assignment, handle)
        root = self._resolve_mailbox_root()
        sdir = root / handle.runtime_sid
        unread, read = sdir / "unread", sdir / "read"
        for d in self.store.conn.execute(
            "SELECT * FROM inbox_deliveries WHERE target_node_id = ? AND channel = 'mailbox' AND state = 'written'",
            (assignment.node_id,),
        ).fetchall():
            env_name = str(d["envelope_name"] or "")
            if env_name and (read / env_name).exists():
                continue
            if env_name:
                try:
                    (unread / env_name).unlink(missing_ok=True)
                except OSError:
                    pass
            now = utc_now_iso()
            with self.store.transaction("IMMEDIATE") as txn:
                txn.execute(
                    "UPDATE inbox_deliveries SET state = 'fallback', updated_at = ? WHERE target_node_id = ? AND message_id = ? AND channel = 'mailbox'",
                    (now, assignment.node_id, d["message_id"]),
                )
                txn.execute(
                    "UPDATE inbox_messages SET state = 'queued', updated_at = ? WHERE target_node_id = ? AND message_id = ? AND state = 'claimed' AND run_id IS NULL",
                    (now, assignment.node_id, d["message_id"]),
                )

    def _has_active_worktree_job(self, conn: sqlite3.Connection, node_id: str) -> bool:
        try:
            row = conn.execute(
                """
                SELECT 1 FROM worktree_jobs
                WHERE node_id = ? AND state IN ('queued', 'running', 'prepared')
                LIMIT 1
                """,
                (node_id,),
            ).fetchone()
            return row is not None
        except sqlite3.OperationalError:
            return False

    def _claim_next_assignment_for_node(self, node_id: str) -> tuple[RunAssignment | None, str | None, str]:
        """Inspect `node_id` while holding `session-<node_id>.lock` and claim either:
        1. An already-admitted active/starting turn (e.g. from `start_session` / `hand_off_to_session`), or
        2. The earliest `queued` message in `inbox_messages`.

        Returns `(assignment_or_none, message_content_or_none, status_reason)`.
        """
        if self._has_active_worktree_job(self.store.conn, node_id):
            return None, None, "worktree_job_active"
        if hasattr(self.engine, "_assert_no_active_worktree_job"):
            try:
                self.engine._assert_no_active_worktree_job(self.store.conn, node_id)
            except SideSessionError as exc:
                if exc.code == ErrorCode.SESSION_BUSY:
                    return None, None, "worktree_job_active"
                raise

        lease = self.store.conn.execute(
            "SELECT lease_until FROM interactive_leases WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        now_iso = self.engine._now_iso() if hasattr(self.engine, "_now_iso") else utc_now_iso()
        if lease is not None and str(lease["lease_until"]) > now_iso:
            return None, None, "interactive_lease"

        with self.store.transaction("IMMEDIATE") as txn:
            if self._has_active_worktree_job(txn.conn, node_id):
                return None, None, "worktree_job_active"
            if hasattr(self.engine, "_assert_no_active_worktree_job"):
                try:
                    self.engine._assert_no_active_worktree_job(txn.conn, node_id)
                except SideSessionError as exc:
                    if exc.code == ErrorCode.SESSION_BUSY:
                        return None, None, "worktree_job_active"
                    raise
            node_row = txn.execute("SELECT * FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
            if node_row is None:
                return None, None, "node_not_found"

            o_row = txn.execute("SELECT * FROM owners WHERE node_id = ?", (node_id,)).fetchone()
            w_alive, m_alive, live_reason = self._check_existing_live_processes(dict(o_row) if o_row else None)
            if w_alive or m_alive:
                return None, None, live_reason or "owner_alive"

            # 1. Check if there is an existing turn in ('queued', 'starting', 'running', 'waiting_input')
            #    or a turn in `owners.current_run_id` awaiting worker finalization / close_run.
            active_turn = txn.execute(
                """
                SELECT * FROM turns
                WHERE node_id = ? AND (
                    execution_state IN ('queued', 'starting', 'running', 'waiting_input')
                    OR run_id = ?
                )
                ORDER BY turn_seq ASC
                LIMIT 1
                """,
                (node_id, o_row["current_run_id"] if (o_row and o_row["state"] == "active") else ""),
            ).fetchone()
            if active_turn is not None:
                run_id = str(active_turn["run_id"])
                owner_epoch = int(o_row["owner_epoch"]) if o_row else int(active_turn["owner_epoch"])
                fencing_token = (
                    str(o_row["fencing_token"])
                    if (o_row and o_row["fencing_token"])
                    else (str(active_turn["fencing_token"]) or f"fence:{node_id}:{uuid.uuid4().hex}")
                )
                self._register_owner_in_txn(
                    txn,
                    node_id=node_id,
                    run_id=run_id,
                    owner_epoch=owner_epoch,
                    fencing_token=fencing_token,
                )
                msg_row = txn.execute(
                    "SELECT payload FROM inbox_messages WHERE target_node_id = ? AND message_id = ?",
                    (node_id, active_turn["message_id"]),
                ).fetchone()
                msg_content = str(msg_row["payload"]) if msg_row else str(node_row["brief_content"] or "")
                assignment = RunAssignment(
                    node_id=node_id,
                    runtime_sid=str(node_row["runtime_session_id"] or f"sess_{node_id}"),
                    turn_seq=int(active_turn["turn_seq"]),
                    run_id=run_id,
                    worker_turn_id=str(active_turn["worker_turn_id"]),
                    input_id=str(active_turn["input_id"] or uuid.uuid4()),
                    message_id=str(active_turn["message_id"]),
                    parent_node_id=str(node_row["parent_node_id"] or ""),
                    dispatch_group_id=str(active_turn["dispatch_group_id"] or ""),
                    member_id=str(active_turn["member_id"] or ""),
                    task_id=active_turn["task_id"],
                    task_revision=active_turn["task_revision"],
                    owner_epoch=owner_epoch,
                    fencing_token=fencing_token,
                )
                return assignment, msg_content, "resumed_active_turn"

            # 2. Check if node is eligible to claim new queued FIFO messages
            if str(node_row["node_status"]) != "active" or bool(node_row["pause_requested"]):
                return None, None, f"node_{node_row['node_status']}"

            queued_msg = txn.execute(
                """
                SELECT * FROM inbox_messages
                WHERE target_node_id = ? AND state = 'queued'
                ORDER BY seq ASC
                LIMIT 1
                """,
                (node_id,),
            ).fetchone()
            if queued_msg is None:
                return None, None, "no_queued_messages"

            parent_id = str(node_row["parent_node_id"] or "")
            run_id = str(queued_msg["run_id"] or uuid.uuid4())
            op_row = txn.execute(
                "SELECT operation_id FROM operations WHERE node_id = ? AND stage IN ('reserved', 'worktree_created', 'session_created', 'brief_accepted') ORDER BY created_at DESC LIMIT 1",
                (node_id,),
            ).fetchone()
            op_id = str(op_row["operation_id"]) if op_row else None

            # Ensure parent slot is reserved before claiming the message (Section 8.1)
            if parent_id:
                existing_slot = txn.execute(
                    "SELECT slot_no FROM parent_slots WHERE parent_node_id = ? AND node_id = ? AND state != 'released'",
                    (parent_id, node_id),
                ).fetchone()
                if existing_slot is None:
                    try:
                        self.engine.reserve_dispatch(txn, parent_id, node_id, operation_id=op_id, run_id=run_id)
                    except SideSessionError as exc:
                        if exc.code == ErrorCode.CAPACITY_EXCEEDED.value:
                            return None, None, "capacity_exceeded"
                        raise

            max_seq_row = txn.execute(
                "SELECT COALESCE(MAX(turn_seq), 0) AS max_seq FROM turns WHERE node_id = ?",
                (node_id,),
            ).fetchone()
            turn_seq = max(int(max_seq_row["max_seq"]) + 1, int(node_row["last_turn_seq"] or 0) + 1 if int(max_seq_row["max_seq"]) > 0 else 1)
            worker_turn_id = str(uuid.uuid4())
            input_id = str(uuid.uuid4())
            owner_epoch = (int(o_row["owner_epoch"]) + 1) if o_row else 1
            fencing_token = f"fence:{node_id}:{uuid.uuid4().hex}"
            task_id = queued_msg["task_id"] or node_row["primary_task_id"]
            task_revision: int | None = None
            if task_id:
                t_meta = txn.execute("SELECT task_revision FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
                task_revision = int(t_meta["task_revision"]) if t_meta else 1

            now = utc_now_iso()
            txn.execute(
                "UPDATE inbox_messages SET state = 'claimed', run_id = ?, updated_at = ? WHERE target_node_id = ? AND message_id = ?",
                (run_id, now, node_id, queued_msg["message_id"]),
            )
            txn.execute(
                "UPDATE nodes SET last_turn_seq = ?, updated_at = ? WHERE node_id = ?",
                (turn_seq, now, node_id),
            )
            if parent_id:
                txn.execute(
                    "UPDATE parent_slots SET state = 'starting', run_id = ?, updated_at = ? WHERE parent_node_id = ? AND node_id = ? AND state != 'released'",
                    (run_id, now, parent_id, node_id),
                )
            if queued_msg["member_id"]:
                txn.execute(
                    "UPDATE dispatch_group_members SET state = 'starting', run_id = ?, updated_at = ? WHERE member_id = ?",
                    (run_id, now, queued_msg["member_id"]),
                )

            txn.execute(
                """
                INSERT INTO turns (
                    run_id, node_id, turn_seq, worker_turn_id, runtime_turn_id,
                    input_id, message_id, dispatch_group_id, member_id, task_id,
                    task_revision, owner_epoch, fencing_token, execution_state,
                    report_state, started_at
                ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, 'starting', 'none', ?)
                """,
                (
                    run_id,
                    node_id,
                    turn_seq,
                    worker_turn_id,
                    input_id,
                    queued_msg["message_id"],
                    queued_msg["dispatch_group_id"],
                    queued_msg["member_id"],
                    task_id,
                    task_revision,
                    owner_epoch,
                    fencing_token,
                    now,
                ),
            )
            self._register_owner_in_txn(
                txn,
                node_id=node_id,
                run_id=run_id,
                owner_epoch=owner_epoch,
                fencing_token=fencing_token,
            )

            assignment = RunAssignment(
                node_id=node_id,
                runtime_sid=str(node_row["runtime_session_id"] or f"sess_{node_id}"),
                turn_seq=turn_seq,
                run_id=run_id,
                worker_turn_id=worker_turn_id,
                input_id=input_id,
                message_id=str(queued_msg["message_id"]),
                parent_node_id=parent_id,
                dispatch_group_id=str(queued_msg["dispatch_group_id"] or ""),
                member_id=str(queued_msg["member_id"] or ""),
                task_id=task_id,
                task_revision=task_revision,
                owner_epoch=owner_epoch,
                fencing_token=fencing_token,
            )
            return assignment, str(queued_msg["payload"]), "claimed_queued_message"

    def run_node(self, node_id: str, *, once: bool = False) -> dict[str, Any]:
        """Acquire `locks/session-<node_id>.lock` non-blocking and drive pending turns/messages for `node_id`."""
        try:
            lock = self.store.session_lock(node_id, blocking=False, timeout_ms=0)
            lock.acquire()
        except SideSessionError as exc:
            if exc.code == ErrorCode.LOCK_BUSY.value:
                return {
                    "ok": False,
                    "node_id": node_id,
                    "status": "lock_busy",
                    "code": ErrorCode.LOCK_BUSY.value,
                    "turns_executed": 0,
                }
            raise

        receipts: list[dict[str, Any]] = []
        last_reason = "idle"
        try:
            while True:
                lock.verify_inode()
                assignment, msg_content, reason = self._claim_next_assignment_for_node(node_id)
                last_reason = reason
                if assignment is None:
                    break

                rcpt = self.run_turn(assignment, message_content=msg_content)
                receipts.append(rcpt.to_dict())

                if once or not rcpt.exit_confirmed:
                    break
        finally:
            lock.release()

        return {
            "ok": True,
            "node_id": node_id,
            "status": "completed" if receipts else last_reason,
            "turns_executed": len(receipts),
            "receipts": receipts,
        }

    # ------------------------------------------------------------------
    # Crash Recovery (`recover`)
    # ------------------------------------------------------------------

    def recover(self, *, skip_unclaimed_deferred: bool = False) -> dict[str, Any]:
        """Scan active/unfinished `nodes`, `turns`, and `operations`, verify worker & model process
        liveness, safely recover terminated runs with fallback failure reports and `close_run`,
        and clean up unreferenced temporary/orphan report artifacts.
        """
        recovered_runs: list[dict[str, Any]] = []
        skipped_live_nodes: list[dict[str, Any]] = []
        reconciled_operations: list[dict[str, Any]] = []
        cleaned_orphan_artifacts: list[str] = []
        node_recovery_statuses: dict[str, str] = {}

        sup_lock: FileLock | None = None
        if not _is_supervisor_lock_held_on_thread():
            try:
                sup_lock = self.store.supervisor_lock(blocking=False, timeout_ms=0)
                sup_lock.acquire()
            except SideSessionError as exc:
                if exc.code == ErrorCode.LOCK_BUSY.value:
                    return {
                        "ok": False,
                        "code": ErrorCode.LOCK_BUSY.value,
                        "status": "lock_busy",
                        "recovered_runs": [],
                        "skipped_live_nodes": [],
                        "reconciled_operations": [],
                    }
                raise

        try:
            return self._recover_body(
                recovered_runs,
                skipped_live_nodes,
                reconciled_operations,
                cleaned_orphan_artifacts,
                node_recovery_statuses,
                skip_unclaimed_deferred=skip_unclaimed_deferred,
            )
        finally:
            if sup_lock is not None:
                sup_lock.release()

    def _recover_body(
        self,
        recovered_runs: list[dict[str, Any]],
        skipped_live_nodes: list[dict[str, Any]],
        reconciled_operations: list[dict[str, Any]],
        cleaned_orphan_artifacts: list[str],
        node_recovery_statuses: dict[str, str],
        *,
        skip_unclaimed_deferred: bool = False,
    ) -> dict[str, Any]:
        # 1. Scan in-flight turns
        active_turns = self.store.conn.execute(
            """
            SELECT * FROM turns
            WHERE execution_state IN ('queued', 'starting', 'running', 'waiting_input', 'stopping')
            ORDER BY started_at ASC, turn_seq ASC
            """
        ).fetchall()

        for t_row in active_turns:
            node_id = str(t_row["node_id"])
            run_id = str(t_row["run_id"])
            turn_seq = int(t_row["turn_seq"])
            o_row = self.store.conn.execute("SELECT * FROM owners WHERE node_id = ?", (node_id,)).fetchone()

            if (
                skip_unclaimed_deferred
                and str(t_row["execution_state"]) in ("queued", "starting")
                and o_row is not None
                and o_row["pid"] is None
                and o_row["model_pid"] is None
                and o_row["runtime_instance_id"] is None
                and str(o_row["state"]) == "active"
            ):
                skipped_live_nodes.append(
                    {
                        "node_id": node_id,
                        "run_id": run_id,
                        "reason": "unclaimed_deferred_turn",
                        "worker_pid": None,
                        "model_pid": None,
                    }
                )
                continue

            w_alive, m_alive, live_reason = self._check_existing_live_processes(dict(o_row) if o_row else None)
            if w_alive or m_alive:
                skipped_live_nodes.append(
                    {
                        "node_id": node_id,
                        "run_id": run_id,
                        "reason": live_reason,
                        "worker_pid": o_row["pid"] if o_row else None,
                        "model_pid": o_row["model_pid"] if o_row else None,
                    }
                )
                continue

            # Try to acquire session lock non-blocking to confirm no live worker holds the lock
            try:
                s_lock = self.store.session_lock(node_id, blocking=False, timeout_ms=0)
                s_lock.acquire()
            except SideSessionError as exc:
                if exc.code == ErrorCode.LOCK_BUSY.value:
                    skipped_live_nodes.append(
                        {
                            "node_id": node_id,
                            "run_id": run_id,
                            "reason": "session_lock_held",
                        }
                    )
                    continue
                raise

            try:
                new_epoch = max(
                    int(t_row["owner_epoch"] or 1),
                    int(o_row["owner_epoch"]) if o_row and o_row["owner_epoch"] is not None else 1,
                ) + 1
                new_fence = f"fence:{node_id}:{uuid.uuid4().hex}"

                with self.store.transaction("IMMEDIATE") as txn:
                    self._register_owner_in_txn(
                        txn,
                        node_id=node_id,
                        run_id=run_id,
                        owner_epoch=new_epoch,
                        fencing_token=new_fence,
                    )

                was_cancelled = bool(t_row["cancel_requested_at"]) or str(t_row["execution_state"]) == "stopping"
                rec_outcome = "cancelled" if was_cancelled else "failed"
                exit_rcpt = ExitReceipt(
                    runtime_instance_id=str(o_row["runtime_instance_id"] if o_row and o_row["runtime_instance_id"] else f"recovered:{run_id}"),
                    process_identity={},
                    exit_confirmed=True,
                    runtime_outcome=rec_outcome,
                    ended_at=utc_now_iso(),
                    exit_code=0 if was_cancelled else -1,
                    evidence_ref=f"recover:{run_id}:{new_epoch}",
                )
                fallback_rep = CanonicalReport(
                    node_id=node_id,
                    run_id=run_id,
                    turn_seq=turn_seq,
                    worker_turn_id=str(t_row["worker_turn_id"]),
                    runtime_turn_id=t_row["runtime_turn_id"],
                    phase="final",
                    report_revision=None,
                    outcome=rec_outcome,
                    blocked=False,
                    block_reason=None,
                    recap=f"Recovered terminated run ({rec_outcome})",
                    full_report=(
                        f"# Crash Recovery Fallback Report\n\n"
                        f"- Node ID: {node_id}\n"
                        f"- Run ID: {run_id}\n"
                        f"- Turn Seq: {turn_seq}\n"
                        f"- Outcome: {rec_outcome}\n"
                        f"- New Owner Epoch: {new_epoch}\n"
                    ),
                    artifacts=[],
                )
                owner_ctx = OwnerContext(
                    node_id=node_id,
                    run_id=run_id,
                    worker_id=self.worker_id,
                    owner_epoch=new_epoch,
                    fencing_token=new_fence,
                )
                rep_res = self.engine.finalize_from_owner(
                    owner_ctx,
                    run_id,
                    fallback_rep,
                    exit_receipt=exit_rcpt,
                )
                close_res = self.engine.close_run(
                    owner_ctx,
                    exit_rcpt,
                    run_id=run_id,
                )
                recovered_runs.append(
                    {
                        "node_id": node_id,
                        "run_id": run_id,
                        "turn_seq": turn_seq,
                        "outcome": close_res.get("outcome", rec_outcome),
                        "owner_epoch": new_epoch,
                        "report_id": rep_res.get("report_id"),
                        "event_id": rep_res.get("event_id"),
                        "slot_released": close_res.get("slot_released", True),
                    }
                )
            finally:
                s_lock.release()

        # 2. Scan unfinished operations
        live_node_ids = {item["node_id"] for item in skipped_live_nodes}
        pending_ops = self.store.conn.execute(
            """
            SELECT * FROM operations
            WHERE stage IN ('preparing_context', 'ready_for_admission', 'reserved', 'worktree_created', 'session_created', 'brief_accepted', 'running')
            ORDER BY created_at ASC
            """
        ).fetchall()

        for op_row in pending_ops:
            op_id = str(op_row["operation_id"])
            op_node_id = str(op_row["node_id"] or "")
            stage = str(op_row["stage"])
            if op_node_id and op_node_id in live_node_ids:
                continue

            if stage == "running" and op_node_id:
                latest_t = self.store.conn.execute(
                    "SELECT execution_state, outcome FROM turns WHERE node_id = ? ORDER BY turn_seq DESC LIMIT 1",
                    (op_node_id,),
                ).fetchone()
                if latest_t and str(latest_t["execution_state"]) in ("exited", "failed", "cancelled"):
                    next_stage = "finished" if str(latest_t["outcome"]) == "success" else "failed"
                    with self.store.transaction("IMMEDIATE") as txn:
                        txn.execute(
                            "UPDATE operations SET stage = ?, result_state = ?, revision = revision + 1, updated_at = ? WHERE operation_id = ?",
                            (next_stage, latest_t["outcome"], utc_now_iso(), op_id),
                        )
                    reconciled_operations.append({"operation_id": op_id, "from_stage": stage, "to_stage": next_stage})
                    continue

            if stage in ("worktree_created", "session_created", "brief_accepted"):
                with self.store.transaction("IMMEDIATE") as txn:
                    txn.execute(
                        "UPDATE operations SET stage = 'reconciliation', revision = revision + 1, updated_at = ? WHERE operation_id = ?",
                        (utc_now_iso(), op_id),
                    )
                reconciled_operations.append({"operation_id": op_id, "from_stage": stage, "to_stage": "reconciliation"})
            elif stage in ("preparing_context", "ready_for_admission", "reserved"):
                lock_held = False
                s_lock = None
                if op_node_id:
                    try:
                        s_lock = self.store.session_lock(op_node_id, blocking=False, timeout_ms=0)
                        s_lock.acquire()
                        lock_held = True
                    except SideSessionError as exc:
                        if exc.code == ErrorCode.LOCK_BUSY.value:
                            reconciled_operations.append(
                                {"operation_id": op_id, "from_stage": stage, "to_stage": "reconciliation", "reason": "OWNER_UNCERTAIN"}
                            )
                            continue
                        raise
                try:
                    o_row = self.store.conn.execute("SELECT * FROM owners WHERE node_id = ?", (op_node_id,)).fetchone() if op_node_id else None
                    w_alive, m_alive, live_reason = self._check_existing_live_processes(dict(o_row) if o_row else None)
                    if w_alive or m_alive:
                        with self.store.transaction("IMMEDIATE") as txn:
                            txn.execute(
                                "UPDATE operations SET stage = 'reconciliation', error = ?, revision = revision + 1, updated_at = ? WHERE operation_id = ?",
                                (live_reason or "OWNER_UNCERTAIN", utc_now_iso(), op_id),
                            )
                        reconciled_operations.append({"operation_id": op_id, "from_stage": stage, "to_stage": "reconciliation", "reason": live_reason})
                    else:
                        with self.store.transaction("IMMEDIATE") as txn:
                            txn.execute(
                                "UPDATE operations SET stage = 'reconciliation', error = 'unproven_reserved_stage', revision = revision + 1, updated_at = ? WHERE operation_id = ?",
                                (utc_now_iso(), op_id),
                            )
                        reconciled_operations.append({"operation_id": op_id, "from_stage": stage, "to_stage": "reconciliation"})
                finally:
                    if s_lock is not None and lock_held:
                        s_lock.release()

        # 3. Verify node recovery_status & dispatch_groups integrity
        all_nodes = self.store.conn.execute("SELECT * FROM nodes").fetchall()
        node_ids_set = {str(r["node_id"]) for r in all_nodes}
        cleaned_wt_nodes = {
            str(r["node_id"])
            for r in self.store.conn.execute(
                "SELECT node_id FROM worktrees WHERE state = 'cleaned'"
            ).fetchall()
        }
        with self.store.transaction("IMMEDIATE") as txn:
            now = utc_now_iso()
            for n_row in all_nodes:
                nid = str(n_row["node_id"])
                pid = n_row["parent_node_id"]
                c_ws = n_row["canonical_workspace"]
                r_sid = n_row["runtime_session_id"]

                if (
                    str(n_row["node_status"]) == "archived"
                    and nid in cleaned_wt_nodes
                    and not (pid and str(pid) not in node_ids_set)
                ):
                    rec_status = str(n_row["recovery_status"] or "topology_restored")
                    if rec_status == "orphaned":
                        rec_status = "topology_restored"
                elif (pid and str(pid) not in node_ids_set) or (
                    c_ws and (not Path(c_ws).exists() or Path(c_ws).is_symlink())
                ):
                    rec_status = "orphaned"
                elif r_sid and bool(n_row["host_link_verified"]):
                    owner_check = self.host_adapter.resolve_owner(str(r_sid))
                    if owner_check.db_check_state in ("deleted", "archived", "mismatch", "missing"):
                        rec_status = "needs_rehydration"
                    else:
                        rec_status = "runtime_resumable"
                else:
                    rec_status = "topology_restored"

                if str(n_row["recovery_status"]) != rec_status:
                    txn.execute(
                        "UPDATE nodes SET recovery_status = ?, updated_at = ? WHERE node_id = ?",
                        (rec_status, now, nid),
                    )
                node_recovery_statuses[nid] = rec_status

            # Check dispatch group member count integrity
            groups = txn.execute("SELECT * FROM dispatch_groups").fetchall()
            for g_row in groups:
                gid = str(g_row["dispatch_group_id"])
                cnt_row = txn.execute(
                    "SELECT COUNT(*) AS cnt FROM dispatch_group_members WHERE dispatch_group_id = ?",
                    (gid,),
                ).fetchone()
                actual_cnt = int(cnt_row["cnt"]) if cnt_row else 0
                if actual_cnt != int(g_row["member_count"]):
                    txn.execute(
                        "UPDATE dispatch_groups SET integrity_state = 'reconciliation', revision = revision + 1 WHERE dispatch_group_id = ?",
                        (gid,),
                    )

        # 4. Clean up unreferenced temporary/orphan report artifacts on disk
        referenced_rel_paths = {
            str(r["relative_blob_path"])
            for r in self.store.conn.execute(
                "SELECT relative_blob_path FROM artifacts WHERE relative_blob_path IS NOT NULL"
            ).fetchall()
        }
        for scan_subdir in ("artifacts/reports", "artifacts/blobs", "exports", "side-session-notes"):
            scan_dir = self.store.root / scan_subdir
            if not scan_dir.exists():
                continue
            for root_dir, _dirs, files in os.walk(scan_dir):
                for fname in files:
                    fpath = Path(root_dir) / fname
                    rel_path = str(fpath.relative_to(self.store.root)).replace("\\", "/")
                    if fname.startswith(".tmp-"):
                        try:
                            fpath.unlink()
                            cleaned_orphan_artifacts.append(rel_path)
                        except OSError:
                            pass
                    elif scan_subdir in ("artifacts/reports", "artifacts/blobs"):
                        if rel_path not in referenced_rel_paths:
                            try:
                                fpath.unlink()
                                cleaned_orphan_artifacts.append(rel_path)
                            except OSError:
                                pass

        try:
            self.store.rebuild_projections()
        except Exception:
            pass

        return {
            "ok": True,
            "recovered_runs": recovered_runs,
            "skipped_live_nodes": skipped_live_nodes,
            "reconciled_operations": reconciled_operations,
            "cleaned_orphan_artifacts": cleaned_orphan_artifacts,
            "node_recovery_statuses": node_recovery_statuses,
            "revision": self.store.get_revision(),
        }

    # ------------------------------------------------------------------
    # Health Check (`doctor`)
    # ------------------------------------------------------------------

    def doctor(self, *, plugin_root: Path | str | None = None) -> dict[str, Any]:
        """Return a structured health check report covering Python interpreter, SQLite WAL,
        state root permissions, Git availability, plugin manifests/script paths, and driver capabilities.
        """
        scripts_dir = Path(__file__).resolve().parent
        resolved_plugin_root = (
            Path(plugin_root).expanduser().resolve()
            if plugin_root is not None
            else scripts_dir.parent
        )

        # 1. Python interpreter check
        py_ok = sys.version_info >= (3, 10)
        python_info = {
            "ok": py_ok,
            "executable": sys.executable,
            "version": sys.version.split()[0],
            "version_info": list(sys.version_info[:3]),
            "isolated_flag": bool(getattr(sys.flags, "isolated", 0)),
        }

        # 2. SQLite WAL & store metadata check
        journal_mode = str(self.store.conn.execute("PRAGMA journal_mode;").fetchone()[0]).lower()
        fk_enabled = bool(self.store.conn.execute("PRAGMA foreign_keys;").fetchone()[0])
        sync_mode = int(self.store.conn.execute("PRAGMA synchronous;").fetchone()[0])
        sqlite_ok = journal_mode == "wal" and fk_enabled
        sqlite_info = {
            "ok": sqlite_ok,
            "sqlite_version": sqlite3.sqlite_version,
            "db_path": str(self.store.db_path),
            "journal_mode": journal_mode,
            "foreign_keys": fk_enabled,
            "synchronous": sync_mode,
            "store_instance_id": self.store.store_instance_id,
            "engine_schema_version": ENGINE_SCHEMA_VERSION,
            "driver_api_version": DRIVER_API_VERSION,
            "export_schema_version": EXPORT_SCHEMA_VERSION,
            "revision": self.store.get_revision(),
        }

        # 3. State root permissions check
        st = os.lstat(self.store.root)
        mode_bits = stat.S_IMODE(st.st_mode)
        uid_match = st.st_uid == os.getuid()
        not_symlink = not stat.S_ISLNK(st.st_mode)
        perms_0700 = (mode_bits & 0o077) == 0
        state_root_ok = uid_match and not_symlink and perms_0700
        state_root_info = {
            "ok": state_root_ok,
            "path": str(self.store.root),
            "exists": self.store.root.exists(),
            "is_symlink": not not_symlink,
            "mode": oct(mode_bits),
            "owner_uid": st.st_uid,
            "expected_uid": os.getuid(),
            "permissions_ok": perms_0700,
        }

        # 4. Git availability check
        git_available = False
        git_version = ""
        try:
            git_proc = subprocess.run(
                ["git", "--version"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5.0,
                check=False,
            )
            if git_proc.returncode == 0:
                git_available = True
                git_version = git_proc.stdout.decode("utf-8", errors="replace").strip()
        except Exception as exc:
            git_version = f"error: {exc}"
        git_info = {
            "ok": git_available,
            "available": git_available,
            "version": git_version,
        }

        # 5. Plugin manifests and script paths check
        manifest_rels = {
            "plugin_json": ".zcode-plugin/plugin.json",
            "mcp_json": ".mcp.json",
            "hooks_json": "hooks/hooks.json",
        }
        manifests_status: dict[str, Any] = {}
        manifests_all_ok = True
        for label, rel in manifest_rels.items():
            m_path = resolved_plugin_root / rel
            exists = m_path.is_file() and not m_path.is_symlink()
            valid_json = False
            if exists:
                try:
                    json.loads(m_path.read_text(encoding="utf-8"))
                    valid_json = True
                except Exception:
                    valid_json = False
            ok_item = exists and valid_json
            if not ok_item:
                manifests_all_ok = False
            manifests_status[label] = {
                "path": str(m_path),
                "exists": exists,
                "valid_json": valid_json,
                "ok": ok_item,
            }

        expected_scripts = (
            "contracts.py",
            "state.py",
            "worktree.py",
            "driver.py",
            "host_adapter.py",
            "engine.py",
            "mcp_server.py",
            "worker_runner.py",
        )
        scripts_status: dict[str, Any] = {}
        scripts_all_ok = True
        for s_name in expected_scripts:
            s_path = resolved_plugin_root / "scripts" / s_name
            s_ok = s_path.is_file() and not s_path.is_symlink()
            if not s_ok:
                scripts_all_ok = False
            scripts_status[s_name] = {
                "path": str(s_path),
                "exists": s_ok,
                "ok": s_ok,
            }

        plugin_info = {
            "ok": manifests_all_ok and scripts_all_ok,
            "plugin_root": str(resolved_plugin_root),
            "manifests": manifests_status,
            "scripts": scripts_status,
        }

        # 6. Driver capability matrix
        caps = self.driver.probe().to_dict()

        overall_ok = (
            python_info["ok"]
            and sqlite_info["ok"]
            and state_root_info["ok"]
            and git_info["ok"]
            and plugin_info["ok"]
        )

        return {
            "ok": overall_ok,
            "checked_at": utc_now_iso(),
            "python": python_info,
            "python_interpreter": python_info,
            "sqlite": sqlite_info,
            "sqlite_wal": sqlite_info,
            "state_root": state_root_info,
            "git": git_info,
            "plugin": plugin_info,
            "plugin_manifests": manifests_status,
            "script_paths": scripts_status,
            "driver_capabilities": caps,
            "capabilities": caps,
            "checks": {
                "python": python_info["ok"],
                "sqlite_wal": sqlite_info["ok"],
                "state_root": state_root_info["ok"],
                "git": git_info["ok"],
                "plugin": plugin_info["ok"],
            },
        }

    # ------------------------------------------------------------------
    # Contract & Component Self-Check (`verify`)
    # ------------------------------------------------------------------

    def verify(
        self,
        *,
        profile: str = "builtin",
        fixture_repo: Path | str | None = None,
        plugin_root: Path | str | None = None,
        parent_sid: str | None = None,
    ) -> dict[str, Any]:
        """Run built-in contract & component self-checks or profile-specific verification."""
        norm_profile = (profile or "builtin").strip().lower()
        if norm_profile not in VALID_VERIFY_PROFILES:
            return {
                "ok": False,
                "profile": norm_profile,
                "exit_code": 1,
                "error": f"Unsupported verify profile: {norm_profile!r}",
                "passed": [],
                "failed": ["profile_validation"],
                "not_run": [],
            }

        passed: list[str] = []
        failed: list[dict[str, Any]] = []
        not_run: list[dict[str, Any]] = []

        try:
            from .mcp_server import TrustedConnection, caller_from_meta, handle_rpc_message, handle_tool_call
        except ImportError:  # pragma: no cover
            from mcp_server import TrustedConnection, caller_from_meta, handle_rpc_message, handle_tool_call  # type: ignore

        try:
            from .engine import Engine
        except ImportError:  # pragma: no cover
            from engine import Engine  # type: ignore

        # 1. Verify contracts & MCP caller_from_meta
        try:
            meta_conn = TrustedConnection(initialized=True)
            c1 = caller_from_meta(
                {
                    "com.zcode/request-context": {
                        "session_id": "sid-verify-1",
                        "turn_id": "turn-verify-1",
                        "workspace_path": "/tmp/ws",
                    }
                },
                connection=meta_conn,
            )
            assert c1.runtime_sid == "sid-verify-1" and c1.runtime_turn_id == "turn-verify-1"

            conflict_caught = False
            try:
                caller_from_meta(
                    {
                        "com.zcode/request-context": {"session_id": "sid-a"},
                        "session_id": "sid-b",
                    },
                    connection=meta_conn,
                )
            except SideSessionError as exc:
                conflict_caught = exc.code == ErrorCode.CALLER_CONTEXT_CONFLICT.value
            assert conflict_caught

            unbound_caught = False
            try:
                caller_from_meta({}, connection=meta_conn)
            except SideSessionError as exc:
                unbound_caught = exc.code == ErrorCode.CALLER_UNBOUND.value
            assert unbound_caught
            passed.append("mcp_caller_from_meta")
        except Exception as exc:
            failed.append({"check": "mcp_caller_from_meta", "error": str(exc)})

        # 2. Verify isolated Store, Engine, MCP tools/call, WorkerRunner turn & recovery
        try:
            with tempfile.TemporaryDirectory(prefix="side-sessions-verify-") as tmp_dir:
                tmp_root = Path(tmp_dir) / "state"
                ws_dir = Path(tmp_dir) / "workspace"
                ws_dir.mkdir(parents=True, exist_ok=True)

                with open_store(tmp_root, writable=True) as v_store:
                    fake_drv = ScriptedFakeDriver(sync_to_host_db=False)
                    v_adapter = HostAdapter(store=v_store)
                    v_adapter.record_human_input(
                        runtime_sid="sid-parent-verify",
                        input_id="inp-verify-1",
                        origin="human_prompt",
                        runtime_turn_id="turn-parent-1",
                    )
                    v_engine = Engine(
                        v_store,
                        driver=fake_drv,
                        host_adapter=v_adapter,
                        worktrees_home=tmp_root / "worktrees",
                    )

                    rpc_conn = TrustedConnection()
                    init_resp = handle_rpc_message(
                        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
                        connection=rpc_conn,
                        engine=v_engine,
                    )
                    assert init_resp is not None and "result" in init_resp
                    handle_rpc_message(
                        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                        connection=rpc_conn,
                        engine=v_engine,
                    )
                    assert rpc_conn.initialized is True
                    list_resp = handle_rpc_message(
                        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                        connection=rpc_conn,
                        engine=v_engine,
                    )
                    assert list_resp is not None and len(list_resp["result"]["tools"]) >= 25
                    passed.append("mcp_initialize_and_tools_list")

                    bg_text = (
                        "总体目标：验证 side-sessions 核心契约、MCP 调用、WorkerRunner 回合执行与兜底报告闭环。\n"
                        "已有决策：使用只读 inherit 模式与 ScriptedFakeDriver 执行无副作用自检。\n"
                        "约束：严格遵循最小权限、状态根隔离与唯一 final 报告约束，不修改用户真实数据。"
                    )
                    call_req = {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "start_session",
                            "arguments": {
                                "initiation": "user_asked",
                                "request_id": str(uuid.uuid4()),
                                "title": "Self-check child session",
                                "prompt": "Inspect workspace and report status.",
                                "context": "fresh",
                                "background": bg_text,
                                "task_kind": "read_only",
                                "use_worktree": False,
                                "name": "verify-child",
                            },
                            "_meta": {
                                "com.zcode/request-context": {
                                    "session_id": "sid-parent-verify",
                                    "turn_id": "turn-parent-1",
                                    "workspace_path": str(ws_dir),
                                }
                            },
                        },
                    }
                    start_res = handle_tool_call(call_req, connection=rpc_conn, engine=v_engine)
                    assert start_res.get("ok") is True, start_res
                    child_node_id = start_res["node_id"]
                    child_sid = str(start_res.get("runtime_session_id") or "")
                    passed.append("engine_start_session_via_mcp")

                    v_runner = WorkerRunner(
                        v_store,
                        engine=v_engine,
                        driver=fake_drv,
                        host_adapter=v_adapter,
                    )
                    if child_sid:
                        fake_drv.queue_event(
                            child_sid,
                            {"kind": "turn.terminal", "outcome": "success"},
                        )
                    node_run_res = v_runner.run_node(child_node_id, once=True)
                    assert node_run_res["ok"] is True and node_run_res["turns_executed"] == 1, node_run_res
                    passed.append("worker_runner_turn_and_fallback_report")

                    rec_res = v_runner.recover()
                    assert rec_res["ok"] is True
                    passed.append("worker_runner_recover")
        except Exception as exc:
            failed.append({"check": "isolated_engine_and_worker_lifecycle", "error": str(exc)})

        # 3. Profile-specific checks
        if norm_profile == "plugin-load":
            doc = self.doctor(plugin_root=plugin_root)
            if doc["plugin"]["ok"]:
                passed.append("plugin_static_manifests_and_scripts")
            else:
                failed.append({"check": "plugin_static_manifests_and_scripts", "details": doc["plugin"]})
            not_run.append(
                {
                    "check": "host_ui_plugin_discovery",
                    "reason": "Requires interactive ZCode Desktop host session",
                }
            )
        elif norm_profile in ("host-contract", "supervisor-survival", "gui-wake"):
            if norm_profile == "gui-wake" and not parent_sid:
                not_run.append({"check": "live_gui_wake", "reason": "Missing explicit --parent-sid for disposable GUI parent"})
            elif norm_profile in ("host-contract", "supervisor-survival") and not fixture_repo:
                not_run.append({"check": f"live_{norm_profile}", "reason": "Missing explicit --fixture-repo path"})
            else:
                not_run.append({"check": f"live_{norm_profile}", "reason": "Live ZCode app-server integration not active in isolated CLI mode"})

        if failed:
            exit_code = 1
        elif not_run and norm_profile in ("host-contract", "plugin-load", "supervisor-survival", "gui-wake"):
            exit_code = 2
        else:
            exit_code = 0

        return {
            "ok": len(failed) == 0 and exit_code == 0,
            "profile": norm_profile,
            "host_version": "0.17.1",
            "protocol_revision": DRIVER_API_VERSION,
            "engine_schema_version": ENGINE_SCHEMA_VERSION,
            "passed": passed,
            "failed": failed,
            "not_run": not_run,
            "exit_code": exit_code,
            "verified_at": utc_now_iso(),
        }

    # ------------------------------------------------------------------
    # Supervisor Loop (`serve`)
    # ------------------------------------------------------------------

    def _list_runnable_node_ids(self, target_node_id: str | None = None) -> list[str]:
        if target_node_id is not None:
            return [target_node_id]

        candidates: list[str] = []
        seen: set[str] = set()

        # 1. Nodes with queued messages ordered by earliest message creation / seq
        q_rows = self.store.conn.execute(
            """
            SELECT m.target_node_id
            FROM inbox_messages m
            JOIN nodes n ON n.node_id = m.target_node_id
            WHERE m.state = 'queued' AND n.node_status = 'active' AND n.pause_requested = 0
            ORDER BY m.created_at ASC, m.seq ASC
            """
        ).fetchall()
        for r in q_rows:
            nid = str(r["target_node_id"])
            if nid not in seen:
                seen.add(nid)
                candidates.append(nid)

        # 2. Nodes with active/starting turns or unclosed owner runs
        t_rows = self.store.conn.execute(
            """
            SELECT DISTINCT node_id FROM turns
            WHERE execution_state IN ('queued', 'starting', 'running', 'waiting_input')
            UNION
            SELECT DISTINCT node_id FROM owners
            WHERE state = 'active' AND current_run_id IS NOT NULL
            """
        ).fetchall()
        for r in t_rows:
            nid = str(r["node_id"])
            if nid not in seen:
                seen.add(nid)
                candidates.append(nid)

        # 3. Nodes with unfinished startup operations
        op_rows = self.store.conn.execute(
            """
            SELECT DISTINCT node_id FROM operations
            WHERE node_id IS NOT NULL
              AND stage IN ('reserved', 'worktree_created', 'session_created', 'brief_accepted', 'running')
            """
        ).fetchall()
        for r in op_rows:
            nid = str(r["node_id"])
            if nid not in seen:
                seen.add(nid)
                candidates.append(nid)

        return candidates

    def _process_proposal_claim_jobs(self) -> list[dict[str, Any]]:
        """Scan `proposal_claim_jobs` for queued or lease-expired jobs and claim proposals."""
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat().replace("+00:00", "Z")
        stale_cutoff_iso = (now_dt - timedelta(seconds=60)).isoformat().replace("+00:00", "Z")

        try:
            rows = self.store.conn.execute(
                """
                SELECT proposal_id, request_id, state, updated_at
                FROM proposal_claim_jobs
                WHERE state = 'queued' OR (state = 'running' AND updated_at < ?)
                ORDER BY updated_at ASC
                """,
                (stale_cutoff_iso,),
            ).fetchall()
        except sqlite3.OperationalError:
            return []

        processed: list[dict[str, Any]] = []
        for j_row in rows:
            p_id = str(j_row["proposal_id"])
            req_id = str(j_row["request_id"])
            with self.store.transaction("IMMEDIATE") as txn:
                cas = txn.execute(
                    """
                    UPDATE proposal_claim_jobs
                    SET state = 'running', updated_at = ?
                    WHERE proposal_id = ?
                      AND (state = 'queued' OR (state = 'running' AND updated_at < ?))
                    """,
                    (now_iso, p_id, stale_cutoff_iso),
                )
                if cas.rowcount == 0:
                    continue
                p_row = txn.execute(
                    "SELECT * FROM proposals WHERE proposal_id = ?",
                    (p_id,),
                ).fetchone()
                if p_row is None:
                    txn.execute(
                        "UPDATE proposal_claim_jobs SET state = 'failed', updated_at = ? WHERE proposal_id = ?",
                        (now_iso, p_id),
                    )
                    continue
                p_state = str(p_row["state"])
                if p_state == "started":
                    txn.execute(
                        "UPDATE proposal_claim_jobs SET state = 'completed', updated_at = ? WHERE proposal_id = ?",
                        (now_iso, p_id),
                    )
                    processed.append({"proposal_id": p_id, "status": "already_started"})
                    continue
                if p_state in ("dismissed", "expired", "cleared", "failed"):
                    txn.execute(
                        "UPDATE proposal_claim_jobs SET state = 'failed', updated_at = ? WHERE proposal_id = ?",
                        (now_iso, p_id),
                    )
                    processed.append({"proposal_id": p_id, "status": p_state})
                    continue
                parent_id = str(p_row["parent_node_id"])
                p_node = txn.execute("SELECT * FROM nodes WHERE node_id = ?", (parent_id,)).fetchone()

            if p_node is None:
                with self.store.transaction("IMMEDIATE") as txn:
                    txn.execute(
                        "UPDATE proposal_claim_jobs SET state = 'failed', updated_at = ? WHERE proposal_id = ?",
                        (utc_now_iso(), p_id),
                    )
                continue

            caller = CallerContext(
                runtime_sid=str(p_node["runtime_session_id"] or f"sid:{parent_id}"),
                workspace_path=p_node["canonical_workspace"],
                node_id=parent_id,
            )
            try:
                claim_res = self.engine.start_session(
                    caller,
                    {"proposal_id": p_id, "request_id": req_id},
                )
                with self.store.transaction("IMMEDIATE") as txn:
                    txn.execute(
                        "UPDATE proposal_claim_jobs SET state = 'completed', updated_at = ? WHERE proposal_id = ?",
                        (utc_now_iso(), p_id),
                    )
                processed.append(
                    {
                        "proposal_id": p_id,
                        "status": "completed",
                        "node_id": claim_res.get("node_id"),
                    }
                )
            except SideSessionError as exc:
                next_st = (
                    "queued"
                    if exc.code in (ErrorCode.CAPACITY_EXCEEDED, ErrorCode.LOCK_BUSY, ErrorCode.RETRY_LATER)
                    else "failed"
                )
                with self.store.transaction("IMMEDIATE") as txn:
                    txn.execute(
                        "UPDATE proposal_claim_jobs SET state = ?, updated_at = ? WHERE proposal_id = ?",
                        (next_st, utc_now_iso(), p_id),
                    )
                processed.append({"proposal_id": p_id, "status": next_st, "code": str(exc.code)})
            except Exception as exc:
                with self.store.transaction("IMMEDIATE") as txn:
                    txn.execute(
                        "UPDATE proposal_claim_jobs SET state = 'failed', updated_at = ? WHERE proposal_id = ?",
                        (utc_now_iso(), p_id),
                    )
                processed.append({"proposal_id": p_id, "status": "failed", "error": str(exc)})
        return processed

    def _process_worktree_jobs(self, target_node_id: str | None = None) -> list[dict[str, Any]]:
        """Scan `worktree_jobs` for queued or lease-expired running/prepared jobs and execute them."""
        if not hasattr(self.engine, "execute_worktree_job"):
            return []
        now_iso = self.engine._now_iso() if hasattr(self.engine, "_now_iso") else utc_now_iso()
        try:
            with self.store.transaction("IMMEDIATE") as txn:
                txn.execute(
                    """
                    UPDATE worktree_jobs
                    SET state = 'queued', updated_at = ?
                    WHERE state = 'running' AND lease_until IS NOT NULL AND lease_until < ?
                    """,
                    (now_iso, now_iso),
                )
            if target_node_id is not None:
                j_rows = self.store.conn.execute(
                    """
                    SELECT job_id FROM worktree_jobs
                    WHERE node_id = ?
                      AND (state = 'queued' OR (state = 'prepared' AND (lease_until IS NULL OR lease_until < ?)))
                    ORDER BY created_at ASC
                    """,
                    (target_node_id, now_iso),
                ).fetchall()
            else:
                j_rows = self.store.conn.execute(
                    """
                    SELECT job_id FROM worktree_jobs
                    WHERE state = 'queued' OR (state = 'prepared' AND (lease_until IS NULL OR lease_until < ?))
                    ORDER BY created_at ASC
                    """,
                    (now_iso,),
                ).fetchall()
        except sqlite3.OperationalError:
            return []

        results: list[dict[str, Any]] = []
        for r in j_rows:
            jid = str(r["job_id"])
            try:
                res = self.engine.execute_worktree_job(jid)
                results.append(res)
            except SideSessionError as exc:
                results.append({"ok": False, "job_id": jid, "code": str(exc.code), "message": exc.message})
            except Exception as exc:
                results.append({"ok": False, "job_id": jid, "error": str(exc)})
        return results

    def drain_node(self, node_id: str, *, _depth: int = 0) -> dict[str, Any]:
        """Run turns for `node_id` without acquiring `supervisor_lock` and re-check up to 3 times for races."""
        self._process_worktree_jobs(node_id)
        last: dict[str, Any] = {}
        total_turns = 0
        for _ in range(4):
            last = self.run_node(node_id, once=False)
            if last.get("status") == "lock_busy":
                return {
                    "ok": True,
                    "node_id": node_id,
                    "status": "lock_busy",
                    "code": ErrorCode.LOCK_BUSY.value,
                    "turns_executed": total_turns,
                }
            total_turns += int(last.get("turns_executed", 0))
            again = self.store.conn.execute(
                "SELECT 1 FROM inbox_messages WHERE target_node_id = ? AND state = 'queued' "
                "UNION SELECT 1 FROM turns WHERE node_id = ? AND execution_state IN ('queued', 'starting')",
                (node_id, node_id),
            ).fetchone()
            if not again:
                break
        self._process_worktree_jobs(node_id)
        if _depth == 0:
            for _ in range(16):
                try:
                    wt_results = self._process_worktree_jobs(None)
                    claimed = self._process_proposal_claim_jobs()
                    followup_nids: list[str] = [
                        str(cj["node_id"])
                        for cj in claimed
                        if cj.get("status") == "completed" and cj.get("node_id")
                    ]
                    for rj in wt_results:
                        wt_nid = rj.get("node_id")
                        if rj.get("ok") is True and wt_nid:
                            has_pending = self.store.conn.execute(
                                "SELECT 1 FROM inbox_messages WHERE target_node_id = ? AND state = 'queued' "
                                "UNION SELECT 1 FROM turns WHERE node_id = ? AND execution_state IN ('queued', 'starting')",
                                (str(wt_nid), str(wt_nid)),
                            ).fetchone()
                            if has_pending is not None:
                                followup_nids.append(str(wt_nid))
                    dedup_nids = list(dict.fromkeys(followup_nids))
                    if not dedup_nids:
                        break
                    for nnid in dedup_nids:
                        self.drain_node(nnid, _depth=1)
                except sqlite3.OperationalError:
                    break
        return {
            "ok": True,
            "node_id": node_id,
            "status": "completed" if total_turns > 0 else last.get("status", "idle"),
            "turns_executed": total_turns,
            "last": last,
        }

    def serve(
        self,
        *,
        once: bool = False,
        node_id: str | None = None,
        max_iterations: int | None = None,
    ) -> dict[str, Any]:
        """Run the supervisor loop or a single pass (`once=True`) across runnable nodes."""
        if once:
            claimed_nids: list[str] = []
            if node_id is None:
                claimed = self._process_proposal_claim_jobs()
                claimed_nids = [
                    str(cj["node_id"])
                    for cj in claimed
                    if cj.get("status") == "completed" and cj.get("node_id")
                ]
            self._process_worktree_jobs(node_id)
            results: dict[str, Any] = {}
            for cnid in claimed_nids:
                results[cnid] = self.drain_node(cnid)
            node_ids = self._list_runnable_node_ids(node_id)
            for nid in node_ids:
                if nid in results:
                    continue
                results[nid] = self.run_node(nid, once=True)
            if node_id is None:
                tail_claimed = self._process_proposal_claim_jobs()
                self._process_worktree_jobs(None)
                for cj in tail_claimed:
                    cnid = cj.get("node_id")
                    if cj.get("status") == "completed" and cnid:
                        results[str(cnid)] = self.drain_node(str(cnid))
            return {
                "ok": True,
                "mode": "once",
                "nodes_checked": len(results),
                "results": results,
            }

        try:
            sup_lock = self.store.supervisor_lock(blocking=False, timeout_ms=0)
            sup_lock.acquire()
        except SideSessionError as exc:
            if exc.code == ErrorCode.LOCK_BUSY.value:
                return {
                    "ok": True,
                    "mode": "already_running",
                    "status": "already_running",
                    "code": ErrorCode.LOCK_BUSY.value,
                }
            raise
        stop_requested = False

        def _handle_sig(_signum: int, _frame: Any) -> None:
            nonlocal stop_requested
            stop_requested = True

        prev_int = signal.signal(signal.SIGINT, _handle_sig)
        prev_term = signal.signal(signal.SIGTERM, _handle_sig)
        iterations = 0
        results_summary: dict[str, Any] = {}
        try:
            self.recover(skip_unclaimed_deferred=True)
            while not stop_requested:
                claimed_nids = []
                if node_id is None:
                    claimed = self._process_proposal_claim_jobs()
                    claimed_nids = [
                        str(cj["node_id"])
                        for cj in claimed
                        if cj.get("status") == "completed" and cj.get("node_id")
                    ]
                self._process_worktree_jobs(node_id)
                for cnid in claimed_nids:
                    if stop_requested:
                        break
                    results_summary[cnid] = self.drain_node(cnid)
                node_ids = self._list_runnable_node_ids(node_id)
                for nid in node_ids:
                    if stop_requested:
                        break
                    if nid in claimed_nids:
                        continue
                    results_summary[nid] = self.run_node(nid, once=True)
                iterations += 1
                if max_iterations is not None and iterations >= max_iterations:
                    break
                time.sleep(self.poll_interval_ms / 1000.0)
        finally:
            signal.signal(signal.SIGINT, prev_int)
            signal.signal(signal.SIGTERM, prev_term)
            sup_lock.release()

        return {
            "ok": True,
            "mode": "serve",
            "iterations": iterations,
            "results": results_summary,
        }


# ------------------------------------------------------------------
# Module-Level Convenience Wrappers & CLI Entrypoint
# ------------------------------------------------------------------


def run_node(
    node_id: str,
    *,
    once: bool = False,
    store: Store | None = None,
    engine: Any = None,
    driver: BaseDriver | Any = None,
    state_root: Path | str | None = None,
) -> dict[str, Any]:
    with WorkerRunner(store, engine=engine, driver=driver, state_root=state_root) as runner:
        return runner.run_node(node_id, once=once)


def run_turn(
    assignment: RunAssignment,
    *,
    store: Store | None = None,
    engine: Any = None,
    driver: BaseDriver | Any = None,
    state_root: Path | str | None = None,
) -> ExitReceipt:
    with WorkerRunner(store, engine=engine, driver=driver, state_root=state_root) as runner:
        return runner.run_turn(assignment)


def recover(
    *,
    store: Store | None = None,
    engine: Any = None,
    driver: BaseDriver | Any = None,
    state_root: Path | str | None = None,
) -> dict[str, Any]:
    with WorkerRunner(store, engine=engine, driver=driver, state_root=state_root) as runner:
        return runner.recover()


def doctor(
    *,
    store: Store | None = None,
    state_root: Path | str | None = None,
    plugin_root: Path | str | None = None,
) -> dict[str, Any]:
    if store is None and state_root is None and not os.environ.get("ZCODE_SIDE_SESSIONS_HOME"):
        default_root = resolve_state_root()
        if not default_root.exists():
            with tempfile.TemporaryDirectory(prefix="side-sessions-doctor-") as tmp_dir:
                with WorkerRunner(state_root=Path(tmp_dir) / "state") as runner:
                    return runner.doctor(plugin_root=plugin_root)
    with WorkerRunner(store, state_root=state_root) as runner:
        return runner.doctor(plugin_root=plugin_root)


def verify(
    *,
    profile: str = "builtin",
    fixture_repo: Path | str | None = None,
    plugin_root: Path | str | None = None,
    parent_sid: str | None = None,
    state_root: Path | str | None = None,
) -> dict[str, Any]:
    if state_root is None and not os.environ.get("ZCODE_SIDE_SESSIONS_HOME"):
        with tempfile.TemporaryDirectory(prefix="side-sessions-verify-") as tmp_dir:
            with WorkerRunner(state_root=Path(tmp_dir) / "state") as runner:
                return runner.verify(
                    profile=profile,
                    fixture_repo=fixture_repo,
                    plugin_root=plugin_root,
                    parent_sid=parent_sid,
                )
    with WorkerRunner(state_root=state_root) as runner:
        return runner.verify(
            profile=profile,
            fixture_repo=fixture_repo,
            plugin_root=plugin_root,
            parent_sid=parent_sid,
        )


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="worker_runner.py",
        description="Supervisor and worker runner for side-sessions.",
    )
    subparsers = parser.add_subparsers(dest="subcommand")

    p_serve = subparsers.add_parser("serve", help="Run supervisor loop or single pass")
    p_serve.add_argument("--once", action="store_true", help="Run a single pass over runnable nodes and exit")
    p_serve.add_argument("--drain", action="store_true", help="With --node-id: run turns until no queued work remains")
    p_serve.add_argument("--node-id", type=str, default=None, help="Restrict execution to a specific node_id")
    p_serve.add_argument("--state-home", type=str, default=None, help="Explicit state root directory")
    p_serve.add_argument("--json", action="store_true", help="Output result as JSON")

    p_recover = subparsers.add_parser("recover", help="Recover terminated runs and reconcile pending operations")
    p_recover.add_argument("--state-home", type=str, default=None, help="Explicit state root directory")
    p_recover.add_argument("--json", action="store_true", help="Output recovery report as JSON")

    p_doctor = subparsers.add_parser("doctor", help="Run environment and state root health checks")
    p_doctor.add_argument("--state-home", type=str, default=None, help="Explicit state root directory")
    p_doctor.add_argument("--plugin-root", type=str, default=None, help="Explicit plugin root directory")
    p_doctor.add_argument("--json", action="store_true", help="Output health check report as JSON")

    p_verify = subparsers.add_parser("verify", help="Run built-in contract self-checks or verification profiles")
    p_verify.add_argument("--profile", type=str, default="builtin", help="Verification profile name")
    p_verify.add_argument("--fixture-repo", type=str, default=None, help="Temporary git repository fixture path")
    p_verify.add_argument("--plugin-root", type=str, default=None, help="Plugin root directory")
    p_verify.add_argument("--parent-sid", type=str, default=None, help="Disposable GUI parent session ID")
    p_verify.add_argument("--state-home", type=str, default=None, help="Explicit state root directory")
    p_verify.add_argument("--json", action="store_true", help="Output verification report as JSON")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `worker_runner.py`."""
    parser = _build_arg_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    cmd = args.subcommand or "doctor"
    state_home = getattr(args, "state_home", None)

    try:
        if cmd == "doctor":
            rep = doctor(
                state_root=state_home,
                plugin_root=getattr(args, "plugin_root", None),
            )
            sys.stdout.write(json.dumps(rep, ensure_ascii=False, indent=2) + "\n")
            sys.stdout.flush()
            return 0 if rep.get("ok") else 1

        if cmd == "verify":
            rep = verify(
                profile=getattr(args, "profile", "builtin"),
                fixture_repo=getattr(args, "fixture_repo", None),
                plugin_root=getattr(args, "plugin_root", None),
                parent_sid=getattr(args, "parent_sid", None),
                state_root=state_home,
            )
            sys.stdout.write(json.dumps(rep, ensure_ascii=False, indent=2) + "\n")
            sys.stdout.flush()
            return int(rep.get("exit_code", 0 if rep.get("ok") else 1))

        if cmd == "recover":
            rep = recover(state_root=state_home)
            sys.stdout.write(json.dumps(rep, ensure_ascii=False, indent=2) + "\n")
            sys.stdout.flush()
            return 0 if rep.get("ok") else 1

        if cmd == "serve":
            with WorkerRunner(state_root=state_home) as runner:
                if getattr(args, "drain", False) and getattr(args, "node_id", None):
                    rep = runner.drain_node(str(args.node_id))
                elif getattr(args, "drain", False):
                    results: dict[str, Any] = {}
                    for _ in range(8):
                        claimed = runner._process_proposal_claim_jobs()
                        wt_res = runner._process_worktree_jobs(None)
                        claimed_nids = [
                            str(cj["node_id"])
                            for cj in claimed
                            if cj.get("status") == "completed" and cj.get("node_id")
                        ]
                        node_ids = list(dict.fromkeys([*claimed_nids, *runner._list_runnable_node_ids(None)]))
                        if not node_ids and not wt_res:
                            break
                        progressed = bool(claimed_nids) or any(r.get("ok") for r in wt_res)
                        for nid in node_ids:
                            d_res = runner.drain_node(nid)
                            results[nid] = d_res
                            if int(d_res.get("turns_executed", 0)) > 0:
                                progressed = True
                        tail_claimed = runner._process_proposal_claim_jobs()
                        tail_wt = runner._process_worktree_jobs(None)
                        tail_nids = [
                            str(cj["node_id"])
                            for cj in tail_claimed
                            if cj.get("status") == "completed" and cj.get("node_id")
                        ]
                        for nid in tail_nids:
                            d_res = runner.drain_node(nid)
                            results[nid] = d_res
                            if int(d_res.get("turns_executed", 0)) > 0:
                                progressed = True
                        if not progressed and not tail_nids and not any(r.get("ok") for r in tail_wt):
                            break
                    rep = {"ok": True, "mode": "drain", "nodes_checked": len(results), "results": results}
                else:
                    try:
                        rep = runner.serve(
                            once=bool(getattr(args, "once", False)),
                            node_id=getattr(args, "node_id", None),
                        )
                    except SideSessionError as exc:
                        if exc.code != ErrorCode.LOCK_BUSY.value:
                            raise
                        rep = {"ok": True, "mode": "already_running"}
            if (
                getattr(args, "json", False)
                or getattr(args, "once", False)
                or getattr(args, "drain", False)
                or rep.get("mode") == "already_running"
            ):
                sys.stdout.write(json.dumps(rep, ensure_ascii=False, indent=2) + "\n")
                sys.stdout.flush()
            return 0 if rep.get("ok") else 1

        return 1
    except SideSessionError as exc:
        err_dict = exc.to_dict()
        sys.stdout.write(json.dumps(err_dict, ensure_ascii=False, indent=2) + "\n")
        sys.stdout.flush()
        return 1
    except Exception as exc:
        err_dict = {
            "ok": False,
            "error": {
                "code": ErrorCode.INVALID_REQUEST.value,
                "message": str(exc),
                "details": {"exception_type": type(exc).__name__},
            },
            "retryable": False,
        }
        sys.stdout.write(json.dumps(err_dict, ensure_ascii=False, indent=2) + "\n")
        sys.stdout.flush()
        return 1


__all__ = [
    "OwnerContext",
    "VALID_VERIFY_PROFILES",
    "WorkerRunner",
    "doctor",
    "main",
    "recover",
    "run_node",
    "run_turn",
    "verify",
]


if __name__ == "__main__":
    raise SystemExit(main())
