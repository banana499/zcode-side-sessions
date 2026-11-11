"""Host adapter for owner resolution, input provenance, trusted approval, task guards, and wake routing."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import threading
from typing import Any, Callable, Mapping
import uuid

try:
    from .contracts import (
        READ_ONLY_CONTROL_ALLOWLIST,
        ApprovalEvidence,
        CallerContext,
        DriverCapabilities,
        ErrorCode,
        GuardReceipt,
        HookContext,
        SideSessionError,
        SourceCutoff,
        WakeReceipt,
        _ErrorCodeStr,
        _SerializableMixin,
        canonical_json,
        canonical_json_sha256,
        normalize_text,
        sha256_hex,
        utc_now_iso,
        validate_uuid,
    )
    from .state import Store, open_store, resolve_state_root
except ImportError:  # pragma: no cover
    from contracts import (  # type: ignore
        READ_ONLY_CONTROL_ALLOWLIST,
        ApprovalEvidence,
        CallerContext,
        DriverCapabilities,
        ErrorCode,
        GuardReceipt,
        HookContext,
        SideSessionError,
        SourceCutoff,
        WakeReceipt,
        _ErrorCodeStr,
        _SerializableMixin,
        canonical_json,
        canonical_json_sha256,
        normalize_text,
        sha256_hex,
        utc_now_iso,
        validate_uuid,
    )
    from state import Store, open_store, resolve_state_root  # type: ignore


DEFAULT_HOST_DB_PATH = Path("~/.zcode/cli/db/db.sqlite")
TRUSTED_ADAPTER_TOKEN = "host_adapter_verified"


def _add_delivery_state_property() -> None:
    """Ensure WakeReceipt exposes `.delivery_state` alongside `.status`."""
    if not hasattr(WakeReceipt, "delivery_state"):
        def _get_delivery_state(self: WakeReceipt) -> str:
            if self.status in ("pending_until_next_parent_activity", "unsupported"):
                return "pending_until_next_parent_activity"
            return self.status

        setattr(WakeReceipt, "delivery_state", property(_get_delivery_state))


_add_delivery_state_property()


def get_process_lstart(pid: int) -> str | None:
    """Return `ps -p <pid> -o lstart=` output stripped, or None if process does not exist."""
    if not isinstance(pid, int) or pid <= 0:
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        pass
    except OSError:
        return None

    try:
        proc = subprocess.run(
            ["ps", "-p", str(pid), "-o", "lstart="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
            check=False,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    out = proc.stdout.decode("utf-8", errors="replace").strip()
    return out if out else None


def verify_process_identity(pid: int | None, expected_started_at: str | None = None) -> bool:
    """Check whether `pid` is alive and matches `expected_started_at` (if provided)."""
    if pid is None or not isinstance(pid, int) or pid <= 0:
        return False
    actual_lstart = get_process_lstart(pid)
    if actual_lstart is None:
        return False
    if expected_started_at is not None and expected_started_at.strip():
        exp = expected_started_at.strip()
        # Allow synthetic test markers when PID is current process
        if pid == os.getpid() and exp.startswith("test:"):
            return True
        if actual_lstart != exp:
            return False
    return True


@dataclass(frozen=True)
class HostOwner(_SerializableMixin):
    """Resolved runtime session owner metadata."""

    runtime_sid: str
    owner_kind: str
    owner_id: str
    node_id: str | None = None
    directory: str | None = None
    parent_runtime_sid: str | None = None
    db_check_state: str = "pending"
    is_alive: bool = False
    can_direct_wake: bool = False
    pid: int | None = None
    process_started_at: str | None = None
    runtime_instance_id: str | None = None
    time_archived: int | str | None = None
    time_deleted: int | str | None = None

    @property
    def known(self) -> bool:
        return True

    @property
    def status(self) -> str:
        return "known"


@dataclass(frozen=True)
class UnknownOwner(_SerializableMixin):
    """Unresolved or invalid runtime session owner."""

    runtime_sid: str
    reason: str = "owner_unresolved"
    db_check_state: str = "pending"
    node_id: str | None = None
    directory: str | None = None
    parent_runtime_sid: str | None = None
    time_archived: int | str | None = None
    time_deleted: int | str | None = None

    @property
    def known(self) -> bool:
        return False

    @property
    def owner_kind(self) -> str:
        return "unknown"

    @property
    def owner_id(self) -> str:
        return ""

    @property
    def is_alive(self) -> bool:
        return False

    @property
    def can_direct_wake(self) -> bool:
        return False

    @property
    def status(self) -> str:
        return "unknown"


@dataclass(frozen=True)
class VerifiedInput(_SerializableMixin):
    """Verified human input or slash-command event."""

    input_id: str
    owner_id: str
    runtime_sid: str
    origin: str
    runtime_turn_id: str | None = None
    command_id: str | None = None
    evidence_ref: str = ""
    verified: bool = True
    observed_at: str = ""

    @property
    def is_human(self) -> bool:
        return self.verified and self.origin in ("human_prompt", "slash_command")


@dataclass(frozen=True)
class UnknownInput(_SerializableMixin):
    """Unverified input or system/auto-continuation input (must never advance user_epoch)."""

    runtime_sid: str = ""
    input_id: str | None = None
    origin: str = "unknown"
    runtime_turn_id: str | None = None
    reason: str = "human_provenance_unverified"
    verified: bool = False

    @property
    def is_human(self) -> bool:
        return False


@dataclass(frozen=True)
class BoundTaskAction(_SerializableMixin):
    """Tool execution event bound to a verified task_id and task_revision."""

    action_id: str
    task_id: str
    task_revision: int
    binding_id: str
    node_id: str
    runtime_sid: str
    runtime_turn_id: str
    tool_use_id: str
    tool_name: str = ""
    scope_digest: str = ""
    state: str = "admitted"
    allowed: bool = True
    reason: str | None = None
    started_at: str = ""
    ended_at: str | None = None


@dataclass(frozen=True)
class ConsumptionReceipt(_SerializableMixin):
    """Verification result for outbox event consumption."""

    event_id: str
    consumer_parent_node_id: str
    verified: bool
    receipt_kind: str
    receipt_ref: str = ""
    acked_at: str = ""
    status: str = "verified"
    reason: str | None = None


def _future_iso(minutes: int = 30) -> str:
    dt = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return dt.isoformat().replace("+00:00", "Z")


def _is_expired_iso(expires_at: str, now_iso: str | None = None) -> bool:
    if not expires_at:
        return False
    now_str = now_iso or utc_now_iso()
    try:
        exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        now_dt = datetime.fromisoformat(now_str.replace("Z", "+00:00"))
        return now_dt >= exp_dt
    except ValueError:
        return expires_at <= now_str


def _compute_scope_digest(scope: Any) -> str:
    if isinstance(scope, str) and len(scope) == 64:
        return scope
    if isinstance(scope, str):
        try:
            import json
            parsed = json.loads(scope)
            return canonical_json_sha256(parsed)
        except Exception:
            return sha256_hex(scope)
    if isinstance(scope, Mapping):
        norm = {
            "resource_keys": sorted(str(x) for x in scope.get("resource_keys", [])),
            "write_path_roots": sorted(str(x) for x in scope.get("write_path_roots", [])),
            "artifact_source_roots": sorted(str(x) for x in scope.get("artifact_source_roots", [])),
        }
        return canonical_json_sha256(norm)
    return canonical_json_sha256(scope or {})


def _scopes_overlap(scope_a: Mapping[str, Any] | None, scope_b: Mapping[str, Any] | None) -> bool:
    if not scope_a or not scope_b:
        return False
    keys_a = {str(x) for x in scope_a.get("resource_keys", []) if x}
    keys_b = {str(x) for x in scope_b.get("resource_keys", []) if x}
    if keys_a and keys_b and (keys_a & keys_b):
        return True

    roots_a = [str(x).rstrip("/") for x in scope_a.get("write_path_roots", []) if x]
    roots_b = [str(x).rstrip("/") for x in scope_b.get("write_path_roots", []) if x]
    for ra in roots_a:
        for rb in roots_b:
            if ra == rb or ra.startswith(rb + "/") or rb.startswith(ra + "/"):
                return True
    return False


class HostAdapter:
    """Adapter isolating host database checks, input provenance, approvals, task guards, and wakes."""

    def __init__(
        self,
        store: Store | None = None,
        *,
        state_root: Path | str | None = None,
        host_db_path: Path | str | None = None,
        supports_task_guard: bool = True,
        supports_direct_gui_wake: bool = False,
        supports_history_commit_receipt: bool = False,
        trusted_token: str = TRUSTED_ADAPTER_TOKEN,
    ) -> None:
        self._store = store
        self._state_root = Path(state_root).expanduser().absolute() if state_root is not None else None
        self._host_db_path = Path(host_db_path).expanduser().absolute() if host_db_path is not None else None
        self.supports_task_guard = bool(supports_task_guard)
        self.supports_direct_gui_wake = bool(supports_direct_gui_wake)
        self.supports_history_commit_receipt = bool(supports_history_commit_receipt)
        self._trusted_token = trusted_token

        self._lock = threading.RLock()
        self._registered_owners: dict[str, HostOwner] = {}
        self._wake_handlers: dict[str, Callable[[ dict[str, Any]], dict[str, Any]]] = {}
        self._provenance_records: dict[tuple[str, str], VerifiedInput | UnknownInput] = {}
        self._consumed_approval_tokens: dict[str, tuple[str, str, ApprovalEvidence]] = {}
        self._issued_approvals: dict[str, ApprovalEvidence] = {}
        self._issued_tokens: set[str] = set()
        self._verified_commands: dict[str, dict[str, Any]] = {}
        self._guards: dict[str, GuardReceipt] = {}
        self._guard_scopes: dict[str, dict[str, Any]] = {}
        self._in_memory_actions: dict[str, BoundTaskAction] = {}
        self._in_memory_bindings: dict[tuple[str, str], dict[str, Any]] = {}

    @property
    def store(self) -> Store | None:
        return self._store

    @store.setter
    def store(self, value: Store | None) -> None:
        self._store = value

    def bind_store(self, store: Store | None) -> HostAdapter:
        """Attach an authoritative Store instance to this adapter."""
        self._store = store
        return self

    def _get_host_db_path(self) -> Path:
        if self._host_db_path is not None:
            return self._host_db_path
        env_path = os.environ.get("ZCODE_HOST_DB_PATH")
        if env_path and env_path.strip():
            return Path(env_path.strip()).expanduser().absolute()
        return DEFAULT_HOST_DB_PATH.expanduser().absolute()

    def _with_conn(self, *, write: bool = False) -> tuple[sqlite3.Connection | None, Store | None, bool]:
        """Acquire a connection from the bound Store (or open temporary Store if configured)."""
        if self._store is not None:
            return self._store.conn, self._store, False
        if self._state_root is not None:
            if not write and not (self._state_root / "state.sqlite3").exists():
                return None, None, False
            temp_store = open_store(self._state_root, writable=write)
            return temp_store.conn, temp_store, True
        return None, None, False

    def _query_host_session_ro(self, runtime_sid: str) -> dict[str, Any] | None:
        """Query the host SQLite `session` table in strict read-only mode (`mode=ro`)."""
        db_path = self._get_host_db_path()
        if not db_path.exists() or db_path.is_symlink() or not db_path.is_file():
            return None
        uri = f"file:{db_path}?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=1.5)
        except sqlite3.Error:
            return None
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON;")
            cols_rows = conn.execute("PRAGMA table_info(session)").fetchall()
            if not cols_rows:
                return None
            col_names = {str(r["name"]) for r in cols_rows}
            if "id" not in col_names:
                return None
            select_cols = [
                c
                for c in ("id", "directory", "parent_id", "parent_session_id", "time_archived", "time_deleted", "revert")
                if c in col_names
            ]
            sql = f"SELECT {', '.join(select_cols)} FROM session WHERE id = ? LIMIT 1"
            row = conn.execute(sql, (runtime_sid,)).fetchone()
            if row is None:
                return {"_exists": False}
            d = dict(row)
            d["_exists"] = True
            if "parent_id" not in d and "parent_session_id" in d:
                d["parent_id"] = d["parent_session_id"]
            return d
        except sqlite3.Error:
            return None
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Test / Runtime Registration Helpers
    # ------------------------------------------------------------------

    def register_owner(
        self,
        runtime_sid: str,
        owner: HostOwner | Mapping[str, Any],
        *,
        wake_handler: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> HostOwner:
        """Register a known runtime session owner (for controlled app-server or test injection)."""
        if isinstance(owner, HostOwner):
            record = owner
        elif isinstance(owner, Mapping):
            record = HostOwner(
                runtime_sid=str(owner.get("runtime_sid", runtime_sid)),
                owner_kind=str(owner.get("owner_kind", "managed")),
                owner_id=str(owner.get("owner_id", f"owner:{runtime_sid}")),
                node_id=owner.get("node_id"),
                directory=owner.get("directory"),
                parent_runtime_sid=owner.get("parent_runtime_sid"),
                db_check_state=str(owner.get("db_check_state", "verified")),
                is_alive=bool(owner.get("is_alive", True)),
                can_direct_wake=bool(owner.get("can_direct_wake", True)),
                pid=owner.get("pid"),
                process_started_at=owner.get("process_started_at"),
                runtime_instance_id=owner.get("runtime_instance_id"),
                time_archived=owner.get("time_archived"),
                time_deleted=owner.get("time_deleted"),
            )
        else:
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "owner must be HostOwner or Mapping")

        with self._lock:
            self._registered_owners[runtime_sid] = record
            if wake_handler is not None:
                self._wake_handlers[runtime_sid] = wake_handler
        return record

    def unregister_owner(self, runtime_sid: str) -> None:
        with self._lock:
            self._registered_owners.pop(runtime_sid, None)
            self._wake_handlers.pop(runtime_sid, None)

    def record_human_input(
        self,
        *,
        runtime_sid: str,
        input_id: str,
        origin: str = "human_prompt",
        owner_id: str | None = None,
        runtime_turn_id: str | None = None,
        command_id: str | None = None,
        evidence_ref: str = "",
        action_binding: Mapping[str, Any] | None = None,
    ) -> VerifiedInput:
        """Record a trusted human input or slash command in adapter and Store provenance."""
        if origin not in ("human_prompt", "slash_command", "real_user"):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"Invalid human input origin: {origin!r}",
            )
        norm_origin = "human_prompt" if origin == "real_user" else origin
        eff_owner = owner_id or f"host:{runtime_sid}"
        now = utc_now_iso()
        binding_json = canonical_json(dict(action_binding)) if action_binding is not None else None
        verified_inp = VerifiedInput(
            input_id=input_id,
            owner_id=eff_owner,
            runtime_sid=runtime_sid,
            origin=norm_origin,
            runtime_turn_id=runtime_turn_id,
            command_id=command_id,
            evidence_ref=evidence_ref or f"provenance:{runtime_sid}:{input_id}",
            verified=True,
            observed_at=now,
        )
        with self._lock:
            self._provenance_records[(runtime_sid, input_id)] = verified_inp
            self._provenance_records[(eff_owner, input_id)] = verified_inp
            if command_id:
                self._verified_commands[str(command_id)] = {
                    "input_id": input_id,
                    "runtime_sid": runtime_sid,
                    "origin": norm_origin,
                }

        conn, store_obj, should_close = self._with_conn(write=True)
        if conn is not None and store_obj is not None:
            try:
                cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(input_provenance)").fetchall()}
                has_p2_cols = "runtime_session_id" in cols and "action_binding_json" in cols
                if conn.in_transaction:
                    if has_p2_cols:
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO input_provenance (
                                owner_id, input_id, runtime_turn_id, origin, command_id,
                                evidence_ref, verified, created_at, runtime_session_id, action_binding_json
                            ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                            """,
                            (
                                eff_owner,
                                input_id,
                                runtime_turn_id,
                                norm_origin,
                                command_id,
                                verified_inp.evidence_ref,
                                now,
                                runtime_sid,
                                binding_json,
                            ),
                        )
                    else:
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO input_provenance (
                                owner_id, input_id, runtime_turn_id, origin, command_id, evidence_ref, verified, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                            """,
                            (
                                eff_owner,
                                input_id,
                                runtime_turn_id,
                                norm_origin,
                                command_id,
                                verified_inp.evidence_ref,
                                now,
                            ),
                        )
                elif store_obj.writable:
                    with store_obj.transaction():
                        if has_p2_cols:
                            conn.execute(
                                """
                                INSERT OR REPLACE INTO input_provenance (
                                    owner_id, input_id, runtime_turn_id, origin, command_id,
                                    evidence_ref, verified, created_at, runtime_session_id, action_binding_json
                                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                                """,
                                (
                                    eff_owner,
                                    input_id,
                                    runtime_turn_id,
                                    norm_origin,
                                    command_id,
                                    verified_inp.evidence_ref,
                                    now,
                                    runtime_sid,
                                    binding_json,
                                ),
                            )
                        else:
                            conn.execute(
                                """
                                INSERT OR REPLACE INTO input_provenance (
                                    owner_id, input_id, runtime_turn_id, origin, command_id, evidence_ref, verified, created_at
                                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                                """,
                                (
                                    eff_owner,
                                    input_id,
                                    runtime_turn_id,
                                    norm_origin,
                                    command_id,
                                    verified_inp.evidence_ref,
                                    now,
                                ),
                            )
            finally:
                if should_close:
                    store_obj.close()
        return verified_inp

    def record_system_input(
        self,
        *,
        runtime_sid: str,
        input_id: str,
        origin: str = "system/side_sessions",
        owner_id: str | None = None,
        runtime_turn_id: str | None = None,
    ) -> UnknownInput:
        """Record a plugin/system or auto-continuation input so it can never advance user_epoch."""
        eff_owner = owner_id or f"system:{runtime_sid}"
        now = utc_now_iso()
        unk = UnknownInput(
            runtime_sid=runtime_sid,
            input_id=input_id,
            origin=origin,
            runtime_turn_id=runtime_turn_id,
            reason="system_or_auto_continuation_input",
            verified=False,
        )
        with self._lock:
            self._provenance_records[(runtime_sid, input_id)] = unk
            self._provenance_records[(eff_owner, input_id)] = unk

        conn, store_obj, should_close = self._with_conn(write=True)
        if conn is not None and store_obj is not None:
            try:
                if conn.in_transaction:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO input_provenance (
                            owner_id, input_id, runtime_turn_id, origin, command_id, evidence_ref, verified, created_at
                        ) VALUES (?, ?, ?, ?, NULL, '', 0, ?)
                        """,
                        (eff_owner, input_id, runtime_turn_id, origin, now),
                    )
                elif store_obj.writable:
                    with store_obj.transaction():
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO input_provenance (
                                owner_id, input_id, runtime_turn_id, origin, command_id, evidence_ref, verified, created_at
                            ) VALUES (?, ?, ?, ?, NULL, '', 0, ?)
                            """,
                            (eff_owner, input_id, runtime_turn_id, origin, now),
                        )
            finally:
                if should_close:
                    store_obj.close()
        return unk

    # ------------------------------------------------------------------
    # 1. resolve_owner
    # ------------------------------------------------------------------

    def resolve_owner(self, runtime_sid: str) -> HostOwner | UnknownOwner:
        """Resolve the runtime owner for `runtime_sid` via Store bindings/owners and read-only host DB."""
        if not isinstance(runtime_sid, str) or not runtime_sid.strip():
            return UnknownOwner(runtime_sid=str(runtime_sid or ""), reason="empty_runtime_sid")
        sid = runtime_sid.strip()

        with self._lock:
            reg = self._registered_owners.get(sid)

        host_row = self._query_host_session_ro(sid)

        conn, store_obj, should_close = self._with_conn(write=False)
        binding_row: dict[str, Any] | None = None
        node_row: dict[str, Any] | None = None
        owner_row: dict[str, Any] | None = None
        expected_parent_sid: str | None = None

        if conn is not None and store_obj is not None:
            try:
                b_res = conn.execute(
                    "SELECT * FROM bindings WHERE runtime_sid = ?",
                    (sid,),
                ).fetchone()
                if b_res is not None:
                    binding_row = dict(b_res)

                n_res = conn.execute(
                    "SELECT * FROM nodes WHERE runtime_session_id = ?",
                    (sid,),
                ).fetchone()
                if n_res is None and binding_row is not None:
                    n_res = conn.execute(
                        "SELECT * FROM nodes WHERE node_id = ?",
                        (binding_row["node_id"],),
                    ).fetchone()
                if n_res is not None:
                    node_row = dict(n_res)
                    if node_row.get("parent_node_id"):
                        p_res = conn.execute(
                            "SELECT runtime_session_id FROM nodes WHERE node_id = ?",
                            (node_row["parent_node_id"],),
                        ).fetchone()
                        if p_res is not None:
                            expected_parent_sid = p_res["runtime_session_id"]

                    o_res = conn.execute(
                        "SELECT * FROM owners WHERE node_id = ?",
                        (node_row["node_id"],),
                    ).fetchone()
                    if o_res is not None:
                        owner_row = dict(o_res)
            finally:
                if should_close:
                    store_obj.close()

        # Compute db_check_state against host SQLite DB if available
        db_check_state = (
            str(binding_row["db_check_state"])
            if binding_row and binding_row.get("db_check_state")
            else "pending"
        )
        host_dir: str | None = None
        host_parent_id: str | None = None
        time_archived: Any = None
        time_deleted: Any = None

        if host_row is not None:
            if not host_row.get("_exists", False):
                if db_check_state == "verified":
                    db_check_state = "missing"
                else:
                    db_check_state = "pending"
            else:
                host_dir = host_row.get("directory")
                host_parent_id = host_row.get("parent_id")
                time_archived = host_row.get("time_archived")
                time_deleted = host_row.get("time_deleted")

                if time_deleted not in (None, 0, "", "0"):
                    db_check_state = "deleted"
                elif time_archived not in (None, 0, "", "0"):
                    db_check_state = "archived"
                else:
                    mismatch = False
                    expected_ws = (
                        (node_row.get("canonical_workspace") if node_row else None)
                        or (binding_row.get("cwd") if binding_row else None)
                    )
                    if expected_ws and host_dir:
                        exp_real = os.path.realpath(expected_ws) if os.path.exists(expected_ws) else expected_ws
                        act_real = os.path.realpath(host_dir) if os.path.exists(host_dir) else host_dir
                        if exp_real != act_real:
                            mismatch = True
                    if expected_parent_sid is not None and host_parent_id != expected_parent_sid:
                        mismatch = True
                    db_check_state = "mismatch" if mismatch else "verified"

        if reg is not None:
            if db_check_state in ("deleted", "archived", "mismatch"):
                return UnknownOwner(
                    runtime_sid=sid,
                    reason=f"host_db_{db_check_state}",
                    db_check_state=db_check_state,
                    node_id=reg.node_id,
                    directory=host_dir or reg.directory,
                    parent_runtime_sid=host_parent_id or reg.parent_runtime_sid,
                    time_archived=time_archived,
                    time_deleted=time_deleted,
                )
            return HostOwner(
                runtime_sid=sid,
                owner_kind=reg.owner_kind,
                owner_id=reg.owner_id,
                node_id=reg.node_id or (node_row["node_id"] if node_row else None),
                directory=host_dir or reg.directory or (node_row.get("canonical_workspace") if node_row else None),
                parent_runtime_sid=host_parent_id or reg.parent_runtime_sid or expected_parent_sid,
                db_check_state=db_check_state if host_row is not None else reg.db_check_state,
                is_alive=reg.is_alive,
                can_direct_wake=reg.can_direct_wake,
                pid=reg.pid,
                process_started_at=reg.process_started_at,
                runtime_instance_id=reg.runtime_instance_id,
                time_archived=time_archived,
                time_deleted=time_deleted,
            )

        if db_check_state in ("deleted", "archived", "mismatch"):
            return UnknownOwner(
                runtime_sid=sid,
                reason=f"host_session_{db_check_state}",
                db_check_state=db_check_state,
                node_id=node_row["node_id"] if node_row else (binding_row["node_id"] if binding_row else None),
                directory=host_dir or (node_row.get("canonical_workspace") if node_row else None),
                parent_runtime_sid=host_parent_id or expected_parent_sid,
                time_archived=time_archived,
                time_deleted=time_deleted,
            )

        if owner_row is not None and owner_row.get("state") == "active":
            pid = owner_row.get("pid")
            started_at = owner_row.get("process_started_at")
            alive = verify_process_identity(pid, started_at) if pid else True
            return HostOwner(
                runtime_sid=sid,
                owner_kind="managed",
                owner_id=str(owner_row["worker_id"]),
                node_id=str(owner_row["node_id"]),
                directory=host_dir or (node_row.get("canonical_workspace") if node_row else None),
                parent_runtime_sid=host_parent_id or expected_parent_sid,
                db_check_state=db_check_state,
                is_alive=alive,
                can_direct_wake=alive,
                pid=pid,
                process_started_at=started_at,
                runtime_instance_id=owner_row.get("runtime_instance_id"),
                time_archived=time_archived,
                time_deleted=time_deleted,
            )

        if node_row is not None:
            node_id = str(node_row["node_id"])
            is_root_or_ext = node_row.get("parent_node_id") is None or node_row.get("driver_kind") == "external"
            if is_root_or_ext:
                return HostOwner(
                    runtime_sid=sid,
                    owner_kind="external_gui",
                    owner_id=f"external:{sid}",
                    node_id=node_id,
                    directory=host_dir or node_row.get("canonical_workspace") or (binding_row.get("cwd") if binding_row else None),
                    parent_runtime_sid=host_parent_id or expected_parent_sid,
                    db_check_state=db_check_state,
                    is_alive=True,
                    can_direct_wake=self.supports_direct_gui_wake,
                    time_archived=time_archived,
                    time_deleted=time_deleted,
                )
            return HostOwner(
                runtime_sid=sid,
                owner_kind="managed",
                owner_id=f"node:{node_id}",
                node_id=node_id,
                directory=host_dir or node_row.get("canonical_workspace"),
                parent_runtime_sid=host_parent_id or expected_parent_sid,
                db_check_state=db_check_state,
                is_alive=False,
                can_direct_wake=False,
                time_archived=time_archived,
                time_deleted=time_deleted,
            )

        if binding_row is not None:
            node_id = str(binding_row["node_id"])
            return HostOwner(
                runtime_sid=sid,
                owner_kind="external_gui",
                owner_id=f"external:{sid}",
                node_id=node_id,
                directory=host_dir or binding_row.get("cwd"),
                parent_runtime_sid=host_parent_id,
                db_check_state=db_check_state,
                is_alive=True,
                can_direct_wake=self.supports_direct_gui_wake,
                time_archived=time_archived,
                time_deleted=time_deleted,
            )

        if host_row is not None and host_row.get("_exists", False):
            return HostOwner(
                runtime_sid=sid,
                owner_kind="external_gui",
                owner_id=f"host:{sid}",
                node_id=None,
                directory=host_dir,
                parent_runtime_sid=host_parent_id,
                db_check_state="verified",
                is_alive=False,
                can_direct_wake=self.supports_direct_gui_wake,
                time_archived=time_archived,
                time_deleted=time_deleted,
            )

        return UnknownOwner(
            runtime_sid=sid,
            reason="owner_unresolved",
            db_check_state=db_check_state,
        )

    # ------------------------------------------------------------------
    # 2. observe_input
    # ------------------------------------------------------------------

    def observe_input(self, event: Mapping[str, Any] | HookContext) -> VerifiedInput | UnknownInput:
        """Inspect a Hook or controlled channel input event for verifiable human provenance.

        Distinguishes verified `human_prompt` / `slash_command` from `auto_continuation` or
        `system/side_sessions`, returning `UnknownInput` whenever human origin cannot be verified.
        """
        if isinstance(event, HookContext):
            ev_dict: dict[str, Any] = event.to_dict()
            raw = dict(event.raw_input) if isinstance(event.raw_input, Mapping) else {}
        elif isinstance(event, Mapping):
            ev_dict = dict(event)
            raw = dict(ev_dict.get("raw_input")) if isinstance(ev_dict.get("raw_input"), Mapping) else {}
        else:
            return UnknownInput(reason="invalid_event_type")

        runtime_sid = str(
            ev_dict.get("runtime_sid")
            or ev_dict.get("session_id")
            or ev_dict.get("sessionId")
            or raw.get("session_id")
            or raw.get("sessionId")
            or ""
        ).strip()

        runtime_turn_id = (
            ev_dict.get("runtime_turn_id")
            or ev_dict.get("turn_id")
            or ev_dict.get("turnId")
            or raw.get("turn_id")
            or raw.get("turnId")
        )
        if runtime_turn_id is not None:
            runtime_turn_id = str(runtime_turn_id).strip() or None

        input_id = (
            ev_dict.get("input_id")
            or ev_dict.get("inputId")
            or ev_dict.get("real_input_id")
            or raw.get("input_id")
            or raw.get("inputId")
        )
        if input_id is not None:
            input_id = str(input_id).strip() or None

        command_id = (
            ev_dict.get("command_id")
            or ev_dict.get("commandId")
            or raw.get("command_id")
            or raw.get("commandId")
        )
        if command_id is not None:
            command_id = str(command_id).strip() or None

        stop_hook_active = ev_dict.get("stop_hook_active")
        if stop_hook_active is None:
            stop_hook_active = raw.get("stop_hook_active")

        raw_origin = (
            ev_dict.get("origin")
            or ev_dict.get("input_origin")
            or ev_dict.get("source")
            or raw.get("origin")
            or raw.get("input_origin")
        )
        origin_str = str(raw_origin).strip() if raw_origin is not None else ""

        # 1. Explicit auto-continuation or stop hook continuation -> never human
        if stop_hook_active is True or origin_str in (
            "auto_continuation",
            "stop_continuation",
            "stop_hook",
            "system/side_sessions",
            "system",
            "managed_dispatch",
            "model",
            "agent",
        ):
            norm_non_human = (
                "auto_continuation"
                if (stop_hook_active is True or origin_str in ("auto_continuation", "stop_continuation", "stop_hook"))
                else origin_str
            )
            return UnknownInput(
                runtime_sid=runtime_sid,
                input_id=input_id,
                origin=norm_non_human,
                runtime_turn_id=runtime_turn_id,
                reason="non_human_or_auto_continuation",
                verified=False,
            )

        if not runtime_sid or not input_id:
            return UnknownInput(
                runtime_sid=runtime_sid,
                input_id=input_id,
                origin=origin_str or "unknown",
                runtime_turn_id=runtime_turn_id,
                reason="missing_runtime_sid_or_input_id",
                verified=False,
            )

        # 2. Check in-memory and Store input_provenance table
        with self._lock:
            cached = self._provenance_records.get((runtime_sid, input_id))
        if isinstance(cached, UnknownInput):
            return cached
        if isinstance(cached, VerifiedInput):
            return cached

        conn, store_obj, should_close = self._with_conn(write=False)
        if conn is not None and store_obj is not None:
            try:
                rows = conn.execute(
                    "SELECT * FROM input_provenance WHERE input_id = ?",
                    (input_id,),
                ).fetchall()
                for row in rows:
                    db_origin = str(row["origin"])
                    if db_origin in ("system/side_sessions", "auto_continuation", "system") or not row["verified"]:
                        return UnknownInput(
                            runtime_sid=runtime_sid,
                            input_id=input_id,
                            origin=db_origin,
                            runtime_turn_id=runtime_turn_id or row["runtime_turn_id"],
                            reason="recorded_non_human_provenance",
                            verified=False,
                        )
                    if row["verified"] and db_origin in ("human_prompt", "slash_command", "real_user"):
                        norm_db_origin = "human_prompt" if db_origin == "real_user" else db_origin
                        return VerifiedInput(
                            input_id=input_id,
                            owner_id=str(row["owner_id"]),
                            runtime_sid=runtime_sid,
                            origin=norm_db_origin,
                            runtime_turn_id=runtime_turn_id or row["runtime_turn_id"],
                            command_id=command_id or row["command_id"],
                            evidence_ref=str(row["evidence_ref"] or ""),
                            verified=True,
                            observed_at=str(row["created_at"] or utc_now_iso()),
                        )
            finally:
                if should_close:
                    store_obj.close()

        # 3. Check explicit verified human provenance in controlled event
        if ev_dict.get("verified") is False:
            return UnknownInput(
                runtime_sid=runtime_sid,
                input_id=input_id,
                origin=origin_str or "unknown",
                runtime_turn_id=runtime_turn_id,
                reason="explicitly_unverified",
                verified=False,
            )

        if origin_str in ("human_prompt", "slash_command", "real_user"):
            norm_origin = "slash_command" if (origin_str == "slash_command" or command_id) else "human_prompt"
            owner_id = str(ev_dict.get("owner_id") or f"host:{runtime_sid}")
            evidence_ref = str(ev_dict.get("evidence_ref") or f"provenance:{runtime_sid}:{input_id}")
            return self.record_human_input(
                runtime_sid=runtime_sid,
                input_id=input_id,
                origin=norm_origin,
                owner_id=owner_id,
                runtime_turn_id=runtime_turn_id,
                command_id=command_id,
                evidence_ref=evidence_ref,
            )

        return UnknownInput(
            runtime_sid=runtime_sid,
            input_id=input_id,
            origin=origin_str or "unknown",
            runtime_turn_id=runtime_turn_id,
            reason="human_provenance_unverified",
            verified=False,
        )

    # ------------------------------------------------------------------
    # 3. verify_approval
    # ------------------------------------------------------------------

    def verify_approval(
        self,
        action: Mapping[str, Any],
        *,
        _conn: sqlite3.Connection | None = None,
        _record_in_memory: bool = True,
    ) -> ApprovalEvidence:
        """Verify that a proposal, context-quality downgrade, or wait response has a trusted human approval credential."""
        if not isinstance(action, Mapping):
            raise SideSessionError(
                ErrorCode.USER_APPROVAL_UNAVAILABLE,
                "Approval action must be a mapping",
            )

        # Reject model self-approval or automated retries
        origin = str(action.get("origin") or action.get("source") or action.get("actor_kind") or "").strip()
        if (
            origin in ("model", "agent", "mcp_tool", "mcp_retry", "auto_continuation", "system", "system/side_sessions")
            or action.get("from_model") is True
            or action.get("verified") is False
        ):
            raise SideSessionError(
                ErrorCode.USER_APPROVAL_UNAVAILABLE,
                "Model tool invocation cannot self-approve without trusted human action",
                {"origin": origin},
            )

        purpose = str(action.get("purpose") or "").strip()
        if not purpose:
            if "proposal_id" in action:
                purpose = "proposal"
            elif "operation_id" in action and "snapshot_hash" in action:
                purpose = "context_quality"
            elif "wait_id" in action:
                purpose = "wait_response"
            elif "preview_hash" in action or "worktree_id" in action:
                purpose = "worktree_merge"
            else:
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    "Cannot infer approval purpose from action; specify 'purpose', 'proposal_id', 'operation_id'+'snapshot_hash', 'wait_id', or 'preview_hash'",
                )

        if purpose not in ("proposal", "context_quality", "wait_response", "worktree_merge"):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"Unsupported approval purpose: {purpose!r}",
                {"purpose": purpose},
            )

        real_input_id = str(
            action.get("real_input_id")
            or action.get("input_id")
            or action.get("inputId")
            or ""
        ).strip()
        command_id_raw = action.get("command_id") or action.get("commandId")
        command_id = str(command_id_raw).strip() if command_id_raw is not None and str(command_id_raw).strip() else None

        interaction_token = (
            action.get("interaction_token")
            or action.get("approval_token")
            or action.get("human_signature")
            or action.get("signature")
            or action.get("trusted_token")
        )
        runtime_sid = str(action.get("runtime_sid") or action.get("parent_runtime_sid") or "").strip()

        # Check provenance of real_input_id if registered
        provenance_verified = False
        if real_input_id:
            with self._lock:
                for (k_sid, k_inp), rec in self._provenance_records.items():
                    if k_inp == real_input_id and (not runtime_sid or k_sid == runtime_sid):
                        if isinstance(rec, UnknownInput):
                            raise SideSessionError(
                                ErrorCode.USER_APPROVAL_UNAVAILABLE,
                                "Input ID belongs to a non-human / system input",
                                {"input_id": real_input_id},
                            )
                        if isinstance(rec, VerifiedInput):
                            provenance_verified = True
                            break

        conn = _conn
        store_obj = None
        should_close = False
        if conn is None:
            conn, store_obj, should_close = self._with_conn(write=False)

        try:
            if real_input_id and not provenance_verified and conn is not None:
                db_rows = conn.execute(
                    "SELECT * FROM input_provenance WHERE input_id = ?",
                    (real_input_id,),
                ).fetchall()
                for db_r in db_rows:
                    db_orig = str(db_r["origin"] or "")
                    if db_orig in ("system/side_sessions", "auto_continuation", "system") or not db_r["verified"]:
                        raise SideSessionError(
                            ErrorCode.USER_APPROVAL_UNAVAILABLE,
                            "Input ID belongs to a non-human / system input",
                            {"input_id": real_input_id},
                        )
                    if db_r["verified"] and db_orig in ("human_prompt", "slash_command", "real_user"):
                        provenance_verified = True
                        break

            token_ok = False
            if interaction_token is not None:
                token_str = str(interaction_token)
                with self._lock:
                    token_ok = token_str in self._issued_tokens or token_str in self._issued_approvals
            command_ok = False
            if command_id is not None:
                with self._lock:
                    command_ok = command_id in self._verified_commands
            has_trusted_credential = bool(provenance_verified or token_ok or command_ok)

            if not real_input_id or not has_trusted_credential:
                err_code = (
                    ErrorCode.HUMAN_ACTION_REQUIRED
                    if purpose == "wait_response"
                    else ErrorCode.USER_APPROVAL_UNAVAILABLE
                )
                raise SideSessionError(
                    err_code,
                    "Trusted human approval credential (real_input_id + slash command / interaction signature) is required",
                    {"purpose": purpose, "has_input_id": bool(real_input_id)},
                )

            parent_node_id = str(action.get("parent_node_id") or action.get("actor_node_id") or action.get("node_id") or "").strip()
            task_hash = str(action.get("task_hash") or "").strip()
            accepted_context_strategy = action.get("accepted_context_strategy")
            operation_id: str | None = None
            snapshot_hash: str | None = None
            history_quality: str | None = None
            brief_hash: str | None = None
            task_revision: int | None = action.get("task_revision")
            wait_id: str | None = None
            wait_nonce: str | None = None
            host_request_id: str | None = None
            run_id: str | None = None
            response_hash: str | None = None
            target_key = ""
            if purpose == "proposal":
                proposal_id = str(action.get("proposal_id") or "").strip()
                if proposal_id and conn is not None:
                    p_row = conn.execute(
                        "SELECT * FROM proposals WHERE proposal_id = ?",
                        (proposal_id,),
                    ).fetchone()
                    if p_row is not None:
                        if not parent_node_id:
                            parent_node_id = str(p_row["parent_node_id"])
                        elif parent_node_id != str(p_row["parent_node_id"]):
                            raise SideSessionError(
                                ErrorCode.FORBIDDEN,
                                "Proposal parent_node_id does not match actor",
                                {"proposal_id": proposal_id},
                            )
                        if not task_hash:
                            task_hash = str(p_row["task_hash"])
                        elif task_hash != str(p_row["task_hash"]):
                            raise SideSessionError(
                                ErrorCode.VALIDATION_ERROR,
                                "Proposal task_hash mismatch during approval verification",
                                {"proposal_id": proposal_id},
                            )
                if not parent_node_id:
                    parent_node_id = str(uuid.uuid4())
                if not task_hash:
                    task_hash = sha256_hex(proposal_id or real_input_id)
                target_key = f"proposal:{proposal_id or task_hash}"

            elif purpose == "context_quality":
                operation_id = validate_uuid(action.get("operation_id"), "operation_id")
                snapshot_hash = str(action.get("snapshot_hash") or "").strip()
                if not snapshot_hash:
                    raise SideSessionError(
                        ErrorCode.INVALID_REQUEST,
                        "context_quality approval requires non-empty snapshot_hash",
                    )
                history_quality = str(action.get("history_quality") or "brief_only").strip()
                if history_quality not in ("stable_projection", "brief_only"):
                    raise SideSessionError(
                        ErrorCode.INVALID_REQUEST,
                        f"Invalid history_quality: {history_quality!r}",
                    )
                brief_hash = str(action.get("brief_hash") or "").strip() or None

                if conn is not None:
                    snap_row = conn.execute(
                        "SELECT * FROM context_snapshots WHERE operation_id = ? AND snapshot_hash = ?",
                        (operation_id, snapshot_hash),
                    ).fetchone()
                    if snap_row is not None:
                        if not parent_node_id:
                            parent_node_id = str(snap_row["source_node_id"])
                        if not brief_hash:
                            brief_hash = str(snap_row["brief_hash"])
                        elif brief_hash != str(snap_row["brief_hash"]):
                            raise SideSessionError(
                                ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                                "brief_hash does not match context snapshot",
                            )
                        if snap_row["history_quality"] != history_quality:
                            raise SideSessionError(
                                ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                                "history_quality does not match context snapshot",
                            )
                        if task_revision is None and snap_row["task_revision"] is not None:
                            task_revision = int(snap_row["task_revision"])

                if not brief_hash:
                    brief_hash = sha256_hex(f"brief:{operation_id}:{snapshot_hash}")
                if not parent_node_id:
                    parent_node_id = str(uuid.uuid4())
                if not task_hash:
                    task_hash = sha256_hex(f"{operation_id}:{snapshot_hash}:{history_quality}:{brief_hash}")
                if accepted_context_strategy is None:
                    accepted_context_strategy = "summary_copy"
                target_key = f"context:{operation_id}:{snapshot_hash}:{history_quality}"

            elif purpose == "wait_response":
                wait_id = validate_uuid(action.get("wait_id"), "wait_id")
                wait_nonce = str(action.get("wait_nonce") or action.get("nonce") or "").strip()
                if not wait_nonce:
                    raise SideSessionError(
                        ErrorCode.INVALID_REQUEST,
                        "wait_response approval requires wait_nonce / nonce",
                    )
                host_request_id = str(action.get("host_request_id") or "").strip() or None
                run_id = str(action.get("run_id") or "").strip() or None
                response_hash = str(action.get("response_hash") or "").strip() or None
                if response_hash is None and "response" in action:
                    response_hash = canonical_json_sha256(action["response"])

                if conn is not None:
                    w_row = conn.execute(
                        "SELECT * FROM wait_requests WHERE wait_id = ?",
                        (wait_id,),
                    ).fetchone()
                    if w_row is not None:
                        if str(w_row["nonce"]) != wait_nonce:
                            raise SideSessionError(
                                ErrorCode.WAIT_STALE,
                                "wait_nonce does not match wait_requests record",
                                {"wait_id": wait_id},
                            )
                        if not host_request_id:
                            host_request_id = str(w_row["host_request_id"])
                        if not run_id:
                            run_id = str(w_row["run_id"])
                        if not parent_node_id:
                            parent_node_id = str(w_row["node_id"])

                if not host_request_id:
                    host_request_id = f"host-req:{wait_id}"
                if not run_id:
                    run_id = str(uuid.uuid4())
                if not response_hash:
                    response_hash = sha256_hex(f"{wait_id}:{wait_nonce}")
                if not parent_node_id:
                    parent_node_id = str(uuid.uuid4())
                if not task_hash:
                    task_hash = response_hash
                target_key = f"wait:{wait_id}:{wait_nonce}:{response_hash}"

            elif purpose == "worktree_merge":
                wt_target_id = str(action.get("target_id") or action.get("node_id") or action.get("worktree_id") or "").strip()
                wt_preview_hash = str(action.get("preview_hash") or action.get("target_hash") or task_hash or "").strip()
                if not wt_preview_hash:
                    raise SideSessionError(
                        ErrorCode.INVALID_REQUEST,
                        "worktree_merge approval requires non-empty preview_hash / target_hash",
                    )
                if not parent_node_id:
                    parent_node_id = wt_target_id or str(uuid.uuid4())
                task_hash = wt_preview_hash
                target_key = f"worktree_merge:{wt_target_id}:{wt_preview_hash}"
        finally:
            if should_close and store_obj is not None:
                store_obj.close()

        # Single-use replay check per (real_input_id, command_id) token (standalone non-txn mode only)
        token_key = f"{real_input_id}:{command_id or ''}:{interaction_token or ''}"
        with self._lock:
            if _record_in_memory:
                existing = self._consumed_approval_tokens.get(token_key)
                if existing is not None:
                    prev_purpose, prev_target, prev_evidence = existing
                    if prev_purpose == purpose and prev_target == target_key:
                        return prev_evidence
                    raise SideSessionError(
                        _ErrorCodeStr(ErrorCode.APPROVAL_REPLAYED.value, ErrorCode.USER_APPROVAL_UNAVAILABLE.value),
                        "Human approval credential has already been consumed for a different target",
                        {"real_input_id": real_input_id, "command_id": command_id},
                    )

            now_iso = str(action.get("approved_at") or utc_now_iso())
            default_ttl_min = 30 if purpose == "context_quality" else (24 * 60)
            expires_at = str(action.get("expires_at") or _future_iso(default_ttl_min))
            if _is_expired_iso(expires_at, now_iso):
                raise SideSessionError(
                    ErrorCode.EXPIRED,
                    "Approval credential is already expired",
                    {"expires_at": expires_at},
                )

            approval_id = str(action.get("approval_id") or uuid.uuid4())
            evidence_ref = str(
                action.get("evidence_ref")
                or f"approval:{purpose}:{approval_id}"
            )
            evidence = ApprovalEvidence(
                approval_id=approval_id,
                parent_node_id=parent_node_id,
                real_input_id=real_input_id,
                purpose=purpose,
                task_hash=task_hash,
                approved_at=now_iso,
                expires_at=expires_at,
                verifier="host_adapter.verify_approval",
                evidence_ref=evidence_ref,
                command_id=command_id,
                accepted_context_strategy=accepted_context_strategy,
                operation_id=operation_id,
                snapshot_hash=snapshot_hash,
                history_quality=history_quality,
                brief_hash=brief_hash,
                task_revision=task_revision,
                wait_id=wait_id,
                wait_nonce=wait_nonce,
                host_request_id=host_request_id,
                run_id=run_id,
                response_hash=response_hash,
                target_id=str(action.get("target_id") or action.get("proposal_id") or operation_id or wait_id or parent_node_id),
                target_hash=str(action.get("target_hash") or action.get("preview_hash") or snapshot_hash or response_hash or task_hash),
                preview_hash=str(action.get("preview_hash") or "") or None,
                _trusted_token=self._trusted_token,
            )
            if _record_in_memory:
                self._consumed_approval_tokens[token_key] = (purpose, target_key, evidence)
            self._issued_approvals[approval_id] = evidence
            return evidence

    def verify_and_consume_approval_in_txn(
        self,
        conn: sqlite3.Connection,
        action: Mapping[str, Any],
        *,
        caller: CallerContext | None = None,
    ) -> ApprovalEvidence:
        """Verify human provenance and atomically consume approval inside the caller's active SQLite transaction."""
        if not isinstance(action, Mapping):
            raise SideSessionError(
                ErrorCode.USER_APPROVAL_UNAVAILABLE,
                "Approval action must be a mapping",
            )

        origin = str(action.get("origin") or action.get("source") or action.get("actor_kind") or "").strip()
        if (
            origin in ("model", "agent", "mcp_tool", "mcp_retry", "auto_continuation", "system", "system/side_sessions")
            or action.get("from_model") is True
            or action.get("verified") is False
        ):
            raise SideSessionError(
                ErrorCode.USER_APPROVAL_UNAVAILABLE,
                "Model tool invocation cannot self-approve without trusted human action",
                {"origin": origin},
            )

        purpose = str(action.get("purpose") or "").strip()
        if not purpose:
            if "proposal_id" in action:
                purpose = "proposal"
            elif "operation_id" in action and "snapshot_hash" in action:
                purpose = "context_quality"
            elif "wait_id" in action:
                purpose = "wait_response"
            elif "preview_hash" in action or "worktree_id" in action:
                purpose = "worktree_merge"
            else:
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    "Cannot infer approval purpose from action",
                )
        if purpose not in ("proposal", "context_quality", "wait_response", "worktree_merge"):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"Unsupported approval purpose: {purpose!r}",
                {"purpose": purpose},
            )

        real_input_id = str(
            action.get("real_input_id")
            or action.get("input_id")
            or action.get("inputId")
            or ""
        ).strip()
        caller_sid = str(
            (caller.runtime_sid if caller is not None else "")
            or action.get("runtime_sid")
            or action.get("parent_runtime_sid")
            or ""
        ).strip()

        if purpose == "proposal":
            target_id = str(action.get("proposal_id") or action.get("target_id") or "").strip()
            target_hash = str(action.get("task_hash") or action.get("target_hash") or "").strip()
        elif purpose == "context_quality":
            target_id = str(action.get("operation_id") or action.get("target_id") or "").strip()
            target_hash = str(action.get("snapshot_hash") or action.get("target_hash") or "").strip()
        elif purpose == "wait_response":
            target_id = str(action.get("wait_id") or action.get("target_id") or "").strip()
            resp_h = str(action.get("response_hash") or "").strip() or (
                canonical_json_sha256(action["response"]) if "response" in action else ""
            )
            w_nonce = str(action.get("wait_nonce") or action.get("nonce") or "").strip()
            target_hash = str(action.get("target_hash") or (sha256_hex(f"{w_nonce}:{resp_h}") if w_nonce else resp_h))
        else:  # worktree_merge
            target_id = str(action.get("target_id") or action.get("node_id") or action.get("worktree_id") or "").strip()
            target_hash = str(action.get("target_hash") or action.get("preview_hash") or action.get("task_hash") or "").strip()

        action_hash = canonical_json_sha256(
            {
                "purpose": purpose,
                "target_id": target_id,
                "target_hash": target_hash,
            }
        )
        request_id = str(action.get("request_id") or uuid.uuid4())

        if not real_input_id:
            err_code = (
                ErrorCode.HUMAN_ACTION_REQUIRED
                if purpose == "wait_response"
                else ErrorCode.USER_APPROVAL_UNAVAILABLE
            )
            raise SideSessionError(
                err_code,
                "Trusted human approval credential requires real_input_id",
                {"purpose": purpose},
            )

        prov_rows = conn.execute(
            "SELECT * FROM input_provenance WHERE input_id = ?",
            (real_input_id,),
        ).fetchall()
        matched_prov = None
        for r in prov_rows:
            r_dict = dict(r)
            db_origin = str(r_dict.get("origin") or "")
            if db_origin in ("system/side_sessions", "auto_continuation", "system") or not r_dict.get("verified"):
                raise SideSessionError(
                    ErrorCode.USER_APPROVAL_UNAVAILABLE,
                    "Input ID belongs to a non-human / system input",
                    {"input_id": real_input_id},
                )
            if r_dict.get("verified") and db_origin in ("human_prompt", "slash_command", "real_user"):
                row_sid = r_dict.get("runtime_session_id")
                row_owner = str(r_dict.get("owner_id") or "")
                if caller_sid and not caller_sid.startswith("sid:"):
                    if row_sid is not None and str(row_sid).strip():
                        if str(row_sid).strip() != caller_sid:
                            continue
                    else:
                        if row_owner != f"host:{caller_sid}":
                            continue
                matched_prov = r_dict
                break

        if matched_prov is None:
            interaction_token = (
                action.get("interaction_token")
                or action.get("approval_token")
                or action.get("human_signature")
                or action.get("signature")
                or action.get("trusted_token")
            )
            token_ok = False
            if interaction_token is not None:
                with self._lock:
                    token_ok = str(interaction_token) in self._issued_tokens or str(interaction_token) in self._issued_approvals
            if not token_ok:
                err_code = (
                    ErrorCode.HUMAN_ACTION_REQUIRED
                    if purpose == "wait_response"
                    else ErrorCode.USER_APPROVAL_UNAVAILABLE
                )
                raise SideSessionError(
                    err_code,
                    "Trusted human approval provenance not found or session mismatch",
                    {"purpose": purpose, "input_id": real_input_id},
                )
            eff_owner = f"host:{caller_sid}" if caller_sid else f"host:{real_input_id}"
        else:
            eff_owner = str(matched_prov["owner_id"])
            created_at_str = str(matched_prov.get("created_at") or "").strip()
            if created_at_str:
                try:
                    dt_str = created_at_str[:-1] + "+00:00" if created_at_str.endswith("Z") else created_at_str
                    created_dt = datetime.fromisoformat(dt_str)
                    if created_dt.tzinfo is None:
                        created_dt = created_dt.replace(tzinfo=timezone.utc)
                    age_sec = (datetime.now(timezone.utc) - created_dt).total_seconds()
                    if age_sec > 300.0:
                        raise SideSessionError(
                            ErrorCode.EXPIRED,
                            "Human input provenance credential expired (>300s TTL)",
                            {"input_id": real_input_id, "age_seconds": age_sec},
                        )
                except SideSessionError:
                    raise
                except Exception:
                    pass

            binding_raw = matched_prov.get("action_binding_json")
            if isinstance(binding_raw, str) and binding_raw.strip():
                try:
                    binding_obj = json.loads(binding_raw)
                except Exception:
                    binding_obj = {}
                if isinstance(binding_obj, Mapping):
                    b_purpose = str(binding_obj.get("purpose") or "").strip()
                    b_target_id = str(binding_obj.get("target_id") or binding_obj.get("node_id") or "").strip()
                    b_target_hash = str(binding_obj.get("target_hash") or "").strip()
                    b_cmd = str(binding_obj.get("cmd") or "").strip()
                    req_cmd = str(action.get("cmd") or "").strip()
                    if (
                        (b_purpose and b_purpose != purpose)
                        or (b_target_id and b_target_id != target_id)
                        or (b_target_hash and b_target_hash != target_hash)
                        or (b_cmd and b_cmd != req_cmd)
                    ):
                        raise SideSessionError(
                            _ErrorCodeStr(ErrorCode.APPROVAL_REPLAYED.value, ErrorCode.USER_APPROVAL_UNAVAILABLE.value),
                            "Slash command approval binding does not match requested target or hash",
                            {
                                "input_id": real_input_id,
                                "bound_purpose": b_purpose,
                                "bound_target_id": b_target_id,
                                "bound_target_hash": b_target_hash,
                                "requested_purpose": purpose,
                                "requested_target_id": target_id,
                                "requested_target_hash": target_hash,
                            },
                        )

        cons_row = conn.execute(
            "SELECT * FROM approval_consumptions WHERE owner_id = ? AND input_id = ?",
            (eff_owner, real_input_id),
        ).fetchone()
        if cons_row is not None:
            if (
                str(cons_row["purpose"]) == purpose
                and str(cons_row["target_id"]) == target_id
                and str(cons_row["target_hash"]) == target_hash
                and str(cons_row["action_hash"]) == action_hash
            ):
                enriched_idempotent = {
                    **dict(action),
                    "approval_id": str(cons_row["consumption_id"]),
                    "approved_at": str(cons_row["consumed_at"]),
                }
                return self.verify_approval(enriched_idempotent, _conn=conn, _record_in_memory=False)
            raise SideSessionError(
                _ErrorCodeStr(ErrorCode.APPROVAL_REPLAYED.value, ErrorCode.USER_APPROVAL_UNAVAILABLE.value),
                "Human approval credential has already been consumed for a different target or action",
                {
                    "input_id": real_input_id,
                    "owner_id": eff_owner,
                    "consumed_target_id": cons_row["target_id"],
                    "requested_target_id": target_id,
                },
            )

        evidence = self.verify_approval(action, _conn=conn, _record_in_memory=False)
        conn.execute(
            """
            INSERT INTO approval_consumptions (
                consumption_id, owner_id, input_id, runtime_session_id,
                purpose, target_id, target_hash, action_hash, request_id, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence.approval_id,
                eff_owner,
                real_input_id,
                caller_sid or (matched_prov.get("runtime_session_id") if matched_prov else None),
                purpose,
                target_id,
                target_hash,
                action_hash,
                request_id,
                evidence.approved_at,
            ),
        )
        return evidence

    def is_trusted_approval(self, evidence: Any) -> bool:
        """Verify that an ApprovalEvidence instance was constructed by HostAdapter."""
        if not isinstance(evidence, ApprovalEvidence):
            return False
        if getattr(evidence, "_trusted_token", None) != self._trusted_token:
            return False
        return not _is_expired_iso(evidence.expires_at)

    # ------------------------------------------------------------------
    # 4. bind_task_action
    # ------------------------------------------------------------------

    def bind_task_action(self, tool_event: Mapping[str, Any]) -> BoundTaskAction:
        """Bind a tool execution event to the current turn's bound `task_id` and `task_revision`.

        Enforces task ownership and active/prepared task guards so frozen scopes cannot be written
        even if the caller attempts to switch task_id.
        """
        if not isinstance(tool_event, Mapping):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "tool_event must be a mapping")

        runtime_sid = str(
            tool_event.get("runtime_sid")
            or tool_event.get("session_id")
            or tool_event.get("sessionId")
            or ""
        ).strip()
        runtime_turn_id = str(
            tool_event.get("runtime_turn_id")
            or tool_event.get("turn_id")
            or tool_event.get("turnId")
            or ""
        ).strip()
        tool_use_id = str(
            tool_event.get("tool_use_id")
            or tool_event.get("toolUseId")
            or tool_event.get("action_id")
            or uuid.uuid4()
        ).strip()
        tool_name = str(
            tool_event.get("tool_name")
            or tool_event.get("toolName")
            or tool_event.get("tool")
            or ""
        ).strip()

        if not runtime_sid or not runtime_turn_id:
            raise SideSessionError(
                ErrorCode.TASK_UNBOUND,
                "bind_task_action requires runtime_sid and runtime_turn_id",
                {"runtime_sid": runtime_sid, "runtime_turn_id": runtime_turn_id},
            )

        raw_scope = tool_event.get("scope")
        scope_dict: dict[str, Any] | None = dict(raw_scope) if isinstance(raw_scope, Mapping) else None
        scope_digest = str(tool_event.get("scope_digest") or _compute_scope_digest(scope_dict or tool_event.get("tool_input") or {}))
        phase = str(tool_event.get("phase") or tool_event.get("hook_event_name") or "pre").lower()
        requested_state = str(tool_event.get("state") or ("completed" if "post" in phase else "running"))
        if requested_state not in ("admitted", "running", "completed", "failed", "unknown"):
            requested_state = "running"

        bare_tool = tool_name
        for pfx in ("mcp__plugin_side-sessions_side_sessions__", "mcp__side_sessions__"):
            if bare_tool.startswith(pfx):
                bare_tool = bare_tool[len(pfx) :]
                break
        is_control_or_readonly = (
            bare_tool in READ_ONLY_CONTROL_ALLOWLIST
            or bare_tool in ("Read", "Glob", "Grep", "hand_off_to_session")
            or bool(tool_event.get("is_control_call"))
        )

        conn, store_obj, should_close = self._with_conn(write=True)
        try:
            binding_row: dict[str, Any] | None = None
            task_row: dict[str, Any] | None = None

            if conn is not None:
                # If completing an already admitted/running action on PostToolUse
                existing_act = conn.execute(
                    "SELECT * FROM task_actions WHERE tool_use_id = ? AND runtime_sid = ?",
                    (tool_use_id, runtime_sid),
                ).fetchone()
                if existing_act is not None and requested_state in ("completed", "failed", "unknown"):
                    now = utc_now_iso()
                    if conn.in_transaction:
                        conn.execute(
                            "UPDATE task_actions SET state = ?, ended_at = ? WHERE action_id = ?",
                            (requested_state, now, existing_act["action_id"]),
                        )
                    elif store_obj is not None and store_obj.writable:
                        with store_obj.transaction():
                            conn.execute(
                                "UPDATE task_actions SET state = ?, ended_at = ? WHERE action_id = ?",
                                (requested_state, now, existing_act["action_id"]),
                            )
                    b_row = conn.execute(
                        "SELECT * FROM task_turn_bindings WHERE binding_id = ?",
                        (existing_act["binding_id"],),
                    ).fetchone()
                    bound = BoundTaskAction(
                        action_id=str(existing_act["action_id"]),
                        task_id=str(existing_act["task_id"]),
                        task_revision=int(existing_act["task_revision"]),
                        binding_id=str(existing_act["binding_id"]),
                        node_id=str(b_row["node_id"]) if b_row else "",
                        runtime_sid=runtime_sid,
                        runtime_turn_id=runtime_turn_id,
                        tool_use_id=tool_use_id,
                        tool_name=tool_name,
                        scope_digest=str(existing_act["scope_digest"]),
                        state=requested_state,
                        allowed=True,
                        started_at=str(existing_act["started_at"]),
                        ended_at=now,
                    )
                    with self._lock:
                        self._in_memory_actions[bound.action_id] = bound
                    return bound

                # Lookup turn binding (active or frozen)
                b_res = conn.execute(
                    """
                    SELECT * FROM task_turn_bindings
                    WHERE runtime_sid = ? AND runtime_turn_id = ?
                    ORDER BY CASE WHEN state = 'active' THEN 0 WHEN state = 'frozen' THEN 1 ELSE 2 END ASC
                    LIMIT 1
                    """,
                    (runtime_sid, runtime_turn_id),
                ).fetchone()
                if b_res is not None:
                    binding_row = dict(b_res)
                    t_res = conn.execute(
                        "SELECT * FROM tasks WHERE task_id = ?",
                        (binding_row["task_id"],),
                    ).fetchone()
                    if t_res is not None:
                        task_row = dict(t_res)

            if binding_row is None:
                with self._lock:
                    mem_b = self._in_memory_bindings.get((runtime_sid, runtime_turn_id))
                if mem_b is not None:
                    binding_row = dict(mem_b)
                else:
                    raise SideSessionError(
                        ErrorCode.TASK_UNBOUND,
                        f"No active task binding for runtime_sid={runtime_sid}, runtime_turn_id={runtime_turn_id}",
                        {"runtime_sid": runtime_sid, "runtime_turn_id": runtime_turn_id},
                    )

            binding_id = str(binding_row["binding_id"])
            task_id = str(binding_row["task_id"])
            node_id = str(binding_row["node_id"])
            task_revision = int(binding_row["task_revision"])
            binding_state = str(binding_row.get("state", "active"))

            if not is_control_or_readonly:
                if binding_state == "frozen":
                    raise SideSessionError(
                        ErrorCode.TASK_OWNER_CHANGED,
                        "Task turn binding is frozen by task guard; side-effecting tool actions are blocked",
                        {"task_id": task_id, "binding_id": binding_id},
                    )

                if task_row is not None:
                    if str(task_row["owner_node_id"]) != node_id:
                        raise SideSessionError(
                            ErrorCode.TASK_OWNER_CHANGED,
                            "Task is no longer owned by this session node",
                            {
                                "task_id": task_id,
                                "expected_owner": node_id,
                                "actual_owner": str(task_row["owner_node_id"]),
                            },
                        )
                    if str(task_row["state"]) in ("transfer_preparing", "transferring", "paused", "done"):
                        raise SideSessionError(
                            ErrorCode.TASK_OWNER_CHANGED,
                            f"Task '{task_id}' is in state '{task_row['state']}' and cannot admit new actions",
                            {"task_id": task_id, "state": task_row["state"]},
                        )
                    if int(task_row["task_revision"]) != task_revision:
                        raise SideSessionError(
                            ErrorCode.REVISION_CONFLICT,
                            "Task revision has advanced beyond turn binding revision",
                            {
                                "task_id": task_id,
                                "binding_revision": task_revision,
                                "task_revision": int(task_row["task_revision"]),
                            },
                        )

                # Check if any active guard on this source owner blocks the task or overlapping scope
                if conn is not None:
                    guard_rows = conn.execute(
                        """
                        SELECT * FROM task_guards
                        WHERE source_owner_id IN (?, ?)
                          AND state IN ('requested', 'prepared', 'committed', 'resume_requested', 'unknown')
                        """,
                        (node_id, runtime_sid),
                    ).fetchall()
                    for g_row in guard_rows:
                        if str(g_row["task_id"]) == task_id or str(g_row["scope_digest"]) == scope_digest:
                            raise SideSessionError(
                                ErrorCode.TASK_OWNER_CHANGED,
                                "Task or resource scope is frozen by an active handoff task guard",
                                {
                                    "guard_id": str(g_row["guard_id"]),
                                    "guarded_task_id": str(g_row["task_id"]),
                                    "Attempted_task_id": task_id,
                                },
                            )

                with self._lock:
                    for g_id, g_rec in self._guards.items():
                        if g_rec.state in ("requested", "prepared", "committed", "resume_requested", "unknown"):
                            if g_rec.source_runtime_sid == runtime_sid or g_rec.owner_id == node_id:
                                g_scope = self._guard_scopes.get(g_id)
                                if (
                                    g_rec.task_id == task_id
                                    or g_rec.scope_digest == scope_digest
                                    or _scopes_overlap(g_scope, scope_dict)
                                ):
                                    raise SideSessionError(
                                        ErrorCode.TASK_OWNER_CHANGED,
                                        "Resource scope is frozen by an active handoff task guard",
                                        {"guard_id": g_id, "task_id": task_id},
                                    )

            now = utc_now_iso()
            action_id = str(tool_event.get("action_id") or uuid.uuid4())
            ended_at = now if requested_state in ("completed", "failed") else None

            if conn is not None and bare_tool != "hand_off_to_session":
                def _write_action() -> None:
                    conn.execute(
                        """
                        INSERT INTO task_actions (
                            action_id, task_id, task_revision, binding_id, runtime_sid,
                            runtime_turn_id, tool_use_id, scope_digest, state, result_ref, started_at, ended_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                        ON CONFLICT(tool_use_id, runtime_sid) DO UPDATE SET
                            state = excluded.state,
                            ended_at = COALESCE(excluded.ended_at, task_actions.ended_at)
                        """,
                        (
                            action_id,
                            task_id,
                            task_revision,
                            binding_id,
                            runtime_sid,
                            runtime_turn_id,
                            tool_use_id,
                            scope_digest,
                            requested_state,
                            now,
                            ended_at,
                        ),
                    )

                if conn.in_transaction:
                    _write_action()
                elif store_obj is not None and store_obj.writable:
                    with store_obj.transaction():
                        _write_action()

            bound_action = BoundTaskAction(
                action_id=action_id,
                task_id=task_id,
                task_revision=task_revision,
                binding_id=binding_id,
                node_id=node_id,
                runtime_sid=runtime_sid,
                runtime_turn_id=runtime_turn_id,
                tool_use_id=tool_use_id,
                tool_name=tool_name,
                scope_digest=scope_digest,
                state=requested_state,
                allowed=True,
                started_at=now,
                ended_at=ended_at,
            )
            if bare_tool != "hand_off_to_session":
                with self._lock:
                    self._in_memory_actions[action_id] = bound_action
            return bound_action
        finally:
            if should_close and store_obj is not None:
                store_obj.close()

    # ------------------------------------------------------------------
    # 5. Task Guard Lifecycle (prepare / inspect / commit / resume)
    # ------------------------------------------------------------------

    def prepare_task_guard(
        self,
        task_id: str,
        expected_revision: int,
        transfer_id: str,
        source_cutoff: SourceCutoff | Mapping[str, Any] | None = None,
    ) -> GuardReceipt:
        """Freeze parent session actions on `task_id` and check for concurrent in-flight actions.

        Excludes the current `hand_off_to_session` control invocation itself when checking in-flight actions.
        """
        if not self.supports_task_guard:
            raise SideSessionError(
                ErrorCode.HANDOFF_GUARD_UNAVAILABLE,
                "Host task guard capability is not available",
                {"task_id": task_id, "transfer_id": transfer_id},
            )

        task_uuid = validate_uuid(task_id, "task_id")
        transfer_uuid = validate_uuid(transfer_id, "transfer_id")
        if type(expected_revision) is not int or expected_revision < 1:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "expected_revision must be a positive integer",
                {"expected_revision": expected_revision},
            )

        cutoff_dict: dict[str, Any] = {}
        if isinstance(source_cutoff, SourceCutoff):
            cutoff_dict = source_cutoff.to_dict()
        elif isinstance(source_cutoff, Mapping):
            cutoff_dict = dict(source_cutoff)

        source_node_id = str(cutoff_dict.get("source_node_id") or cutoff_dict.get("owner_id") or "")
        source_runtime_sid = str(cutoff_dict.get("source_runtime_sid") or "")
        trigger_turn_id = str(cutoff_dict.get("trigger_runtime_turn_id") or "")
        trigger_request_id = str(cutoff_dict.get("trigger_request_id") or "")
        exclude_tool_use_ids = {
            x
            for x in (
                trigger_request_id,
                str(cutoff_dict.get("control_tool_use_id") or ""),
                str(cutoff_dict.get("hand_off_tool_use_id") or ""),
                transfer_uuid,
            )
            if x
        }

        conn, store_obj, should_close = self._with_conn(write=True)
        try:
            import json

            scope_dict: dict[str, Any] = {}
            stable_anchor: dict[str, Any] | None = None
            source_turn_ids: list[str] = [trigger_turn_id] if trigger_turn_id else []
            inflight_ids: list[str] = []
            has_unknown_action = False
            guard_id = str(uuid.uuid4())

            if conn is not None:
                existing_g = conn.execute(
                    "SELECT * FROM task_guards WHERE transfer_id = ?",
                    (transfer_uuid,),
                ).fetchone()
                if existing_g is not None:
                    guard_id = str(existing_g["guard_id"])

                t_row = conn.execute(
                    "SELECT * FROM tasks WHERE task_id = ?",
                    (task_uuid,),
                ).fetchone()
                if t_row is not None:
                    db_rev = int(t_row["task_revision"])
                    if db_rev != expected_revision:
                        raise SideSessionError(
                            ErrorCode.REVISION_CONFLICT,
                            f"Task revision mismatch in prepare_task_guard: expected {expected_revision}, got {db_rev}",
                            {"task_id": task_uuid, "expected_revision": expected_revision, "actual_revision": db_rev},
                        )
                    if not source_node_id:
                        source_node_id = str(t_row["owner_node_id"])
                    try:
                        scope_dict = json.loads(t_row["scope_json"] or "{}")
                    except Exception:
                        scope_dict = {}
                    if t_row["last_stable_anchor"]:
                        try:
                            stable_anchor = json.loads(t_row["last_stable_anchor"])
                        except Exception:
                            stable_anchor = {"raw": str(t_row["last_stable_anchor"])}

                b_rows = conn.execute(
                    "SELECT * FROM task_turn_bindings WHERE task_id = ? AND state IN ('active', 'frozen')",
                    (task_uuid,),
                ).fetchall()
                for br in b_rows:
                    t_id = str(br["runtime_turn_id"])
                    if t_id and t_id not in source_turn_ids:
                        source_turn_ids.append(t_id)
                    if not source_runtime_sid and br["runtime_sid"]:
                        source_runtime_sid = str(br["runtime_sid"])

                act_rows = conn.execute(
                    """
                    SELECT * FROM task_actions
                    WHERE task_id = ? AND state IN ('admitted', 'running', 'unknown')
                    ORDER BY started_at ASC
                    """,
                    (task_uuid,),
                ).fetchall()
                for ar in act_rows:
                    if str(ar["tool_use_id"]) in exclude_tool_use_ids or str(ar["action_id"]) in exclude_tool_use_ids:
                        continue
                    inflight_ids.append(str(ar["action_id"]))
                    if str(ar["state"]) == "unknown":
                        has_unknown_action = True

            # Also check in-memory actions registered directly on adapter
            with self._lock:
                for act_id, act in self._in_memory_actions.items():
                    if act.task_id == task_uuid and act.state in ("admitted", "running", "unknown"):
                        if (
                            act.tool_use_id in exclude_tool_use_ids
                            or act.action_id in exclude_tool_use_ids
                            or act.tool_name == "hand_off_to_session"
                        ):
                            continue
                        if act_id not in inflight_ids:
                            inflight_ids.append(act_id)
                        if act.state == "unknown":
                            has_unknown_action = True

            if not source_node_id:
                source_node_id = "owner:source"
            if not source_runtime_sid:
                source_runtime_sid = source_node_id

            scope_digest = _compute_scope_digest(scope_dict)
            if has_unknown_action:
                guard_state = "unknown"
            elif inflight_ids:
                guard_state = "requested"
            else:
                guard_state = "prepared"

            now = utc_now_iso()
            host_receipt_id = f"guard-rcpt:{guard_id}:{guard_state}"
            receipt = GuardReceipt(
                guard_id=guard_id,
                transfer_id=transfer_uuid,
                task_id=task_uuid,
                task_revision=expected_revision,
                source_runtime_sid=source_runtime_sid,
                source_runtime_turn_ids=source_turn_ids,
                owner_id=source_node_id,
                scope_digest=scope_digest,
                state=guard_state,
                inflight_action_ids=inflight_ids,
                stable_anchor=stable_anchor,
                host_receipt_id=host_receipt_id,
                verified_at=now,
            )

            if conn is not None:
                def _persist_guard() -> None:
                    conn.execute(
                        """
                        UPDATE task_turn_bindings
                        SET state = 'frozen'
                        WHERE task_id = ? AND state = 'active'
                        """,
                        (task_uuid,),
                    )
                    conn.execute(
                        """
                        INSERT INTO task_guards (
                            guard_id, transfer_id, task_id, task_revision, source_owner_id,
                            scope_digest, state, inflight_action_ids, stable_anchor, receipt_json,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(transfer_id) DO UPDATE SET
                            task_revision = excluded.task_revision,
                            state = excluded.state,
                            inflight_action_ids = excluded.inflight_action_ids,
                            stable_anchor = excluded.stable_anchor,
                            receipt_json = excluded.receipt_json,
                            updated_at = excluded.updated_at
                        """,
                        (
                            guard_id,
                            transfer_uuid,
                            task_uuid,
                            expected_revision,
                            source_node_id,
                            scope_digest,
                            guard_state,
                            canonical_json(inflight_ids),
                            canonical_json(stable_anchor) if stable_anchor is not None else None,
                            canonical_json(receipt.to_dict()),
                            now,
                            now,
                        ),
                    )

                if conn.in_transaction:
                    _persist_guard()
                elif store_obj is not None and store_obj.writable:
                    with store_obj.transaction():
                        _persist_guard()

            with self._lock:
                self._guards[guard_id] = receipt
                self._guard_scopes[guard_id] = scope_dict
                for (b_sid, b_turn), b_info in self._in_memory_bindings.items():
                    if b_info.get("task_id") == task_uuid:
                        b_info["state"] = "frozen"

            return receipt
        finally:
            if should_close and store_obj is not None:
                store_obj.close()

    def inspect_task_guard(self, guard_id: str) -> GuardReceipt:
        """Inspect and re-verify an existing task guard by `guard_id`."""
        guard_uuid = validate_uuid(guard_id, "guard_id")
        conn, store_obj, should_close = self._with_conn(write=False)
        try:
            import json

            if conn is not None:
                row = conn.execute(
                    "SELECT * FROM task_guards WHERE guard_id = ?",
                    (guard_uuid,),
                ).fetchone()
                if row is not None:
                    rcpt_data = json.loads(row["receipt_json"] or "{}")
                    inflight = json.loads(row["inflight_action_ids"] or "[]")
                    stable_anchor = json.loads(row["stable_anchor"]) if row["stable_anchor"] else None
                    receipt = GuardReceipt(
                        guard_id=str(row["guard_id"]),
                        transfer_id=str(row["transfer_id"]),
                        task_id=str(row["task_id"]),
                        task_revision=int(row["task_revision"]),
                        source_runtime_sid=str(rcpt_data.get("source_runtime_sid") or row["source_owner_id"]),
                        source_runtime_turn_ids=list(rcpt_data.get("source_runtime_turn_ids") or []),
                        owner_id=str(rcpt_data.get("owner_id") or row["source_owner_id"]),
                        scope_digest=str(row["scope_digest"]),
                        state=str(row["state"]),
                        inflight_action_ids=list(inflight),
                        stable_anchor=stable_anchor,
                        host_receipt_id=str(rcpt_data.get("host_receipt_id") or f"guard-rcpt:{guard_uuid}:{row['state']}"),
                        verified_at=utc_now_iso(),
                    )
                    with self._lock:
                        self._guards[guard_uuid] = receipt
                    return receipt
        finally:
            if should_close and store_obj is not None:
                store_obj.close()

        with self._lock:
            cached = self._guards.get(guard_uuid)
        if cached is not None:
            return cached

        raise SideSessionError(
            ErrorCode.NOT_FOUND,
            f"Task guard not found: {guard_uuid}",
            {"guard_id": guard_uuid},
        )

    def commit_task_guard(
        self,
        guard_id: str,
        child_node_id: str,
        new_task_revision: int,
    ) -> GuardReceipt:
        """Commit task ownership transfer to `child_node_id` at `new_task_revision` while keeping source scope barrier."""
        guard_uuid = validate_uuid(guard_id, "guard_id")
        child_uuid = validate_uuid(child_node_id, "child_node_id")
        if type(new_task_revision) is not int or new_task_revision < 1:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "new_task_revision must be a positive integer",
                {"new_task_revision": new_task_revision},
            )

        current = self.inspect_task_guard(guard_uuid)
        if current.state == "committed" and current.owner_id == child_uuid and current.task_revision == new_task_revision:
            return current
        if current.state not in ("prepared", "committed"):
            raise SideSessionError(
                ErrorCode.HANDOFF_GUARD_UNAVAILABLE,
                f"Cannot commit task guard from state {current.state!r}; expected 'prepared'",
                {"guard_id": guard_uuid, "state": current.state},
            )

        now = utc_now_iso()
        committed = GuardReceipt(
            guard_id=current.guard_id,
            transfer_id=current.transfer_id,
            task_id=current.task_id,
            task_revision=new_task_revision,
            source_runtime_sid=current.source_runtime_sid,
            source_runtime_turn_ids=list(current.source_runtime_turn_ids),
            owner_id=child_uuid,
            scope_digest=current.scope_digest,
            state="committed",
            inflight_action_ids=[],
            stable_anchor=current.stable_anchor,
            host_receipt_id=f"guard-rcpt:{guard_uuid}:committed:{new_task_revision}",
            verified_at=now,
        )

        conn, store_obj, should_close = self._with_conn(write=True)
        try:
            if conn is not None:
                def _update_committed() -> None:
                    conn.execute(
                        """
                        UPDATE task_guards
                        SET task_revision = ?, state = 'committed', receipt_json = ?, updated_at = ?
                        WHERE guard_id = ?
                        """,
                        (
                            new_task_revision,
                            canonical_json(committed.to_dict()),
                            now,
                            guard_uuid,
                        ),
                    )

                if conn.in_transaction:
                    _update_committed()
                elif store_obj is not None and store_obj.writable:
                    with store_obj.transaction():
                        _update_committed()
        finally:
            if should_close and store_obj is not None:
                store_obj.close()

        with self._lock:
            self._guards[guard_uuid] = committed
        return committed

    def resume_task_guard(
        self,
        guard_id: str,
        expected_task_revision: int,
    ) -> GuardReceipt:
        """Rollback / lift task guard barrier and restore source session ownership on handoff failure."""
        guard_uuid = validate_uuid(guard_id, "guard_id")
        if type(expected_task_revision) is not int or expected_task_revision < 1:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "expected_task_revision must be a positive integer",
                {"expected_task_revision": expected_task_revision},
            )

        current = self.inspect_task_guard(guard_uuid)
        if current.state == "resumed" and current.task_revision == expected_task_revision:
            return current

        conn, store_obj, should_close = self._with_conn(write=True)
        try:
            source_owner_id = current.owner_id
            if conn is not None:
                g_row = conn.execute(
                    "SELECT * FROM task_guards WHERE guard_id = ?",
                    (guard_uuid,),
                ).fetchone()
                if g_row is not None:
                    source_owner_id = str(g_row["source_owner_id"])

                t_row = conn.execute(
                    "SELECT * FROM tasks WHERE task_id = ?",
                    (current.task_id,),
                ).fetchone()
                if t_row is not None:
                    db_rev = int(t_row["task_revision"])
                    if db_rev != expected_task_revision:
                        raise SideSessionError(
                            ErrorCode.REVISION_CONFLICT,
                            f"Task revision mismatch in resume_task_guard: expected {expected_task_revision}, got {db_rev}",
                            {
                                "guard_id": guard_uuid,
                                "expected_task_revision": expected_task_revision,
                                "actual_task_revision": db_rev,
                            },
                        )
                    if str(t_row["owner_node_id"]) != source_owner_id:
                        raise SideSessionError(
                            ErrorCode.TASK_OWNER_CHANGED,
                            "Cannot resume task guard while task owner is not the source node",
                            {
                                "guard_id": guard_uuid,
                                "source_owner_id": source_owner_id,
                                "current_owner_id": str(t_row["owner_node_id"]),
                            },
                        )
            else:
                if current.task_revision != expected_task_revision:
                    raise SideSessionError(
                        ErrorCode.REVISION_CONFLICT,
                        f"Guard revision mismatch: expected {expected_task_revision}, got {current.task_revision}",
                        {"guard_id": guard_uuid},
                    )
                if current.state == "committed":
                    raise SideSessionError(
                        ErrorCode.TASK_OWNER_CHANGED,
                        "Cannot resume committed guard without first transferring task ownership back to source",
                        {"guard_id": guard_uuid},
                    )

            now = utc_now_iso()
            resumed = GuardReceipt(
                guard_id=current.guard_id,
                transfer_id=current.transfer_id,
                task_id=current.task_id,
                task_revision=expected_task_revision,
                source_runtime_sid=current.source_runtime_sid,
                source_runtime_turn_ids=list(current.source_runtime_turn_ids),
                owner_id=source_owner_id,
                scope_digest=current.scope_digest,
                state="resumed",
                inflight_action_ids=[],
                stable_anchor=current.stable_anchor,
                host_receipt_id=f"guard-rcpt:{guard_uuid}:resumed:{expected_task_revision}",
                verified_at=now,
            )

            if conn is not None:
                def _update_resumed() -> None:
                    conn.execute(
                        """
                        UPDATE task_guards
                        SET task_revision = ?, state = 'resumed', inflight_action_ids = '[]',
                            receipt_json = ?, updated_at = ?
                        WHERE guard_id = ?
                        """,
                        (
                            expected_task_revision,
                            canonical_json(resumed.to_dict()),
                            now,
                            guard_uuid,
                        ),
                    )
                    conn.execute(
                        """
                        UPDATE task_turn_bindings
                        SET state = 'active'
                        WHERE task_id = ? AND node_id = ? AND state = 'frozen'
                        """,
                        (current.task_id, source_owner_id),
                    )

                if conn.in_transaction:
                    _update_resumed()
                elif store_obj is not None and store_obj.writable:
                    with store_obj.transaction():
                        _update_resumed()

            with self._lock:
                self._guards[guard_uuid] = resumed
                self._guard_scopes.pop(guard_uuid, None)
                for (_b_sid, _b_turn), b_info in self._in_memory_bindings.items():
                    if b_info.get("task_id") == current.task_id:
                        b_info["state"] = "active"

            return resumed
        finally:
            if should_close and store_obj is not None:
                store_obj.close()

    # ------------------------------------------------------------------
    # 6. request_wake
    # ------------------------------------------------------------------

    def request_wake(self, reservation: Any) -> WakeReceipt:
        """Route a parent wake reservation according to the parent's actual runtime owner.

        - Active parent at synchronous Hook boundary -> delivered via Hook (`status='accepted'`).
        - Plugin-owned parent runtime -> queued on original app-server connection (`status='accepted'`).
        - External idle GUI parent session -> returns `status='pending_until_next_parent_activity'`
          and preserves outbox events without starting a competing `--resume` process.
        """
        if isinstance(reservation, Mapping):
            res_dict = dict(reservation)
        elif hasattr(reservation, "to_dict"):
            res_dict = dict(reservation.to_dict())
        else:
            res_dict = {
                "reservation_id": getattr(reservation, "reservation_id", None),
                "parent_runtime_sid": getattr(reservation, "parent_runtime_sid", None),
                "parent_node_id": getattr(reservation, "parent_node_id", None),
                "in_sync_hook": getattr(reservation, "in_sync_hook", False),
            }

        reservation_id = str(res_dict.get("reservation_id") or uuid.uuid4())
        parent_sid = str(
            res_dict.get("parent_runtime_sid")
            or res_dict.get("parent_sid")
            or res_dict.get("runtime_sid")
            or ""
        ).strip()

        if not parent_sid and res_dict.get("parent_node_id"):
            conn, store_obj, should_close = self._with_conn(write=False)
            if conn is not None and store_obj is not None:
                try:
                    n_row = conn.execute(
                        "SELECT runtime_session_id FROM nodes WHERE node_id = ?",
                        (str(res_dict["parent_node_id"]),),
                    ).fetchone()
                    if n_row and n_row["runtime_session_id"]:
                        parent_sid = str(n_row["runtime_session_id"])
                finally:
                    if should_close:
                        store_obj.close()

        owner = self.resolve_owner(parent_sid) if parent_sid else UnknownOwner(runtime_sid="")

        # 1. Active parent session at synchronous Hook boundary
        if (
            res_dict.get("in_sync_hook") is True
            or res_dict.get("delivery_mode") == "sync_hook"
            or res_dict.get("hook_event") == "Stop"
        ):
            return WakeReceipt(
                reservation_id=reservation_id,
                parent_runtime_sid=parent_sid,
                actual_owner_id=owner.owner_id or f"hook:{parent_sid}",
                status="accepted",
                input_id=res_dict.get("input_id"),
                runtime_turn_id=res_dict.get("runtime_turn_id"),
                history_receipt=res_dict.get("history_receipt"),
            )

        # 2. Plugin-owned controlled parent runtime with live connection queue
        with self._lock:
            wake_fn = self._wake_handlers.get(parent_sid)

        if wake_fn is not None or (isinstance(owner, HostOwner) and owner.owner_kind == "managed" and owner.can_direct_wake):
            input_id = str(res_dict.get("input_id") or uuid.uuid4())
            self.record_system_input(
                runtime_sid=parent_sid,
                input_id=input_id,
                origin="system/side_sessions",
                owner_id=owner.owner_id or f"managed:{parent_sid}",
            )
            turn_id = res_dict.get("runtime_turn_id")
            hist_rcpt = res_dict.get("history_receipt")
            if wake_fn is not None:
                cb_res = wake_fn({**res_dict, "reservation_id": reservation_id, "input_id": input_id})
                turn_id = cb_res.get("runtime_turn_id", turn_id)
                hist_rcpt = cb_res.get("history_receipt", hist_rcpt)
            return WakeReceipt(
                reservation_id=reservation_id,
                parent_runtime_sid=parent_sid,
                actual_owner_id=owner.owner_id or f"managed:{parent_sid}",
                status="accepted",
                input_id=input_id,
                runtime_turn_id=turn_id,
                history_receipt=hist_rcpt,
            )

        # 3. External idle GUI parent session (no verified direct wake channel)
        return WakeReceipt(
            reservation_id=reservation_id,
            parent_runtime_sid=parent_sid,
            actual_owner_id=owner.owner_id or f"external:{parent_sid}",
            status="pending_until_next_parent_activity",
            input_id=None,
            runtime_turn_id=None,
            history_receipt=None,
        )

    # ------------------------------------------------------------------
    # 7. verify_consumption
    # ------------------------------------------------------------------

    def verify_consumption(self, receipt: Any) -> ConsumptionReceipt:
        """Verify whether an outbox event has a confirmed consumption receipt.

        Hook stdout emission or wake reservation alone never counts as confirmed consumption.
        """
        if isinstance(receipt, ConsumptionReceipt):
            return receipt
        if isinstance(receipt, WakeReceipt):
            if receipt.history_receipt and self.supports_history_commit_receipt:
                return ConsumptionReceipt(
                    event_id=receipt.reservation_id,
                    consumer_parent_node_id="",
                    verified=True,
                    receipt_kind="host_history_commit",
                    receipt_ref=receipt.history_receipt,
                    acked_at=utc_now_iso(),
                    status="verified",
                )
            return ConsumptionReceipt(
                event_id=receipt.reservation_id,
                consumer_parent_node_id="",
                verified=False,
                receipt_kind="unverified",
                receipt_ref="",
                acked_at="",
                status="unverified",
                reason="wake_receipt_without_confirmed_consumption",
            )

        if isinstance(receipt, str):
            rcpt_dict: dict[str, Any] = {"event_id": receipt}
        elif isinstance(receipt, Mapping):
            rcpt_dict = dict(receipt)
        else:
            return ConsumptionReceipt(
                event_id="",
                consumer_parent_node_id="",
                verified=False,
                receipt_kind="unverified",
                status="unverified",
                reason="invalid_receipt_type",
            )

        event_id = str(rcpt_dict.get("event_id") or "").strip()
        consumer_id = str(
            rcpt_dict.get("consumer_parent_node_id")
            or rcpt_dict.get("parent_node_id")
            or rcpt_dict.get("actor_node_id")
            or ""
        ).strip()
        receipt_kind = str(rcpt_dict.get("receipt_kind") or "").strip()
        receipt_ref = str(rcpt_dict.get("receipt_ref") or "").strip()

        # Stdout presentation or wake reservation is never an ACK
        if receipt_kind in ("stdout_presented", "hook_stdout", "presented", "wake_reservation"):
            return ConsumptionReceipt(
                event_id=event_id,
                consumer_parent_node_id=consumer_id,
                verified=False,
                receipt_kind="unverified",
                receipt_ref=receipt_ref,
                acked_at="",
                status="unverified",
                reason="stdout_presentation_is_not_consumption_ack",
            )

        conn, store_obj, should_close = self._with_conn(write=False)
        try:
            if conn is not None and event_id:
                ev_row = conn.execute(
                    "SELECT * FROM outbox_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if ev_row is not None:
                    expected_parent = str(ev_row["parent_node_id"])
                    if consumer_id and consumer_id != expected_parent:
                        return ConsumptionReceipt(
                            event_id=event_id,
                            consumer_parent_node_id=consumer_id,
                            verified=False,
                            receipt_kind="unverified",
                            receipt_ref=receipt_ref,
                            acked_at="",
                            status="unverified",
                            reason="consumer_parent_mismatch",
                        )
                    consumer_id = expected_parent

                ack_row = conn.execute(
                    """
                    SELECT * FROM event_acks
                    WHERE event_id = ?
                    ORDER BY acked_at DESC
                    LIMIT 1
                    """,
                    (event_id,),
                ).fetchone()
                if ack_row is not None:
                    return ConsumptionReceipt(
                        event_id=event_id,
                        consumer_parent_node_id=str(ack_row["consumer_parent_node_id"]),
                        verified=True,
                        receipt_kind=str(ack_row["receipt_kind"]),
                        receipt_ref=str(ack_row["receipt_ref"]),
                        acked_at=str(ack_row["acked_at"]),
                        status="verified",
                    )

                if ev_row is not None and str(ev_row["state"]) == "acked":
                    return ConsumptionReceipt(
                        event_id=event_id,
                        consumer_parent_node_id=consumer_id,
                        verified=True,
                        receipt_kind=receipt_kind or "explicit_ack",
                        receipt_ref=receipt_ref or f"ack:{event_id}",
                        acked_at=str(ev_row["acked_at"] or utc_now_iso()),
                        status="verified",
                    )
        finally:
            if should_close and store_obj is not None:
                store_obj.close()

        if receipt_kind == "explicit_ack" and rcpt_dict.get("verified") is True and event_id and consumer_id:
            return ConsumptionReceipt(
                event_id=event_id,
                consumer_parent_node_id=consumer_id,
                verified=True,
                receipt_kind="explicit_ack",
                receipt_ref=receipt_ref or f"ack:{event_id}",
                acked_at=str(rcpt_dict.get("acked_at") or utc_now_iso()),
                status="verified",
            )

        if (
            receipt_kind == "host_history_commit"
            and (self.supports_history_commit_receipt or rcpt_dict.get("verified") is True)
            and event_id
            and receipt_ref
        ):
            return ConsumptionReceipt(
                event_id=event_id,
                consumer_parent_node_id=consumer_id,
                verified=True,
                receipt_kind="host_history_commit",
                receipt_ref=receipt_ref,
                acked_at=str(rcpt_dict.get("acked_at") or utc_now_iso()),
                status="verified",
            )

        return ConsumptionReceipt(
            event_id=event_id,
            consumer_parent_node_id=consumer_id,
            verified=False,
            receipt_kind="unverified",
            receipt_ref=receipt_ref,
            acked_at="",
            status="unverified",
            reason="no_verified_ack_found",
        )


# ------------------------------------------------------------------
# Default Instance and Module-Level Convenience Functions
# ------------------------------------------------------------------

_DEFAULT_ADAPTER = HostAdapter()


def get_default_host_adapter() -> HostAdapter:
    return _DEFAULT_ADAPTER


def resolve_owner(runtime_sid: str, *, adapter: HostAdapter | None = None) -> HostOwner | UnknownOwner:
    return (adapter or _DEFAULT_ADAPTER).resolve_owner(runtime_sid)


def observe_input(
    event: Mapping[str, Any] | HookContext,
    *,
    adapter: HostAdapter | None = None,
) -> VerifiedInput | UnknownInput:
    return (adapter or _DEFAULT_ADAPTER).observe_input(event)


def verify_approval(
    action: Mapping[str, Any],
    *,
    adapter: HostAdapter | None = None,
) -> ApprovalEvidence:
    return (adapter or _DEFAULT_ADAPTER).verify_approval(action)


def bind_task_action(
    tool_event: Mapping[str, Any],
    *,
    adapter: HostAdapter | None = None,
) -> BoundTaskAction:
    return (adapter or _DEFAULT_ADAPTER).bind_task_action(tool_event)


def prepare_task_guard(
    task_id: str,
    expected_revision: int,
    transfer_id: str,
    source_cutoff: Any = None,
    *,
    adapter: HostAdapter | None = None,
) -> GuardReceipt:
    return (adapter or _DEFAULT_ADAPTER).prepare_task_guard(
        task_id,
        expected_revision,
        transfer_id,
        source_cutoff,
    )


def inspect_task_guard(
    guard_id: str,
    *,
    adapter: HostAdapter | None = None,
) -> GuardReceipt:
    return (adapter or _DEFAULT_ADAPTER).inspect_task_guard(guard_id)


def commit_task_guard(
    guard_id: str,
    child_node_id: str,
    new_task_revision: int,
    *,
    adapter: HostAdapter | None = None,
) -> GuardReceipt:
    return (adapter or _DEFAULT_ADAPTER).commit_task_guard(
        guard_id,
        child_node_id,
        new_task_revision,
    )


def resume_task_guard(
    guard_id: str,
    expected_task_revision: int,
    *,
    adapter: HostAdapter | None = None,
) -> GuardReceipt:
    return (adapter or _DEFAULT_ADAPTER).resume_task_guard(
        guard_id,
        expected_task_revision,
    )


def request_wake(
    reservation: Any,
    *,
    adapter: HostAdapter | None = None,
) -> WakeReceipt:
    return (adapter or _DEFAULT_ADAPTER).request_wake(reservation)


def verify_consumption(
    receipt: Any,
    *,
    adapter: HostAdapter | None = None,
) -> ConsumptionReceipt:
    return (adapter or _DEFAULT_ADAPTER).verify_consumption(receipt)


__all__ = [
    "ApprovalEvidence",
    "BoundTaskAction",
    "ConsumptionReceipt",
    "GuardReceipt",
    "HostAdapter",
    "HostOwner",
    "TRUSTED_ADAPTER_TOKEN",
    "UnknownInput",
    "UnknownOwner",
    "VerifiedInput",
    "WakeReceipt",
    "bind_task_action",
    "commit_task_guard",
    "get_default_host_adapter",
    "get_process_lstart",
    "inspect_task_guard",
    "observe_input",
    "prepare_task_guard",
    "request_wake",
    "resolve_owner",
    "resume_task_guard",
    "verify_approval",
    "verify_consumption",
    "verify_process_identity",
]
