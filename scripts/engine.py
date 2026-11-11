"""Core session tree, slot quota, proposal/handoff state machine, and outbox/hook engine."""

from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import html
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import threading
import time
from typing import Any, Callable, Iterable, Mapping
import uuid

try:
    from . import worktree as _worktree_mod
    from .contracts import (
         DEFAULT_ARTIFACT_CHUNK_BYTES,
        DRIVER_API_VERSION,
        ENGINE_SCHEMA_VERSION,
        FORMATTER_VERSION,
        MAX_ACK_EVENTS,
        MAX_ARTIFACT_CHUNK_BYTES,
        MAX_EVENT_PAGE_LIMIT,
        MAX_HOOK_CONTEXT_BYTES,
        MAX_HOOK_EVENTS,
        MAX_PROMPT_CHARS,
        MAX_SLOTS_PER_PARENT,
        MAX_WAKE_BUDGET_PER_EPOCH,
        READ_ONLY_CONTROL_ALLOWLIST,
        VALID_HOOK_EVENTS,
        ApprovalEvidence,
        ArtifactChunk,
        ArtifactRef,
        BoundWait,
        BriefSnapshot,
        CallerContext,
        CanonicalReport,
        CanonicalRequest,
        ControlReceipt,
        ControlResult,
        DispatchGroupResult,
        DriverCapabilities,
        ErrorCode,
        EventPage,
        EventView,
        ExitReceipt,
        GuardReceipt,
        HistoryProjection,
        HookContext,
        HookOutput,
        HookOutputDict,
        QueueResult,
        ReportReceipt,
        ReportView,
        RunAssignment,
        RuntimeCreateSpec,
        RuntimeHandle,
        RuntimeInput,
        RuntimeProfile,
        RuntimeResumeSpec,
        RuntimeSnapshot,
        SendReceipt,
        SessionResult,
        SideSessionError,
        SourceAnchor,
        SourceCutoff,
        StartResult,
        TaskResult,
        WorkspaceSpec,
        WorktreeRecord,
        canonical_json,
        canonical_json_bytes,
        canonical_json_sha256,
        format_recap_400,
        format_ssref,
        normalize_request,
        normalize_text,
        parse_ssref,
        runtime_profile_for_task_kind,
        sha256_hex,
        utc_now_iso,
        validate_fresh_background,
        validate_hook_output,
        validate_short_name,
        validate_uuid,
    )
    from .state import Store, TransactionContext, resolve_worktrees_home, safe_resolve_under
except ImportError:  # pragma: no cover
    import worktree as _worktree_mod  # type: ignore
    from contracts import (  # type: ignore
        DEFAULT_ARTIFACT_CHUNK_BYTES,
        DRIVER_API_VERSION,
        ENGINE_SCHEMA_VERSION,
        FORMATTER_VERSION,
        MAX_ACK_EVENTS,
        MAX_ARTIFACT_CHUNK_BYTES,
        MAX_EVENT_PAGE_LIMIT,
        MAX_HOOK_CONTEXT_BYTES,
        MAX_HOOK_EVENTS,
        MAX_PROMPT_CHARS,
        MAX_SLOTS_PER_PARENT,
        MAX_WAKE_BUDGET_PER_EPOCH,
        READ_ONLY_CONTROL_ALLOWLIST,
        VALID_HOOK_EVENTS,
        ApprovalEvidence,
        ArtifactChunk,
        ArtifactRef,
        BoundWait,
        BriefSnapshot,
        CallerContext,
        CanonicalReport,
        CanonicalRequest,
        ControlReceipt,
        ControlResult,
        DispatchGroupResult,
        DriverCapabilities,
        ErrorCode,
        EventPage,
        EventView,
        ExitReceipt,
        GuardReceipt,
        HistoryProjection,
        HookContext,
        HookOutput,
        HookOutputDict,
        QueueResult,
        ReportReceipt,
        ReportView,
        RunAssignment,
        RuntimeCreateSpec,
        RuntimeHandle,
        RuntimeInput,
        RuntimeProfile,
        RuntimeResumeSpec,
        RuntimeSnapshot,
        SendReceipt,
        SessionResult,
        SideSessionError,
        SourceAnchor,
        SourceCutoff,
        StartResult,
        TaskResult,
        WorkspaceSpec,
        WorktreeRecord,
        canonical_json,
        canonical_json_bytes,
        canonical_json_sha256,
        format_recap_400,
        format_ssref,
        normalize_request,
        normalize_text,
        parse_ssref,
        runtime_profile_for_task_kind,
        sha256_hex,
        utc_now_iso,
        validate_fresh_background,
        validate_hook_output,
        validate_short_name,
        validate_uuid,
    )
    from state import Store, TransactionContext, resolve_worktrees_home, safe_resolve_under  # type: ignore


if not hasattr(CallerContext, "runtime_session_id"):
    setattr(CallerContext, "runtime_session_id", property(lambda self: self.runtime_sid))


MAX_PROPOSALS_PER_PARENT = 20
MAX_PROPOSALS_PER_TURN = 4


class _AliasStr(str):
    """String subclass matching both primary code/status and compatibility aliases."""

    def __new__(cls, primary: str, *aliases: str) -> _AliasStr:
        obj = super().__new__(cls, primary)
        all_codes = {primary, *(str(a) for a in aliases if a)}
        if "CALLER_CONTEXT_CONFLICT" in all_codes or primary == "HOOK_IDENTITY_MISMATCH":
            all_codes.add("CALLER_IDENTITY_CONFLICT")
        if any(c in all_codes for c in ("SYMLINK_FORBIDDEN", "PATH_ESCAPE", "UNSAFE_PATH")):
            all_codes.add("PATH_SECURITY_VIOLATION")
        obj._aliases = frozenset(all_codes)
        return obj

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Enum):
            return other.value in self._aliases
        if isinstance(other, str):
            return str.__str__(other) in self._aliases or super().__eq__(other)
        return super().__eq__(other)

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return super().__hash__()


def _err(
    code: str | ErrorCode,
    message: str,
    details: Mapping[str, Any] | None = None,
    *,
    retryable: bool = False,
    aliases: Iterable[str | ErrorCode] = (),
) -> SideSessionError:
    primary = code.value if isinstance(code, Enum) else str(code)
    alias_strs = [a.value if isinstance(a, Enum) else str(a) for a in aliases]
    det = dict(details) if details else {}
    if alias_strs:
        det.setdefault("alias_codes", alias_strs)
    exc = SideSessionError(primary, message, det, retryable=retryable)
    if alias_strs:
        exc.code = _AliasStr(primary, *alias_strs)
    return exc


def _try_parse_uuid(val: Any) -> str | None:
    if not isinstance(val, str) or not val.strip():
        return None
    try:
        return str(uuid.UUID(val.strip()))
    except ValueError:
        return None


def _proposal_short_id(proposal_uuid: str) -> str:
    return f"task_{proposal_uuid.replace('-', '')[:8]}"


class _TestOnlyDriver:
    """Explicit test-only stub driver (not implicitly instantiated on Engine)."""

    def __init__(self) -> None:
        self._caps = DriverCapabilities()
        self.history_quality = "stable_projection"

    def probe(self) -> DriverCapabilities:
        return self._caps

    def capture_anchor(self, source: SourceCutoff) -> SourceAnchor:
        return SourceAnchor(
            status="stable",
            source_session_id=source.source_runtime_sid,
            cutoff=source,
            source_revision=source.source_revision or 1,
            anchor_message_id=f"msg:{source.accepted_input_high_watermark}",
            sequence=1,
            anchor_turn_id=source.trigger_runtime_turn_id,
            checkpoint_id=f"ckpt:{source.trigger_request_id}",
            effective_chain_hash=sha256_hex(f"{source.source_runtime_sid}:{source.trigger_request_id}"),
        )

    def capture_history(self, source: SourceAnchor) -> HistoryProjection:
        quality = "brief_only" if source.status != "stable" else self.history_quality
        summary = (
            f"Projected history for {source.source_session_id} at {source.anchor_message_id or 'unavailable'}"
        )
        snap_hash = canonical_json_sha256(
            {
                "anchor": source.to_dict(),
                "history_quality": quality,
                "summary": summary,
                "formatter_version": FORMATTER_VERSION,
            }
        )
        return HistoryProjection(
            anchor=source,
            history_quality=quality,
            summary=summary,
            excluded_ranges=[],
            snapshot_hash=snap_hash,
            formatter_version=FORMATTER_VERSION,
        )

    def validate_anchor(self, anchor: SourceAnchor | Mapping[str, Any]) -> dict[str, Any]:
        if isinstance(anchor, SourceAnchor):
            ok = anchor.status == "stable"
        elif isinstance(anchor, Mapping):
            ok = anchor.get("status", "stable") == "stable"
        else:
            ok = True
        return {"ok": ok, "valid": ok}

    def create(self, spec: RuntimeCreateSpec) -> RuntimeHandle:
        sid = spec.preallocated_session_id or spec.assignment.runtime_sid
        return RuntimeHandle(
            runtime_sid=sid,
            runtime_instance_id=f"inst:{sid}:{spec.assignment.run_id[:8]}",
            owner_connection_id=f"conn:{sid}",
            snapshot_revision=1,
            canonical_workspace=spec.workspace_path,
            process_identity={},
        )

    def resume(self, spec: RuntimeResumeSpec) -> RuntimeHandle:
        sid = spec.assignment.runtime_sid
        return RuntimeHandle(
            runtime_sid=sid,
            runtime_instance_id=f"inst:{sid}:{spec.assignment.run_id[:8]}",
            owner_connection_id=f"conn:{sid}",
            snapshot_revision=1,
            canonical_workspace=spec.expected_workspace,
            process_identity={},
        )

    def send(self, handle: RuntimeHandle, input: RuntimeInput) -> SendReceipt:
        return SendReceipt(
            input_id=input.input_id,
            status="accepted",
            runtime_turn_id=f"rturn:{input.input_id[:12]}",
            response_revision=handle.snapshot_revision + 1,
            evidence_ref=f"send:{handle.runtime_sid}:{input.input_id}",
        )

    def inspect(self, handle: RuntimeHandle) -> RuntimeSnapshot:
        return RuntimeSnapshot(
            runtime_sid=handle.runtime_sid,
            canonical_workspace=handle.canonical_workspace,
            model={"providerId": "default", "modelId": "default"},
            mode="default",
            status="running",
            tool_profile_check="verified",
            notes_access_check="verified",
            revision=handle.snapshot_revision,
        )

    def respond_wait(
        self,
        handle: RuntimeHandle,
        request: BoundWait,
        response: Mapping[str, Any],
        control_id: str,
    ) -> ControlReceipt:
        return ControlReceipt(
            control_id=control_id,
            status="applied",
            runtime_instance_id=request.runtime_instance_id,
            owner_epoch=request.owner_epoch,
            observed_wait_state="resolved",
            host_receipt_id=f"wait-rcpt:{control_id}",
        )

    def stop_and_wait(self, handle: RuntimeHandle, deadline_ms: int = 5000) -> ExitReceipt:
        return ExitReceipt(
            runtime_instance_id=handle.runtime_instance_id,
            process_identity=handle.process_identity,
            exit_confirmed=True,
            runtime_outcome="cancelled",
            ended_at=utc_now_iso(),
            exit_code=0,
            evidence_ref=f"stop:{handle.runtime_instance_id}",
        )


_FallbackDriver = _TestOnlyDriver


class Engine:
    """Authoritative session tree, proposal/handoff state machine, and hook coordinator."""

    def __init__(
        self,
        store: Store,
        *,
        clock: Callable[[], str | datetime | float | int] | Any = None,
        id_factory: Callable[..., str] | None = None,
        supervisor_port: Any = None,
        host_adapter: Any = None,
        driver: Any = None,
        worktrees_home: Path | str | None = None,
        runtime_execution: str = "inline",
    ) -> None:
        if runtime_execution not in ("inline", "deferred"):
            raise _err(ErrorCode.INVALID_REQUEST, f"Invalid runtime_execution mode: {runtime_execution!r}")
        self.store = store
        self._clock = clock
        self._id_factory = id_factory
        self.supervisor_port = supervisor_port
        self._host_adapter = host_adapter
        self._driver = driver
        self._worktrees_home = Path(worktrees_home).expanduser().absolute() if worktrees_home else None
        self.runtime_execution = runtime_execution
        self._artifact_identity_cache: dict[str, dict[str, Any]] = {}
        self._pending_emit_deliveries: list[tuple[str, str]] = []
        if self._host_adapter is not None and hasattr(self._host_adapter, "bind_store"):
            try:
                self._host_adapter.bind_store(self.store)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Lazy Adapter / Driver & Clock / ID Helpers
    # ------------------------------------------------------------------

    @property
    def host_adapter(self) -> Any:
        if self._host_adapter is None:
            try:
                from . import host_adapter as ha_mod  # type: ignore
            except ImportError:
                try:
                    import host_adapter as ha_mod  # type: ignore
                except ImportError:
                    ha_mod = None
            if ha_mod is not None:
                if hasattr(ha_mod, "HostAdapter"):
                    self._host_adapter = ha_mod.HostAdapter(store=self.store)
                elif hasattr(ha_mod, "get_default_host_adapter"):
                    inst = ha_mod.get_default_host_adapter()
                    if hasattr(inst, "bind_store"):
                        inst.bind_store(self.store)
                    self._host_adapter = inst
                else:
                    self._host_adapter = ha_mod
        if self._host_adapter is not None and hasattr(self._host_adapter, "bind_store"):
            try:
                if getattr(self._host_adapter, "store", None) is None:
                    self._host_adapter.bind_store(self.store)
            except Exception:
                pass
        return self._host_adapter

    @property
    def driver(self) -> Any:
        if self._driver is None:
            if os.environ.get("ZCODE_SIDE_SESSIONS_DRIVER") == "zcode":
                try:
                    from . import driver as drv_mod  # type: ignore
                except ImportError:
                    try:
                        import driver as drv_mod  # type: ignore
                    except ImportError:
                        drv_mod = None
                if drv_mod is not None and hasattr(drv_mod, "ZCodeDriver"):
                    self._driver = drv_mod.ZCodeDriver()
            if self._driver is None:
                raise _err(ErrorCode.CAPABILITY_UNAVAILABLE, "no runtime driver injected")
        return self._driver

    @property
    def worktrees_home(self) -> Path:
        if self._worktrees_home is not None:
            return self._worktrees_home
        return resolve_worktrees_home()

    def _now_dt(self) -> datetime:
        if self._clock is None:
            return datetime.now(timezone.utc)
        val: Any = None
        if callable(self._clock):
            val = self._clock()
        elif hasattr(self._clock, "now") and callable(self._clock.now):
            val = self._clock.now()
        elif hasattr(self._clock, "iso") and callable(self._clock.iso):
            val = self._clock.iso()
        else:
            val = self._clock
        if isinstance(val, datetime):
            return val.astimezone(timezone.utc) if val.tzinfo else val.replace(tzinfo=timezone.utc)
        if isinstance(val, (int, float)):
            return datetime.fromtimestamp(float(val), tz=timezone.utc)
        if isinstance(val, str):
            try:
                return datetime.fromisoformat(val.replace("Z", "+00:00")).astimezone(timezone.utc)
            except ValueError:
                return datetime.now(timezone.utc)
        return datetime.now(timezone.utc)

    def _now_iso(self) -> str:
        return self._now_dt().isoformat().replace("+00:00", "Z")

    def _future_iso(self, *, hours: int = 0, minutes: int = 0, seconds: int = 0) -> str:
        dt = self._now_dt() + timedelta(hours=hours, minutes=minutes, seconds=seconds)
        return dt.isoformat().replace("+00:00", "Z")

    def _is_expired(self, expires_at: str | None) -> bool:
        if not expires_at or not str(expires_at).strip():
            return False
        try:
            exp_dt = datetime.fromisoformat(str(expires_at).strip().replace("Z", "+00:00"))
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            return self._now_dt() >= exp_dt
        except ValueError:
            return str(expires_at) <= self._now_iso()

    def _new_uuid(self) -> str:
        if self._id_factory is not None:
            try:
                raw = self._id_factory()
            except TypeError:
                raw = self._id_factory("uuid")
            parsed = _try_parse_uuid(raw)
            if parsed is not None:
                return parsed
            return str(uuid.uuid5(uuid.NAMESPACE_OID, str(raw)))
        return str(uuid.uuid4())

    def _coerce_caller(self, caller: Any) -> CallerContext:
        if isinstance(caller, CallerContext):
            if not isinstance(caller.runtime_sid, str) or not caller.runtime_sid.strip():
                raise SideSessionError(ErrorCode.CALLER_UNBOUND, "Caller runtime_sid cannot be empty")
            return caller
        if isinstance(caller, Mapping):
            sid = caller.get("runtime_sid") or caller.get("runtime_session_id") or caller.get("session_id")
            if not isinstance(sid, str) or not sid.strip():
                raise SideSessionError(ErrorCode.CALLER_UNBOUND, "Caller runtime_sid is missing")
            return CallerContext(
                runtime_sid=sid.strip(),
                runtime_turn_id=caller.get("runtime_turn_id") or caller.get("turn_id"),
                runtime_scope=caller.get("runtime_scope"),
                workspace_path=caller.get("workspace_path") or caller.get("cwd"),
                trace_id=caller.get("trace_id"),
                connection_id=caller.get("connection_id"),
                node_id=caller.get("node_id"),
            )
        if isinstance(caller, str) and caller.strip():
            return CallerContext(runtime_sid=caller.strip())
        sid_attr = getattr(caller, "runtime_sid", None) or getattr(caller, "runtime_session_id", None)
        if isinstance(sid_attr, str) and sid_attr.strip():
            return CallerContext(
                runtime_sid=sid_attr.strip(),
                runtime_turn_id=getattr(caller, "runtime_turn_id", None) or getattr(caller, "turn_id", None),
                runtime_scope=getattr(caller, "runtime_scope", None),
                workspace_path=getattr(caller, "workspace_path", None) or getattr(caller, "cwd", None),
                trace_id=getattr(caller, "trace_id", None),
                connection_id=getattr(caller, "connection_id", None),
                node_id=getattr(caller, "node_id", None),
            )
        raise SideSessionError(ErrorCode.CALLER_UNBOUND, "Caller identity is missing or unbound")

    def _merge_args(
        self,
        args: Mapping[str, Any] | CanonicalRequest | None,
        kwargs: Mapping[str, Any],
    ) -> dict[str, Any]:
        if isinstance(args, CanonicalRequest):
            out = dict(args.payload)
        elif isinstance(args, Mapping):
            out = dict(args)
        elif args is None:
            out = {}
        else:
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "Tool arguments must be a mapping")
        if kwargs:
            out.update(kwargs)
        return out

    def _resolve_proposal_row(
        self,
        conn: Any,
        proposal_ref: str,
        *,
        parent_node_id: str | None = None,
    ) -> dict[str, Any] | None:
        ref = str(proposal_ref or "").strip()
        if not ref:
            return None
        row = conn.execute("SELECT * FROM proposals WHERE proposal_id = ?", (ref,)).fetchone()
        if row is not None:
            return dict(row)
        if ref.startswith("task_"):
            hex_prefix = ref[len("task_") :].lower()
            if not re.fullmatch(r"[0-9a-f]{8,32}", hex_prefix):
                return None
            rows = conn.execute("SELECT * FROM proposals ORDER BY created_at DESC").fetchall()
            for r in rows:
                pid_clean = str(r["proposal_id"]).replace("-", "").lower()
                if pid_clean.startswith(hex_prefix):
                    if parent_node_id is None or str(r["parent_node_id"]) == parent_node_id:
                        return dict(r)
        return None

    def _preprocess_proposal_id_arg(self, raw_args: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
        """Allow `proposal_id` to be passed either as full UUID or `task_<8hex>` short ID."""
        if "proposal_id" not in raw_args:
            return raw_args, None
        raw_pid = raw_args.get("proposal_id")
        if isinstance(raw_pid, str) and raw_pid.strip().startswith("task_"):
            matched = self._resolve_proposal_row(self.store.conn, raw_pid.strip())
            cloned = dict(raw_args)
            if matched is not None:
                cloned["proposal_id"] = matched["proposal_id"]
                return cloned, matched["proposal_id"]
            synth_uuid = str(uuid.uuid5(uuid.NAMESPACE_OID, raw_pid.strip()))
            cloned["proposal_id"] = synth_uuid
            return cloned, raw_pid.strip()
        return raw_args, None

    def _probe_capabilities(self) -> DriverCapabilities:
        drv = self.driver
        if hasattr(drv, "probe") and callable(drv.probe):
            res = drv.probe()
            if isinstance(res, DriverCapabilities):
                return res
            if isinstance(res, Mapping):
                return DriverCapabilities(**{k: v for k, v in res.items() if hasattr(DriverCapabilities, k)})
        return DriverCapabilities()

    def _is_capability_supported(
        self,
        caps: DriverCapabilities,
        name: str,
        *,
        require_integration_verified: bool = False,
    ) -> bool:
        drv = self.driver
        drv_override = getattr(drv, name, None)
        if isinstance(drv_override, bool):
            return drv_override
        cap = getattr(caps, name, None)
        if isinstance(cap, bool):
            return cap
        if cap is None:
            return False
        if require_integration_verified or bool(getattr(drv, "require_integration_verified", False)):
            return bool(getattr(cap, "enabled", False))
        return bool(getattr(cap, "source_supported", False) or getattr(cap, "enabled", False))

    # ------------------------------------------------------------------
    # 1. Identity Binding & Family Authorization (Section 5 & Prompt #1)
    # ------------------------------------------------------------------

    def ensure_caller_node(self, caller: CallerContext | Mapping[str, Any] | str) -> dict[str, Any]:
        """Bind `caller.runtime_sid` into `bindings` and `nodes` (creating a root node if top-level)."""
        ctx = self._coerce_caller(caller)
        sid = ctx.runtime_sid
        turn_id = ctx.runtime_turn_id
        raw_ws = ctx.workspace_path or ""
        canonical_ws = (
            os.path.realpath(raw_ws)
            if raw_ws and os.path.exists(raw_ws) and not os.path.islink(raw_ws)
            else (raw_ws if raw_ws else str(self.store.root))
        )
        now = self._now_iso()

        def _ensure_in_conn(conn: Any) -> dict[str, Any]:
            b_row = conn.execute("SELECT * FROM bindings WHERE runtime_sid = ?", (sid,)).fetchone()
            n_row = conn.execute("SELECT * FROM nodes WHERE runtime_session_id = ?", (sid,)).fetchone()

            if b_row is not None and n_row is not None and str(b_row["node_id"]) != str(n_row["node_id"]):
                raise SideSessionError(
                    ErrorCode.CALLER_CONTEXT_CONFLICT,
                    "Binding node_id conflicts with nodes.runtime_session_id",
                    {"runtime_sid": sid, "binding_node_id": b_row["node_id"], "node_id": n_row["node_id"]},
                )

            if n_row is None and b_row is not None:
                n_row = conn.execute("SELECT * FROM nodes WHERE node_id = ?", (b_row["node_id"],)).fetchone()

            if ctx.node_id is not None:
                explicit_node_id = _try_parse_uuid(ctx.node_id) or str(ctx.node_id).strip()
                if n_row is not None and str(n_row["node_id"]) != explicit_node_id:
                    raise SideSessionError(
                        ErrorCode.CALLER_CONTEXT_CONFLICT,
                        "Caller node_id conflicts with bound runtime_sid",
                        {"runtime_sid": sid, "caller_node_id": explicit_node_id, "bound_node_id": n_row["node_id"]},
                    )
                if n_row is None:
                    by_id = conn.execute("SELECT * FROM nodes WHERE node_id = ?", (explicit_node_id,)).fetchone()
                    if by_id is not None:
                        if by_id["runtime_session_id"] and str(by_id["runtime_session_id"]) != sid:
                            raise SideSessionError(
                                ErrorCode.CALLER_CONTEXT_CONFLICT,
                                "Node is already bound to a different runtime_session_id",
                                {"node_id": explicit_node_id, "runtime_sid": sid},
                            )
                        n_row = by_id

            if n_row is not None:
                node_id = str(n_row["node_id"])
                if not n_row["runtime_session_id"]:
                    conn.execute(
                        "UPDATE nodes SET runtime_session_id = ?, updated_at = ? WHERE node_id = ?",
                        (sid, now, node_id),
                    )
                if raw_ws and not n_row["canonical_workspace"]:
                    conn.execute(
                        "UPDATE nodes SET canonical_workspace = ?, updated_at = ? WHERE node_id = ?",
                        (canonical_ws, now, node_id),
                    )
                conn.execute(
                    """
                    INSERT INTO bindings (
                        runtime_sid, node_id, schema_version, last_turn_id, cwd, last_seen_at, db_check_state
                    ) VALUES (?, ?, ?, ?, ?, ?, 'pending')
                    ON CONFLICT(runtime_sid) DO UPDATE SET
                        last_turn_id = COALESCE(excluded.last_turn_id, bindings.last_turn_id),
                        cwd = CASE WHEN excluded.cwd != '' THEN excluded.cwd ELSE bindings.cwd END,
                        last_seen_at = excluded.last_seen_at
                    """,
                    (sid, node_id, ENGINE_SCHEMA_VERSION, turn_id, canonical_ws, now),
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO wake_budget (
                        parent_node_id, user_epoch, wake_count, parent_stop_state, updated_at
                    ) VALUES (?, 0, 0, 'idle', ?)
                    """,
                    (node_id, now),
                )
                refreshed = conn.execute("SELECT * FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
                return dict(refreshed)

            # Top-level session: create root node automatically
            node_id = _try_parse_uuid(ctx.node_id) or self._new_uuid()
            short_hex = node_id.replace("-", "")[:8]
            root_name = f"main-{short_hex}"
            if conn.execute(
                "SELECT 1 FROM nodes WHERE parent_node_id IS NULL AND name = ?",
                (root_name,),
            ).fetchone():
                root_name = f"main-{short_hex}-{uuid.uuid4().hex[:4]}"

            conn.execute(
                """
                INSERT INTO nodes (
                    node_id, runtime_session_id, parent_node_id, root_node_id, name, title,
                    node_status, pause_requested, task_kind, context_requested, context_applied,
                    workspace_mode, canonical_workspace, host_link_verified, recovery_status,
                    last_turn_report, last_turn_seq, revision, created_at, updated_at
                ) VALUES (?, ?, NULL, ?, ?, 'Primary Session', 'active', 0, 'write_code', 'fresh', 'fresh',
                          'inherit', ?, 1, 'runtime_resumable', '', 0, 1, ?, ?)
                """,
                (node_id, sid, node_id, root_name, canonical_ws, now, now),
            )
            conn.execute(
                """
                INSERT INTO bindings (
                    runtime_sid, node_id, schema_version, last_turn_id, cwd, last_seen_at, db_check_state
                ) VALUES (?, ?, ?, ?, ?, ?, 'pending')
                ON CONFLICT(runtime_sid) DO UPDATE SET
                    node_id = excluded.node_id,
                    last_turn_id = COALESCE(excluded.last_turn_id, bindings.last_turn_id),
                    cwd = excluded.cwd,
                    last_seen_at = excluded.last_seen_at
                """,
                (sid, node_id, ENGINE_SCHEMA_VERSION, turn_id, canonical_ws, now),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO wake_budget (
                    parent_node_id, user_epoch, wake_count, parent_stop_state, updated_at
                ) VALUES (?, 0, 0, 'idle', ?)
                """,
                (node_id, now),
            )
            created = conn.execute("SELECT * FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
            return dict(created)

        if self.store.conn.in_transaction:
            return _ensure_in_conn(self.store.conn)
        with self.store.transaction("IMMEDIATE") as txn:
            return _ensure_in_conn(txn.conn)

    def _verify_ancestry_and_no_cycles(
        self,
        conn: Any,
        start_node_id: str,
    ) -> list[str]:
        """Walk parent chain from `start_node_id` to root; return `[start_node_id, ..., root_id]` or raise TOPOLOGY_CORRUPT."""
        visited: set[str] = set()
        chain: list[str] = []
        cur_id: str | None = start_node_id
        while cur_id is not None:
            if cur_id in visited:
                raise SideSessionError(
                    ErrorCode.TOPOLOGY_CORRUPT,
                    f"Cycle detected in session topology at node {cur_id}",
                    {"node_id": cur_id, "chain": chain},
                )
            visited.add(cur_id)
            chain.append(cur_id)
            row = conn.execute(
                "SELECT node_id, parent_node_id, root_node_id FROM nodes WHERE node_id = ?",
                (cur_id,),
            ).fetchone()
            if row is None:
                raise SideSessionError(
                    ErrorCode.TOPOLOGY_CORRUPT,
                    f"Broken parent reference in session topology: {cur_id}",
                    {"missing_node_id": cur_id},
                )
            cur_id = str(row["parent_node_id"]) if row["parent_node_id"] is not None else None
        return chain

    def _verify_family_topology(self, conn: Any, root_node_id: str) -> None:
        rows = conn.execute(
            "SELECT node_id, parent_node_id FROM nodes WHERE root_node_id = ?",
            (root_node_id,),
        ).fetchall()
        parent_map = {str(r["node_id"]): (str(r["parent_node_id"]) if r["parent_node_id"] else None) for r in rows}
        for nid in parent_map:
            seen: set[str] = set()
            cur: str | None = nid
            while cur is not None:
                if cur in seen:
                    raise SideSessionError(
                        ErrorCode.TOPOLOGY_CORRUPT,
                        f"Cycle detected in family {root_node_id} at node {cur}",
                        {"root_node_id": root_node_id, "node_id": cur},
                    )
                seen.add(cur)
                if cur not in parent_map:
                    p_row = conn.execute("SELECT parent_node_id FROM nodes WHERE node_id = ?", (cur,)).fetchone()
                    if p_row is None:
                        raise SideSessionError(
                            ErrorCode.TOPOLOGY_CORRUPT,
                            f"Missing ancestor node {cur} in family {root_node_id}",
                        )
                    cur = str(p_row["parent_node_id"]) if p_row["parent_node_id"] else None
                else:
                    cur = parent_map[cur]

    def _is_ancestor_or_self(self, conn: Any, manager_node_id: str, target_node_id: str) -> bool:
        chain = self._verify_ancestry_and_no_cycles(conn, target_node_id)
        return manager_node_id in chain

    def _is_strict_ancestor(self, conn: Any, ancestor_node_id: str, target_node_id: str) -> bool:
        if ancestor_node_id == target_node_id:
            return False
        chain = self._verify_ancestry_and_no_cycles(conn, target_node_id)
        return ancestor_node_id in chain[1:]

    def resolve_target_node(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        target_ref: str,
        *,
        target_kind: str = "node",
        require_manage: bool = False,
    ) -> dict[str, Any]:
        """Resolve a target session by `node_id`, `runtime_session_id`, `"parent"`, or unique family short `name`."""
        caller_node = self.ensure_caller_node(caller)
        conn = self.store.conn
        caller_id = str(caller_node["node_id"])
        caller_root_id = str(caller_node["root_node_id"])

        self._verify_ancestry_and_no_cycles(conn, caller_id)
        self._verify_family_topology(conn, caller_root_id)

        if not isinstance(target_ref, str) or not target_ref.strip():
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "target_ref must be a non-empty string")
        ref = normalize_text(target_ref, strip=True)

        target_row: Any = None
        if ref == "self":
            target_row = caller_node
        elif ref == "parent":
            parent_id = caller_node.get("parent_node_id")
            if not parent_id:
                raise SideSessionError(
                    ErrorCode.NO_PARENT,
                    "Root session has no parent",
                    {"node_id": caller_id},
                )
            target_row = conn.execute("SELECT * FROM nodes WHERE node_id = ?", (parent_id,)).fetchone()
            if target_row is None:
                raise SideSessionError(ErrorCode.TOPOLOGY_CORRUPT, f"Parent node {parent_id} is missing")
        elif target_kind == "runtime":
            target_row = conn.execute("SELECT * FROM nodes WHERE runtime_session_id = ?", (ref,)).fetchone()
            if target_row is None:
                b_row = conn.execute("SELECT node_id FROM bindings WHERE runtime_sid = ?", (ref,)).fetchone()
                if b_row is not None:
                    target_row = conn.execute("SELECT * FROM nodes WHERE node_id = ?", (b_row["node_id"],)).fetchone()
            if target_row is None:
                raise SideSessionError(ErrorCode.NOT_FOUND, f"Runtime session not found: {ref}", {"target_ref": ref})
        else:
            # 1. By node_id
            target_row = conn.execute("SELECT * FROM nodes WHERE node_id = ?", (ref,)).fetchone()
            # 2. By runtime_session_id
            if target_row is None:
                target_row = conn.execute("SELECT * FROM nodes WHERE runtime_session_id = ?", (ref,)).fetchone()
            # 3. By short name within family
            if target_row is None:
                family_matches = conn.execute(
                    "SELECT * FROM nodes WHERE root_node_id = ? AND name = ? ORDER BY created_at ASC, node_id ASC",
                    (caller_root_id, ref),
                ).fetchall()
                if len(family_matches) > 1:
                    raise SideSessionError(
                        ErrorCode.AMBIGUOUS_SESSION,
                        f"Session short name '{ref}' is ambiguous within family",
                        {
                            "name": ref,
                            "candidate_node_ids": [str(m["node_id"]) for m in family_matches],
                        },
                    )
                if len(family_matches) == 1:
                    target_row = family_matches[0]
                else:
                    other_family = conn.execute(
                        "SELECT node_id, root_node_id FROM nodes WHERE name = ? LIMIT 1",
                        (ref,),
                    ).fetchone()
                    if other_family is not None:
                        raise _err(
                            "PERMISSION_DENIED",
                            f"Session '{ref}' belongs to another authorization family",
                            {"target_ref": ref, "caller_root_id": caller_root_id},
                            aliases=(ErrorCode.FORBIDDEN, ErrorCode.NOT_FOUND_OR_FORBIDDEN),
                        )
                    raise SideSessionError(
                        ErrorCode.NOT_FOUND,
                        f"Target session not found: {ref}",
                        {"target_ref": ref},
                    )

        target_dict = dict(target_row)
        target_id = str(target_dict["node_id"])
        target_chain = self._verify_ancestry_and_no_cycles(conn, target_id)
        target_root_id = target_chain[-1]

        if target_root_id != caller_root_id or str(target_dict["root_node_id"]) != caller_root_id:
            raise _err(
                "PERMISSION_DENIED",
                "Caller and target session do not belong to the same authorized family",
                {
                    "caller_node_id": caller_id,
                    "caller_root_node_id": caller_root_id,
                    "target_node_id": target_id,
                    "target_root_node_id": str(target_dict["root_node_id"]),
                },
                aliases=(ErrorCode.FORBIDDEN, ErrorCode.NOT_FOUND_OR_FORBIDDEN),
            )

        if require_manage and caller_id not in target_chain:
            raise _err(
                "PERMISSION_DENIED",
                "Caller is not authorized to manage target session",
                {"caller_node_id": caller_id, "target_node_id": target_id},
                aliases=(ErrorCode.FORBIDDEN, ErrorCode.NOT_FOUND_OR_FORBIDDEN),
            )

        return target_dict

    # ------------------------------------------------------------------
    # Request Idempotency Helpers
    # ------------------------------------------------------------------

    def _check_idempotent_request(
        self,
        conn: Any,
        actor_node_id: str,
        tool_name: str,
        request_id: str,
        normalized_hash: str,
    ) -> dict[str, Any] | None:
        rows = conn.execute(
            "SELECT * FROM requests WHERE actor_node_id = ? AND request_id = ?",
            (actor_node_id, request_id),
        ).fetchall()
        if not rows:
            return None
        for row in rows:
            if str(row["tool_name"]) != tool_name or str(row["normalized_hash"]) != normalized_hash:
                raise SideSessionError(
                    ErrorCode.REQUEST_ID_CONFLICT,
                    f"request_id '{request_id}' was already used with different tool or parameters",
                    {
                        "request_id": request_id,
                        "tool_name": tool_name,
                        "existing_tool_name": row["tool_name"],
                    },
                )
        saved = json.loads(rows[0]["result"])
        # Re-hydrate _AliasStr on status if awaiting context approval
        if isinstance(saved, dict) and saved.get("status") in (
            "awaiting_context_approval",
            "awaiting_context_acceptance",
        ):
            saved["status"] = _AliasStr(
                "awaiting_context_approval",
                "awaiting_context_acceptance",
                "CONTEXT_QUALITY_APPROVAL_REQUIRED",
            )
        return saved

    def _record_idempotent_request(
        self,
        conn: Any,
        actor_node_id: str,
        tool_name: str,
        request_id: str,
        normalized_hash: str,
        result: Mapping[str, Any],
        operation_id: str | None = None,
    ) -> None:
        conn.execute(
            """
            INSERT OR REPLACE INTO requests (
                actor_node_id, tool_name, request_id, normalized_hash, result, operation_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                actor_node_id,
                tool_name,
                request_id,
                normalized_hash,
                canonical_json(result),
                operation_id,
                self._now_iso(),
            ),
        )

    # ------------------------------------------------------------------
    # 4-Slot Quota Reservation & Dispatch Groups (Section 8.1, 8.3 & R02)
    # ------------------------------------------------------------------

    def _active_parent_slots(self, conn: Any, parent_node_id: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            """
            SELECT * FROM parent_slots
            WHERE parent_node_id = ?
              AND state IN ('reserved', 'starting', 'running', 'waiting_input', 'stopping', 'reconciliation')
            ORDER BY slot_no ASC
            """,
            (parent_node_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def reserve_dispatch(
        self,
        txn: TransactionContext | Any,
        parent_node_id: str,
        node_id: str,
        operation_id: str | None = None,
        run_id: str | None = None,
    ) -> int:
        """Atomically reserve one of the 4 execution slots on `parent_node_id` inside an active transaction."""
        conn = txn.conn if isinstance(txn, TransactionContext) else txn
        now = self._now_iso()

        existing = conn.execute(
            """
            SELECT * FROM parent_slots
            WHERE parent_node_id = ? AND node_id = ? AND state != 'released'
            """,
            (parent_node_id, node_id),
        ).fetchone()
        if existing is not None:
            slot_no = int(existing["slot_no"])
            conn.execute(
                """
                UPDATE parent_slots
                SET operation_id = COALESCE(?, operation_id),
                    run_id = COALESCE(?, run_id),
                    updated_at = ?
                WHERE parent_node_id = ? AND slot_no = ?
                """,
                (operation_id, run_id, now, parent_node_id, slot_no),
            )
            return slot_no

        active_rows = self._active_parent_slots(conn, parent_node_id)
        if len(active_rows) >= MAX_SLOTS_PER_PARENT:
            raise SideSessionError(
                ErrorCode.CAPACITY_EXCEEDED,
                f"Parent session {parent_node_id} has reached the maximum of {MAX_SLOTS_PER_PARENT} active slots",
                {
                    "parent_node_id": parent_node_id,
                    "active_slots": len(active_rows),
                    "max_slots": MAX_SLOTS_PER_PARENT,
                },
            )

        used_slots = {int(r["slot_no"]) for r in active_rows}
        chosen_slot = next(s for s in range(1, MAX_SLOTS_PER_PARENT + 1) if s not in used_slots)
        conn.execute(
            """
            INSERT INTO parent_slots (
                parent_node_id, slot_no, node_id, operation_id, run_id, state, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'reserved', ?, ?)
            ON CONFLICT(parent_node_id, slot_no) DO UPDATE SET
                node_id = excluded.node_id,
                operation_id = excluded.operation_id,
                run_id = excluded.run_id,
                state = 'reserved',
                created_at = excluded.created_at,
                updated_at = excluded.updated_at
            """,
            (parent_node_id, chosen_slot, node_id, operation_id, run_id, now, now),
        )
        return chosen_slot

    def _validate_open_dispatch_group_In_conn(
        self,
        conn: Any,
        dispatch_group_id: str,
        expected_parent_node_id: str,
    ) -> dict[str, Any]:
        g_row = conn.execute(
            "SELECT * FROM dispatch_groups WHERE dispatch_group_id = ?",
            (dispatch_group_id,),
        ).fetchone()
        if g_row is None:
            raise SideSessionError(
                ErrorCode.GROUP_NOT_OPEN,
                f"Dispatch group does not exist: {dispatch_group_id}",
                {"dispatch_group_id": dispatch_group_id},
            )
        group = dict(g_row)
        if str(group["parent_node_id"]) != expected_parent_node_id:
            raise SideSessionError(
                ErrorCode.GROUP_SCOPE_MISMATCH,
                "Dispatch group belongs to a different parent session",
                {
                    "dispatch_group_id": dispatch_group_id,
                    "expected_parent_node_id": expected_parent_node_id,
                    "actual_parent_node_id": group["parent_node_id"],
                },
            )
        if group["assembly_state"] == "open" and self._is_expired(group.get("seal_deadline")):
            conn.execute(
                "UPDATE dispatch_groups SET assembly_state = 'closed_incomplete', revision = revision + 1 WHERE dispatch_group_id = ?",
                (dispatch_group_id,),
            )
            group["assembly_state"] = "closed_incomplete"
        if group["assembly_state"] != "open":
            raise SideSessionError(
                ErrorCode.GROUP_NOT_OPEN,
                f"Dispatch group is not open (assembly_state={group['assembly_state']})",
                {"dispatch_group_id": dispatch_group_id, "assembly_state": group["assembly_state"]},
            )
        if int(group["member_count"]) >= int(group["expected_member_count"]) or int(group["member_count"]) >= MAX_SLOTS_PER_PARENT:
            raise SideSessionError(
                ErrorCode.GROUP_FULL,
                "Dispatch group has already reached its expected member count",
                {
                    "dispatch_group_id": dispatch_group_id,
                    "member_count": group["member_count"],
                    "expected_member_count": group["expected_member_count"],
                },
            )
        return group

    def _admit_dispatch_group_member_in_conn(
        self,
        conn: Any,
        *,
        parent_node_id: str,
        child_node_id: str,
        message_id: str,
        operation_id: str | None,
        run_id: str | None,
        dispatch_group_id: str | None,
        batch_id: str | None = None,
        initial_state: str = "queued",
    ) -> tuple[str, str, int]:
        now = self._now_iso()
        member_id = self._new_uuid()
        if dispatch_group_id is not None:
            group = self._validate_open_dispatch_group_In_conn(conn, dispatch_group_id, parent_node_id)
            ordinal = int(group["member_count"]) + 1
            conn.execute(
                """
                UPDATE dispatch_groups
                SET member_count = ?, revision = revision + 1
                WHERE dispatch_group_id = ?
                """,
                (ordinal, dispatch_group_id),
            )
            eff_group_id = dispatch_group_id
        else:
            eff_group_id = self._new_uuid()
            ordinal = 1
            conn.execute(
                """
                INSERT INTO dispatch_groups (
                    dispatch_group_id, parent_node_id, batch_id, assembly_state, completion_state,
                    integrity_state, expected_member_count, member_count, revision, created_by,
                    created_at, sealed_at, incomplete_acknowledged
                ) VALUES (?, ?, ?, 'sealed', 'pending', 'ok', 1, 1, 1, ?, ?, ?, 0)
                """,
                (eff_group_id, parent_node_id, batch_id, parent_node_id, now, now),
            )

        conn.execute(
            """
            INSERT INTO dispatch_group_members (
                member_id, dispatch_group_id, node_id, message_id, operation_id, run_id,
                ordinal, state, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                member_id,
                eff_group_id,
                child_node_id,
                message_id,
                operation_id,
                run_id,
                ordinal,
                initial_state,
                now,
                now,
            ),
        )
        return eff_group_id, member_id, ordinal

    def _build_dispatch_group_result(self, conn: Any, dispatch_group_id: str) -> dict[str, Any]:
        g_row = conn.execute(
            "SELECT * FROM dispatch_groups WHERE dispatch_group_id = ?",
            (dispatch_group_id,),
        ).fetchone()
        if g_row is None:
            raise SideSessionError(ErrorCode.NOT_FOUND, f"Dispatch group not found: {dispatch_group_id}")
        members = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM dispatch_group_members WHERE dispatch_group_id = ? ORDER BY ordinal ASC",
                (dispatch_group_id,),
            ).fetchall()
        ]
        prep_ops = [
            str(r["operation_id"])
            for r in conn.execute(
                """
                SELECT operation_id FROM operations
                WHERE requested_group_id = ?
                  AND stage IN ('preparing_context', 'awaiting_context_acceptance', 'ready_for_admission')
                ORDER BY created_at ASC
                """,
                (dispatch_group_id,),
            ).fetchall()
        ]
        res = DispatchGroupResult(
            dispatch_group_id=str(g_row["dispatch_group_id"]),
            parent_node_id=str(g_row["parent_node_id"]),
            assembly_state=str(g_row["assembly_state"]),
            completion_state=str(g_row["completion_state"]),
            expected_members=int(g_row["expected_member_count"]),
            member_count=int(g_row["member_count"]),
            revision=int(g_row["revision"]),
            members=members,
            preparing_operation_ids=prep_ops,
            manifest_ref=g_row["manifest_ref"],
        ).to_dict()
        res["ok"] = True
        res["integrity_state"] = g_row["integrity_state"]
        res["incomplete_acknowledged"] = bool(g_row["incomplete_acknowledged"])
        return res

    def create_dispatch_group(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("create_dispatch_group", raw_args)
        parent_node = self.ensure_caller_node(caller)
        parent_id = str(parent_node["node_id"])

        with self.store.transaction("IMMEDIATE") as txn:
            cached = self._check_idempotent_request(
                txn.conn,
                parent_id,
                "create_dispatch_group",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

            group_id = self._new_uuid()
            now = self._now_iso()
            deadline = self._future_iso(minutes=10)
            txn.execute(
                """
                INSERT INTO dispatch_groups (
                    dispatch_group_id, parent_node_id, batch_id, assembly_state, completion_state,
                    integrity_state, expected_member_count, member_count, revision, created_by,
                    created_at, seal_deadline, incomplete_acknowledged
                ) VALUES (?, ?, ?, 'open', 'pending', 'ok', ?, 0, 1, ?, ?, ?, 0)
                """,
                (group_id, parent_id, req["batch_id"], req["expected_members"], parent_id, now, deadline),
            )
            res = self._build_dispatch_group_result(txn.conn, group_id)
            res["request_id"] = req.request_id
            self._record_idempotent_request(
                txn.conn,
                parent_id,
                "create_dispatch_group",
                req.request_id,
                req.normalized_hash,
                res,
            )
            return res

    def _maybe_finalize_dispatch_group_in_conn(
        self,
        conn: Any,
        dispatch_group_id: str,
        store_instance_id: str,
    ) -> None:
        g_row = conn.execute(
            "SELECT * FROM dispatch_groups WHERE dispatch_group_id = ?",
            (dispatch_group_id,),
        ).fetchone()
        if g_row is None:
            return
        members = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM dispatch_group_members WHERE dispatch_group_id = ? ORDER BY ordinal ASC",
                (dispatch_group_id,),
            ).fetchall()
        ]
        if len(members) != int(g_row["member_count"]):
            conn.execute(
                "UPDATE dispatch_groups SET integrity_state = 'reconciliation' WHERE dispatch_group_id = ?",
                (dispatch_group_id,),
            )
            return
        if not members:
            return

        all_terminal = all(
            m["state"] == "terminal" and bool(m.get("exit_confirmed"))
            for m in members
        )
        if not all_terminal:
            return

        now = self._now_iso()
        manifest_ref = g_row["manifest_ref"]
        if not manifest_ref and g_row["assembly_state"] in ("sealed", "closed_incomplete"):
            manifest_obj = {
                "schema_version": ENGINE_SCHEMA_VERSION,
                "dispatch_group_id": dispatch_group_id,
                "parent_node_id": g_row["parent_node_id"],
                "assembly_state": g_row["assembly_state"],
                "expected_member_count": int(g_row["expected_member_count"]),
                "member_count": int(g_row["member_count"]),
                "members": [
                    {
                        "member_id": m["member_id"],
                        "ordinal": m["ordinal"],
                        "node_id": m["node_id"],
                        "message_id": m["message_id"],
                        "run_id": m["run_id"],
                        "outcome": m["outcome"],
                        "exit_confirmed": m["exit_confirmed"],
                        "report_id": m["report_id"],
                        "report_ref": (
                            format_ssref(store_instance_id, "report", m["report_id"])
                            if m.get("report_id")
                            else None
                        ),
                        "terminal_reason": m["terminal_reason"],
                    }
                    for m in members
                ],
            }
            manifest_bytes = canonical_json_bytes(manifest_obj)
            art_id = self._new_uuid()
            conn.execute(
                """
                INSERT INTO artifacts (
                    artifact_id, owner_node_id, run_id, kind, storage_kind,
                    inline_bytes, relative_blob_path, sha256, byte_length,
                    media_type, state, created_at
                ) VALUES (?, ?, NULL, 'group_manifest', 'inline', ?, NULL, ?, ?, 'application/json', 'published', ?)
                """,
                (art_id, g_row["parent_node_id"], manifest_bytes, sha256_hex(manifest_bytes), len(manifest_bytes), now),
            )
            manifest_ref = format_ssref(store_instance_id, "artifact", art_id)

        if (
            g_row["assembly_state"] == "sealed"
            and int(g_row["member_count"]) == int(g_row["expected_member_count"])
        ):
            conn.execute(
                """
                UPDATE dispatch_groups
                SET completion_state = 'completed',
                    manifest_ref = COALESCE(?, manifest_ref),
                    revision = revision + 1
                WHERE dispatch_group_id = ?
                """,
                (manifest_ref, dispatch_group_id),
            )
            producer_key = f"group:{dispatch_group_id}:completed"
            existing_ev = conn.execute(
                "SELECT event_id FROM outbox_events WHERE producer_key = ?",
                (producer_key,),
            ).fetchone()
            # Emit explicit group completion event for multi-member groups or groups without any turn report
            has_turn_events = conn.execute(
                "SELECT 1 FROM outbox_events WHERE dispatch_group_id = ? AND turn_seq IS NOT NULL LIMIT 1",
                (dispatch_group_id,),
            ).fetchone()
            if existing_ev is None and (int(g_row["expected_member_count"]) > 1 or not has_turn_events):
                self._insert_outbox_event_in_conn(
                    conn,
                    store_instance_id=store_instance_id,
                    producer_key=producer_key,
                    parent_node_id=str(g_row["parent_node_id"]),
                    child_node_id=None,
                    turn_seq=None,
                    run_id=None,
                    dispatch_group_id=dispatch_group_id,
                    member_id=None,
                    kind="group_completed",
                    outcome="success" if all(m.get("outcome") == "success" for m in members) else "completed",
                    recap=f"Dispatch group {dispatch_group_id} completed ({len(members)}/{g_row['expected_member_count']} members)",
                    report_ref=None,
                    report_semantic_sha256=None,
                    manifest_ref=manifest_ref,
                    artifact_refs=[],
                )
        elif manifest_ref:
            conn.execute(
                "UPDATE dispatch_groups SET manifest_ref = COALESCE(?, manifest_ref) WHERE dispatch_group_id = ?",
                (manifest_ref, dispatch_group_id),
            )

    def seal_dispatch_group(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("seal_dispatch_group", raw_args)
        parent_node = self.ensure_caller_node(caller)
        parent_id = str(parent_node["node_id"])
        group_id = req["dispatch_group_id"]

        with self.store.transaction("IMMEDIATE") as txn:
            cached = self._check_idempotent_request(
                txn.conn,
                parent_id,
                "seal_dispatch_group",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

            g_row = txn.execute(
                "SELECT * FROM dispatch_groups WHERE dispatch_group_id = ?",
                (group_id,),
            ).fetchone()
            if g_row is None:
                raise SideSessionError(ErrorCode.NOT_FOUND, f"Dispatch group not found: {group_id}")
            if str(g_row["parent_node_id"]) != parent_id:
                raise SideSessionError(ErrorCode.GROUP_SCOPE_MISMATCH, "Caller is not the parent of this dispatch group")
            if g_row["assembly_state"] == "open" and self._is_expired(g_row["seal_deadline"]):
                txn.execute(
                    "UPDATE dispatch_groups SET assembly_state = 'closed_incomplete', revision = revision + 1 WHERE dispatch_group_id = ?",
                    (group_id,),
                )
                raise SideSessionError(ErrorCode.GROUP_NOT_OPEN, "Dispatch group seal_deadline has expired")
            if g_row["assembly_state"] != "open":
                raise SideSessionError(
                    ErrorCode.GROUP_NOT_OPEN,
                    f"Dispatch group cannot be sealed from state {g_row['assembly_state']}",
                )
            if int(g_row["revision"]) != int(req["expected_revision"]):
                raise SideSessionError(
                    ErrorCode.REVISION_CONFLICT,
                    "Dispatch group revision mismatch",
                    {"expected_revision": req["expected_revision"], "actual_revision": g_row["revision"]},
                )
            prep_count = txn.execute(
                """
                SELECT COUNT(*) AS cnt FROM operations
                WHERE requested_group_id = ?
                  AND stage IN ('preparing_context', 'awaiting_context_acceptance', 'ready_for_admission')
                """,
                (group_id,),
            ).fetchone()["cnt"]
            if int(g_row["member_count"]) != int(g_row["expected_member_count"]) or int(prep_count) > 0:
                raise SideSessionError(
                    ErrorCode.GROUP_INCOMPLETE,
                    "Dispatch group member_count does not match expected_member_count or has pending admissions",
                    {
                        "member_count": g_row["member_count"],
                        "expected_member_count": g_row["expected_member_count"],
                        "preparing_operations": prep_count,
                    },
                )

            now = self._now_iso()
            txn.execute(
                """
                UPDATE dispatch_groups
                SET assembly_state = 'sealed', sealed_at = ?, revision = revision + 1
                WHERE dispatch_group_id = ?
                """,
                (now, group_id),
            )
            self._maybe_finalize_dispatch_group_in_conn(txn.conn, group_id, txn.store_instance_id)
            res = self._build_dispatch_group_result(txn.conn, group_id)
            res["request_id"] = req.request_id
            self._record_idempotent_request(
                txn.conn,
                parent_id,
                "seal_dispatch_group",
                req.request_id,
                req.normalized_hash,
                res,
            )
            return res

    def close_dispatch_group(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("close_dispatch_group", raw_args)
        parent_node = self.ensure_caller_node(caller)
        parent_id = str(parent_node["node_id"])
        group_id = req["dispatch_group_id"]

        with self.store.transaction("IMMEDIATE") as txn:
            cached = self._check_idempotent_request(
                txn.conn,
                parent_id,
                "close_dispatch_group",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

            g_row = txn.execute(
                "SELECT * FROM dispatch_groups WHERE dispatch_group_id = ?",
                (group_id,),
            ).fetchone()
            if g_row is None:
                raise SideSessionError(ErrorCode.NOT_FOUND, f"Dispatch group not found: {group_id}")
            if str(g_row["parent_node_id"]) != parent_id:
                raise SideSessionError(ErrorCode.GROUP_SCOPE_MISMATCH, "Caller is not the parent of this dispatch group")
            if g_row["assembly_state"] == "sealed":
                raise SideSessionError(ErrorCode.GROUP_NOT_OPEN, "Sealed dispatch group cannot be closed as incomplete")
            if int(g_row["revision"]) != int(req["expected_revision"]):
                raise SideSessionError(
                    ErrorCode.REVISION_CONFLICT,
                    "Dispatch group revision mismatch",
                    {"expected_revision": req["expected_revision"], "actual_revision": g_row["revision"]},
                )

            txn.execute(
                """
                UPDATE dispatch_groups
                SET assembly_state = 'closed_incomplete',
                    incomplete_acknowledged = 1,
                    revision = revision + 1
                WHERE dispatch_group_id = ?
                """,
                (group_id,),
            )
            self._maybe_finalize_dispatch_group_in_conn(txn.conn, group_id, txn.store_instance_id)
            res = self._build_dispatch_group_result(txn.conn, group_id)
            res["request_id"] = req.request_id
            self._record_idempotent_request(
                txn.conn,
                parent_id,
                "close_dispatch_group",
                req.request_id,
                req.normalized_hash,
                res,
            )
            return res

    def get_dispatch_group(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("get_dispatch_group", raw_args)
        caller_node = self.ensure_caller_node(caller)
        group_id = req["dispatch_group_id"]

        g_row = self.store.conn.execute(
            "SELECT * FROM dispatch_groups WHERE dispatch_group_id = ?",
            (group_id,),
        ).fetchone()
        if g_row is None:
            raise SideSessionError(ErrorCode.NOT_FOUND_OR_FORBIDDEN, f"Dispatch group not found: {group_id}")

        group_parent_id = str(g_row["parent_node_id"])
        if not self._is_ancestor_or_self(self.store.conn, str(caller_node["node_id"]), group_parent_id):
            raise _err(
                ErrorCode.NOT_FOUND_OR_FORBIDDEN,
                "Caller is not authorized to read this dispatch group",
                {"dispatch_group_id": group_id},
                aliases=("PERMISSION_DENIED", ErrorCode.FORBIDDEN),
            )
        return self._build_dispatch_group_result(self.store.conn, group_id)

    # ------------------------------------------------------------------
    # 2. Session Initiation, Proposals & Context Quality Gate (Section 6.1, 7 & Prompt #2)
    # ------------------------------------------------------------------

    def _check_proposal_quotas(
        self,
        conn: Any,
        parent_node_id: str,
        caller_turn_id: str | None,
    ) -> None:
        pending_rows = conn.execute(
            """
            SELECT canonical_task FROM proposals
            WHERE parent_node_id = ?
              AND state IN ('waiting_user', 'awaiting_brief', 'approved')
            """,
            (parent_node_id,),
        ).fetchall()
        if len(pending_rows) >= MAX_PROPOSALS_PER_PARENT:
            raise SideSessionError(
                ErrorCode.CAPACITY_EXCEEDED,
                f"Parent session has reached the maximum of {MAX_PROPOSALS_PER_PARENT} pending proposals",
                {"parent_node_id": parent_node_id, "max_proposals": MAX_PROPOSALS_PER_PARENT},
            )
        if caller_turn_id:
            turn_count = 0
            for r in pending_rows:
                try:
                    t_obj = json.loads(r["canonical_task"] or "{}")
                    if t_obj.get("_caller_turn_id") == caller_turn_id:
                        turn_count += 1
                except Exception:
                    continue
            if turn_count >= MAX_PROPOSALS_PER_TURN:
                raise SideSessionError(
                    ErrorCode.CAPACITY_EXCEEDED,
                    f"Parent session has reached the maximum of {MAX_PROPOSALS_PER_TURN} proposals in the current turn",
                    {"parent_node_id": parent_node_id, "max_proposals_per_turn": MAX_PROPOSALS_PER_TURN},
                )

    def _allocate_child_short_name(
        self,
        conn: Any,
        parent_node_id: str,
        requested_name: str | None,
        node_id: str,
    ) -> str:
        if requested_name is not None:
            cleaned = validate_short_name(requested_name)
            dup = conn.execute(
                "SELECT 1 FROM nodes WHERE parent_node_id = ? AND name = ?",
                (parent_node_id, cleaned),
            ).fetchone()
            if dup is not None:
                raise SideSessionError(
                    ErrorCode.INVALID_NAME,
                    f"Child session name '{cleaned}' already exists under parent {parent_node_id}",
                    {"name": cleaned, "parent_node_id": parent_node_id},
                )
            return cleaned

        base_name = f"side-{node_id.replace('-', '')[:8]}"
        if not conn.execute(
            "SELECT 1 FROM nodes WHERE parent_node_id = ? AND name = ?",
            (parent_node_id, base_name),
        ).fetchone():
            return base_name
        return f"side-{node_id.replace('-', '')[:12]}"

    def _build_brief_markdown(
        self,
        *,
        title: str,
        prompt: str,
        context_mode: str,
        background_sections: Mapping[str, str] | None,
        background_raw: str | None,
        history_summary: str | None,
        remaining_plan: str | None,
        assignment_view: Mapping[str, Any],
    ) -> str:
        sections = dict(background_sections or {})
        overall = sections.get("overall_goal") or (background_raw or title)
        decisions = sections.get("decisions") or "尚无"
        constraints = sections.get("constraints") or "遵循当前任务工作区与工具限制"
        lines = [
            f"# {title}",
            "",
            "## 任务分配元数据",
            f"- `node_id`: `{assignment_view.get('node_id', '')}`",
            f"- `run_id`: `{assignment_view.get('run_id', '')}`",
            f"- `turn_seq`: `{assignment_view.get('turn_seq', 1)}`",
            f"- `worker_turn_id`: `{assignment_view.get('worker_turn_id', '')}`",
            f"- `context_applied`: `{context_mode}`",
            "",
            "## 结构化背景",
            f"总体目标：{overall}",
            f"已有决策：{decisions}",
            f"约束：{constraints}",
            "",
            "## 本轮指令",
            prompt,
        ]
        if remaining_plan:
            lines.extend(["", "## 剩余执行计划 (Remaining Plan)", remaining_plan])
        if history_summary:
            lines.extend(["", "## 源会话历史摘要投影 (History Projection)", history_summary])
        return "\n".join(lines) + "\n"

    def _driver_capture_anchor(self, cutoff: SourceCutoff) -> SourceAnchor:
        drv = self.driver
        if hasattr(drv, "capture_anchor") and callable(drv.capture_anchor):
            res = drv.capture_anchor(cutoff)
            if isinstance(res, SourceAnchor):
                return res
            if isinstance(res, Mapping):
                return SourceAnchor(
                    status=str(res.get("status", "stable")),
                    source_session_id=str(res.get("source_session_id", cutoff.source_runtime_sid)),
                    cutoff=cutoff,
                    source_revision=res.get("source_revision", cutoff.source_revision),
                    anchor_message_id=res.get("anchor_message_id"),
                    sequence=res.get("sequence"),
                    anchor_turn_id=res.get("anchor_turn_id", cutoff.trigger_runtime_turn_id),
                    checkpoint_id=res.get("checkpoint_id"),
                    effective_chain_hash=res.get("effective_chain_hash"),
                    reason=res.get("reason"),
                )
        raise _err(ErrorCode.CAPABILITY_UNAVAILABLE, "driver does not implement capture_anchor")

    def _driver_capture_history(self, anchor: SourceAnchor) -> HistoryProjection:
        drv = self.driver
        if hasattr(drv, "capture_history") and callable(drv.capture_history):
            res = drv.capture_history(anchor)
            if isinstance(res, HistoryProjection):
                return res
            if isinstance(res, Mapping):
                quality = str(res.get("history_quality", "stable_projection"))
                summary = str(res.get("summary", ""))
                excl = list(res.get("excluded_ranges") or [])
                snap_hash = str(
                    res.get("snapshot_hash")
                    or canonical_json_sha256({"anchor": anchor.to_dict(), "history_quality": quality, "summary": summary})
                )
                return HistoryProjection(
                    anchor=anchor,
                    history_quality=quality,
                    summary=summary,
                    excluded_ranges=excl,
                    snapshot_hash=snap_hash,
                    formatter_version=str(res.get("formatter_version", FORMATTER_VERSION)),
                    effective_chain_ref=res.get("effective_chain_ref"),
                )
        raise _err(ErrorCode.CAPABILITY_UNAVAILABLE, "driver does not implement capture_history")

    def _driver_validate_anchor(
        self,
        anchor: SourceAnchor | Mapping[str, Any],
        *,
        allow_unavailable: bool = False,
    ) -> bool:
        drv = self.driver
        orig_status = (
            anchor.status
            if isinstance(anchor, SourceAnchor)
            else (str(anchor.get("status") or "stable") if isinstance(anchor, Mapping) else "stable")
        )
        if hasattr(drv, "validate_anchor") and callable(drv.validate_anchor):
            res = drv.validate_anchor(anchor)
            if isinstance(res, bool):
                return res
            if isinstance(res, Mapping):
                if allow_unavailable and orig_status == "unavailable":
                    if res.get("status") == "unavailable" and not res.get("reverted", False):
                        return True
                return bool(res.get("ok", res.get("valid", True)))
            if allow_unavailable and orig_status == "unavailable":
                if getattr(res, "status", None) == "unavailable" and not getattr(res, "reverted", False):
                    return True
            return bool(getattr(res, "ok", getattr(res, "valid", True)))
        return True

    def _prepare_fork_context_snapshot(
        self,
        *,
        parent_node: Mapping[str, Any],
        caller: CallerContext,
        request_id: str,
        operation_id: str,
        kind: str,
        title: str,
        prompt: str,
        remaining_plan: str | None,
        task_id: str | None,
        task_revision: int | None,
        requested_group_id: str | None,
        brief_hash: str,
    ) -> tuple[HistoryProjection, str, str | None]:
        """Capture source anchor and history projection, persist context_snapshots row, and check R08."""
        parent_id = str(parent_node["node_id"])
        parent_sid = str(parent_node["runtime_session_id"] or caller.runtime_sid)
        cutoff = SourceCutoff(
            source_node_id=parent_id,
            source_runtime_sid=parent_sid,
            trigger_runtime_turn_id=caller.runtime_turn_id or "turn-0",
            trigger_request_id=request_id,
            owner_id=parent_id,
            accepted_input_high_watermark=request_id,
            source_revision=int(parent_node.get("revision") or 1),
            task_id=task_id,
        )
        anchor = self._driver_capture_anchor(cutoff)
        projection = self._driver_capture_history(anchor)

        quality = projection.history_quality
        if anchor.status != "stable":
            quality = "brief_only"
        if quality not in ("stable_projection", "brief_only"):
            quality = "brief_only"

        manifest_payload = {
            "schema_version": ENGINE_SCHEMA_VERSION,
            "operation_id": operation_id,
            "source_node_id": parent_id,
            "source_runtime_sid": parent_sid,
            "source_turn_id": cutoff.trigger_runtime_turn_id,
            "source_revision": cutoff.source_revision,
            "task_id": task_id,
            "task_revision": task_revision,
            "cutoff": cutoff.to_dict(),
            "anchor": anchor.to_dict(),
            "history_quality": quality,
            "summary": projection.summary,
            "excluded_ranges": projection.excluded_ranges,
            "brief_hash": brief_hash,
            "formatter_version": projection.formatter_version,
        }
        snapshot_hash = projection.snapshot_hash or canonical_json_sha256(manifest_payload)
        manifest_payload["snapshot_hash"] = snapshot_hash

        # Write immutable history snapshot file outside DB transaction
        hist_rel = f"artifacts/history/{snapshot_hash}.json"
        hist_export = self.store.write_artifact_blob(hist_rel, canonical_json_bytes(manifest_payload))
        projection = replace(projection, history_quality=quality, snapshot_hash=snapshot_hash)

        now = self._now_iso()
        exp_iso = self._future_iso(minutes=30)

        with self.store.transaction("IMMEDIATE") as txn:
            existing_snap = txn.execute(
                "SELECT * FROM context_snapshots WHERE snapshot_hash = ?",
                (snapshot_hash,),
            ).fetchone()
            if existing_snap is not None:
                snapshot_id = str(existing_snap["snapshot_id"])
                eff_op_id = str(existing_snap["operation_id"])
            else:
                snapshot_id = self._new_uuid()
                eff_op_id = operation_id

            manifest_art_id = self._new_uuid()
            manifest_bytes = canonical_json_bytes(manifest_payload)
            txn.execute(
                """
                INSERT INTO artifacts (
                    artifact_id, owner_node_id, run_id, kind, storage_kind,
                    inline_bytes, relative_blob_path, sha256, byte_length,
                    media_type, state, created_at
                ) VALUES (?, ?, NULL, 'context_manifest', 'inline', ?, NULL, ?, ?, 'application/json', 'published', ?)
                """,
                (
                    manifest_art_id,
                    parent_id,
                    manifest_bytes,
                    sha256_hex(manifest_bytes),
                    len(manifest_bytes),
                    now,
                ),
            )
            manifest_ref = format_ssref(txn.store_instance_id, "artifact", manifest_art_id)

            init_state = "candidate" if quality == "brief_only" else "authorized"
            if existing_snap is None:
                txn.execute(
                    """
                    INSERT INTO context_snapshots (
                        snapshot_id, operation_id, source_node_id, source_runtime_sid,
                        source_turn_id, source_revision, task_revision, anchor_json,
                        history_quality, projection_ref, projection_sha256, brief_hash,
                        snapshot_hash, excluded_ranges, reason, created_at, expires_at, state
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        eff_op_id,
                        parent_id,
                        parent_sid,
                        cutoff.trigger_runtime_turn_id,
                        cutoff.source_revision,
                        task_revision,
                        canonical_json(anchor.to_dict()),
                        quality,
                        manifest_ref,
                        hist_export.sha256,
                        brief_hash,
                        snapshot_hash,
                        canonical_json(projection.excluded_ranges),
                        anchor.reason,
                        now,
                        exp_iso,
                        init_state,
                    ),
                )

            init_stage = "awaiting_context_acceptance" if quality == "brief_only" else "ready_for_admission"
            txn.execute(
                """
                INSERT INTO operations (
                    operation_id, request_id, node_id, actor_node_id, task_id, kind,
                    requested_group_id, source_cutoff, context_snapshot_id, stage,
                    attempt, external_ids, expected_paths, revision, created_at, updated_at
                ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, 1, '{}', '{}', 1, ?, ?)
                ON CONFLICT(operation_id) DO UPDATE SET
                    context_snapshot_id = excluded.context_snapshot_id,
                    stage = CASE
                        WHEN operations.stage IN ('ready_for_admission', 'reserved', 'running', 'finished')
                        THEN operations.stage
                        ELSE excluded.stage
                    END,
                    updated_at = excluded.updated_at
                """,
                (
                    eff_op_id,
                    request_id,
                    parent_id,
                    task_id,
                    kind,
                    requested_group_id,
                    canonical_json(cutoff.to_dict()),
                    snapshot_id,
                    init_stage,
                    now,
                    now,
                ),
            )
        return projection, snapshot_id, manifest_ref

    def _verify_existing_context_acceptance_in_conn(
        self,
        conn: Any,
        *,
        operation_id: str,
        snapshot_hash: str,
        expected_brief_hash: str,
        expected_task_revision: int | None,
        anchor: SourceAnchor | Mapping[str, Any],
    ) -> dict[str, Any] | None:
        acc_row = conn.execute(
            """
            SELECT * FROM context_acceptances
            WHERE operation_id = ? AND snapshot_hash = ? AND history_quality = 'brief_only'
            ORDER BY created_at DESC LIMIT 1
            """,
            (operation_id, snapshot_hash),
        ).fetchone()
        if acc_row is None:
            return None
        acc = dict(acc_row)
        if acc["state"] in ("stale", "expired", "rejected") or self._is_expired(acc["expires_at"]):
            conn.execute(
                "UPDATE context_acceptances SET state = 'expired' WHERE acceptance_id = ?",
                (acc["acceptance_id"],),
            )
            conn.execute(
                "UPDATE operations SET stage = 'failed', error = ? WHERE operation_id = ?",
                (ErrorCode.CONTEXT_ACCEPTANCE_STALE.value, operation_id),
            )
            raise SideSessionError(
                ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                "Context acceptance has expired or was invalidated",
                {"operation_id": operation_id, "snapshot_hash": snapshot_hash},
            )
        if str(acc["brief_hash"]) != expected_brief_hash or acc.get("task_revision") != expected_task_revision:
            conn.execute(
                "UPDATE context_acceptances SET state = 'stale' WHERE acceptance_id = ?",
                (acc["acceptance_id"],),
            )
            conn.execute(
                "UPDATE operations SET stage = 'failed', error = ? WHERE operation_id = ?",
                (ErrorCode.CONTEXT_ACCEPTANCE_STALE.value, operation_id),
            )
            raise SideSessionError(
                ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                "Context acceptance no longer matches brief_hash or task_revision",
                {
                    "operation_id": operation_id,
                    "expected_brief_hash": expected_brief_hash,
                    "accepted_brief_hash": acc["brief_hash"],
                    "expected_task_revision": expected_task_revision,
                    "accepted_task_revision": acc.get("task_revision"),
                },
            )
        if not self._driver_validate_anchor(anchor, allow_unavailable=True):
            conn.execute(
                "UPDATE context_acceptances SET state = 'stale' WHERE acceptance_id = ?",
                (acc["acceptance_id"],),
            )
            raise SideSessionError(
                ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                "Source anchor became invalid after context acceptance",
                {"operation_id": operation_id},
            )
        return acc

    def _execute_session_admission_and_start(
        self,
        *,
        caller: CallerContext,
        parent_node: Mapping[str, Any],
        request_id: str,
        normalized_hash: str,
        tool_name: str,
        operation_id: str,
        title: str,
        prompt: str,
        task_kind: str,
        workspace_mode: str,
        context_requested: str,
        context_applied: str,
        history_quality: str | None,
        snapshot_hash: str | None,
        history_summary: str | None,
        background_raw: str | None,
        background_sections: Mapping[str, str] | None,
        requested_name: str | None,
        dispatch_group_id: str | None,
        batch_id: str | None,
        proposal_id: str | None = None,
        dirty_policy: str = "reject",
        approved_path_manifest: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run atomic 4-slot admission and 5-stage startup (`reserved -> worktree_created -> session_created -> brief_accepted -> running`)."""
        parent_id = str(parent_node["node_id"])
        parent_sid = str(parent_node["runtime_session_id"] or caller.runtime_sid)
        root_id = str(parent_node["root_node_id"])
        source_cwd = str(parent_node.get("canonical_workspace") or caller.workspace_path or self.store.root)

        node_id = self._new_uuid()
        child_runtime_sid = f"sess_{self._new_uuid()}"
        run_id = self._new_uuid()
        worker_turn_id = self._new_uuid()
        input_id = self._new_uuid()
        message_id = self._new_uuid()
        brief_id = self._new_uuid()
        task_id = self._new_uuid()
        fencing_token = f"fence:{node_id}:{uuid.uuid4().hex}"
        now = self._now_iso()

        # Stage 1: Atomic 4-slot reservation, node/group admission, operation='reserved'
        with self.store.transaction("IMMEDIATE") as txn:
            self._assert_no_active_worktree_job(txn.conn, parent_id)
            child_name = self._allocate_child_short_name(txn.conn, parent_id, requested_name, node_id)
            slot_no = self.reserve_dispatch(txn, parent_id, node_id, operation_id=operation_id, run_id=run_id)
            eff_group_id, member_id, _ordinal = self._admit_dispatch_group_member_in_conn(
                txn.conn,
                parent_node_id=parent_id,
                child_node_id=node_id,
                message_id=message_id,
                operation_id=operation_id,
                run_id=run_id,
                dispatch_group_id=dispatch_group_id,
                batch_id=batch_id,
                initial_state="queued",
            )

            assignment = RunAssignment(
                node_id=node_id,
                runtime_sid=child_runtime_sid,
                turn_seq=1,
                run_id=run_id,
                worker_turn_id=worker_turn_id,
                input_id=input_id,
                message_id=message_id,
                parent_node_id=parent_id,
                dispatch_group_id=eff_group_id,
                member_id=member_id,
                task_id=task_id,
                task_revision=1,
                owner_epoch=1,
                fencing_token=fencing_token,
            )
            brief_content = self._build_brief_markdown(
                title=title,
                prompt=prompt,
                context_mode=context_applied,
                background_sections=background_sections,
                background_raw=background_raw,
                history_summary=history_summary,
                remaining_plan=None,
                assignment_view=assignment.child_view(),
            )
            brief_hash = sha256_hex(brief_content)

            txn.execute(
                """
                INSERT INTO operations (
                    operation_id, request_id, node_id, actor_node_id, task_id, kind,
                    requested_group_id, member_id, stage, attempt, external_ids,
                    expected_paths, revision, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'start_session', ?, ?, 'reserved', 1, ?, '{}', 1, ?, ?)
                ON CONFLICT(operation_id) DO UPDATE SET
                    node_id = excluded.node_id,
                    task_id = excluded.task_id,
                    member_id = excluded.member_id,
                    stage = 'reserved',
                    external_ids = excluded.external_ids,
                    revision = operations.revision + 1,
                    updated_at = excluded.updated_at
                """,
                (
                    operation_id,
                    request_id,
                    node_id,
                    parent_id,
                    task_id,
                    eff_group_id,
                    member_id,
                    canonical_json({"preallocated_runtime_sid": child_runtime_sid, "run_id": run_id, "slot_no": slot_no}),
                    now,
                    now,
                ),
            )
            if proposal_id is not None:
                txn.execute(
                    """
                    UPDATE proposals
                    SET state = 'claiming', child_node_id = ?, operation_id = ?, updated_at = ?
                    WHERE proposal_id = ?
                    """,
                    (node_id, operation_id, now, proposal_id),
                )
                txn.execute(
                    """
                    UPDATE proposal_claim_jobs
                    SET state = 'running', updated_at = ?
                    WHERE proposal_id = ? AND state IN ('queued', 'running')
                    """,
                    (now, proposal_id),
                )

        # Stage 2: Prepare workspace (worktree.prepare outside DB transaction) & write immutable brief
        wt_record: WorktreeRecord | None = None
        try:
            ws_spec = WorkspaceSpec(
                node_id=node_id,
                workspace_mode=workspace_mode,
                source_cwd=source_cwd,
                dirty_policy=dirty_policy,
                approved_path_manifest=approved_path_manifest,
                name=child_name,
            )
            wt_record = _worktree_mod.prepare(
                ws_spec,
                operation_id=operation_id,
                worktrees_home=self.worktrees_home,
            )
            brief_rel = f"artifacts/briefs/{node_id}/{brief_id}.md"
            self.store.write_artifact_blob(brief_rel, brief_content.encode("utf-8"))
            self.store.export_child_brief(parent_id, node_id, brief_content)
            # Also export `<name>-brief.md` alias projection under side-session-notes/<parent_id>/
            self.store.atomic_export(f"side-session-notes/{parent_id}/{child_name}-brief.md", brief_content)
        except Exception as exc:
            is_transient_claim_err = isinstance(exc, SideSessionError) and (
                exc.code in (
                    ErrorCode.LOCK_BUSY,
                    ErrorCode.RETRY_LATER,
                    ErrorCode.CAPACITY_EXCEEDED,
                )
                or bool(getattr(exc, "retryable", False))
            )
            with self.store.transaction("IMMEDIATE") as comp_txn:
                comp_txn.execute(
                    "UPDATE parent_slots SET state = 'released', updated_at = ? WHERE parent_node_id = ? AND node_id = ?",
                    (self._now_iso(), parent_id, node_id),
                )
                comp_txn.execute(
                    """
                    UPDATE dispatch_group_members
                    SET state = 'terminal', outcome = 'failed', exit_confirmed = 'not_started_proven',
                        terminal_reason = ?, updated_at = ?
                    WHERE member_id = ?
                    """,
                    (str(exc), self._now_iso(), member_id),
                )
                comp_txn.execute(
                    "UPDATE operations SET stage = 'failed', error = ?, updated_at = ? WHERE operation_id = ?",
                    (str(exc), self._now_iso(), operation_id),
                )
                if proposal_id is not None:
                    now_p = self._now_iso()
                    if is_transient_claim_err:
                        comp_txn.execute(
                            """
                            UPDATE proposals
                            SET state = CASE WHEN kind = 'offer' THEN 'awaiting_brief' ELSE 'approved' END,
                                child_node_id = NULL,
                                operation_id = NULL,
                                updated_at = ?
                            WHERE proposal_id = ?
                            """,
                            (now_p, proposal_id),
                        )
                        comp_txn.execute(
                            "UPDATE proposal_claim_jobs SET state = 'queued', updated_at = ? WHERE proposal_id = ?",
                            (now_p, proposal_id),
                        )
                    else:
                        comp_txn.execute(
                            "UPDATE proposals SET state = 'failed', updated_at = ? WHERE proposal_id = ?",
                            (now_p, proposal_id),
                        )
                        comp_txn.execute(
                            "UPDATE proposal_claim_jobs SET state = 'failed', updated_at = ? WHERE proposal_id = ?",
                            (now_p, proposal_id),
                        )
                self._maybe_finalize_dispatch_group_in_conn(comp_txn.conn, eff_group_id, comp_txn.store_instance_id)
            raise

        assert wt_record is not None
        canonical_ws = wt_record.canonical_worktree_path

        with self.store.transaction("IMMEDIATE") as txn:
            now = self._now_iso()
            txn.execute(
                """
                INSERT INTO nodes (
                    node_id, runtime_session_id, parent_node_id, root_node_id, name, title,
                    node_status, pause_requested, task_kind, context_requested, context_applied,
                    workspace_mode, canonical_workspace, repo_root, base_commit,
                    host_link_verified, recovery_status, last_turn_report, last_turn_seq,
                    primary_task_id, brief_id, brief_revision, brief_hash, brief_content,
                    revision, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'active', 0, ?, ?, ?, ?, ?, ?, ?, 0, 'topology_restored',
                          '', 1, ?, ?, 1, ?, ?, 1, ?, ?)
                """,
                (
                    node_id,
                    child_runtime_sid,
                    parent_id,
                    root_id,
                    child_name,
                    title,
                    task_kind,
                    context_requested,
                    context_applied,
                    workspace_mode,
                    canonical_ws,
                    wt_record.repo_root,
                    wt_record.base_commit,
                    task_id,
                    brief_id,
                    brief_hash,
                    brief_content,
                    now,
                    now,
                ),
            )
            txn.execute(
                """
                INSERT INTO bindings (
                    runtime_sid, node_id, schema_version, last_turn_id, cwd, last_seen_at, db_check_state
                ) VALUES (?, ?, ?, NULL, ?, ?, 'pending')
                """,
                (child_runtime_sid, node_id, ENGINE_SCHEMA_VERSION, canonical_ws, now),
            )
            txn.execute(
                """
                INSERT INTO tasks (
                    task_id, origin_node_id, owner_node_id, title, remaining_plan,
                    task_kind, scope_json, state, task_revision, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', 1, ?, ?)
                """,
                (
                    task_id,
                    parent_id,
                    node_id,
                    title,
                    prompt,
                    task_kind,
                    canonical_json(
                        {
                            "resource_keys": [],
                            "write_path_roots": [canonical_ws] if task_kind == "write_code" else [],
                            "artifact_source_roots": [canonical_ws],
                            "tool_profile_hash": "",
                        }
                    ),
                    now,
                    now,
                ),
            )
            if workspace_mode == "branch":
                txn.execute(
                    """
                    INSERT INTO worktrees (
                        worktree_id, node_id, operation_id, canonical_worktree_path,
                        worktrees_home, workspace_mode, repo_key, repo_root, base_commit,
                        branch, source_patch_hash, ownership_marker, state, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'branch', ?, ?, ?, ?, ?, ?, 'in_use', ?, ?)
                    """,
                    (
                        wt_record.worktree_id,
                        node_id,
                        operation_id,
                        wt_record.canonical_worktree_path,
                        wt_record.worktrees_home,
                        wt_record.repo_key,
                        wt_record.repo_root,
                        wt_record.base_commit,
                        wt_record.branch,
                        wt_record.source_patch_hash,
                        wt_record.ownership_marker,
                        now,
                        now,
                    ),
                )
            msg_envelope = (
                f'<cross-session-message from="{parent_id}" name="{parent_node["name"]}">\n'
                f"{brief_content}\n"
                f"</cross-session-message>"
            )
            txn.execute(
                """
                INSERT INTO inbox_messages (
                    message_id, target_node_id, source_node_id, seq, delivery_kind,
                    dispatch_group_id, member_id, task_id, payload_hash, payload,
                    state, run_id, created_at, updated_at
                ) VALUES (?, ?, ?, 1, 'managed_dispatch', ?, ?, ?, ?, ?, 'claimed', ?, ?, ?)
                """,
                (
                    message_id,
                    node_id,
                    parent_id,
                    eff_group_id,
                    member_id,
                    task_id,
                    sha256_hex(msg_envelope),
                    msg_envelope,
                    run_id,
                    now,
                    now,
                ),
            )
            txn.execute(
                """
                INSERT INTO owners (
                    node_id, worker_id, owner_token, owner_epoch, fencing_token,
                    current_run_id, heartbeat, state
                ) VALUES (?, ?, ?, 1, ?, ?, ?, 'active')
                """,
                (
                    node_id,
                    f"worker:{node_id[:8]}",
                    f"tok:{uuid.uuid4().hex}",
                    fencing_token,
                    run_id,
                    now,
                ),
            )
            txn.execute(
                """
                INSERT INTO turns (
                    run_id, node_id, turn_seq, worker_turn_id, runtime_turn_id,
                    input_id, message_id, dispatch_group_id, member_id, task_id,
                    task_revision, owner_epoch, fencing_token, execution_state,
                    report_state, started_at
                ) VALUES (?, ?, 1, ?, NULL, ?, ?, ?, ?, ?, 1, 1, ?, 'starting', 'none', ?)
                """,
                (
                    run_id,
                    node_id,
                    worker_turn_id,
                    input_id,
                    message_id,
                    eff_group_id,
                    member_id,
                    task_id,
                    fencing_token,
                    now,
                ),
            )
            txn.execute(
                "UPDATE parent_slots SET state = 'starting', updated_at = ? WHERE parent_node_id = ? AND node_id = ?",
                (now, parent_id, node_id),
            )
            txn.execute(
                "UPDATE dispatch_group_members SET state = 'starting', updated_at = ? WHERE member_id = ?",
                (now, member_id),
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
                (canonical_json({"workspace": canonical_ws, "branch": wt_record.branch}), now, operation_id),
            )

        if self.runtime_execution == "deferred":
            with self.store.transaction("IMMEDIATE") as txn:
                now = self._now_iso()
                if proposal_id is not None:
                    txn.execute(
                        "UPDATE proposals SET state = 'started', child_node_id = ?, updated_at = ? WHERE proposal_id = ?",
                        (node_id, now, proposal_id),
                    )
                    txn.execute(
                        "UPDATE proposal_claim_jobs SET state = 'completed', updated_at = ? WHERE proposal_id = ?",
                        (now, proposal_id),
                    )
                start_res = StartResult(
                    request_id=request_id,
                    proposal_id=proposal_id,
                    node_id=node_id,
                    runtime_session_id=child_runtime_sid,
                    operation_id=operation_id,
                    status="starting",
                    context_requested=context_requested,
                    context_applied=context_applied,
                    history_quality=history_quality,
                    snapshot_hash=snapshot_hash,
                    workspace_mode=workspace_mode,
                    host_link_verified=False,
                    revision=txn.revision,
                ).to_dict()
                start_res.update(
                    {
                        "ok": True,
                        "name": child_name,
                        "title": title,
                        "task_kind": task_kind,
                        "task_id": task_id,
                        "run_id": run_id,
                        "turn_seq": 1,
                        "worker_turn_id": worker_turn_id,
                        "dispatch_group_id": eff_group_id,
                        "member_id": member_id,
                        "branch": wt_record.branch,
                        "worktree_path": canonical_ws,
                        "runtime_state": "queued_for_worker",
                    }
                )
                self._record_idempotent_request(
                    txn.conn,
                    parent_id,
                    tool_name,
                    request_id,
                    normalized_hash,
                    start_res,
                    operation_id=operation_id,
                )

            self.store.export_parent_notes(parent_id)
            self._notify_supervisor(
                {
                    "event": "session_started",
                    "operation_id": operation_id,
                    "node_id": node_id,
                    "run_id": run_id,
                }
            )
            return start_res

        # Stage 3, 4, 5: session_created -> brief_accepted -> running
        handle: RuntimeHandle | None = None
        prof = runtime_profile_for_task_kind(task_kind)
        create_spec = RuntimeCreateSpec(
            assignment=assignment,
            workspace_path=canonical_ws,
            parent_runtime_sid=parent_sid,
            mode=prof.mode,
            model={},
            tool_allowlist=list(prof.tool_allowlist or []),
            tool_denylist=list(prof.tool_denylist),
            additional_directories=[],
            persistence="immediate",
            preallocated_session_id=child_runtime_sid,
            brief_ref=f"side-session-notes/{parent_id}/{node_id}-brief.md",
            context_applied=context_applied,
        )

        try:
            handle = self._driver_create(create_spec)
            actual_sid = handle.runtime_sid or child_runtime_sid
            if os.path.realpath(handle.canonical_workspace) != os.path.realpath(canonical_ws):
                raise SideSessionError(
                    ErrorCode.WORKSPACE_MISMATCH,
                    f"Created runtime workspace ({handle.canonical_workspace}) does not match expected ({canonical_ws})",
                )
        except Exception as exc:
            self._compensate_admission_failure(
                parent_id=parent_id,
                node_id=node_id,
                member_id=member_id,
                operation_id=operation_id,
                proposal_id=proposal_id,
                group_id=eff_group_id,
                handle=handle,
                exc=exc,
                mismatch=isinstance(exc, SideSessionError) and exc.code == ErrorCode.WORKSPACE_MISMATCH,
            )
            raise

        with self.store.transaction("IMMEDIATE") as txn:
            now = self._now_iso()
            if actual_sid != child_runtime_sid:
                txn.execute("UPDATE nodes SET runtime_session_id = ? WHERE node_id = ?", (actual_sid, node_id))
                txn.execute("UPDATE bindings SET runtime_sid = ? WHERE node_id = ?", (actual_sid, node_id))
            txn.execute(
                "UPDATE operations SET stage = 'session_created', revision = revision + 1, updated_at = ? WHERE operation_id = ?",
                (now, operation_id),
            )
            txn.execute(
                "UPDATE operations SET stage = 'brief_accepted', revision = revision + 1, updated_at = ? WHERE operation_id = ?",
                (now, operation_id),
            )

        try:
            send_rcpt = self._driver_send(
                handle,
                RuntimeInput(input_id=input_id, content=brief_content, origin="system/side_sessions"),
            )
        except Exception as exc:
            self._compensate_admission_failure(
                parent_id=parent_id,
                node_id=node_id,
                member_id=member_id,
                operation_id=operation_id,
                proposal_id=proposal_id,
                group_id=eff_group_id,
                handle=handle,
                exc=exc,
                mismatch=False,
                send_uncertain=True,
            )
            raise
        runtime_turn_id = send_rcpt.runtime_turn_id or f"rturn:{run_id[:8]}"

        with self.store.transaction("IMMEDIATE") as txn:
            now = self._now_iso()
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
            txn.execute(
                """
                UPDATE turns
                SET runtime_turn_id = ?, execution_state = 'running'
                WHERE run_id = ?
                """,
                (runtime_turn_id, run_id),
            )
            txn.execute(
                """
                INSERT INTO task_turn_bindings (
                    binding_id, task_id, node_id, runtime_sid, runtime_turn_id,
                    task_revision, state, created_at
                ) VALUES (?, ?, ?, ?, ?, 1, 'active', ?)
                """,
                (self._new_uuid(), task_id, node_id, actual_sid, runtime_turn_id, now),
            )
            txn.execute(
                "UPDATE inbox_messages SET state = 'running', updated_at = ? WHERE target_node_id = ? AND message_id = ?",
                (now, node_id, message_id),
            )
            txn.execute(
                "UPDATE parent_slots SET state = 'running', updated_at = ? WHERE parent_node_id = ? AND node_id = ?",
                (now, parent_id, node_id),
            )
            txn.execute(
                "UPDATE dispatch_group_members SET state = 'running', updated_at = ? WHERE member_id = ?",
                (now, member_id),
            )
            txn.execute(
                "UPDATE owners SET runtime_instance_id = ?, heartbeat = ? WHERE node_id = ?",
                (handle.runtime_instance_id, now, node_id),
            )
            txn.execute(
                """
                UPDATE operations
                SET stage = 'running', result_state = 'running', revision = revision + 1, updated_at = ?
                WHERE operation_id = ?
                """,
                (now, operation_id),
            )
            if proposal_id is not None:
                txn.execute(
                    "UPDATE proposals SET state = 'started', child_node_id = ?, updated_at = ? WHERE proposal_id = ?",
                    (node_id, now, proposal_id),
                )
                txn.execute(
                    "UPDATE proposal_claim_jobs SET state = 'completed', updated_at = ? WHERE proposal_id = ?",
                    (now, proposal_id),
                )

            start_res = StartResult(
                request_id=request_id,
                proposal_id=proposal_id,
                node_id=node_id,
                runtime_session_id=actual_sid,
                operation_id=operation_id,
                status="running",
                context_requested=context_requested,
                context_applied=context_applied,
                history_quality=history_quality,
                snapshot_hash=snapshot_hash,
                workspace_mode=workspace_mode,
                host_link_verified=True,
                revision=txn.revision,
            ).to_dict()
            start_res.update(
                {
                    "ok": True,
                    "name": child_name,
                    "title": title,
                    "task_kind": task_kind,
                    "task_id": task_id,
                    "run_id": run_id,
                    "turn_seq": 1,
                    "worker_turn_id": worker_turn_id,
                    "dispatch_group_id": eff_group_id,
                    "member_id": member_id,
                    "branch": wt_record.branch,
                    "worktree_path": canonical_ws,
                }
            )
            self._record_idempotent_request(
                txn.conn,
                parent_id,
                tool_name,
                request_id,
                normalized_hash,
                start_res,
                operation_id=operation_id,
            )

        self.store.export_parent_notes(parent_id)
        self._notify_supervisor(
            {
                "event": "session_started",
                "operation_id": operation_id,
                "node_id": node_id,
                "run_id": run_id,
            }
        )
        return start_res

    def _compensate_admission_failure(
        self,
        *,
        parent_id: str,
        node_id: str,
        member_id: str,
        operation_id: str,
        proposal_id: str | None,
        group_id: str | None,
        handle: RuntimeHandle | None,
        exc: BaseException,
        mismatch: bool = False,
        send_uncertain: bool = False,
    ) -> None:
        """Classify Stage 3–5 failure: proven-dead → released/failed; unknown → reconciliation."""
        now = self._now_iso()
        exit_confirmed = False
        if handle is not None:
            try:
                rcpt = self.driver.stop_and_wait(handle, deadline_ms=5000)
                exit_confirmed = bool(getattr(rcpt, "exit_confirmed", False))
            except Exception:
                exit_confirmed = False
            try:
                snap = self.driver.inspect(handle)
                if str(getattr(snap, "status", "")) not in ("exited", "stopped", "dead"):
                    exit_confirmed = False
            except Exception:
                pass

        proven_dead = handle is None or (exit_confirmed and not send_uncertain)
        if mismatch and handle is not None and not exit_confirmed:
            proven_dead = False

        with self.store.transaction("IMMEDIATE") as txn:
            if proven_dead:
                txn.execute(
                    "UPDATE parent_slots SET state = 'released', updated_at = ? WHERE parent_node_id = ? AND node_id = ?",
                    (now, parent_id, node_id),
                )
                txn.execute(
                    """
                    UPDATE dispatch_group_members
                    SET state = 'terminal', outcome = 'failed', exit_confirmed = 'not_started_proven',
                        terminal_reason = ?, updated_at = ?
                    WHERE member_id = ?
                    """,
                    (str(exc), now, member_id),
                )
                txn.execute(
                    "UPDATE operations SET stage = 'failed', error = ?, updated_at = ? WHERE operation_id = ?",
                    (str(exc), now, operation_id),
                )
                txn.execute("UPDATE turns SET execution_state = 'failed', ended_at = ? WHERE node_id = ?", (now, node_id))
                txn.execute("UPDATE owners SET state = 'idle', pid = NULL, model_pid = NULL, current_run_id = NULL, heartbeat = ? WHERE node_id = ?", (now, node_id))
                txn.execute("UPDATE inbox_messages SET state = 'failed', updated_at = ? WHERE target_node_id = ?", (now, node_id))
                if proposal_id is not None:
                    is_transient_claim_err = (
                        handle is None
                        and isinstance(exc, SideSessionError)
                        and (
                            exc.code in (ErrorCode.LOCK_BUSY, ErrorCode.RETRY_LATER, ErrorCode.CAPACITY_EXCEEDED)
                            or bool(getattr(exc, "retryable", False))
                        )
                    )
                    if is_transient_claim_err:
                        txn.execute(
                            "UPDATE nodes SET node_status = 'archived', name = ?, updated_at = ? WHERE node_id = ?",
                            (f"aborted-{node_id[:8]}", now, node_id),
                        )
                        txn.execute(
                            """
                            UPDATE proposals
                            SET state = CASE WHEN kind = 'offer' THEN 'awaiting_brief' ELSE 'approved' END,
                                child_node_id = NULL,
                                operation_id = NULL,
                                updated_at = ?
                            WHERE proposal_id = ?
                            """,
                            (now, proposal_id),
                        )
                        txn.execute(
                            "UPDATE proposal_claim_jobs SET state = 'queued', updated_at = ? WHERE proposal_id = ?",
                            (now, proposal_id),
                        )
                    else:
                        txn.execute(
                            "UPDATE proposals SET state = 'failed', updated_at = ? WHERE proposal_id = ?",
                            (now, proposal_id),
                        )
                        txn.execute(
                            "UPDATE proposal_claim_jobs SET state = 'failed', updated_at = ? WHERE proposal_id = ?",
                            (now, proposal_id),
                        )
                if group_id:
                    self._maybe_finalize_dispatch_group_in_conn(txn.conn, group_id, txn.store_instance_id)
            else:
                txn.execute(
                    "UPDATE parent_slots SET state = 'reconciliation', updated_at = ? WHERE parent_node_id = ? AND node_id = ?",
                    (now, parent_id, node_id),
                )
                txn.execute(
                    "UPDATE operations SET stage = 'reconciliation', error = ?, updated_at = ? WHERE operation_id = ?",
                    (str(exc), now, operation_id),
                )
                txn.execute(
                    "UPDATE dispatch_group_members SET state = 'reconciliation', updated_at = ? WHERE member_id = ?",
                    (now, member_id),
                )
                txn.execute(
                    "UPDATE turns SET execution_state = 'reconciliation' WHERE node_id = ? AND execution_state IN ('starting', 'running', 'queued')",
                    (node_id,),
                )

    def _driver_create(self, spec: RuntimeCreateSpec) -> RuntimeHandle:
        drv = self.driver
        if hasattr(drv, "create") and callable(drv.create):
            res = drv.create(spec)
            if isinstance(res, RuntimeHandle):
                return res
            if isinstance(res, Mapping):
                sid = str(
                    res.get("runtime_sid")
                    or (res.get("session") or {}).get("sessionId")
                    or spec.preallocated_session_id
                )
                ws = str(
                    res.get("canonical_workspace")
                    or ((res.get("session") or {}).get("workspace") or {}).get("workspacePath")
                    or spec.workspace_path
                )
                return RuntimeHandle(
                    runtime_sid=sid,
                    runtime_instance_id=str(res.get("runtime_instance_id") or f"inst:{sid}"),
                    owner_connection_id=str(res.get("owner_connection_id") or f"conn:{sid}"),
                    snapshot_revision=int(res.get("snapshot_revision", 1)),
                    canonical_workspace=ws,
                    process_identity=dict(res.get("process_identity") or {}),
                )
        raise _err(ErrorCode.CAPABILITY_UNAVAILABLE, "driver does not implement create")

    def _driver_send(self, handle: RuntimeHandle, runtime_input: RuntimeInput) -> SendReceipt:
        drv = self.driver
        if hasattr(drv, "send") and callable(drv.send):
            res = drv.send(handle, runtime_input)
            if isinstance(res, SendReceipt):
                return res
            if isinstance(res, Mapping):
                return SendReceipt(
                    input_id=str(res.get("input_id", runtime_input.input_id)),
                    status=str(res.get("status", "accepted")),
                    runtime_turn_id=res.get("runtime_turn_id"),
                    response_revision=res.get("response_revision"),
                    evidence_ref=res.get("evidence_ref"),
                )
        raise _err(ErrorCode.CAPABILITY_UNAVAILABLE, "driver does not implement send")

    def _notify_supervisor(self, payload: Mapping[str, Any]) -> None:
        port = self.supervisor_port
        if port is None:
            return
        try:
            if callable(port):
                port(dict(payload))
                return
            for method_name in ("notify", "enqueue", "submit", "wake"):
                fn = getattr(port, method_name, None)
                if callable(fn):
                    fn(dict(payload))
                    return
        except Exception:
            pass

    def start_session(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Start a child session, create an offer/own_initiative proposal, or claim an approved proposal."""
        ctx = self._coerce_caller(caller)
        dirty_policy = str(kwargs.pop("dirty_policy", "reject"))
        approved_path_manifest = kwargs.pop("approved_path_manifest", None)
        raw_args = self._merge_args(args, kwargs)
        allow_degraded_context = bool(raw_args.pop("allow_degraded_context", False))
        operation_id_override = raw_args.pop("operation_id", None)

        pre_args, raw_proposal_ref = self._preprocess_proposal_id_arg(raw_args)
        req = normalize_request("start_session", pre_args)
        parent_node = self.ensure_caller_node(ctx)
        parent_id = str(parent_node["node_id"])

        # Check request_id idempotency (unless resuming an awaiting_context_acceptance operation that is now approved)
        existing_res = self._check_idempotent_request(
            self.store.conn,
            parent_id,
            "start_session",
            req.request_id,
            req.normalized_hash,
        )
        if existing_res is not None:
            if existing_res.get("status") in ("awaiting_context_approval", "awaiting_context_acceptance"):
                op_id = existing_res.get("operation_id")
                if op_id:
                    op_row = self.store.conn.execute(
                        "SELECT stage, context_acceptance_id FROM operations WHERE operation_id = ?",
                        (op_id,),
                    ).fetchone()
                    if op_row and (op_row["stage"] == "ready_for_admission" or op_row["context_acceptance_id"]):
                        operation_id_override = str(op_id)
                        existing_res = None
            if existing_res is not None:
                return existing_res

        # 1. Variant: offer (initial)
        if req.variant == "offer":
            with self.store.transaction("IMMEDIATE") as txn:
                self._check_proposal_quotas(txn.conn, parent_id, ctx.runtime_turn_id)
                proposal_id = self._new_uuid()
                now = self._now_iso()
                exp_iso = self._future_iso(hours=24)
                task_obj = {
                    "title": req["title"],
                    "context": "fresh",
                    "task_kind": "read_only",
                    "use_worktree": False,
                    "workspace_mode": "inherit",
                    "_caller_turn_id": ctx.runtime_turn_id,
                }
                task_hash = canonical_json_sha256(task_obj)
                txn.execute(
                    """
                    INSERT INTO proposals (
                        proposal_id, parent_node_id, kind, state, canonical_task,
                        task_hash, expires_at, request_id, created_at, updated_at
                    ) VALUES (?, ?, 'offer', 'waiting_user', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        proposal_id,
                        parent_id,
                        canonical_json(task_obj),
                        task_hash,
                        exp_iso,
                        req.request_id,
                        now,
                        now,
                    ),
                )
                res = StartResult(
                    request_id=req.request_id,
                    proposal_id=proposal_id,
                    status="waiting_user",
                    context_requested="fresh",
                    context_applied=None,
                    workspace_mode="inherit",
                    host_link_verified=False,
                    revision=txn.revision,
                ).to_dict()
                res["ok"] = True
                res["proposal_short_id"] = _proposal_short_id(proposal_id)
                self._record_idempotent_request(
                    txn.conn,
                    parent_id,
                    "start_session",
                    req.request_id,
                    req.normalized_hash,
                    res,
                )
                return res

        # 2. Variant: own_initiative (creates waiting_user proposal)
        if req.variant == "own_initiative":
            with self.store.transaction("IMMEDIATE") as txn:
                if req.get("dispatch_group_id") is not None:
                    self._validate_open_dispatch_group_In_conn(txn.conn, req["dispatch_group_id"], parent_id)
                self._check_proposal_quotas(txn.conn, parent_id, ctx.runtime_turn_id)
                proposal_id = self._new_uuid()
                now = self._now_iso()
                exp_iso = self._future_iso(hours=24)
                task_obj = dict(req.payload)
                task_obj.pop("request_id", None)
                task_obj["_caller_turn_id"] = ctx.runtime_turn_id
                task_hash = canonical_json_sha256(task_obj)
                txn.execute(
                    """
                    INSERT INTO proposals (
                        proposal_id, parent_node_id, kind, state, canonical_task,
                        task_hash, expires_at, request_id, created_at, updated_at
                    ) VALUES (?, ?, 'own_initiative', 'waiting_user', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        proposal_id,
                        parent_id,
                        canonical_json(task_obj),
                        task_hash,
                        exp_iso,
                        req.request_id,
                        now,
                        now,
                    ),
                )
                res = StartResult(
                    request_id=req.request_id,
                    proposal_id=proposal_id,
                    status="waiting_user",
                    context_requested=req["context"],
                    context_applied=None,
                    workspace_mode=req["workspace_mode"],
                    host_link_verified=False,
                    revision=txn.revision,
                ).to_dict()
                res["ok"] = True
                res["proposal_short_id"] = _proposal_short_id(proposal_id)
                self._record_idempotent_request(
                    txn.conn,
                    parent_id,
                    "start_session",
                    req.request_id,
                    req.normalized_hash,
                    res,
                )
                return res

        # 3. Variant: claim_offer / claim_full_proposal
        proposal_id_for_start: str | None = None
        if req.variant in ("claim_offer", "claim_full_proposal"):
            lookup_ref = raw_proposal_ref or req["proposal_id"]
            prop_row = self._resolve_proposal_row(self.store.conn, lookup_ref)
            if prop_row is None:
                raise SideSessionError(
                    ErrorCode.NOT_FOUND,
                    f"Proposal not found: {lookup_ref}",
                    {"proposal_id": lookup_ref},
                )
            if str(prop_row["parent_node_id"]) != parent_id:
                raise _err(
                    "PERMISSION_DENIED",
                    "Proposal belongs to a different parent session",
                    {"proposal_id": prop_row["proposal_id"]},
                    aliases=(ErrorCode.FORBIDDEN, ErrorCode.NOT_FOUND_OR_FORBIDDEN),
                )

            p_state = str(prop_row["state"])
            p_kind = str(prop_row["kind"])
            p_id = str(prop_row["proposal_id"])
            saved_task = json.loads(prop_row["canonical_task"] or "{}")

            if p_state in ("dismissed", "cleared"):
                raise SideSessionError(
                    ErrorCode.ALREADY_DISMISSED,
                    "Proposal has already been dismissed",
                    {"proposal_id": p_id, "state": p_state},
                )
            if p_state == "expired" or (
                p_state in ("waiting_user", "awaiting_brief", "approved")
                and self._is_expired(prop_row["expires_at"])
            ):
                if p_state != "expired":
                    with self.store.transaction("IMMEDIATE") as txn:
                        txn.execute(
                            "UPDATE proposals SET state = 'expired', updated_at = ? WHERE proposal_id = ?",
                            (self._now_iso(), p_id),
                        )
                raise _err(
                    ErrorCode.PROPOSAL_EXPIRED,
                    "Proposal has expired",
                    {"proposal_id": p_id},
                    aliases=(ErrorCode.EXPIRED,),
                )
            if p_state == "started":
                if saved_task.get("_auto_claimed_by_approve") and prop_row.get("child_node_id"):
                    # First ClaimFullProposal after approve_proposal auto-claimed it: return that child's StartResult
                    with self.store.transaction("IMMEDIATE") as txn:
                        saved_task.pop("_auto_claimed_by_approve", None)
                        txn.execute(
                            "UPDATE proposals SET canonical_task = ?, updated_at = ? WHERE proposal_id = ?",
                            (canonical_json(saved_task), self._now_iso(), p_id),
                        )
                        c_row = txn.execute(
                            "SELECT * FROM nodes WHERE node_id = ?",
                            (prop_row["child_node_id"],),
                        ).fetchone()
                        res = StartResult(
                            request_id=req.request_id,
                            proposal_id=p_id,
                            node_id=str(c_row["node_id"]),
                            runtime_session_id=str(c_row["runtime_session_id"]),
                            operation_id=prop_row.get("operation_id"),
                            status="running",
                            context_requested=str(c_row["context_requested"]),
                            context_applied=str(c_row["context_applied"]),
                            workspace_mode=str(c_row["workspace_mode"]),
                            host_link_verified=bool(c_row["host_link_verified"]),
                            revision=txn.revision,
                        ).to_dict()
                        res["ok"] = True
                        self._record_idempotent_request(
                            txn.conn,
                            parent_id,
                            "start_session",
                            req.request_id,
                            req.normalized_hash,
                            res,
                            operation_id=prop_row.get("operation_id"),
                        )
                        return res
                raise SideSessionError(
                    ErrorCode.ALREADY_STARTED,
                    "Proposal has already been started",
                    {"proposal_id": p_id, "child_node_id": prop_row.get("child_node_id")},
                )
            if p_state == "waiting_user":
                raise _err(
                    "PROPOSAL_NOT_APPROVED",
                    "Proposal is still waiting_user and has not been approved by human action",
                    {"proposal_id": p_id, "state": p_state},
                    aliases=(ErrorCode.HUMAN_ACTION_REQUIRED, ErrorCode.USER_APPROVAL_UNAVAILABLE, ErrorCode.FORBIDDEN),
                )
            if p_state == "reconciliation":
                raise SideSessionError(
                    ErrorCode.SPAWN_IN_FLIGHT,
                    "Proposal claim is in reconciliation",
                    {"proposal_id": p_id},
                )
            if p_state == "claiming":
                op_id = prop_row.get("operation_id")
                op_row = (
                    self.store.conn.execute("SELECT stage FROM operations WHERE operation_id = ?", (op_id,)).fetchone()
                    if op_id
                    else None
                )
                if not op_row or op_row["stage"] not in ("awaiting_context_acceptance", "ready_for_admission"):
                    raise SideSessionError(
                        ErrorCode.SPAWN_IN_FLIGHT,
                        "Proposal claim is already in flight",
                        {"proposal_id": p_id, "operation_id": op_id},
                    )
                operation_id_override = str(op_id)

            proposal_id_for_start = p_id
            self._assert_no_active_worktree_job(self.store.conn, parent_id)
            if prop_row.get("child_node_id"):
                self._assert_no_active_worktree_job(self.store.conn, str(prop_row["child_node_id"]))
            if p_kind == "offer":
                if req.variant != "claim_offer":
                    raise SideSessionError(
                        ErrorCode.INVALID_REQUEST,
                        "Offer proposal requires prompt and background (ClaimOffer)",
                        {"proposal_id": p_id},
                    )
                title = str(saved_task["title"])
                prompt = req["prompt"]
                background_raw = req["background"]
                background_sections = req["background_sections"]
                task_kind = "read_only"
                workspace_mode = "inherit"
                context_requested = "fresh"
                context_strategy = None
                requested_name = None
                dispatch_group_id = None
                batch_id = None
            else:
                if req.variant != "claim_full_proposal":
                    raise SideSessionError(
                        ErrorCode.INVALID_REQUEST,
                        "Full proposal claim cannot override approved task fields",
                        {"proposal_id": p_id},
                    )
                title = str(saved_task["title"])
                prompt = str(saved_task["prompt"])
                background_raw = saved_task.get("background")
                background_sections = saved_task.get("background_sections") or {}
                task_kind = str(saved_task["task_kind"])
                workspace_mode = str(saved_task["workspace_mode"])
                context_requested = str(saved_task.get("context", "fresh"))
                context_strategy = saved_task.get("context_strategy")
                requested_name = saved_task.get("name")
                dispatch_group_id = saved_task.get("dispatch_group_id")
                batch_id = saved_task.get("batch_id")
        else:
            # 4. Variant: user_asked
            if bool(getattr(self.host_adapter, "strict_user_intent", False)):
                obs = self.host_adapter.observe_input(
                    {
                        "runtime_sid": ctx.runtime_sid,
                        "runtime_turn_id": ctx.runtime_turn_id,
                        "input_id": ctx.runtime_turn_id or req.request_id,
                    }
                )
                if not getattr(obs, "verified", False):
                    raise SideSessionError(
                        ErrorCode.USER_INTENT_UNVERIFIED,
                        "user_asked initiation could not be verified against trusted human input provenance",
                        {"runtime_sid": ctx.runtime_sid},
                    )
            title = req["title"]
            prompt = req["prompt"]
            background_raw = req.get("background")
            background_sections = req.get("background_sections") or {}
            task_kind = req["task_kind"]
            workspace_mode = req["workspace_mode"]
            context_requested = req["context"]
            context_strategy = req.get("context_strategy")
            requested_name = req.get("name")
            dispatch_group_id = req.get("dispatch_group_id")
            batch_id = req.get("batch_id")

        self._assert_no_active_worktree_job(self.store.conn, parent_id)

        # Capability check for read_only / write_code
        caps = self._probe_capabilities()
        if task_kind == "read_only":
            if not self._is_capability_supported(caps, "supports_tool_restrictions"):
                raise SideSessionError(
                    ErrorCode.CAPABILITY_UNAVAILABLE,
                    "Driver does not support tool restrictions required for read_only session",
                    {"task_kind": task_kind},
                )
        elif task_kind == "write_code":
            if getattr(self.driver, "supports_workspace_write_scope", None) is False:
                raise SideSessionError(
                    ErrorCode.CAPABILITY_UNAVAILABLE,
                    "Driver does not support workspace write scope isolation",
                    {"task_kind": task_kind},
                )

        operation_id = str(operation_id_override or self._new_uuid())
        history_quality: str | None = None
        snapshot_hash: str | None = None
        history_summary: str | None = None

        if context_requested == "fresh":
            context_applied = "fresh"
        else:
            # context_requested == "fork"
            if context_strategy is None:
                if allow_degraded_context:
                    context_strategy = "summary_copy"
                else:
                    raise SideSessionError(
                        ErrorCode.CONTEXT_DOWNGRADE_REQUIRES_ACCEPTANCE,
                        "fork context requires explicit context_strategy='summary_copy' or downgrade acceptance",
                        {"recommended_strategy": "summary_copy"},
                    )
            if context_strategy == "native_fork":
                if workspace_mode == "branch":
                    raise SideSessionError(
                        ErrorCode.UNSUPPORTED_CONTEXT_WORKSPACE,
                        "native_fork cannot be combined with branch worktree workspace",
                    )
                if not self._is_capability_supported(caps, "supports_live_fork", require_integration_verified=True):
                    raise SideSessionError(
                        ErrorCode.UNSUPPORTED_LIVE_FORK,
                        "native_fork is not supported from a live parent turn",
                    )
                if not self._is_capability_supported(caps, "supports_native_fork", require_integration_verified=True):
                    raise SideSessionError(
                        ErrorCode.CAPABILITY_UNAVAILABLE,
                        "native_fork capability is not enabled",
                    )
                context_applied = "native_fork"
            else:
                # summary_copy
                prelim_brief = self._build_brief_markdown(
                    title=title,
                    prompt=prompt,
                    context_mode="summary_copy",
                    background_sections=background_sections,
                    background_raw=background_raw,
                    history_summary=None,
                    remaining_plan=None,
                    assignment_view={"node_id": "pending", "run_id": "pending", "turn_seq": 1, "worker_turn_id": "pending"},
                )
                prelim_brief_hash = sha256_hex(prelim_brief)

                existing_snap_row = self.store.conn.execute(
                    """
                    SELECT cs.* FROM context_snapshots cs
                    WHERE cs.operation_id = ?
                    ORDER BY cs.created_at DESC LIMIT 1
                    """,
                    (operation_id,),
                ).fetchone()
                if existing_snap_row is not None:
                    snapshot_hash = str(existing_snap_row["snapshot_hash"])
                    history_quality = str(existing_snap_row["history_quality"])
                    anchor_obj = json.loads(existing_snap_row["anchor_json"] or "{}")
                    manifest_ref = existing_snap_row["projection_ref"]
                    history_summary = f"Summary from snapshot {snapshot_hash}"
                    prelim_brief_hash = str(existing_snap_row["brief_hash"])
                else:
                    proj, _snap_id, manifest_ref = self._prepare_fork_context_snapshot(
                        parent_node=parent_node,
                        caller=ctx,
                        request_id=req.request_id,
                        operation_id=operation_id,
                        kind="start_session",
                        title=title,
                        prompt=prompt,
                        remaining_plan=None,
                        task_id=None,
                        task_revision=None,
                        requested_group_id=dispatch_group_id,
                        brief_hash=prelim_brief_hash,
                    )
                    history_quality = proj.history_quality
                    snapshot_hash = proj.snapshot_hash
                    history_summary = proj.summary
                    anchor_obj = proj.anchor

                if history_quality == "brief_only":
                    with self.store.transaction("IMMEDIATE") as txn:
                        acc = self._verify_existing_context_acceptance_in_conn(
                            txn.conn,
                            operation_id=operation_id,
                            snapshot_hash=snapshot_hash,
                            expected_brief_hash=prelim_brief_hash,
                            expected_task_revision=None,
                            anchor=anchor_obj,
                        )
                        if acc is None:
                            if proposal_id_for_start is not None:
                                txn.execute(
                                    "UPDATE proposals SET state = 'claiming', operation_id = ?, updated_at = ? WHERE proposal_id = ?",
                                    (operation_id, self._now_iso(), proposal_id_for_start),
                                )
                            await_res = StartResult(
                                request_id=req.request_id,
                                proposal_id=proposal_id_for_start,
                                node_id=None,
                                runtime_session_id=None,
                                operation_id=operation_id,
                                status="awaiting_context_approval",
                                context_requested="fork",
                                context_applied="brief_only",
                                history_quality="brief_only",
                                snapshot_hash=snapshot_hash,
                                workspace_mode=workspace_mode,
                                host_link_verified=False,
                                revision=txn.revision,
                            ).to_dict()
                            await_res["status"] = _AliasStr(
                                "awaiting_context_approval",
                                "awaiting_context_acceptance",
                                "CONTEXT_QUALITY_APPROVAL_REQUIRED",
                            )
                            await_res["ok"] = True
                            await_res["code"] = ErrorCode.CONTEXT_QUALITY_APPROVAL_REQUIRED.value
                            await_res["brief_hash"] = prelim_brief_hash
                            await_res["manifest_ref"] = manifest_ref
                            self._record_idempotent_request(
                                txn.conn,
                                parent_id,
                                "start_session",
                                req.request_id,
                                req.normalized_hash,
                                await_res,
                                operation_id=operation_id,
                            )
                            return await_res

                        txn.execute(
                            "UPDATE context_acceptances SET state = 'used' WHERE acceptance_id = ?",
                            (acc["acceptance_id"],),
                        )
                        txn.execute(
                            "UPDATE context_snapshots SET state = 'authorized' WHERE operation_id = ? AND snapshot_hash = ?",
                            (operation_id, snapshot_hash),
                        )
                    context_applied = "brief_only"
                else:
                    if not self._driver_validate_anchor(anchor_obj):
                        raise SideSessionError(
                            ErrorCode.SOURCE_SNAPSHOT_STALE,
                            "Source anchor is no longer valid on effective chain",
                            {"operation_id": operation_id, "snapshot_hash": snapshot_hash},
                        )
                    context_applied = "summary_copy"

        return self._execute_session_admission_and_start(
            caller=ctx,
            parent_node=parent_node,
            request_id=req.request_id,
            normalized_hash=req.normalized_hash,
            tool_name="start_session",
            operation_id=operation_id,
            title=title,
            prompt=prompt,
            task_kind=task_kind,
            workspace_mode=workspace_mode,
            context_requested=context_requested,
            context_applied=context_applied,
            history_quality=history_quality,
            snapshot_hash=snapshot_hash,
            history_summary=history_summary,
            background_raw=background_raw,
            background_sections=background_sections,
            requested_name=requested_name,
            dispatch_group_id=dispatch_group_id,
            batch_id=batch_id,
            proposal_id=proposal_id_for_start,
            dirty_policy=dirty_policy,
            approved_path_manifest=approved_path_manifest,
        )

    def _assert_no_active_worktree_job(self, conn: sqlite3.Connection, node_id: str) -> None:
        try:
            job_row = conn.execute(
                """
                SELECT job_id, kind, state FROM worktree_jobs
                WHERE node_id = ? AND state IN ('queued', 'running', 'prepared')
                LIMIT 1
                """,
                (node_id,),
            ).fetchone()
        except sqlite3.OperationalError:
            job_row = None
        if job_row is not None:
            raise SideSessionError(
                ErrorCode.SESSION_BUSY,
                "worktree merge/cleanup job in progress",
                {
                    "node_id": node_id,
                    "job_id": job_row["job_id"],
                    "job_kind": job_row["kind"],
                    "job_state": job_row["state"],
                },
            )

    def _obtain_or_verify_approval_evidence(
        self,
        *,
        purpose: str,
        evidence: Any,
        action_dict: dict[str, Any],
        conn: sqlite3.Connection | None = None,
        caller: CallerContext | None = None,
    ) -> ApprovalEvidence:
        eff_conn = conn if conn is not None else self.store.conn
        if isinstance(evidence, ApprovalEvidence):
            if self._is_expired(evidence.expires_at):
                raise SideSessionError(ErrorCode.EXPIRED, "ApprovalEvidence has expired")
            cons_row = eff_conn.execute(
                "SELECT * FROM approval_consumptions WHERE consumption_id = ?",
                (evidence.approval_id,),
            ).fetchone()
            if cons_row is None or str(cons_row["purpose"]) != purpose:
                raise _err(
                    ErrorCode.USER_APPROVAL_UNAVAILABLE,
                    "Forged or unconsumed ApprovalEvidence rejected; approval must be recorded in approval_consumptions",
                    {"purpose": purpose, "approval_id": evidence.approval_id},
                    aliases=(ErrorCode.HUMAN_ACTION_REQUIRED,),
                )
            if purpose == "proposal":
                exp_tid = str(action_dict.get("proposal_id") or "")
                exp_thash = str(action_dict.get("task_hash") or "")
            elif purpose == "context_quality":
                exp_tid = str(action_dict.get("operation_id") or "")
                exp_thash = str(action_dict.get("snapshot_hash") or "")
            elif purpose == "wait_response":
                exp_tid = str(action_dict.get("wait_id") or action_dict.get("target_id") or "").strip()
                w_nonce = str(action_dict.get("wait_nonce") or action_dict.get("nonce") or "").strip()
                resp_h = str(action_dict.get("response_hash") or "").strip()
                if not resp_h and "response" in action_dict:
                    resp_h = canonical_json_sha256(action_dict["response"])
                exp_thash = sha256_hex(f"{w_nonce}:{resp_h}") if w_nonce else resp_h
            else:
                exp_tid = str(action_dict.get("target_id") or action_dict.get("node_id") or "")
                exp_thash = str(action_dict.get("preview_hash") or action_dict.get("target_hash") or "")
            if (
                (
                    purpose == "wait_response"
                    and (str(cons_row["target_id"]) != exp_tid or str(cons_row["target_hash"]) != exp_thash)
                )
                or (exp_tid and str(cons_row["target_id"]) != exp_tid)
                or (exp_thash and str(cons_row["target_hash"]) != exp_thash)
            ):
                raise _err(
                    ErrorCode.APPROVAL_REPLAYED,
                    "ApprovalEvidence target_id or target_hash does not match approval_consumptions record",
                    {"purpose": purpose, "approval_id": evidence.approval_id},
                    aliases=(ErrorCode.USER_APPROVAL_UNAVAILABLE,),
                )
            return evidence
        if isinstance(evidence, Mapping):
            merged = {**action_dict, **dict(evidence), "purpose": purpose}
        else:
            merged = {**action_dict, "purpose": purpose}
        if not merged.get("real_input_id") and not merged.get("input_id") and not merged.get("interaction_token"):
            raise _err(
                ErrorCode.HUMAN_ACTION_REQUIRED,
                "Trusted human approval requires a registered real_input_id or interaction_token",
                {"purpose": purpose},
                aliases=(ErrorCode.USER_APPROVAL_UNAVAILABLE,),
            )

        adapter = self.host_adapter
        if adapter is None or not hasattr(adapter, "verify_approval") or not callable(adapter.verify_approval):
            raise _err(
                ErrorCode.USER_APPROVAL_UNAVAILABLE,
                "Host adapter verify_approval is unavailable; cannot mint ApprovalEvidence from model arguments",
                {"purpose": purpose},
                aliases=(ErrorCode.HUMAN_ACTION_REQUIRED,),
            )
        if conn is not None and hasattr(adapter, "verify_and_consume_approval_in_txn"):
            res = adapter.verify_and_consume_approval_in_txn(conn, merged, caller=caller)
        else:
            res = adapter.verify_approval(merged)
        if isinstance(res, ApprovalEvidence):
            return res
        if isinstance(res, Mapping):
            return ApprovalEvidence(**{k: v for k, v in res.items() if hasattr(ApprovalEvidence, k)})
        raise _err(
            ErrorCode.USER_APPROVAL_UNAVAILABLE,
            "verify_approval did not return valid ApprovalEvidence",
            {"purpose": purpose},
            aliases=(ErrorCode.HUMAN_ACTION_REQUIRED,),
        )

    def approve_proposal(
        self,
        caller_or_proposal_id: Any,
        args_or_evidence: Any = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Verify human approval for a proposal; transitions `offer` -> `awaiting_brief` and `own_initiative` -> `approved` (and claims if applicable)."""
        caller_ctx: CallerContext | None = None
        raw_args: dict[str, Any] = {}
        evidence_arg: Any = None

        if isinstance(caller_or_proposal_id, CallerContext) or (
            isinstance(caller_or_proposal_id, Mapping)
            and ("runtime_sid" in caller_or_proposal_id or "runtime_session_id" in caller_or_proposal_id)
        ):
            caller_ctx = self._coerce_caller(caller_or_proposal_id)
            if isinstance(args_or_evidence, ApprovalEvidence):
                evidence_arg = args_or_evidence
                raw_args = dict(kwargs)
            else:
                raw_args = self._merge_args(args_or_evidence, kwargs)
                evidence_arg = raw_args.pop("evidence", None)
            proposal_ref = str(raw_args.get("proposal_id") or "").strip()
            auto_claim_default = True
        else:
            proposal_ref = str(caller_or_proposal_id or kwargs.get("proposal_id") or "").strip()
            if isinstance(args_or_evidence, ApprovalEvidence):
                evidence_arg = args_or_evidence
                raw_args = dict(kwargs)
            elif isinstance(args_or_evidence, Mapping) and "purpose" in args_or_evidence and "real_input_id" in args_or_evidence:
                evidence_arg = args_or_evidence
                raw_args = dict(kwargs)
            else:
                raw_args = self._merge_args(args_or_evidence, kwargs)
                evidence_arg = raw_args.pop("evidence", None)
            if "caller" in raw_args:
                caller_ctx = self._coerce_caller(raw_args.pop("caller"))
            auto_claim_default = False

        if not proposal_ref:
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "proposal_id is required")

        prop_row = self._resolve_proposal_row(self.store.conn, proposal_ref)
        if prop_row is None:
            raise SideSessionError(ErrorCode.NOT_FOUND, f"Proposal not found: {proposal_ref}")

        p_id = str(prop_row["proposal_id"])
        parent_id = str(prop_row["parent_node_id"])
        if caller_ctx is not None:
            caller_node = self.ensure_caller_node(caller_ctx)
            if str(caller_node["node_id"]) != parent_id:
                raise _err(
                    "PERMISSION_DENIED",
                    "Caller is not the parent of this proposal",
                    {"proposal_id": p_id},
                    aliases=(ErrorCode.FORBIDDEN, ErrorCode.NOT_FOUND_OR_FORBIDDEN),
                )
        else:
            p_node_row = self.store.conn.execute("SELECT * FROM nodes WHERE node_id = ?", (parent_id,)).fetchone()
            caller_ctx = CallerContext(
                runtime_sid=str(p_node_row["runtime_session_id"] or f"sid:{parent_id}"),
                workspace_path=p_node_row["canonical_workspace"],
                node_id=parent_id,
            )

        p_state = str(prop_row["state"])
        if p_state in ("dismissed", "cleared"):
            raise SideSessionError(ErrorCode.ALREADY_DISMISSED, "Proposal has already been dismissed", {"proposal_id": p_id})
        if p_state == "started":
            raise SideSessionError(ErrorCode.ALREADY_STARTED, "Proposal has already been started", {"proposal_id": p_id})
        if p_state == "expired" or self._is_expired(prop_row["expires_at"]):
            with self.store.transaction("IMMEDIATE") as txn:
                txn.execute("UPDATE proposals SET state = 'expired', updated_at = ? WHERE proposal_id = ?", (self._now_iso(), p_id))
            raise _err(ErrorCode.PROPOSAL_EXPIRED, "Proposal has expired", {"proposal_id": p_id}, aliases=(ErrorCode.EXPIRED,))

        action_payload = {
            **raw_args,
            "proposal_id": p_id,
            "parent_node_id": parent_id,
            "task_hash": prop_row["task_hash"],
            "runtime_sid": caller_ctx.runtime_sid,
        }
        p_kind = str(prop_row["kind"])
        new_state = "awaiting_brief" if p_kind == "offer" else "approved"
        should_claim = bool(raw_args.get("auto_claim", raw_args.get("claim", auto_claim_default)))
        now = self._now_iso()

        with self.store.transaction("IMMEDIATE") as txn:
            cur_p_pre = txn.execute("SELECT * FROM proposals WHERE proposal_id = ?", (p_id,)).fetchone()
            if cur_p_pre is None:
                raise SideSessionError(ErrorCode.NOT_FOUND, f"Proposal not found: {p_id}")
            cur_st_pre = str(cur_p_pre["state"])
            if cur_st_pre in ("dismissed", "cleared"):
                raise SideSessionError(ErrorCode.ALREADY_DISMISSED, "Proposal has already been dismissed", {"proposal_id": p_id})
            if cur_st_pre in ("started", "claiming"):
                raise SideSessionError(ErrorCode.ALREADY_STARTED, "Proposal has already been started", {"proposal_id": p_id})
            if cur_st_pre == "expired" or self._is_expired(cur_p_pre["expires_at"]):
                txn.execute("UPDATE proposals SET state = 'expired', updated_at = ? WHERE proposal_id = ?", (now, p_id))
                raise _err(ErrorCode.PROPOSAL_EXPIRED, "Proposal has expired", {"proposal_id": p_id}, aliases=(ErrorCode.EXPIRED,))
            if cur_st_pre != "waiting_user":
                raise SideSessionError(
                    ErrorCode.VALIDATION_ERROR,
                    f"Proposal is not in waiting_user state (got {cur_st_pre!r})",
                    {"proposal_id": p_id, "state": cur_st_pre},
                )

            evidence = self._obtain_or_verify_approval_evidence(
                purpose="proposal",
                evidence=evidence_arg,
                action_dict=action_payload,
                conn=txn.conn,
                caller=caller_ctx,
            )
            if evidence.task_hash and evidence.task_hash != str(prop_row["task_hash"]):
                raise SideSessionError(
                    ErrorCode.VALIDATION_ERROR,
                    "ApprovalEvidence task_hash does not match proposal task_hash",
                    {"proposal_id": p_id},
                )

            cas = txn.execute(
                """
                UPDATE proposals
                SET state = ?,
                    approval_source = ?,
                    approval_id = ?,
                    approved_task_hash = ?,
                    updated_at = ?
                WHERE proposal_id = ?
                  AND parent_node_id = ?
                  AND state = 'waiting_user'
                  AND task_hash = ?
                  AND expires_at > ?
                """,
                (
                    new_state,
                    evidence.verifier,
                    evidence.approval_id,
                    evidence.task_hash or prop_row["task_hash"],
                    now,
                    p_id,
                    parent_id,
                    prop_row["task_hash"],
                    now,
                ),
            )
            if cas.rowcount == 0:
                raise SideSessionError(
                    ErrorCode.VALIDATION_ERROR,
                    "Proposal CAS update failed due to concurrent state or task_hash modification",
                    {"proposal_id": p_id},
                )
            if new_state == "approved" and not should_claim:
                claim_job_req_id = _try_parse_uuid(raw_args.get("request_id")) or str(
                    uuid.uuid5(uuid.NAMESPACE_OID, f"proposal-claim:{p_id}")
                )
                txn.execute(
                    """
                    INSERT OR IGNORE INTO proposal_claim_jobs (
                        proposal_id, request_id, state, updated_at
                    ) VALUES (?, ?, 'queued', ?)
                    """,
                    (p_id, claim_job_req_id, now),
                )
            rev = txn.revision

        if p_kind == "offer":
            return {
                "ok": True,
                "proposal_id": p_id,
                "proposal_short_id": _proposal_short_id(p_id),
                "kind": "offer",
                "state": "awaiting_brief",
                "status": "awaiting_brief",
                "approval_id": evidence.approval_id,
                "revision": rev,
            }

        should_claim = bool(raw_args.get("auto_claim", raw_args.get("claim", auto_claim_default)))
        if should_claim:
            active_slots = self._active_parent_slots(self.store.conn, parent_id)
            if len(active_slots) < MAX_SLOTS_PER_PARENT:
                claim_req_id = _try_parse_uuid(raw_args.get("request_id")) or self._new_uuid()
                claim_res = self.start_session(
                    caller_ctx,
                    {"proposal_id": p_id, "request_id": claim_req_id},
                )
                if claim_res.get("node_id"):
                    with self.store.transaction("IMMEDIATE") as txn:
                        saved_task = json.loads(prop_row["canonical_task"] or "{}")
                        saved_task["_auto_claimed_by_approve"] = True
                        txn.execute(
                            "UPDATE proposals SET canonical_task = ? WHERE proposal_id = ?",
                            (canonical_json(saved_task), p_id),
                        )
                claim_res["state"] = "approved"
                claim_res["approval_id"] = evidence.approval_id
                return claim_res

        return {
            "ok": True,
            "proposal_id": p_id,
            "proposal_short_id": _proposal_short_id(p_id),
            "kind": p_kind,
            "state": "approved",
            "status": "approved",
            "approval_id": evidence.approval_id,
            "revision": rev,
        }

    def reject_proposal(
        self,
        caller_or_proposal_id: Any,
        args_or_evidence: Any = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Reject / dismiss a pending proposal."""
        if isinstance(caller_or_proposal_id, CallerContext) or (
            isinstance(caller_or_proposal_id, Mapping)
            and ("runtime_sid" in caller_or_proposal_id or "runtime_session_id" in caller_or_proposal_id)
        ):
            raw_args = self._merge_args(args_or_evidence, kwargs)
            if "request_id" not in raw_args:
                raw_args["request_id"] = self._new_uuid()
            return self.dismiss_task(caller_or_proposal_id, raw_args)

        proposal_ref = str(caller_or_proposal_id or kwargs.get("proposal_id") or "").strip()
        prop_row = self._resolve_proposal_row(self.store.conn, proposal_ref)
        if prop_row is None:
            raise SideSessionError(ErrorCode.NOT_FOUND, f"Proposal not found: {proposal_ref}")
        parent_id = str(prop_row["parent_node_id"])
        p_node = self.store.conn.execute("SELECT * FROM nodes WHERE node_id = ?", (parent_id,)).fetchone()
        caller_ctx = CallerContext(
            runtime_sid=str(p_node["runtime_session_id"] or f"sid:{parent_id}"),
            node_id=parent_id,
        )
        return self.dismiss_task(
            caller_ctx,
            {"request_id": self._new_uuid(), "proposal_id": prop_row["proposal_id"]},
        )

    def approve_context(
        self,
        caller_or_operation_id: Any,
        args_or_snapshot_hash: Any = None,
        evidence: Any = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Verify human approval for a `brief_only` degraded context snapshot (R08) and record `context_acceptances`."""
        caller_ctx: CallerContext | None = None
        raw_args: dict[str, Any] = {}
        evidence_arg: Any = evidence

        if isinstance(caller_or_operation_id, CallerContext) or (
            isinstance(caller_or_operation_id, Mapping)
            and ("runtime_sid" in caller_or_operation_id or "runtime_session_id" in caller_or_operation_id)
        ):
            caller_ctx = self._coerce_caller(caller_or_operation_id)
            raw_args = self._merge_args(args_or_snapshot_hash, kwargs)
            if evidence_arg is None:
                evidence_arg = raw_args.pop("evidence", None)
            operation_id = validate_uuid(raw_args.get("operation_id"), "operation_id")
            snapshot_hash = str(raw_args.get("snapshot_hash") or "").strip()
        else:
            operation_id = validate_uuid(caller_or_operation_id, "operation_id")
            if isinstance(args_or_snapshot_hash, str):
                snapshot_hash = args_or_snapshot_hash.strip()
                raw_args = dict(kwargs)
            else:
                raw_args = self._merge_args(args_or_snapshot_hash, kwargs)
                snapshot_hash = str(raw_args.get("snapshot_hash") or "").strip()
            if evidence_arg is None:
                evidence_arg = raw_args.pop("evidence", None)
            if "caller" in raw_args:
                caller_ctx = self._coerce_caller(raw_args.pop("caller"))

        if not snapshot_hash:
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "snapshot_hash is required for approve_context")

        op_row = self.store.conn.execute(
            "SELECT * FROM operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if op_row is None:
            raise SideSessionError(ErrorCode.NOT_FOUND, f"Operation not found: {operation_id}")

        actor_id = str(op_row["actor_node_id"])
        if caller_ctx is not None:
            caller_node = self.ensure_caller_node(caller_ctx)
            if str(caller_node["node_id"]) != actor_id:
                raise _err(
                    "PERMISSION_DENIED",
                    "Caller is not the owner of this operation",
                    {"operation_id": operation_id},
                    aliases=(ErrorCode.FORBIDDEN, ErrorCode.NOT_FOUND_OR_FORBIDDEN),
                )

        snap_row = self.store.conn.execute(
            "SELECT * FROM context_snapshots WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if snap_row is None:
            raise SideSessionError(ErrorCode.NOT_FOUND, f"Context snapshot not found for operation {operation_id}")

        if str(snap_row["snapshot_hash"]) != snapshot_hash:
            raise SideSessionError(
                ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                "snapshot_hash does not match the operation's candidate context snapshot",
                {
                    "operation_id": operation_id,
                    "expected_snapshot_hash": snap_row["snapshot_hash"],
                    "provided_snapshot_hash": snapshot_hash,
                },
            )

        if self._is_expired(snap_row["expires_at"]) or snap_row["state"] in ("stale", "expired", "rejected"):
            raise SideSessionError(
                ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                "Candidate context snapshot has expired or is stale",
                {"operation_id": operation_id, "snapshot_hash": snapshot_hash},
            )

        req_quality = str(raw_args.get("history_quality") or snap_row["history_quality"])
        if req_quality != str(snap_row["history_quality"]):
            raise SideSessionError(
                ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                "Approved history_quality does not match candidate snapshot quality",
                {"expected_quality": snap_row["history_quality"], "provided_quality": req_quality},
            )

        req_brief_hash = str(raw_args.get("brief_hash") or snap_row["brief_hash"])
        if req_brief_hash != str(snap_row["brief_hash"]):
            raise SideSessionError(
                ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                "Approved brief_hash does not match candidate snapshot brief_hash",
                {"expected_brief_hash": snap_row["brief_hash"], "provided_brief_hash": req_brief_hash},
            )

        snap_task_rev = snap_row["task_revision"]
        if "task_revision" in raw_args and raw_args["task_revision"] != snap_task_rev:
            raise SideSessionError(
                ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                "Approved task_revision does not match candidate snapshot task_revision",
                {"expected_task_revision": snap_task_rev, "provided_task_revision": raw_args["task_revision"]},
            )

        if op_row["task_id"]:
            t_row = self.store.conn.execute(
                "SELECT task_revision, state, owner_node_id FROM tasks WHERE task_id = ?",
                (op_row["task_id"],),
            ).fetchone()
            if t_row is None or int(t_row["task_revision"]) != int(snap_task_rev or 0):
                raise SideSessionError(
                    ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                    "Task revision advanced while awaiting context approval",
                    {"operation_id": operation_id, "task_id": op_row["task_id"]},
                )

        anchor_obj = json.loads(snap_row["anchor_json"] or "{}")
        if not self._driver_validate_anchor(
            anchor_obj,
            allow_unavailable=(req_quality == "brief_only"),
        ):
            raise SideSessionError(
                ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                "Source anchor became stale while awaiting context approval",
                {"operation_id": operation_id},
            )

        action_payload = {
            **raw_args,
            "operation_id": operation_id,
            "snapshot_hash": snapshot_hash,
            "history_quality": req_quality,
            "brief_hash": req_brief_hash,
            "task_revision": snap_task_rev,
            "parent_node_id": actor_id,
            "runtime_sid": caller_ctx.runtime_sid if caller_ctx is not None else "",
        }

        acceptance_id = self._new_uuid()
        now = self._now_iso()
        with self.store.transaction("IMMEDIATE") as txn:
            cur_op = txn.execute(
                "SELECT * FROM operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if cur_op is None:
                raise SideSessionError(ErrorCode.NOT_FOUND, f"Operation not found: {operation_id}")
            cur_op_stage = str(cur_op["stage"] or "")
            if cur_op_stage in (
                "ready_for_admission",
                "reserved",
                "worktree_created",
                "session_created",
                "brief_accepted",
                "running",
                "finished",
            ):
                raise _err(
                    ErrorCode.ALREADY_STARTED if cur_op_stage != "ready_for_admission" else ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                    f"Operation {operation_id} is no longer awaiting context acceptance (stage={cur_op_stage})",
                    {"operation_id": operation_id, "stage": cur_op_stage},
                    aliases=(
                        ErrorCode.ALREADY_STARTED,
                        ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                        ErrorCode.REVISION_CONFLICT,
                        ErrorCode.VALIDATION_ERROR,
                    ),
                )
            if cur_op_stage != "awaiting_context_acceptance":
                raise _err(
                    ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                    f"Operation {operation_id} is not awaiting context acceptance (stage={cur_op_stage})",
                    {"operation_id": operation_id, "stage": cur_op_stage},
                    aliases=(ErrorCode.VALIDATION_ERROR, ErrorCode.REVISION_CONFLICT),
                )
            cur_snap = txn.execute(
                "SELECT * FROM context_snapshots WHERE snapshot_id = ?",
                (snap_row["snapshot_id"],),
            ).fetchone()
            if cur_snap is None or self._is_expired(cur_snap["expires_at"]) or cur_snap["state"] in ("stale", "expired", "rejected"):
                raise SideSessionError(
                    ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                    "Candidate context snapshot became stale or expired before approval",
                    {"operation_id": operation_id, "snapshot_hash": snapshot_hash},
                )
            if cur_op["task_id"]:
                cur_t = txn.execute(
                    "SELECT task_revision FROM tasks WHERE task_id = ?",
                    (cur_op["task_id"],),
                ).fetchone()
                if cur_t is None or int(cur_t["task_revision"]) != int(snap_task_rev or 0):
                    raise SideSessionError(
                        ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                        "Task revision advanced concurrently while awaiting context approval",
                        {"operation_id": operation_id, "task_id": cur_op["task_id"]},
                    )

            ev = self._obtain_or_verify_approval_evidence(
                purpose="context_quality",
                evidence=evidence_arg,
                action_dict=action_payload,
                conn=txn.conn,
                caller=caller_ctx,
            )
            if (
                ev.operation_id != operation_id
                or ev.snapshot_hash != snapshot_hash
                or ev.history_quality != req_quality
                or ev.brief_hash != req_brief_hash
                or ev.task_revision != snap_task_rev
            ):
                raise SideSessionError(
                    ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                    "ApprovalEvidence fields do not match candidate context snapshot",
                    {"operation_id": operation_id, "snapshot_hash": snapshot_hash},
                )

            txn.execute(
                """
                INSERT INTO context_acceptances (
                    acceptance_id, operation_id, snapshot_hash, history_quality,
                    brief_hash, task_hash, task_revision, approved_by, input_id,
                    approval_evidence_ref, expires_at, state, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
                ON CONFLICT(operation_id, snapshot_hash, history_quality) DO UPDATE SET
                    brief_hash = excluded.brief_hash,
                    task_revision = excluded.task_revision,
                    approved_by = excluded.approved_by,
                    input_id = excluded.input_id,
                    approval_evidence_ref = excluded.approval_evidence_ref,
                    expires_at = excluded.expires_at,
                    state = 'active'
                """,
                (
                    acceptance_id,
                    operation_id,
                    snapshot_hash,
                    req_quality,
                    req_brief_hash,
                    ev.task_hash,
                    snap_task_rev,
                    actor_id,
                    ev.real_input_id,
                    ev.evidence_ref,
                    ev.expires_at,
                    now,
                ),
            )
            txn.execute(
                "UPDATE context_snapshots SET state = 'authorized' WHERE snapshot_id = ?",
                (snap_row["snapshot_id"],),
            )
            cas_op = txn.execute(
                """
                UPDATE operations
                SET context_acceptance_id = ?,
                    stage = 'ready_for_admission',
                    revision = revision + 1,
                    updated_at = ?
                WHERE operation_id = ? AND stage = 'awaiting_context_acceptance'
                """,
                (acceptance_id, now, operation_id),
            )
            if cas_op.rowcount == 0:
                raise _err(
                    ErrorCode.CONTEXT_ACCEPTANCE_STALE,
                    f"Operation {operation_id} stage changed concurrently during context approval",
                    {"operation_id": operation_id},
                    aliases=(ErrorCode.VALIDATION_ERROR, ErrorCode.REVISION_CONFLICT),
                )
            rev = txn.revision

        self._notify_supervisor(
            {
                "event": "context_approved",
                "operation_id": operation_id,
                "snapshot_hash": snapshot_hash,
            }
        )
        return {
            "ok": True,
            "acceptance_id": acceptance_id,
            "operation_id": operation_id,
            "snapshot_hash": snapshot_hash,
            "history_quality": req_quality,
            "brief_hash": req_brief_hash,
            "task_revision": snap_task_rev,
            "stage": "ready_for_admission",
            "status": "ready_for_admission",
            "revision": rev,
        }

    def dismiss_task(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Withdraw an unstarted proposal (`waiting_user`, `awaiting_brief`, or `approved`)."""
        raw_args = self._merge_args(args, kwargs)
        pre_args, raw_proposal_ref = self._preprocess_proposal_id_arg(raw_args)
        req = normalize_request("dismiss_task", pre_args)
        caller_node = self.ensure_caller_node(caller)
        caller_id = str(caller_node["node_id"])

        with self.store.transaction("IMMEDIATE") as txn:
            cached = self._check_idempotent_request(
                txn.conn,
                caller_id,
                "dismiss_task",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

            lookup_ref = raw_proposal_ref or req["proposal_id"]
            prop_row = self._resolve_proposal_row(txn.conn, lookup_ref)
            if prop_row is None:
                raise SideSessionError(ErrorCode.NOT_FOUND, f"Proposal not found: {lookup_ref}")

            p_id = str(prop_row["proposal_id"])
            if str(prop_row["parent_node_id"]) != caller_id:
                raise _err(
                    "PERMISSION_DENIED",
                    "Caller is not authorized to dismiss this proposal",
                    {"proposal_id": p_id},
                    aliases=(ErrorCode.FORBIDDEN, ErrorCode.NOT_FOUND_OR_FORBIDDEN),
                )

            p_state = str(prop_row["state"])
            if p_state in ("started", "claiming", "reconciliation"):
                raise SideSessionError(
                    ErrorCode.ALREADY_STARTED,
                    "Cannot dismiss a proposal that has already started",
                    {"proposal_id": p_id, "state": p_state},
                )
            if p_state in ("dismissed", "cleared"):
                raise SideSessionError(
                    ErrorCode.ALREADY_DISMISSED,
                    "Proposal is already dismissed",
                    {"proposal_id": p_id},
                )
            if p_state == "expired" or self._is_expired(prop_row["expires_at"]):
                txn.execute(
                    "UPDATE proposals SET state = 'expired', updated_at = ? WHERE proposal_id = ?",
                    (self._now_iso(), p_id),
                )
                raise _err(
                    ErrorCode.PROPOSAL_EXPIRED,
                    "Proposal has already expired",
                    {"proposal_id": p_id},
                    aliases=(ErrorCode.EXPIRED,),
                )

            txn.execute(
                "UPDATE proposals SET state = 'dismissed', updated_at = ? WHERE proposal_id = ?",
                (self._now_iso(), p_id),
            )
            res = {
                "ok": True,
                "request_id": req.request_id,
                "proposal_id": p_id,
                "proposal_short_id": _proposal_short_id(p_id),
                "state": "dismissed",
                "status": "dismissed",
                "revision": txn.revision,
            }
            self._record_idempotent_request(
                txn.conn,
                caller_id,
                "dismiss_task",
                req.request_id,
                req.normalized_hash,
                res,
            )
            return res

    def get_operation(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("get_operation", raw_args)
        caller_node = self.ensure_caller_node(caller)
        op_id = req["operation_id"]

        op_row = self.store.conn.execute(
            "SELECT * FROM operations WHERE operation_id = ?",
            (op_id,),
        ).fetchone()
        if op_row is None:
            raise SideSessionError(ErrorCode.NOT_FOUND_OR_FORBIDDEN, f"Operation not found: {op_id}")

        actor_id = str(op_row["actor_node_id"])
        if not self._is_ancestor_or_self(self.store.conn, str(caller_node["node_id"]), actor_id):
            raise _err(
                ErrorCode.NOT_FOUND_OR_FORBIDDEN,
                "Caller is not authorized to read this operation",
                {"operation_id": op_id},
                aliases=("PERMISSION_DENIED", ErrorCode.FORBIDDEN),
            )

        snap_dict: dict[str, Any] | None = None
        if op_row["context_snapshot_id"]:
            s_row = self.store.conn.execute(
                "SELECT * FROM context_snapshots WHERE snapshot_id = ?",
                (op_row["context_snapshot_id"],),
            ).fetchone()
            if s_row is not None:
                snap_dict = dict(s_row)

        op_dict = dict(op_row)
        op_dict["ok"] = True
        op_dict["status"] = op_row["stage"]
        op_dict["context_candidate"] = snap_dict
        op_dict["store_revision"] = self.store.get_revision()
        return op_dict

    # ------------------------------------------------------------------
    # 3. Topology Queries & Session Lifecycle (Section 6.2, 6.4 & Prompt #3)
    # ------------------------------------------------------------------

    def _enrich_node_row(self, conn: Any, row: Mapping[str, Any]) -> dict[str, Any]:
        row = dict(row)
        node_id = str(row["node_id"])
        latest_turn = conn.execute(
            "SELECT * FROM turns WHERE node_id = ? ORDER BY turn_seq DESC LIMIT 1",
            (node_id,),
        ).fetchone()
        wt_row = conn.execute(
            "SELECT * FROM worktrees WHERE node_id = ? ORDER BY created_at DESC LIMIT 1",
            (node_id,),
        ).fetchone()
        pending_events = conn.execute(
            "SELECT COUNT(*) AS cnt FROM outbox_events WHERE parent_node_id = ? AND state IN ('pending', 'presented')",
            (node_id,),
        ).fetchone()["cnt"]

        exec_state = str(latest_turn["execution_state"]) if latest_turn is not None else "idle"
        rep_state = str(latest_turn["report_state"]) if latest_turn is not None else "none"
        branch = str(wt_row["branch"]) if (wt_row is not None and wt_row["branch"]) else None
        wt_path = (
            str(wt_row["canonical_worktree_path"])
            if wt_row is not None
            else (str(row["canonical_workspace"]) if row.get("canonical_workspace") else None)
        )

        return {
            "node_id": node_id,
            "runtime_session_id": row["runtime_session_id"],
            "parent_node_id": row["parent_node_id"],
            "root_node_id": row["root_node_id"],
            "name": row["name"],
            "title": row["title"],
            "status": row["node_status"],
            "node_status": row["node_status"],
            "pause_requested": bool(row["pause_requested"]),
            "execution_state": exec_state,
            "report_state": rep_state,
            "task_kind": row["task_kind"],
            "context_requested": row["context_requested"],
            "context_applied": row["context_applied"],
            "workspace_mode": row["workspace_mode"],
            "branch": branch,
            "worktree_path": wt_path,
            "canonical_workspace": row["canonical_workspace"],
            "repo_root": row["repo_root"],
            "base_commit": row["base_commit"],
            "host_link_verified": bool(row["host_link_verified"]),
            "recovery_status": row["recovery_status"],
            "last_turn_report": row["last_turn_report"] or "",
            "last_turn_seq": int(row["last_turn_seq"] or 0),
            "primary_task_id": row["primary_task_id"],
            "pending_event_count": int(pending_events),
            "revision": int(row["revision"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _collect_subtree_ids(
        self,
        nodes_by_parent: Mapping[str | None, list[dict[str, Any]]],
        start_id: str,
    ) -> set[str]:
        collected: set[str] = set()
        stack = [start_id]
        while stack:
            cur = stack.pop()
            if cur in collected:
                raise SideSessionError(ErrorCode.TOPOLOGY_CORRUPT, f"Cycle detected while traversing subtree at {cur}")
            collected.add(cur)
            for child in nodes_by_parent.get(cur, []):
                stack.append(str(child["node_id"]))
        return collected

    def _render_tree_view(
        self,
        enriched_nodes: list[dict[str, Any]],
        caller_node_id: str,
    ) -> str:
        by_id = {n["node_id"]: n for n in enriched_nodes}
        children_map: dict[str | None, list[dict[str, Any]]] = {}
        for n in enriched_nodes:
            pid = n["parent_node_id"] if n["parent_node_id"] in by_id else None
            children_map.setdefault(pid, []).append(n)

        lines: list[str] = []

        def _fmt_node(n: dict[str, Any]) -> str:
            you_tag = " *current*" if n["node_id"] == caller_node_id else ""
            br_tag = f" branch={n['branch']}" if n.get("branch") else ""
            line = (
                f"[{n['name']}]{you_tag} ({n['node_id']}) "
                f"status={n['status']} exec={n['execution_state']} "
                f"mode={n['workspace_mode']}{br_tag} "
                f"verified={n['host_link_verified']}"
            )
            if n.get("last_turn_report"):
                line += f" | report: {n['last_turn_report']}"
            return line

        def _walk(node_dict: dict[str, Any], prefix: str, is_last: bool, is_root: bool) -> None:
            if is_root:
                lines.append(_fmt_node(node_dict))
                child_prefix = ""
            else:
                connector = "└── " if is_last else "├── "
                lines.append(f"{prefix}{connector}{_fmt_node(node_dict)}")
                child_prefix = prefix + ("    " if is_last else "│   ")
            kids = children_map.get(node_dict["node_id"], [])
            for idx, kid in enumerate(kids):
                _walk(kid, child_prefix, idx == len(kids) - 1, False)

        roots = children_map.get(None, [])
        for r_idx, r_node in enumerate(roots):
            _walk(r_node, "", r_idx == len(roots) - 1, True)

        return "\n".join(lines)

    def list_sessions(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Return the caller's authorized family session tree, proposals, dispatch groups, and slot usage."""
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("list_sessions", raw_args)
        caller_node = self.ensure_caller_node(caller)
        conn = self.store.conn
        caller_id = str(caller_node["node_id"])
        root_id = str(caller_node["root_node_id"])

        self._verify_ancestry_and_no_cycles(conn, caller_id)
        self._verify_family_topology(conn, root_id)

        focus_parent_id = caller_id
        if req["parent_session_id"] is not None:
            target_parent = self.resolve_target_node(caller, req["parent_session_id"], require_manage=True)
            focus_parent_id = str(target_parent["node_id"])

        family_rows = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM nodes WHERE root_node_id = ? ORDER BY created_at ASC, node_id ASC",
                (root_id,),
            ).fetchall()
        ]
        by_parent: dict[str | None, list[dict[str, Any]]] = {}
        for r in family_rows:
            by_parent.setdefault(r["parent_node_id"], []).append(r)

        if req["parent_session_id"] is not None:
            allowed_ids = self._collect_subtree_ids(by_parent, focus_parent_id)
        elif req["linked"]:
            allowed_ids = {str(r["node_id"]) for r in family_rows}
        else:
            allowed_ids = self._collect_subtree_ids(by_parent, caller_id)

        enriched_nodes: list[dict[str, Any]] = []
        for r in family_rows:
            nid = str(r["node_id"])
            if nid not in allowed_ids:
                continue
            if not req["include_archived"] and r["node_status"] == "archived" and nid != caller_id:
                continue
            enriched_nodes.append(self._enrich_node_row(conn, r))

        tree_view = self._render_tree_view(enriched_nodes, caller_id)

        proposals = [
            {
                **dict(p),
                "proposal_short_id": _proposal_short_id(str(p["proposal_id"])),
            }
            for p in conn.execute(
                """
                SELECT * FROM proposals
                WHERE parent_node_id IN (SELECT node_id FROM nodes WHERE root_node_id = ?)
                ORDER BY created_at ASC
                """,
                (root_id,),
            ).fetchall()
        ]

        groups = [
            self._build_dispatch_group_result(conn, str(g["dispatch_group_id"]))
            for g in conn.execute(
                "SELECT dispatch_group_id FROM dispatch_groups WHERE parent_node_id = ? ORDER BY created_at ASC",
                (focus_parent_id,),
            ).fetchall()
        ]

        active_slots = self._active_parent_slots(conn, focus_parent_id)
        pending_events = conn.execute(
            "SELECT COUNT(*) AS cnt FROM outbox_events WHERE parent_node_id = ? AND state IN ('pending', 'presented')",
            (focus_parent_id,),
        ).fetchone()["cnt"]

        return {
            "ok": True,
            "caller_node_id": caller_id,
            "root_node_id": root_id,
            "parent_session_id": focus_parent_id,
            "tree_view": tree_view,
            "nodes": enriched_nodes,
            "proposals": proposals,
            "dispatch_groups": groups,
            "active_slots": len(active_slots),
            "max_slots": MAX_SLOTS_PER_PARENT,
            "slots": active_slots,
            "pending_event_count": int(pending_events),
            "revision": self.store.get_revision(),
        }

    def get_session(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Return detailed metadata, active tasks, wait summaries, and recent report references for a single node."""
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("get_session", raw_args)
        target_row = self.resolve_target_node(caller, req["session_id"], target_kind=req["target_kind"])
        conn = self.store.conn
        target_id = str(target_row["node_id"])
        store_id = self.store.store_instance_id

        node_info = self._enrich_node_row(conn, target_row)
        task_ids = [
            str(r["task_id"])
            for r in conn.execute(
                "SELECT task_id FROM tasks WHERE owner_node_id = ? AND state != 'done' ORDER BY created_at ASC",
                (target_id,),
            ).fetchall()
        ]
        active_turn = conn.execute(
            """
            SELECT run_id FROM turns
            WHERE node_id = ?
              AND execution_state IN ('starting', 'running', 'waiting_input', 'stopping', 'reconciliation')
            ORDER BY turn_seq DESC LIMIT 1
            """,
            (target_id,),
        ).fetchone()
        active_run_id = str(active_turn["run_id"]) if active_turn is not None else None

        wait_summaries = self._get_wait_summaries_in_conn(conn, target_id, only_open=True)
        report_rows = conn.execute(
            """
            SELECT report_id FROM reports
            WHERE node_id = ?
            ORDER BY turn_seq DESC, CASE WHEN phase = 'final' THEN 0 ELSE 1 END ASC, report_revision DESC
            LIMIT 16
            """,
            (target_id,),
        ).fetchall()
        recent_report_refs = [format_ssref(store_id, "report", str(r["report_id"])) for r in report_rows]
        latest_report_ref = recent_report_refs[0] if recent_report_refs else None

        op_rows = [
            dict(r)
            for r in conn.execute(
                "SELECT operation_id, request_id, kind, stage, revision, updated_at FROM operations WHERE node_id = ? OR actor_node_id = ? ORDER BY created_at DESC LIMIT 16",
                (target_id, target_id),
            ).fetchall()
        ]
        group_rows = [
            dict(r)
            for r in conn.execute(
                "SELECT dispatch_group_id, assembly_state, completion_state, expected_member_count, member_count, revision FROM dispatch_groups WHERE parent_node_id = ? ORDER BY created_at DESC LIMIT 16",
                (target_id,),
            ).fetchall()
        ]

        res = SessionResult(
            node=node_info,
            revision=self.store.get_revision(),
            current_task_ids=task_ids,
            wait_summaries=wait_summaries,
            pending_event_count=node_info["pending_event_count"],
            recent_report_refs=recent_report_refs,
            operation_summaries=op_rows,
            dispatch_group_summaries=group_rows,
            active_run_id=active_run_id,
            latest_report_ref=latest_report_ref,
        ).to_dict()
        res["ok"] = True
        for k, v in node_info.items():
            res.setdefault(k, v)
        return res

    def set_session_status(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("set_session_status", raw_args)
        caller_node = self.ensure_caller_node(caller)
        caller_id = str(caller_node["node_id"])
        target_row = self.resolve_target_node(caller, req["session_id"], require_manage=True)
        target_id = str(target_row["node_id"])

        with self.store.transaction("IMMEDIATE") as txn:
            cached = self._check_idempotent_request(
                txn.conn,
                caller_id,
                "set_session_status",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

            self._assert_no_active_worktree_job(txn.conn, target_id)
            fresh_target = txn.execute("SELECT * FROM nodes WHERE node_id = ?", (target_id,)).fetchone()
            if fresh_target["node_status"] == "archived":
                raise SideSessionError(ErrorCode.SESSION_ARCHIVED, "Cannot change status of an archived session")
            exp_rev = int(req["expected_revision"])
            if exp_rev not in (int(fresh_target["revision"]), int(txn.revision) - 1, int(txn.revision)):
                raise SideSessionError(
                    ErrorCode.REVISION_CONFLICT,
                    "Session revision mismatch",
                    {"expected_revision": exp_rev, "actual_revision": fresh_target["revision"]},
                )

            new_status = req["status"]
            active_turn = txn.execute(
                """
                SELECT run_id FROM turns
                WHERE node_id = ? AND execution_state IN ('starting', 'running', 'waiting_input', 'stopping')
                LIMIT 1
                """,
                (target_id,),
            ).fetchone()
            pause_req = 1 if (new_status == "paused" and active_turn is not None) else 0
            txn.execute(
                """
                UPDATE nodes
                SET node_status = ?, pause_requested = ?, revision = revision + 1, updated_at = ?
                WHERE node_id = ?
                """,
                (new_status, pause_req, self._now_iso(), target_id),
            )
            res = self.get_session(caller, {"session_id": target_id})
            res["request_id"] = req.request_id
            self._record_idempotent_request(
                txn.conn,
                caller_id,
                "set_session_status",
                req.request_id,
                req.normalized_hash,
                res,
            )
            return res

    def archive_session(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Archive a session node after verifying no active runs, pending operations, or queued messages remain."""
        raw_args = self._merge_args(args, kwargs)
        if "expected_revision" not in raw_args and raw_args.get("session_id"):
            try:
                t_pre = self.resolve_target_node(caller, str(raw_args["session_id"]), require_manage=True)
                pre_rev = int(t_pre["revision"])
                cand_req_id = _try_parse_uuid(raw_args.get("request_id"))
                if cand_req_id and str(t_pre.get("node_status") or "") == "archived" and pre_rev > 1:
                    c_node = self.ensure_caller_node(caller)
                    has_prior = self.store.conn.execute(
                        "SELECT 1 FROM requests WHERE actor_node_id = ? AND tool_name = 'archive_session' AND request_id = ?",
                        (str(c_node["node_id"]), cand_req_id),
                    ).fetchone()
                    if has_prior is not None:
                        pre_rev -= 1
                raw_args["expected_revision"] = pre_rev
            except Exception:
                pass
        req = normalize_request("archive_session", raw_args)
        caller_node = self.ensure_caller_node(caller)
        caller_id = str(caller_node["node_id"])
        target_row = self.resolve_target_node(caller, req["session_id"], require_manage=True)
        target_id = str(target_row["node_id"])

        with self.store.transaction("IMMEDIATE") as txn:
            cached = self._check_idempotent_request(
                txn.conn,
                caller_id,
                "archive_session",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

            fresh_target = txn.execute("SELECT * FROM nodes WHERE node_id = ?", (target_id,)).fetchone()
            exp_rev = int(req["expected_revision"])
            if exp_rev not in (int(fresh_target["revision"]), int(txn.revision) - 1, int(txn.revision)):
                raise SideSessionError(
                    ErrorCode.REVISION_CONFLICT,
                    "Session revision mismatch on archive_session",
                    {"expected_revision": exp_rev, "actual_revision": fresh_target["revision"]},
                )

            busy_slot = txn.execute(
                "SELECT 1 FROM parent_slots WHERE node_id = ? AND state != 'released' LIMIT 1",
                (target_id,),
            ).fetchone()
            busy_turn = txn.execute(
                """
                SELECT 1 FROM turns
                WHERE node_id = ?
                  AND execution_state IN ('queued', 'starting', 'running', 'waiting_input', 'stopping', 'reconciliation')
                LIMIT 1
                """,
                (target_id,),
            ).fetchone()
            busy_msg = txn.execute(
                """
                SELECT 1 FROM inbox_messages
                WHERE target_node_id = ?
                  AND state IN ('queued', 'claimed', 'running', 'reconciliation')
                LIMIT 1
                """,
                (target_id,),
            ).fetchone()
            busy_op = txn.execute(
                """
                SELECT 1 FROM operations
                WHERE node_id = ?
                  AND stage IN ('preparing_context', 'awaiting_context_acceptance', 'ready_for_admission',
                                'reserved', 'worktree_created', 'session_created', 'brief_accepted', 'running', 'reconciliation')
                LIMIT 1
                """,
                (target_id,),
            ).fetchone()

            self._assert_no_active_worktree_job(txn.conn, target_id)
            lease_row = txn.execute(
                "SELECT lease_until FROM interactive_leases WHERE node_id = ?",
                (target_id,),
            ).fetchone()
            has_active_lease = lease_row is not None and not self._is_expired(lease_row["lease_until"])
            has_live_worker = self._has_external_live_worker(txn.conn, target_id)

            if busy_slot or busy_turn or busy_msg or busy_op or has_active_lease or has_live_worker:
                raise SideSessionError(
                    ErrorCode.SESSION_BUSY,
                    "Cannot archive session while it has active runs, pending operations, queued messages, or active leases",
                    {"session_id": target_id},
                )

            now = self._now_iso()
            txn.execute(
                """
                UPDATE nodes
                SET node_status = 'archived', pause_requested = 0, revision = revision + 1, updated_at = ?
                WHERE node_id = ?
                """,
                (now, target_id),
            )
            txn.execute(
                "UPDATE bindings SET db_check_state = 'archived' WHERE node_id = ?",
                (target_id,),
            )

            res = self.get_session(caller, {"session_id": target_id})
            res["request_id"] = req.request_id
            self._record_idempotent_request(
                txn.conn,
                caller_id,
                "archive_session",
                req.request_id,
                req.normalized_hash,
                res,
            )
            return res

    def execute_ui_action(
        self,
        kind: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Execute a sidebar UI action (`archive_session` or `cancel_run`) as the target node's parent using `requests` idempotency."""
        action_id = str(
            payload.get("actionId")
            or payload.get("action_id")
            or payload.get("request_id")
            or ""
        ).strip()
        target_node_id = str(
            payload.get("nodeId")
            or payload.get("node_id")
            or payload.get("session_id")
            or ""
        ).strip()
        try:
            validate_uuid(action_id, "actionId")
            validate_uuid(target_node_id, "nodeId")
            if kind not in ("archive_session", "cancel_run"):
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    f"Unsupported UI action kind: {kind!r}",
                    {"kind": kind},
                )
            target_row = self.store.conn.execute(
                "SELECT * FROM nodes WHERE node_id = ?",
                (target_node_id,),
            ).fetchone()
            if target_row is None:
                raise SideSessionError(
                    ErrorCode.NOT_FOUND,
                    f"Target session not found: {target_node_id}",
                    {"node_id": target_node_id},
                )
            parent_id = target_row["parent_node_id"]
            if not parent_id:
                raise SideSessionError(
                    ErrorCode.FORBIDDEN,
                    "UI actions are only allowed on child sessions with a parent node",
                    {"node_id": target_node_id},
                )
            parent_row = self.store.conn.execute(
                "SELECT * FROM nodes WHERE node_id = ?",
                (parent_id,),
            ).fetchone()
            if parent_row is None:
                raise SideSessionError(
                    ErrorCode.NOT_FOUND,
                    f"Parent session not found: {parent_id}",
                    {"parent_node_id": parent_id},
                )
            caller = CallerContext(
                runtime_sid=str(parent_row["runtime_session_id"] or f"sid:{parent_id}"),
                workspace_path=parent_row["canonical_workspace"],
                node_id=str(parent_id),
            )
            if kind == "archive_session":
                raw_rev = (
                    payload.get("expectedRevision")
                    if "expectedRevision" in payload
                    else payload.get("expected_revision")
                )
                if type(raw_rev) is not int or raw_rev < 1:
                    raise SideSessionError(
                        ErrorCode.VALIDATION_ERROR,
                        "UI archive_session requires an integer expectedRevision >= 1",
                        {"expectedRevision": raw_rev},
                    )
                res = self.archive_session(
                    caller,
                    {
                        "request_id": action_id,
                        "session_id": target_node_id,
                        "expected_revision": raw_rev,
                    },
                )
            else:
                run_id = str(
                    payload.get("runId")
                    or payload.get("run_id")
                    or payload.get("activeRunId")
                    or ""
                ).strip()
                reason = str(payload.get("reason") or "cancelled from sidebar UI").strip()
                res = self.cancel_run(
                    caller,
                    {
                        "request_id": action_id,
                        "session_id": target_node_id,
                        "run_id": run_id,
                        "reason": reason,
                    },
                    strict_node=True,
                )
            return {
                "actionId": action_id,
                "ok": True,
                "kind": kind,
                "nodeId": target_node_id,
                "result": res,
            }
        except SideSessionError as exc:
            return {
                "actionId": action_id,
                "ok": False,
                "kind": kind,
                "nodeId": target_node_id,
                "code": str(exc.code),
                "message": exc.message,
            }

    # ------------------------------------------------------------------
    # 3b. Worktree Read-Only Diff & Controlled Merge / Cleanup (Phase 2 S3)
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_worktree_record(wt_row: sqlite3.Row | Mapping[str, Any]) -> WorktreeRecord:
        d = dict(wt_row)
        return WorktreeRecord(
            worktree_id=str(d["worktree_id"]),
            node_id=str(d["node_id"]),
            operation_id=str(d["operation_id"]),
            canonical_worktree_path=str(d["canonical_worktree_path"]),
            worktrees_home=str(d["worktrees_home"]),
            workspace_mode=str(d.get("workspace_mode") or "branch"),
            repo_key=d.get("repo_key"),
            repo_root=d.get("repo_root"),
            base_commit=d.get("base_commit"),
            branch=d.get("branch"),
            source_patch_hash=d.get("source_patch_hash"),
            ownership_marker=d.get("ownership_marker"),
            state=str(d.get("state") or "created"),
            last_known_tip=d.get("last_known_tip"),
            merged_into_ref=d.get("merged_into_ref"),
            merged_commit=d.get("merged_commit"),
            merged_tree=d.get("merged_tree"),
            merge_mode=d.get("merge_mode"),
            pre_parent_head=d.get("pre_parent_head"),
            cleaned_at=d.get("cleaned_at"),
        )

    def _is_node_busy_in_conn(
        self,
        conn: sqlite3.Connection,
        node_id: str,
        *,
        exclude_job_id: str | None = None,
    ) -> bool:
        busy_slot = conn.execute(
            "SELECT 1 FROM parent_slots WHERE node_id = ? AND state != 'released' LIMIT 1",
            (node_id,),
        ).fetchone()
        if busy_slot:
            return True
        busy_turn = conn.execute(
            """
            SELECT 1 FROM turns
            WHERE node_id = ?
              AND execution_state IN ('queued', 'starting', 'running', 'waiting_input', 'stopping', 'reconciliation')
            LIMIT 1
            """,
            (node_id,),
        ).fetchone()
        if busy_turn:
            return True
        busy_msg = conn.execute(
            """
            SELECT 1 FROM inbox_messages
            WHERE target_node_id = ?
              AND state IN ('queued', 'claimed', 'running', 'reconciliation')
            LIMIT 1
            """,
            (node_id,),
        ).fetchone()
        if busy_msg:
            return True
        busy_op = conn.execute(
            """
            SELECT 1 FROM operations
            WHERE node_id = ?
              AND stage IN ('preparing_context', 'awaiting_context_acceptance', 'ready_for_admission',
                            'reserved', 'worktree_created', 'session_created', 'brief_accepted', 'running', 'reconciliation')
            LIMIT 1
            """,
            (node_id,),
        ).fetchone()
        if busy_op:
            return True
        try:
            if exclude_job_id is not None:
                busy_wt_job = conn.execute(
                    """
                    SELECT 1 FROM worktree_jobs
                    WHERE node_id = ? AND job_id != ? AND state IN ('queued', 'running', 'prepared')
                    LIMIT 1
                    """,
                    (node_id, exclude_job_id),
                ).fetchone()
            else:
                busy_wt_job = conn.execute(
                    """
                    SELECT 1 FROM worktree_jobs
                    WHERE node_id = ? AND state IN ('queued', 'running', 'prepared')
                    LIMIT 1
                    """,
                    (node_id,),
                ).fetchone()
            if busy_wt_job is not None:
                return True
        except sqlite3.OperationalError:
            pass
        lease_row = conn.execute(
            "SELECT lease_until FROM interactive_leases WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        if lease_row is not None and not self._is_expired(lease_row["lease_until"]):
            return True
        if self._has_external_live_worker(conn, node_id):
            return True
        return False

    @staticmethod
    def _find_path_prefix_collisions(
        ignored_paths: Iterable[str],
        changed_paths: Iterable[str],
    ) -> list[str]:
        ig_items: list[tuple[str, tuple[str, ...]]] = []
        for raw_ig in ignored_paths:
            norm_ig = str(raw_ig or "").strip("/")
            if norm_ig:
                pts = tuple(p for p in norm_ig.split("/") if p)
                if pts:
                    ig_items.append((norm_ig, pts))
        ch_pts_list: list[tuple[str, ...]] = []
        for raw_ch in changed_paths:
            norm_ch = str(raw_ch or "").strip("/")
            if norm_ch:
                pts = tuple(p for p in norm_ch.split("/") if p)
                if pts:
                    ch_pts_list.append(pts)
        if not ig_items or not ch_pts_list:
            return []
        collisions: set[str] = set()
        for norm_ig, ig_pts in ig_items:
            ig_len = len(ig_pts)
            for ch_pts in ch_pts_list:
                min_len = min(ig_len, len(ch_pts))
                if ig_pts[:min_len] == ch_pts[:min_len]:
                    collisions.add(norm_ig)
                    break
        return sorted(collisions)

    @staticmethod
    def _inspect_parent_repo_for_merge(repo_root: str) -> dict[str, Any]:
        sym_proc = _worktree_mod._run_git(repo_root, ["symbolic-ref", "-q", "HEAD"], isolated=True)
        parent_full_ref = sym_proc.stdout.decode("utf-8", errors="replace").strip() if sym_proc.returncode == 0 else None
        head_proc = _worktree_mod._run_git(repo_root, ["rev-parse", "--verify", "HEAD^{commit}"], isolated=True)
        parent_head = head_proc.stdout.decode("utf-8", errors="replace").strip() if head_proc.returncode == 0 else None
        st_proc = _worktree_mod._run_git(repo_root, ["status", "--porcelain=v1", "-z", "-uall"], isolated=True)
        dirty_entries = [e for e in st_proc.stdout.decode("utf-8", errors="replace").split("\x00") if e]
        ig_proc = _worktree_mod._run_git(
            repo_root,
            ["ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z"],
            isolated=True,
        )
        ignored_entries = [e for e in ig_proc.stdout.decode("utf-8", errors="replace").split("\x00") if e]

        in_progress_ops: list[str] = []
        for marker_name in (
            "MERGE_HEAD",
            "REBASE_HEAD",
            "CHERRY_PICK_HEAD",
            "REVERT_HEAD",
            "rebase-merge",
            "rebase-apply",
            "sequencer",
        ):
            gp = _worktree_mod._run_git(repo_root, ["rev-parse", "--git-path", marker_name], isolated=True)
            if gp.returncode == 0:
                rel_or_abs = gp.stdout.decode("utf-8", errors="replace").strip()
                if rel_or_abs:
                    cand = Path(rel_or_abs) if os.path.isabs(rel_or_abs) else (Path(repo_root) / rel_or_abs)
                    if cand.exists():
                        in_progress_ops.append(marker_name)

        return {
            "parent_full_ref": parent_full_ref,
            "parent_head": parent_head,
            "clean": st_proc.returncode == 0 and len(dirty_entries) == 0 and len(in_progress_ops) == 0,
            "dirty_entries": dirty_entries,
            "ignored_entries": ignored_entries,
            "in_progress_ops": in_progress_ops,
        }

    def _compute_worktree_diff_and_preview(
        self,
        wt_record: WorktreeRecord,
        *,
        max_bytes: int = 65536,
    ) -> dict[str, Any]:
        post_chk = _worktree_mod.verify_owned_post_run(wt_record)
        wt_path = wt_record.canonical_worktree_path
        base_commit = str(wt_record.base_commit or "")
        actual_head = str(post_chk.get("actual_head") or base_commit)
        actual_tree = str(post_chk.get("actual_tree") or "")

        changed_files: list[dict[str, Any]] = []
        changed_paths_set: set[str] = set()
        if post_chk.get("actual_head") and base_commit and Path(wt_path).is_dir():
            ns_proc = _worktree_mod._run_git(
                wt_path,
                ["diff", "--no-ext-diff", "--no-textconv", "--name-status", "-z", "-M", base_commit, actual_head, "--"],
                isolated=True,
            )
            tokens = [t for t in ns_proc.stdout.decode("utf-8", errors="replace").split("\x00") if t]
            idx = 0
            while idx < len(tokens):
                st_code = tokens[idx]
                if st_code.startswith(("R", "C")) and (idx + 2) < len(tokens):
                    old_p = tokens[idx + 1]
                    new_p = tokens[idx + 2]
                    changed_files.append({"status": st_code, "old_path": old_p, "path": new_p})
                    changed_paths_set.add(old_p)
                    changed_paths_set.add(new_p)
                    idx += 3
                elif (idx + 1) < len(tokens):
                    p_str = tokens[idx + 1]
                    changed_files.append({"status": st_code, "path": p_str})
                    changed_paths_set.add(p_str)
                    idx += 2
                else:
                    idx += 1

            num_proc = _worktree_mod._run_git(
                wt_path,
                ["diff", "--no-ext-diff", "--no-textconv", "--numstat", "-z", "-M", base_commit, actual_head, "--"],
                isolated=True,
            )
            num_tokens = num_proc.stdout.decode("utf-8", errors="replace").split("\x00")
            if num_tokens and num_tokens[-1] == "":
                num_tokens.pop()
            numstat_by_path: dict[str, tuple[int | None, int | None, bool]] = {}
            numstat_by_pair: dict[tuple[str, str], tuple[int | None, int | None, bool]] = {}
            n_idx = 0
            while n_idx < len(num_tokens):
                tok = num_tokens[n_idx]
                if not tok:
                    n_idx += 1
                    continue
                parts = tok.split("\t", 2)
                if len(parts) == 3:
                    ins_s, del_s, tail_p = parts[0], parts[1], parts[2]
                    try:
                        add_v = None if ins_s == "-" else int(ins_s)
                        del_v = None if del_s == "-" else int(del_s)
                    except ValueError:
                        n_idx += 1
                        continue
                    is_bin = ins_s == "-" or del_s == "-"
                    if tail_p == "" and (n_idx + 2) < len(num_tokens):
                        old_p = num_tokens[n_idx + 1]
                        new_p = num_tokens[n_idx + 2]
                        numstat_by_pair[(old_p, new_p)] = (add_v, del_v, is_bin)
                        numstat_by_path[new_p] = (add_v, del_v, is_bin)
                        n_idx += 3
                    else:
                        numstat_by_path[tail_p] = (add_v, del_v, is_bin)
                        n_idx += 1
                else:
                    n_idx += 1

            for cf in changed_files:
                stat_tuple = None
                if "old_path" in cf:
                    stat_tuple = numstat_by_pair.get((str(cf["old_path"]), str(cf["path"])))
                if stat_tuple is None:
                    stat_tuple = numstat_by_path.get(str(cf["path"]))
                if stat_tuple is not None:
                    cf["additions"], cf["deletions"], cf["binary"] = stat_tuple

        patch_hasher = hashlib.sha256()
        preview_buf = bytearray()
        total_patch_bytes = 0
        if post_chk.get("actual_head") and base_commit and Path(wt_path).is_dir():
            git_cmd = [
                "git",
                *_worktree_mod._GIT_ISOLATED_PREFIX_ARGS,
                "-C",
                str(wt_path),
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--binary",
                base_commit,
                actual_head,
                "--",
            ]
            env = _worktree_mod._build_isolated_git_env()
            diff_deadline = time.monotonic() + 15.0
            try:
                proc = subprocess.Popen(
                    git_cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
            except FileNotFoundError as exc:
                raise SideSessionError(
                    ErrorCode.CAPABILITY_UNAVAILABLE,
                    "git executable is not available on PATH",
                    {"cmd": git_cmd},
                ) from exc

            stderr_chunks: list[bytes] = []
            stderr_collected = 0

            def _drain_stderr(pipe: Any) -> None:
                nonlocal stderr_collected
                try:
                    while True:
                        b = pipe.read(8192)
                        if not b:
                            break
                        if stderr_collected < 16384:
                            take_err = min(len(b), 16384 - stderr_collected)
                            stderr_chunks.append(b[:take_err])
                            stderr_collected += take_err
                except Exception:
                    pass

            err_thread = threading.Thread(target=_drain_stderr, args=(proc.stderr,), daemon=True)
            err_thread.start()
            timed_out = False

            def _kill_on_timeout() -> None:
                nonlocal timed_out
                timed_out = True
                try:
                    proc.kill()
                except Exception:
                    pass

            watchdog = threading.Timer(max(0.1, diff_deadline - time.monotonic()), _kill_on_timeout)
            watchdog.daemon = True
            watchdog.start()
            try:
                assert proc.stdout is not None
                while True:
                    if time.monotonic() >= diff_deadline:
                        timed_out = True
                        proc.kill()
                        break
                    chunk = proc.stdout.read(32768)
                    if not chunk:
                        break
                    patch_hasher.update(chunk)
                    total_patch_bytes += len(chunk)
                    if len(preview_buf) < max_bytes:
                        take = min(len(chunk), max_bytes - len(preview_buf))
                        preview_buf.extend(chunk[:take])
                rem_wait = max(0.05, diff_deadline - time.monotonic())
                proc.wait(timeout=rem_wait)
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                proc.kill()
                proc.wait()
                raise SideSessionError(
                    ErrorCode.RETRY_LATER,
                    "git diff --binary timed out after 15.0s",
                    {"cmd": git_cmd},
                    retryable=True,
                ) from exc
            except BaseException:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait()
                except Exception:
                    pass
                raise
            finally:
                watchdog.cancel()
                err_thread.join(timeout=1.0)
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()

            if timed_out:
                raise SideSessionError(
                    ErrorCode.RETRY_LATER,
                    "git diff --binary timed out after 15.0s",
                    {"cmd": git_cmd},
                    retryable=True,
                )
            if proc.returncode != 0:
                err_msg = b"".join(stderr_chunks).decode("utf-8", errors="replace").strip()
                raise SideSessionError(
                    ErrorCode.INVALID_TASK_WORKSPACE,
                    f"git diff --binary failed with rc={proc.returncode}: {err_msg}",
                    {"returncode": proc.returncode, "stderr": err_msg},
                )

        tree_diff_sha256 = patch_hasher.hexdigest()
        parent_info = (
            self._inspect_parent_repo_for_merge(wt_record.repo_root)
            if wt_record.repo_root and Path(wt_record.repo_root).is_dir()
            else {
                "parent_full_ref": None,
                "parent_head": None,
                "clean": False,
                "dirty_entries": [],
                "ignored_entries": [],
                "in_progress_ops": [],
            }
        )

        preview_payload = {
            "store_instance_id": self.store.store_instance_id,
            "worktree_id": wt_record.worktree_id,
            "repo_key": wt_record.repo_key,
            "base_commit": wt_record.base_commit,
            "child_tip": actual_head,
            "child_tree": actual_tree,
            "parent_full_ref": parent_info["parent_full_ref"],
            "parent_head": parent_info["parent_head"],
            "source_patch_hash": wt_record.source_patch_hash,
            "tree_diff_sha256": tree_diff_sha256,
            "clean": bool(post_chk.get("clean")),
        }
        preview_hash = canonical_json_sha256(preview_payload)
        return {
            "post_chk": post_chk,
            "parent_info": parent_info,
            "changed_files": changed_files,
            "changed_paths_set": changed_paths_set,
            "patch_preview": bytes(preview_buf).decode("utf-8", errors="replace"),
            "patch_truncated": total_patch_bytes > max_bytes,
            "patch_total_bytes": total_patch_bytes,
            "tree_diff_sha256": tree_diff_sha256,
            "preview_hash": preview_hash,
        }

    def diff_worktree(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Read-only diff and merge-eligibility preview for an owned branch worktree."""
        ctx = self._coerce_caller(caller)
        raw_args = self._merge_args(args, kwargs)
        if "session_id" not in raw_args and "node_id" in raw_args:
            raw_args["session_id"] = raw_args.pop("node_id")
        req = normalize_request("diff_worktree", raw_args)
        self.ensure_caller_node(ctx)
        target_row = self.resolve_target_node(ctx, req["session_id"])
        target_id = str(target_row["node_id"])

        wt_row = self.store.conn.execute(
            "SELECT * FROM worktrees WHERE node_id = ? ORDER BY created_at DESC LIMIT 1",
            (target_id,),
        ).fetchone()
        if wt_row is None or str(wt_row["workspace_mode"]) != "branch":
            raise SideSessionError(
                ErrorCode.INVALID_TASK_WORKSPACE,
                "Target session does not have an owned branch worktree",
                {"session_id": target_id},
            )
        wt_record = self._row_to_worktree_record(wt_row)
        calc = self._compute_worktree_diff_and_preview(wt_record, max_bytes=int(req["max_bytes"]))
        post_chk = calc["post_chk"]
        parent_info = calc["parent_info"]
        is_idle = not self._is_node_busy_in_conn(self.store.conn, target_id)

        has_custom_drivers = False
        if wt_record.repo_root and Path(wt_record.repo_root).is_dir():
            try:
                _worktree_mod.check_no_custom_git_drivers(wt_record.repo_root)
            except SideSessionError:
                has_custom_drivers = True
        conflicting_ignored = self._find_path_prefix_collisions(
            parent_info.get("ignored_entries") or (),
            calc["changed_paths_set"],
        )

        merge_eligible = True
        merge_block_reason: str | None = None
        if wt_record.source_patch_hash:
            merge_eligible = False
            merge_block_reason = ErrorCode.BASELINE_UNAVAILABLE.value
        elif has_custom_drivers:
            merge_eligible = False
            merge_block_reason = ErrorCode.CAPABILITY_UNAVAILABLE.value
        elif not post_chk["ok"] or not post_chk["clean"]:
            merge_eligible = False
            merge_block_reason = post_chk.get("reason") or "WORKTREE_DIRTY"
        elif post_chk.get("has_submodule") or post_chk.get("has_escaping_symlink"):
            merge_eligible = False
            merge_block_reason = "UNSAFE_GIT_ENTRIES"
        elif not is_idle:
            merge_eligible = False
            merge_block_reason = ErrorCode.SESSION_BUSY.value
        elif not parent_info["parent_full_ref"] or not parent_info["clean"]:
            merge_eligible = False
            merge_block_reason = "PARENT_REPO_NOT_READY"
        elif conflicting_ignored:
            merge_eligible = False
            merge_block_reason = ErrorCode.DIRTY_SOURCE.value

        return {
            "ok": True,
            "session_id": target_id,
            "node_id": target_id,
            "worktree_id": wt_record.worktree_id,
            "branch": wt_record.branch,
            "base_commit": wt_record.base_commit,
            "child_tip": post_chk["actual_head"],
            "child_tree": post_chk["actual_tree"],
            "parent_full_ref": parent_info["parent_full_ref"],
            "parent_head": parent_info["parent_head"],
            "clean": bool(post_chk["clean"]),
            "commits_ahead": int(post_chk["commits_ahead"]),
            "changed_files": calc["changed_files"],
            "patch": calc["patch_preview"],
            "patch_truncated": calc["patch_truncated"],
            "patch_total_bytes": calc["patch_total_bytes"],
            "tree_diff_sha256": calc["tree_diff_sha256"],
            "preview_hash": calc["preview_hash"],
            "merge_eligible": merge_eligible,
            "merge_block_reason": merge_block_reason,
        }

    def enqueue_merge_worktree_job(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        *,
        session_ref: str,
        preview_hash: str,
        mode: str = "merge",
        cleanup_after: bool = False,
        real_input_id: str | None = None,
        command_id: str | None = "/side-sessions:merge",
        evidence: Any = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Validate merge parameters and enqueue a `worktree_jobs` row in <50ms without running Git."""
        ctx = self._coerce_caller(caller)
        norm_hash = str(preview_hash or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", norm_hash):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "preview_hash must be a 64-character lowercase hex SHA-256 string",
                {"preview_hash": preview_hash},
            )
        norm_mode = str(mode or "merge").strip().lower()
        if norm_mode not in ("ff-only", "merge", "squash"):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"Invalid merge mode: {mode!r} (expected 'ff-only', 'merge', or 'squash')",
                {"mode": mode},
            )
        self.ensure_caller_node(ctx)
        target_row = self.resolve_target_node(ctx, session_ref, require_manage=True)
        target_id = str(target_row["node_id"])
        req_id = _try_parse_uuid(request_id) or self._new_uuid()
        job_id = self._new_uuid()
        now = self._now_iso()

        with self.store.transaction("IMMEDIATE") as txn:
            self._assert_no_active_worktree_job(txn.conn, target_id)
            if self._is_node_busy_in_conn(txn.conn, target_id):
                raise SideSessionError(
                    ErrorCode.SESSION_BUSY,
                    "Cannot merge worktree while child session is active or busy",
                    {"session_id": target_id},
                )
            wt_row = txn.execute(
                "SELECT * FROM worktrees WHERE node_id = ? ORDER BY created_at DESC LIMIT 1",
                (target_id,),
            ).fetchone()
            if wt_row is None or str(wt_row["workspace_mode"]) != "branch":
                raise SideSessionError(
                    ErrorCode.INVALID_TASK_WORKSPACE,
                    "Target session does not have an owned branch worktree",
                    {"session_id": target_id},
                )
            if wt_row["source_patch_hash"]:
                raise SideSessionError(
                    ErrorCode.BASELINE_UNAVAILABLE,
                    "Cannot merge worktree created from a dirty baseline",
                    {"session_id": target_id, "worktree_id": wt_row["worktree_id"]},
                )
            if str(wt_row["state"]) == "cleaned":
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    "Worktree has already been cleaned",
                    {"session_id": target_id, "worktree_id": wt_row["worktree_id"]},
                )

            action_payload = {
                "purpose": "worktree_merge",
                "target_id": target_id,
                "node_id": target_id,
                "worktree_id": str(wt_row["worktree_id"]),
                "preview_hash": norm_hash,
                "target_hash": norm_hash,
                "task_hash": norm_hash,
                "real_input_id": real_input_id,
                "command_id": command_id,
                "runtime_sid": ctx.runtime_sid,
                "request_id": req_id,
            }
            ev = self._obtain_or_verify_approval_evidence(
                purpose="worktree_merge",
                evidence=evidence,
                action_dict=action_payload,
                conn=txn.conn,
                caller=ctx,
            )
            repo_key = str(wt_row["repo_key"] or sha256_hex(str(wt_row["repo_root"] or target_id)))
            txn.execute(
                """
                INSERT INTO worktree_jobs (
                    job_id, request_id, node_id, worktree_id, repo_key,
                    kind, mode, cleanup_after, preview_hash, approval_id,
                    state, candidate_commit, candidate_tree, lease_until,
                    result_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'merge', ?, ?, ?, ?, 'queued', NULL, NULL, NULL, NULL, ?, ?)
                """,
                (
                    job_id,
                    req_id,
                    target_id,
                    str(wt_row["worktree_id"]),
                    repo_key,
                    norm_mode,
                    1 if cleanup_after else 0,
                    norm_hash,
                    ev.approval_id,
                    now,
                    now,
                ),
            )

        self._notify_supervisor({"event": "worktree_job_queued", "job_id": job_id, "node_id": target_id})
        return {
            "ok": True,
            "job_id": job_id,
            "request_id": req_id,
            "node_id": target_id,
            "worktree_id": str(wt_row["worktree_id"]),
            "mode": norm_mode,
            "cleanup_after": bool(cleanup_after),
            "preview_hash": norm_hash,
            "approval_id": ev.approval_id,
            "state": "queued",
            "status": "queued",
        }

    def _resolve_cleanup_target_node(
        self,
        ctx: CallerContext,
        session_ref: str,
    ) -> dict[str, Any]:
        ref = str(session_ref or "").strip()
        if not ref:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "Usage: /side-sessions:cleanup <session>",
            )
        try:
            target_row = self.resolve_target_node(ctx, ref, require_manage=True)
        except SideSessionError as exc:
            if exc.code != ErrorCode.NOT_FOUND:
                raise
            target_row = self.resolve_target_node(ctx, ref, target_kind="runtime", require_manage=True)
        if not target_row.get("parent_node_id"):
            raise SideSessionError(
                ErrorCode.INVALID_TASK_WORKSPACE,
                "Target session is a root session and does not have an owned branch worktree",
                {"session_id": str(target_row["node_id"])},
            )
        return target_row

    def enqueue_cleanup_worktree_job(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        payload: Mapping[str, Any] | None = None,
        *,
        session_ref: str | None = None,
        real_input_id: str | None = None,
        command_id: str | None = "/side-sessions:cleanup",
        evidence: Any = None,
        request_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Validate cleanup parameters, consume human approval, and enqueue a `worktree_jobs(kind='cleanup')` row."""
        ctx = self._coerce_caller(caller)
        raw_args = self._merge_args(payload, kwargs)
        eff_ref = str(
            session_ref
            or raw_args.get("session_ref")
            or raw_args.get("session_id")
            or raw_args.get("node_id")
            or raw_args.get("session")
            or ""
        ).strip()
        eff_input_id = (
            real_input_id
            or raw_args.get("real_input_id")
            or raw_args.get("input_id")
        )
        eff_cmd_id = str(raw_args.get("command_id") or command_id or "/side-sessions:cleanup")
        eff_evidence = evidence if evidence is not None else raw_args.get("evidence")
        req_id = _try_parse_uuid(request_id or raw_args.get("request_id")) or self._new_uuid()

        self.ensure_caller_node(ctx)
        target_row = self._resolve_cleanup_target_node(ctx, eff_ref)
        target_id = str(target_row["node_id"])
        cleanup_hash = canonical_json_sha256({"cmd": "cleanup", "node_id": target_id})
        job_id = self._new_uuid()
        now = self._now_iso()

        with self.store.transaction("IMMEDIATE") as txn:
            self._assert_no_active_worktree_job(txn.conn, target_id)
            if self._is_node_busy_in_conn(txn.conn, target_id):
                raise SideSessionError(
                    ErrorCode.SESSION_BUSY,
                    "Cannot clean up worktree while child session is active or busy",
                    {"session_id": target_id},
                )
            wt_row = txn.execute(
                "SELECT * FROM worktrees WHERE node_id = ? ORDER BY created_at DESC LIMIT 1",
                (target_id,),
            ).fetchone()
            if wt_row is None or str(wt_row["workspace_mode"]) != "branch":
                raise SideSessionError(
                    ErrorCode.INVALID_TASK_WORKSPACE,
                    "Target session does not have an owned branch worktree",
                    {"session_id": target_id},
                )
            if str(wt_row["state"]) == "cleaned":
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    "Worktree has already been cleaned",
                    {"session_id": target_id, "worktree_id": wt_row["worktree_id"]},
                )

            action_payload = {
                "purpose": "worktree_merge",
                "cmd": "cleanup",
                "target_id": target_id,
                "node_id": target_id,
                "worktree_id": str(wt_row["worktree_id"]),
                "target_hash": cleanup_hash,
                "task_hash": cleanup_hash,
                "real_input_id": eff_input_id,
                "command_id": eff_cmd_id,
                "runtime_sid": ctx.runtime_sid,
                "request_id": req_id,
            }
            ev = self._obtain_or_verify_approval_evidence(
                purpose="worktree_merge",
                evidence=eff_evidence,
                action_dict=action_payload,
                conn=txn.conn,
                caller=ctx,
            )
            repo_key = str(wt_row["repo_key"] or sha256_hex(str(wt_row["repo_root"] or target_id)))
            txn.execute(
                """
                INSERT INTO worktree_jobs (
                    job_id, request_id, node_id, worktree_id, repo_key,
                    kind, mode, cleanup_after, preview_hash, approval_id,
                    state, candidate_commit, candidate_tree, lease_until,
                    result_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'cleanup', NULL, 0, ?, ?, 'queued', NULL, NULL, NULL, NULL, ?, ?)
                """,
                (
                    job_id,
                    req_id,
                    target_id,
                    str(wt_row["worktree_id"]),
                    repo_key,
                    cleanup_hash,
                    ev.approval_id,
                    now,
                    now,
                ),
            )

        self._notify_supervisor(
            {"event": "worktree_job_queued", "job_id": job_id, "kind": "cleanup", "node_id": target_id}
        )
        return {
            "ok": True,
            "job_id": job_id,
            "kind": "cleanup",
            "request_id": req_id,
            "node_id": target_id,
            "worktree_id": str(wt_row["worktree_id"]),
            "approval_id": ev.approval_id,
            "state": "queued",
            "status": "queued",
        }

    def _cleanup_worktree_under_locks(
        self,
        wt_record: WorktreeRecord,
        *,
        expected_head: str | None = None,
        delete_branch: bool = True,
    ) -> dict[str, Any]:
        cleanup_res = _worktree_mod.cleanup_owned(
            wt_record,
            expected_operation_id=wt_record.operation_id,
            idle_evidence={"idle": True},
            expected_head=expected_head,
            delete_branch=delete_branch,
        )
        now = self._now_iso()
        with self.store.transaction("IMMEDIATE") as txn:
            if cleanup_res.cleaned:
                txn.execute(
                    """
                    UPDATE worktrees
                    SET state = 'cleaned', cleaned_at = ?, updated_at = ?
                    WHERE worktree_id = ?
                    """,
                    (now, now, wt_record.worktree_id),
                )
                txn.execute(
                    """
                    UPDATE nodes
                    SET node_status = 'archived', pause_requested = 0, revision = revision + 1, updated_at = ?
                    WHERE node_id = ?
                    """,
                    (now, wt_record.node_id),
                )
                txn.execute(
                    "UPDATE bindings SET db_check_state = 'archived' WHERE node_id = ?",
                    (wt_record.node_id,),
                )
            else:
                next_st = (
                    cleanup_res.state
                    if cleanup_res.state in ("retained_dirty", "reconciliation")
                    else "reconciliation"
                )
                txn.execute(
                    "UPDATE worktrees SET state = ?, updated_at = ? WHERE worktree_id = ?",
                    (next_st, now, wt_record.worktree_id),
                )
        return {
            "cleaned": cleanup_res.cleaned,
            "state": cleanup_res.state,
            "branch_removed": cleanup_res.branch_removed,
            "branch_retained": not cleanup_res.branch_removed,
            "reason": cleanup_res.reason,
        }

    def _verify_and_cleanup_worktree_under_locks(
        self,
        wt_rec: WorktreeRecord,
    ) -> dict[str, Any]:
        if wt_rec.merged_commit and wt_rec.repo_root:
            tree_chk = _worktree_mod._run_git(
                wt_rec.repo_root,
                ["rev-parse", "--verify", f"{wt_rec.merged_commit}^{{tree}}"],
                isolated=True,
            )
            if tree_chk.returncode != 0 or (
                wt_rec.merged_tree
                and tree_chk.stdout.decode("utf-8", errors="replace").strip() != wt_rec.merged_tree
            ):
                raise SideSessionError(
                    ErrorCode.VALIDATION_ERROR,
                    "Recorded merged_commit or merged_tree cannot be verified in parent repository",
                    {"worktree_id": wt_rec.worktree_id, "merged_commit": wt_rec.merged_commit},
                )

        wt_disk_path = Path(wt_rec.canonical_worktree_path)
        if not wt_disk_path.exists() and not wt_disk_path.is_symlink():
            return self._cleanup_worktree_under_locks(
                wt_rec,
                expected_head=wt_rec.last_known_tip or wt_rec.base_commit,
                delete_branch=False,
            )

        post_chk = _worktree_mod.verify_owned_post_run(wt_rec)
        now = self._now_iso()
        if not post_chk["ok"]:
            with self.store.transaction("IMMEDIATE") as txn:
                txn.execute(
                    "UPDATE worktrees SET state = 'reconciliation', updated_at = ? WHERE worktree_id = ?",
                    (now, wt_rec.worktree_id),
                )
            return {
                "cleaned": False,
                "state": "reconciliation",
                "branch_removed": False,
                "branch_retained": True,
                "reason": post_chk.get("reason") or "worktree post-run verification failed",
            }

        if not post_chk["clean"] or post_chk.get("has_ignored"):
            dirty_list = list(post_chk.get("dirty_entries") or [])
            ignored_list = list(post_chk.get("ignored_entries") or [])
            reasons_list: list[str] = []
            if dirty_list or not post_chk["clean"]:
                reasons_list.append(
                    f"uncommitted/untracked changes ({', '.join(dirty_list[:5])})"
                    if dirty_list
                    else "uncommitted or untracked changes"
                )
            if ignored_list or post_chk.get("has_ignored"):
                reasons_list.append(
                    f"ignored files ({', '.join(ignored_list[:5])})"
                    if ignored_list
                    else "ignored untracked files"
                )
            dirty_reason = "Refusing to delete dirty worktree: " + "; ".join(reasons_list)
            with self.store.transaction("IMMEDIATE") as txn:
                txn.execute(
                    "UPDATE worktrees SET state = 'retained_dirty', updated_at = ? WHERE worktree_id = ?",
                    (now, wt_rec.worktree_id),
                )
            return {
                "cleaned": False,
                "state": "retained_dirty",
                "branch_removed": False,
                "branch_retained": True,
                "reason": dirty_reason,
                "dirty_entries": dirty_list,
                "ignored_entries": ignored_list,
            }

        actual_head = str(post_chk["actual_head"])
        commits_ahead = int(post_chk.get("commits_ahead") or 0)
        merged_mode = str(wt_rec.merge_mode or "")
        if (
            wt_rec.merged_commit
            and merged_mode in ("ff-only", "merge")
            and (not wt_rec.last_known_tip or actual_head == wt_rec.last_known_tip)
        ):
            should_delete_branch = True
        elif not wt_rec.merged_commit and commits_ahead == 0 and actual_head == wt_rec.base_commit:
            should_delete_branch = True
        else:
            should_delete_branch = False

        cl_res = self._cleanup_worktree_under_locks(
            wt_rec,
            expected_head=actual_head,
            delete_branch=should_delete_branch,
        )
        return {
            **cl_res,
            "actual_head": actual_head,
            "commits_ahead": commits_ahead,
        }

    def execute_worktree_job(self, job_id: str) -> dict[str, Any]:
        """Execute or recover a queued/running/prepared `worktree_jobs` row under `session -> repo_merge` locks."""
        j_row = self.store.conn.execute(
            "SELECT * FROM worktree_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if j_row is None:
            raise SideSessionError(ErrorCode.NOT_FOUND, f"Worktree job not found: {job_id}")
        node_id = str(j_row["node_id"])
        worktree_id = str(j_row["worktree_id"])
        repo_key = str(j_row["repo_key"])
        mode = str(j_row["mode"] or "merge")
        cleanup_after = bool(j_row["cleanup_after"])

        with self.store.session_lock(node_id, blocking=True, timeout_ms=5000):
            with self.store.repo_merge_lock(repo_key, blocking=True, timeout_ms=5000):
                j_fresh = self.store.conn.execute(
                    "SELECT * FROM worktree_jobs WHERE job_id = ?",
                    (job_id,),
                ).fetchone()
                wt_row = self.store.conn.execute(
                    "SELECT * FROM worktrees WHERE worktree_id = ?",
                    (worktree_id,),
                ).fetchone()
                if j_fresh is None or wt_row is None:
                    raise SideSessionError(ErrorCode.NOT_FOUND, f"Worktree job or worktree record missing: {job_id}")
                wt_record = self._row_to_worktree_record(wt_row)
                cur_state = str(j_fresh["state"])

                if cur_state in ("completed", "failed", "reconciliation"):
                    return json.loads(j_fresh["result_json"] or "{}") or {
                        "ok": cur_state == "completed",
                        "job_id": job_id,
                        "state": cur_state,
                    }

                if str(j_fresh["kind"]) == "cleanup":
                    if self._is_node_busy_in_conn(self.store.conn, node_id, exclude_job_id=job_id):
                        busy_exc = SideSessionError(
                            ErrorCode.SESSION_BUSY,
                            "Child session became busy before worktree cleanup",
                            {"node_id": node_id},
                        )
                        now_b = self._now_iso()
                        busy_payload = {
                            "ok": False,
                            "job_id": job_id,
                            "kind": "cleanup",
                            "state": "failed",
                            "code": str(busy_exc.code),
                            "message": busy_exc.message,
                            "details": busy_exc.details,
                        }
                        with self.store.transaction("IMMEDIATE") as txn:
                            txn.execute(
                                "UPDATE worktree_jobs SET state = 'failed', result_json = ?, updated_at = ? WHERE job_id = ?",
                                (canonical_json(busy_payload), now_b, job_id),
                            )
                        raise busy_exc

                    now_run = self._now_iso()
                    with self.store.transaction("IMMEDIATE") as txn:
                        txn.execute(
                            """
                            UPDATE worktree_jobs
                            SET state = 'running', lease_until = ?, updated_at = ?
                            WHERE job_id = ?
                            """,
                            (self._future_iso(seconds=60), now_run, job_id),
                        )

                    try:
                        cl_info = self._verify_and_cleanup_worktree_under_locks(wt_record)
                    except SideSessionError as cl_exc:
                        now_err = self._now_iso()
                        err_payload = {
                            "ok": False,
                            "job_id": job_id,
                            "kind": "cleanup",
                            "state": "failed",
                            "code": str(cl_exc.code),
                            "message": cl_exc.message,
                            "details": cl_exc.details,
                        }
                        with self.store.transaction("IMMEDIATE") as txn:
                            txn.execute(
                                "UPDATE worktree_jobs SET state = 'failed', result_json = ?, updated_at = ? WHERE job_id = ?",
                                (canonical_json(err_payload), now_err, job_id),
                            )
                        raise

                    job_next_state = (
                        "completed"
                        if cl_info["cleaned"]
                        else ("failed" if cl_info["state"] == "retained_dirty" else "reconciliation")
                    )
                    res_cleanup = {
                        "ok": bool(cl_info["cleaned"]),
                        "job_id": job_id,
                        "kind": "cleanup",
                        "node_id": node_id,
                        "worktree_id": worktree_id,
                        **cl_info,
                        "job_state": job_next_state,
                        "status": "cleaned" if cl_info["cleaned"] else str(cl_info["state"]),
                    }
                    now_done = self._now_iso()
                    with self.store.transaction("IMMEDIATE") as txn:
                        txn.execute(
                            "UPDATE worktree_jobs SET state = ?, result_json = ?, updated_at = ? WHERE job_id = ?",
                            (job_next_state, canonical_json(res_cleanup), now_done, job_id),
                        )
                    return res_cleanup

                # Crash recovery when job was left in 'prepared' state (FABLE-16)
                if cur_state == "prepared":
                    saved_meta = json.loads(j_fresh["result_json"] or "{}")
                    cand_commit = str(j_fresh["candidate_commit"] or "")
                    cand_tree = str(j_fresh["candidate_tree"] or "")
                    exp_parent_head = str(saved_meta.get("parent_head") or "")
                    exp_parent_ref = str(saved_meta.get("parent_ref") or "")
                    exp_child_tip = str(saved_meta.get("child_tip") or "")
                    p_info = self._inspect_parent_repo_for_merge(str(wt_record.repo_root))
                    cur_p_head = p_info.get("parent_head")
                    cur_p_ref = p_info.get("parent_full_ref")
                    now = self._now_iso()

                    if cand_commit and exp_parent_ref and cur_p_ref == exp_parent_ref and cur_p_head == cand_commit:
                        pass
                    elif (
                        cand_commit
                        and exp_parent_ref
                        and cur_p_ref == exp_parent_ref
                        and exp_parent_head
                        and cur_p_head == exp_parent_head
                        and p_info.get("clean")
                    ):
                        id_args = _worktree_mod.git_identity_fallback_args(str(wt_record.repo_root))
                        ff_proc = _worktree_mod._run_git(
                            str(wt_record.repo_root),
                            [*id_args, "merge", "--ff-only", cand_commit],
                            isolated=True,
                        )
                        if ff_proc.returncode != 0:
                            res_rec = {
                                "ok": False,
                                "job_id": job_id,
                                "state": "reconciliation",
                                "status": "reconciliation",
                                "reason": ff_proc.stderr.decode("utf-8", errors="replace").strip(),
                            }
                            with self.store.transaction("IMMEDIATE") as txn:
                                txn.execute("UPDATE worktrees SET state = 'reconciliation', updated_at = ? WHERE worktree_id = ?", (now, worktree_id))
                                txn.execute(
                                    "UPDATE worktree_jobs SET state = 'reconciliation', result_json = ?, updated_at = ? WHERE job_id = ?",
                                    (canonical_json(res_rec), now, job_id),
                                )
                            return res_rec
                    else:
                        res_rec = {
                            "ok": False,
                            "job_id": job_id,
                            "state": "reconciliation",
                            "status": "reconciliation",
                            "reason": "parent HEAD or branch ref diverged during prepared recovery",
                        }
                        with self.store.transaction("IMMEDIATE") as txn:
                            txn.execute("UPDATE worktrees SET state = 'reconciliation', updated_at = ? WHERE worktree_id = ?", (now, worktree_id))
                            txn.execute(
                                "UPDATE worktree_jobs SET state = 'reconciliation', result_json = ?, updated_at = ? WHERE job_id = ?",
                                (canonical_json(res_rec), now, job_id),
                            )
                        return res_rec

                    res_done: dict[str, Any] = {
                        "ok": True,
                        "job_id": job_id,
                        "node_id": node_id,
                        "worktree_id": worktree_id,
                        "mode": mode,
                        "merged_commit": cand_commit,
                        "merged_tree": cand_tree,
                        "merged_into_ref": exp_parent_ref,
                        "pre_parent_head": exp_parent_head,
                        "child_tip": exp_child_tip,
                        "state": "completed",
                        "status": "merged",
                    }
                    already_cleaned = str(wt_row["state"]) == "cleaned"
                    with self.store.transaction("IMMEDIATE") as txn:
                        if not already_cleaned:
                            try:
                                txn.execute(
                                    """
                                    UPDATE worktrees
                                    SET state = 'merged',
                                        last_known_tip = ?,
                                        merged_into_ref = ?,
                                        merged_commit = ?,
                                        merged_tree = ?,
                                        merge_mode = ?,
                                        pre_parent_head = ?,
                                        updated_at = ?
                                    WHERE worktree_id = ?
                                    """,
                                    (
                                        exp_child_tip,
                                        exp_parent_ref,
                                        cand_commit,
                                        cand_tree,
                                        mode,
                                        exp_parent_head,
                                        now,
                                        worktree_id,
                                    ),
                                )
                            except sqlite3.IntegrityError:
                                txn.execute(
                                    """
                                    UPDATE worktrees
                                    SET state = 'verified',
                                        last_known_tip = ?,
                                        merged_into_ref = ?,
                                        merged_commit = ?,
                                        merged_tree = ?,
                                        merge_mode = ?,
                                        pre_parent_head = ?,
                                        updated_at = ?
                                    WHERE worktree_id = ?
                                    """,
                                    (
                                        exp_child_tip,
                                        exp_parent_ref,
                                        cand_commit,
                                        cand_tree,
                                        mode,
                                        exp_parent_head,
                                        now,
                                        worktree_id,
                                    ),
                                )
                        if not cleanup_after:
                            txn.execute(
                                "UPDATE worktree_jobs SET state = 'completed', result_json = ?, updated_at = ? WHERE job_id = ?",
                                (canonical_json(res_done), now, job_id),
                            )
                    if cleanup_after:
                        if already_cleaned:
                            cl_info = {
                                "cleaned": True,
                                "state": "cleaned",
                                "branch_removed": mode != "squash",
                                "branch_retained": mode == "squash",
                                "reason": None,
                            }
                        else:
                            wt_after = self.store.conn.execute("SELECT * FROM worktrees WHERE worktree_id = ?", (worktree_id,)).fetchone()
                            cl_info = self._cleanup_worktree_under_locks(
                                self._row_to_worktree_record(wt_after),
                                expected_head=exp_child_tip,
                                delete_branch=(mode != "squash"),
                            )
                        res_done["cleanup"] = cl_info
                        with self.store.transaction("IMMEDIATE") as txn:
                            txn.execute(
                                "UPDATE worktree_jobs SET state = 'completed', result_json = ?, updated_at = ? WHERE job_id = ?",
                                (canonical_json(res_done), self._now_iso(), job_id),
                            )
                    return res_done

                # Step 1: Verify child idle, clean baseline, no custom drivers, post-run verification
                def _fail_job(err_code: ErrorCode | str, msg: str, details: Mapping[str, Any] | None = None) -> SideSessionError:
                    exc_obj = SideSessionError(err_code, msg, details)
                    now_f = self._now_iso()
                    fail_payload = {
                        "ok": False,
                        "job_id": job_id,
                        "state": "failed",
                        "code": str(exc_obj.code),
                        "message": exc_obj.message,
                        "details": exc_obj.details,
                    }
                    with self.store.transaction("IMMEDIATE") as txn:
                        txn.execute(
                            "UPDATE worktree_jobs SET state = 'failed', result_json = ?, updated_at = ? WHERE job_id = ?",
                            (canonical_json(fail_payload), now_f, job_id),
                        )
                    return exc_obj

                if self._is_node_busy_in_conn(self.store.conn, node_id, exclude_job_id=job_id):
                    raise _fail_job(ErrorCode.SESSION_BUSY, "Child session became busy before worktree merge")
                if wt_record.source_patch_hash:
                    raise _fail_job(ErrorCode.BASELINE_UNAVAILABLE, "Worktree has non-empty source_patch_hash")
                if not wt_record.repo_root or not Path(wt_record.repo_root).is_dir():
                    raise _fail_job(ErrorCode.INVALID_TASK_WORKSPACE, "Parent repository root is missing")

                try:
                    _worktree_mod.check_no_custom_git_drivers(wt_record.repo_root)
                except SideSessionError as drv_exc:
                    raise _fail_job(drv_exc.code, drv_exc.message, drv_exc.details) from drv_exc

                try:
                    calc = self._compute_worktree_diff_and_preview(wt_record)
                except SideSessionError as calc_exc:
                    raise _fail_job(calc_exc.code, calc_exc.message, calc_exc.details) from calc_exc
                post_chk = calc["post_chk"]
                parent_info = calc["parent_info"]

                if not post_chk["ok"] or not post_chk["clean"]:
                    raise _fail_job(
                        ErrorCode.DIRTY_SOURCE,
                        post_chk.get("reason") or "Child worktree has uncommitted or untracked files",
                        {"dirty_entries": post_chk.get("dirty_entries"), "has_ignored": post_chk.get("has_ignored")},
                    )
                if post_chk.get("has_submodule") or post_chk.get("has_escaping_symlink"):
                    raise _fail_job(
                        ErrorCode.UNSAFE_PATH,
                        "Child worktree contains forbidden git submodule (160000) or escaping symlink (120000)",
                    )

                # Step 2: Verify parent repository is on a branch, clean, and has no in-progress git ops
                parent_full_ref = parent_info.get("parent_full_ref")
                parent_head = parent_info.get("parent_head")
                if not parent_full_ref or not parent_head or not parent_info.get("clean"):
                    raise _fail_job(
                        ErrorCode.DIRTY_SOURCE,
                        "Parent repository is dirty, detached, or has an in-progress git operation",
                        {
                            "parent_full_ref": parent_full_ref,
                            "dirty_entries": parent_info.get("dirty_entries"),
                            "in_progress_ops": parent_info.get("in_progress_ops"),
                        },
                    )

                conflicting_ignored = self._find_path_prefix_collisions(
                    parent_info.get("ignored_entries") or (),
                    calc["changed_paths_set"],
                )
                if conflicting_ignored:
                    raise _fail_job(
                        ErrorCode.DIRTY_SOURCE,
                        "Merge would overwrite ignored untracked file(s) in parent repository",
                        {"conflicting_ignored": conflicting_ignored},
                    )

                # Step 3: Verify recomputed preview_hash matches job.preview_hash
                if calc["preview_hash"] != str(j_fresh["preview_hash"]):
                    raise _fail_job(
                        ErrorCode.STALE_PREVIEW,
                        "Worktree or parent repository changed since preview_hash was computed",
                        {
                            "expected_preview_hash": j_fresh["preview_hash"],
                            "actual_preview_hash": calc["preview_hash"],
                        },
                    )

                child_tip = str(post_chk["actual_head"])
                child_tree = str(post_chk["actual_tree"])
                now = self._now_iso()
                running_meta = {
                    "parent_ref": parent_full_ref,
                    "parent_head": parent_head,
                    "child_tip": child_tip,
                    "child_tree": child_tree,
                }
                with self.store.transaction("IMMEDIATE") as txn:
                    txn.execute(
                        """
                        UPDATE worktree_jobs
                        SET state = 'running', lease_until = ?, result_json = ?, updated_at = ?
                        WHERE job_id = ?
                        """,
                        (self._future_iso(seconds=60), canonical_json(running_meta), now, job_id),
                    )

                # Step 4: Conflict precheck via `git merge-tree --write-tree --name-only -z`
                try:
                    mt_proc = _worktree_mod._run_git(
                        wt_record.repo_root,
                        ["merge-tree", "--write-tree", "--name-only", "-z", parent_head, child_tip],
                        isolated=True,
                    )
                except SideSessionError as mt_exc:
                    raise _fail_job(mt_exc.code, mt_exc.message, mt_exc.details) from mt_exc
                if mt_proc.returncode not in (0, 1):
                    raise _fail_job(
                        ErrorCode.CAPABILITY_UNAVAILABLE,
                        f"git merge-tree --write-tree failed with rc={mt_proc.returncode}",
                        {"returncode": mt_proc.returncode, "stderr": mt_proc.stderr.decode("utf-8", errors="replace").strip()},
                    )

                segs = mt_proc.stdout.decode("utf-8", errors="replace").split("\x00")
                merged_tree_oid = segs[0].strip() if segs else ""
                if mt_proc.returncode == 1:
                    conflict_files: list[str] = []
                    for s in segs[1:]:
                        if s == "":
                            break
                        conflict_files.append(s)
                    rec_payload = {
                        "ok": False,
                        "job_id": job_id,
                        "node_id": node_id,
                        "worktree_id": worktree_id,
                        "state": "reconciliation",
                        "status": "reconciliation",
                        "conflict_files": conflict_files,
                    }
                    now_r = self._now_iso()
                    with self.store.transaction("IMMEDIATE") as txn:
                        txn.execute(
                            "UPDATE worktrees SET state = 'reconciliation', updated_at = ? WHERE worktree_id = ?",
                            (now_r, worktree_id),
                        )
                        txn.execute(
                            "UPDATE worktree_jobs SET state = 'reconciliation', result_json = ?, updated_at = ? WHERE job_id = ?",
                            (canonical_json(rec_payload), now_r, job_id),
                        )
                    return rec_payload

                id_args = _worktree_mod.git_identity_fallback_args(wt_record.repo_root)
                # Construct candidate commit in object database without touching parent working tree
                if mode == "ff-only":
                    anc_proc = _worktree_mod._run_git(
                        wt_record.repo_root,
                        ["merge-base", "--is-ancestor", parent_head, child_tip],
                        isolated=True,
                    )
                    if anc_proc.returncode != 0:
                        rec_payload = {
                            "ok": False,
                            "job_id": job_id,
                            "node_id": node_id,
                            "worktree_id": worktree_id,
                            "state": "reconciliation",
                            "status": "reconciliation",
                            "reason": "ff-only requested but parent HEAD has diverged from child branch",
                        }
                        now_r = self._now_iso()
                        with self.store.transaction("IMMEDIATE") as txn:
                            txn.execute(
                                "UPDATE worktrees SET state = 'reconciliation', updated_at = ? WHERE worktree_id = ?",
                                (now_r, worktree_id),
                            )
                            txn.execute(
                                "UPDATE worktree_jobs SET state = 'reconciliation', result_json = ?, updated_at = ? WHERE job_id = ?",
                                (canonical_json(rec_payload), now_r, job_id),
                            )
                        return rec_payload
                    candidate_oid = child_tip
                elif mode == "merge":
                    if child_tip == parent_head:
                        candidate_oid = child_tip
                    else:
                        commit_msg = f"Merge side-session {wt_record.branch} ({node_id})"
                        ct_proc = _worktree_mod._run_git(
                            wt_record.repo_root,
                            [*id_args, "commit-tree", merged_tree_oid, "-p", parent_head, "-p", child_tip, "-m", commit_msg],
                            isolated=True,
                        )
                        if ct_proc.returncode != 0:
                            raise _fail_job(
                                ErrorCode.CAPABILITY_UNAVAILABLE,
                                f"git commit-tree failed: {ct_proc.stderr.decode('utf-8', errors='replace').strip()}",
                            )
                        candidate_oid = ct_proc.stdout.decode("utf-8", errors="replace").strip()
                else:  # squash
                    commit_msg = f"Squash side-session {wt_record.branch} ({node_id})"
                    ct_proc = _worktree_mod._run_git(
                        wt_record.repo_root,
                        [*id_args, "commit-tree", merged_tree_oid, "-p", parent_head, "-m", commit_msg],
                        isolated=True,
                    )
                    if ct_proc.returncode != 0:
                        raise _fail_job(
                            ErrorCode.CAPABILITY_UNAVAILABLE,
                            f"git commit-tree failed: {ct_proc.stderr.decode('utf-8', errors='replace').strip()}",
                        )
                    candidate_oid = ct_proc.stdout.decode("utf-8", errors="replace").strip()

                # Step 5: Persist prepared state, then fast-forward parent repository
                now_p = self._now_iso()
                with self.store.transaction("IMMEDIATE") as txn:
                    txn.execute(
                        """
                        UPDATE worktree_jobs
                        SET state = 'prepared',
                            candidate_commit = ?,
                            candidate_tree = ?,
                            lease_until = ?,
                            updated_at = ?
                        WHERE job_id = ?
                        """,
                        (candidate_oid, merged_tree_oid, self._future_iso(seconds=60), now_p, job_id),
                    )

                p_recheck = self._inspect_parent_repo_for_merge(wt_record.repo_root)
                if (
                    not p_recheck.get("clean")
                    or p_recheck.get("parent_head") != parent_head
                    or p_recheck.get("parent_full_ref") != parent_full_ref
                ):
                    rec_payload = {
                        "ok": False,
                        "job_id": job_id,
                        "node_id": node_id,
                        "worktree_id": worktree_id,
                        "state": "reconciliation",
                        "status": "reconciliation",
                        "reason": "parent repository changed immediately before ff-only install",
                    }
                    now_r = self._now_iso()
                    with self.store.transaction("IMMEDIATE") as txn:
                        txn.execute(
                            "UPDATE worktrees SET state = 'reconciliation', updated_at = ? WHERE worktree_id = ?",
                            (now_r, worktree_id),
                        )
                        txn.execute(
                            "UPDATE worktree_jobs SET state = 'reconciliation', result_json = ?, updated_at = ? WHERE job_id = ?",
                            (canonical_json(rec_payload), now_r, job_id),
                        )
                    return rec_payload

                ff_proc = _worktree_mod._run_git(
                    wt_record.repo_root,
                    [*id_args, "merge", "--ff-only", candidate_oid],
                    isolated=True,
                )
                if ff_proc.returncode != 0:
                    rec_payload = {
                        "ok": False,
                        "job_id": job_id,
                        "node_id": node_id,
                        "worktree_id": worktree_id,
                        "state": "reconciliation",
                        "status": "reconciliation",
                        "reason": ff_proc.stderr.decode("utf-8", errors="replace").strip(),
                    }
                    now_r = self._now_iso()
                    with self.store.transaction("IMMEDIATE") as txn:
                        txn.execute(
                            "UPDATE worktrees SET state = 'reconciliation', updated_at = ? WHERE worktree_id = ?",
                            (now_r, worktree_id),
                        )
                        txn.execute(
                            "UPDATE worktree_jobs SET state = 'reconciliation', result_json = ?, updated_at = ? WHERE job_id = ?",
                            (canonical_json(rec_payload), now_r, job_id),
                        )
                    return rec_payload

                now_c = self._now_iso()
                res_done = {
                    "ok": True,
                    "job_id": job_id,
                    "node_id": node_id,
                    "worktree_id": worktree_id,
                    "mode": mode,
                    "merged_commit": candidate_oid,
                    "merged_tree": merged_tree_oid,
                    "merged_into_ref": parent_full_ref,
                    "pre_parent_head": parent_head,
                    "child_tip": child_tip,
                    "state": "completed",
                    "status": "merged",
                }
                with self.store.transaction("IMMEDIATE") as txn:
                    try:
                        txn.execute(
                            """
                            UPDATE worktrees
                            SET state = 'merged',
                                last_known_tip = ?,
                                merged_into_ref = ?,
                                merged_commit = ?,
                                merged_tree = ?,
                                merge_mode = ?,
                                pre_parent_head = ?,
                                updated_at = ?
                            WHERE worktree_id = ?
                            """,
                            (
                                child_tip,
                                parent_full_ref,
                                candidate_oid,
                                merged_tree_oid,
                                mode,
                                parent_head,
                                now_c,
                                worktree_id,
                            ),
                        )
                    except sqlite3.IntegrityError:
                        txn.execute(
                            """
                            UPDATE worktrees
                            SET state = 'verified',
                                last_known_tip = ?,
                                merged_into_ref = ?,
                                merged_commit = ?,
                                merged_tree = ?,
                                merge_mode = ?,
                                pre_parent_head = ?,
                                updated_at = ?
                            WHERE worktree_id = ?
                            """,
                            (
                                child_tip,
                                parent_full_ref,
                                candidate_oid,
                                merged_tree_oid,
                                mode,
                                parent_head,
                                now_c,
                                worktree_id,
                            ),
                        )
                    if not cleanup_after:
                        txn.execute(
                            "UPDATE worktree_jobs SET state = 'completed', result_json = ?, updated_at = ? WHERE job_id = ?",
                            (canonical_json(res_done), now_c, job_id),
                        )

                if cleanup_after:
                    wt_after = self.store.conn.execute(
                        "SELECT * FROM worktrees WHERE worktree_id = ?",
                        (worktree_id,),
                    ).fetchone()
                    cl_info = self._cleanup_worktree_under_locks(
                        self._row_to_worktree_record(wt_after),
                        expected_head=child_tip,
                        delete_branch=(mode != "squash"),
                    )
                    res_done["cleanup"] = cl_info
                    with self.store.transaction("IMMEDIATE") as txn:
                        txn.execute(
                            "UPDATE worktree_jobs SET state = 'completed', result_json = ?, updated_at = ? WHERE job_id = ?",
                            (canonical_json(res_done), self._now_iso(), job_id),
                        )
                return res_done

    def merge_worktree(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        *,
        execute_now: bool = True,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Controlled internal entrypoint to enqueue (and optionally execute) a worktree merge job."""
        raw_args = self._merge_args(args, kwargs)
        session_ref = str(
            raw_args.get("session_id")
            or raw_args.get("node_id")
            or raw_args.get("session")
            or ""
        ).strip()
        preview_hash = str(raw_args.get("preview_hash") or "").strip()
        mode = str(raw_args.get("mode") or "merge").strip()
        cleanup_after = bool(raw_args.get("cleanup_after") or raw_args.get("cleanup", False))
        enq = self.enqueue_merge_worktree_job(
            caller,
            session_ref=session_ref,
            preview_hash=preview_hash,
            mode=mode,
            cleanup_after=cleanup_after,
            real_input_id=raw_args.get("real_input_id") or raw_args.get("input_id"),
            command_id=raw_args.get("command_id", "/side-sessions:merge"),
            evidence=raw_args.get("evidence"),
            request_id=raw_args.get("request_id"),
        )
        if not execute_now:
            return enq
        return self.execute_worktree_job(enq["job_id"])

    def cleanup_worktree(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Safely remove an owned worktree after verifying head/merge state and archive the child node."""
        ctx = self._coerce_caller(caller)
        raw_args = self._merge_args(args, kwargs)
        session_ref = str(
            raw_args.get("session_id")
            or raw_args.get("node_id")
            or raw_args.get("session")
            or ""
        ).strip()
        self.ensure_caller_node(ctx)
        target_row = self.resolve_target_node(ctx, session_ref, require_manage=True)
        target_id = str(target_row["node_id"])
        wt_row = self.store.conn.execute(
            "SELECT * FROM worktrees WHERE node_id = ? ORDER BY created_at DESC LIMIT 1",
            (target_id,),
        ).fetchone()
        if wt_row is None or str(wt_row["workspace_mode"]) != "branch":
            raise SideSessionError(
                ErrorCode.INVALID_TASK_WORKSPACE,
                "Target session does not have an owned branch worktree",
                {"session_id": target_id},
            )
        wt_record = self._row_to_worktree_record(wt_row)
        repo_key = str(wt_record.repo_key or sha256_hex(str(wt_record.repo_root or target_id)))

        with self.store.session_lock(target_id, blocking=True, timeout_ms=5000):
            with self.store.repo_merge_lock(repo_key, blocking=True, timeout_ms=5000):
                self._assert_no_active_worktree_job(self.store.conn, target_id)
                if self._is_node_busy_in_conn(self.store.conn, target_id):
                    raise SideSessionError(
                        ErrorCode.SESSION_BUSY,
                        "Cannot clean up worktree while child session is active or busy",
                        {"session_id": target_id},
                    )
                wt_fresh = self.store.conn.execute(
                    "SELECT * FROM worktrees WHERE worktree_id = ?",
                    (wt_record.worktree_id,),
                ).fetchone()
                wt_rec = self._row_to_worktree_record(wt_fresh)
                cl_res = self._verify_and_cleanup_worktree_under_locks(wt_rec)
                return {
                    "ok": cl_res["cleaned"],
                    "node_id": target_id,
                    "worktree_id": wt_rec.worktree_id,
                    **cl_res,
                }

    # ------------------------------------------------------------------
    # 4. Task Registration & Mid-Turn Handoff (Section 6.6, 7.6 & Prompt #4 & R03/R07)
    # ------------------------------------------------------------------

    def _build_task_result(self, row: Mapping[str, Any], revision: int | None = None) -> dict[str, Any]:
        row = dict(row)
        scope_obj = json.loads(row["scope_json"] or "{}")
        anchor_obj = json.loads(row["last_stable_anchor"]) if row.get("last_stable_anchor") else None
        res = TaskResult(
            task_id=str(row["task_id"]),
            owner_node_id=str(row["owner_node_id"]),
            state=str(row["state"]),
            task_revision=int(row["task_revision"]),
            title=str(row["title"]),
            remaining_plan=str(row["remaining_plan"]),
            task_kind=str(row["task_kind"]),
            scope=scope_obj,
            last_stable_anchor=anchor_obj,
            current_transfer_id=row.get("current_transfer_id"),
        ).to_dict()
        res["ok"] = True
        res["origin_node_id"] = row["origin_node_id"]
        res["revision"] = self.store.get_revision() if revision is None else revision
        return res

    def register_task(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Register a task for the current session and bind it to the caller's active runtime turn."""
        ctx = self._coerce_caller(caller)
        raw_args = self._merge_args(args, kwargs)
        if "scope" not in raw_args:
            raw_args["scope"] = {
                "resource_keys": [],
                "write_path_roots": [],
                "artifact_source_roots": [],
                "tool_profile_hash": "",
            }
        req = normalize_request("register_task", raw_args)
        caller_node = self.ensure_caller_node(ctx)
        caller_id = str(caller_node["node_id"])
        turn_key = ctx.runtime_turn_id or "turn-default"

        with self.store.transaction("IMMEDIATE") as txn:
            cached = self._check_idempotent_request(
                txn.conn,
                caller_id,
                "register_task",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

            if ctx.runtime_turn_id:
                existing_bind = txn.execute(
                    """
                    SELECT * FROM task_turn_bindings
                    WHERE runtime_sid = ? AND runtime_turn_id = ? AND state = 'active'
                    """,
                    (ctx.runtime_sid, turn_key),
                ).fetchone()
                if existing_bind is not None:
                    raise SideSessionError(
                        ErrorCode.TURN_ALREADY_BOUND,
                        f"Runtime turn {turn_key} is already bound to active task {existing_bind['task_id']}",
                        {"runtime_turn_id": turn_key, "task_id": existing_bind["task_id"]},
                    )
            else:
                txn.execute(
                    "UPDATE task_turn_bindings SET state = 'released' WHERE runtime_sid = ? AND runtime_turn_id = 'turn-default' AND state = 'active'",
                    (ctx.runtime_sid,),
                )

            task_id = self._new_uuid()
            binding_id = self._new_uuid()
            now = self._now_iso()
            scope = dict(req["scope"])

            txn.execute(
                """
                INSERT INTO tasks (
                    task_id, origin_node_id, owner_node_id, title, remaining_plan,
                    task_kind, scope_json, state, task_revision, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', 1, ?, ?)
                """,
                (
                    task_id,
                    caller_id,
                    caller_id,
                    req["title"],
                    req["remaining_plan"],
                    req["task_kind"],
                    canonical_json(scope),
                    now,
                    now,
                ),
            )
            txn.execute(
                """
                INSERT INTO task_turn_bindings (
                    binding_id, task_id, node_id, runtime_sid, runtime_turn_id,
                    task_revision, state, created_at
                ) VALUES (?, ?, ?, ?, ?, 1, 'active', ?)
                """,
                (binding_id, task_id, caller_id, ctx.runtime_sid, turn_key, now),
            )
            if not caller_node.get("primary_task_id"):
                txn.execute(
                    "UPDATE nodes SET primary_task_id = ?, updated_at = ? WHERE node_id = ?",
                    (task_id, now, caller_id),
                )

            t_row = txn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
            res = self._build_task_result(t_row, revision=txn.revision)
            res["request_id"] = req.request_id
            res["binding_id"] = binding_id
            self._record_idempotent_request(
                txn.conn,
                caller_id,
                "register_task",
                req.request_id,
                req.normalized_hash,
                res,
            )
            return res

    def bind_current_task(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        ctx = self._coerce_caller(caller)
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("bind_current_task", raw_args)
        caller_node = self.ensure_caller_node(ctx)
        caller_id = str(caller_node["node_id"])
        turn_key = ctx.runtime_turn_id or "turn-default"
        task_id = req["task_id"]

        with self.store.transaction("IMMEDIATE") as txn:
            cached = self._check_idempotent_request(
                txn.conn,
                caller_id,
                "bind_current_task",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

            t_row = txn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
            if t_row is None:
                raise SideSessionError(ErrorCode.NOT_FOUND, f"Task not found: {task_id}")
            if str(t_row["owner_node_id"]) != caller_id:
                raise SideSessionError(
                    ErrorCode.TASK_OWNER_CHANGED,
                    "Caller is not the owner of this task",
                    {"task_id": task_id, "owner_node_id": t_row["owner_node_id"]},
                )
            if str(t_row["state"]) != "active":
                raise SideSessionError(
                    ErrorCode.TASK_OWNER_CHANGED,
                    f"Task cannot be bound while in state '{t_row['state']}'",
                    {"task_id": task_id, "state": t_row["state"]},
                )
            if int(t_row["task_revision"]) != int(req["expected_task_revision"]):
                raise SideSessionError(
                    ErrorCode.REVISION_CONFLICT,
                    "Task revision mismatch in bind_current_task",
                    {"expected": req["expected_task_revision"], "actual": t_row["task_revision"]},
                )

            existing_turn_bind = txn.execute(
                """
                SELECT * FROM task_turn_bindings
                WHERE runtime_sid = ? AND runtime_turn_id = ? AND state = 'active'
                """,
                (ctx.runtime_sid, turn_key),
            ).fetchone()
            if existing_turn_bind is not None and str(existing_turn_bind["task_id"]) != task_id:
                raise SideSessionError(
                    ErrorCode.TURN_ALREADY_BOUND,
                    f"Current turn is already bound to another task ({existing_turn_bind['task_id']})",
                )

            txn.execute(
                "UPDATE task_turn_bindings SET state = 'released' WHERE task_id = ? AND state = 'active'",
                (task_id,),
            )
            binding_id = self._new_uuid()
            txn.execute(
                """
                INSERT INTO task_turn_bindings (
                    binding_id, task_id, node_id, runtime_sid, runtime_turn_id,
                    task_revision, state, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
                """,
                (
                    binding_id,
                    task_id,
                    caller_id,
                    ctx.runtime_sid,
                    turn_key,
                    int(t_row["task_revision"]),
                    self._now_iso(),
                ),
            )
            res = self._build_task_result(t_row, revision=txn.revision)
            res["request_id"] = req.request_id
            res["binding_id"] = binding_id
            self._record_idempotent_request(
                txn.conn,
                caller_id,
                "bind_current_task",
                req.request_id,
                req.normalized_hash,
                res,
            )
            return res

    def _upgrade_synthetic_turn_binding(
        self,
        node_id: str,
        runtime_sid: str,
        real_turn_id: str | None,
        *,
        run_id: str | None = None,
        conn: Any = None,
    ) -> bool:
        """Atomically upgrade NULL or synthetic 'rturn:%' turn bindings to the real host runtime_turn_id."""
        if not real_turn_id or not isinstance(real_turn_id, str):
            return False
        clean_turn = real_turn_id.strip()
        if not clean_turn or clean_turn.startswith("rturn:") or clean_turn == "turn-default":
            return False

        def _do_upgrade(c: Any) -> bool:
            if run_id:
                t_row = c.execute(
                    "SELECT * FROM turns WHERE run_id = ? AND node_id = ?",
                    (run_id, node_id),
                ).fetchone()
            else:
                t_row = c.execute(
                    """
                    SELECT * FROM turns
                    WHERE node_id = ?
                      AND execution_state IN ('starting', 'running', 'waiting_input', 'queued')
                    ORDER BY turn_seq DESC
                    LIMIT 1
                    """,
                    (node_id,),
                ).fetchone()

            synth_binds = c.execute(
                """
                SELECT * FROM task_turn_bindings
                WHERE (node_id = ? OR runtime_sid = ?)
                  AND state = 'active'
                  AND (runtime_turn_id IS NULL OR runtime_turn_id = '' OR runtime_turn_id LIKE 'rturn:%')
                ORDER BY created_at DESC
                """,
                (node_id, runtime_sid),
            ).fetchall()

            turn_needs_upgrade = (
                t_row is not None
                and (not t_row["runtime_turn_id"] or str(t_row["runtime_turn_id"]).startswith("rturn:"))
            )
            if not turn_needs_upgrade and not synth_binds:
                return False

            now = self._now_iso()
            if turn_needs_upgrade and t_row is not None:
                c.execute(
                    """
                    UPDATE turns
                    SET runtime_turn_id = ?
                    WHERE run_id = ?
                      AND (runtime_turn_id IS NULL OR runtime_turn_id = '' OR runtime_turn_id LIKE 'rturn:%')
                    """,
                    (clean_turn, t_row["run_id"]),
                )
                c.execute(
                    """
                    UPDATE wait_requests
                    SET runtime_turn_id = ?
                    WHERE run_id = ?
                      AND (runtime_turn_id IS NULL OR runtime_turn_id = '' OR runtime_turn_id LIKE 'rturn:%')
                    """,
                    (clean_turn, t_row["run_id"]),
                )
            c.execute(
                """
                UPDATE bindings
                SET last_turn_id = ?, last_seen_at = ?
                WHERE (runtime_sid = ? OR node_id = ?)
                  AND (last_turn_id IS NULL OR last_turn_id = '' OR last_turn_id LIKE 'rturn:%' OR last_turn_id = ?)
                """,
                (clean_turn, now, runtime_sid, node_id, clean_turn),
            )
            if synth_binds:
                target_bind = synth_binds[0]
                eff_sid = str(runtime_sid or target_bind["runtime_sid"])
                c.execute(
                    """
                    UPDATE task_turn_bindings
                    SET state = 'released'
                    WHERE runtime_sid = ?
                      AND runtime_turn_id = ?
                      AND state = 'active'
                      AND binding_id != ?
                    """,
                    (eff_sid, clean_turn, target_bind["binding_id"]),
                )
                c.execute(
                    """
                    UPDATE task_turn_bindings
                    SET runtime_turn_id = ?, runtime_sid = ?
                    WHERE binding_id = ?
                    """,
                    (clean_turn, eff_sid, target_bind["binding_id"]),
                )
                for extra_bind in synth_binds[1:]:
                    c.execute(
                        "UPDATE task_turn_bindings SET state = 'released' WHERE binding_id = ?",
                        (extra_bind["binding_id"],),
                    )
            elif t_row is not None and t_row["task_id"]:
                existing_active = c.execute(
                    """
                    SELECT binding_id FROM task_turn_bindings
                    WHERE (node_id = ? OR runtime_sid = ?) AND state = 'active'
                    LIMIT 1
                    """,
                    (node_id, runtime_sid),
                ).fetchone()
                if existing_active is None:
                    c.execute(
                        """
                        INSERT INTO task_turn_bindings (
                            binding_id, task_id, node_id, runtime_sid, runtime_turn_id,
                            task_revision, state, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
                        """,
                        (
                            self._new_uuid(),
                            t_row["task_id"],
                            node_id,
                            runtime_sid,
                            clean_turn,
                            int(t_row["task_revision"] or 1),
                            now,
                        ),
                    )
            return True

        if conn is not None:
            return _do_upgrade(conn)
        if self.store.conn.in_transaction:
            return _do_upgrade(self.store.conn)
        with self.store.transaction("IMMEDIATE") as txn:
            return _do_upgrade(txn.conn)

    def get_current_task(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        ctx = self._coerce_caller(caller)
        raw_args = self._merge_args(args, kwargs)
        normalize_request("get_current_task", raw_args)
        caller_node = self.ensure_caller_node(ctx)
        caller_id = str(caller_node["node_id"])
        turn_key = ctx.runtime_turn_id or "turn-default"

        b_row = self.store.conn.execute(
            """
            SELECT * FROM task_turn_bindings
            WHERE runtime_sid = ? AND runtime_turn_id = ? AND state = 'active'
            LIMIT 1
            """,
            (ctx.runtime_sid, turn_key),
        ).fetchone()
        if b_row is None and ctx.runtime_turn_id:
            if self._upgrade_synthetic_turn_binding(caller_id, ctx.runtime_sid, ctx.runtime_turn_id):
                b_row = self.store.conn.execute(
                    """
                    SELECT * FROM task_turn_bindings
                    WHERE runtime_sid = ? AND runtime_turn_id = ? AND state = 'active'
                    LIMIT 1
                    """,
                    (ctx.runtime_sid, turn_key),
                ).fetchone()
        if b_row is None:
            active_turn = self.store.conn.execute(
                """
                SELECT * FROM turns
                WHERE node_id = ?
                  AND execution_state IN ('starting', 'running', 'waiting_input', 'queued')
                ORDER BY turn_seq DESC
                LIMIT 1
                """,
                (caller_id,),
            ).fetchone()
            active_binds = self.store.conn.execute(
                """
                SELECT * FROM task_turn_bindings
                WHERE (node_id = ? OR runtime_sid = ?) AND state = 'active'
                ORDER BY created_at DESC
                """,
                (caller_id, ctx.runtime_sid),
            ).fetchall()
            if len(active_binds) == 1:
                cand = active_binds[0]
                cand_turn = str(cand["runtime_turn_id"] or "")
                if (
                    cand_turn.startswith("rturn:")
                    or not ctx.runtime_turn_id
                    or active_turn is not None
                ):
                    if ctx.runtime_turn_id and cand_turn.startswith("rturn:"):
                        self._upgrade_synthetic_turn_binding(caller_id, ctx.runtime_sid, ctx.runtime_turn_id)
                        cand = (
                            self.store.conn.execute(
                                "SELECT * FROM task_turn_bindings WHERE binding_id = ?",
                                (cand["binding_id"],),
                            ).fetchone()
                            or cand
                        )
                    b_row = cand
        if b_row is None:
            raise SideSessionError(
                ErrorCode.TASK_UNBOUND,
                f"No active task bound to runtime_sid={ctx.runtime_sid}, turn={turn_key}",
            )
        t_row = self.store.conn.execute(
            "SELECT * FROM tasks WHERE task_id = ?",
            (b_row["task_id"],),
        ).fetchone()
        if t_row is None:
            raise SideSessionError(ErrorCode.TASK_UNBOUND, f"Bound task {b_row['task_id']} not found")
        return self._build_task_result(t_row)

    def get_task(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("get_task", raw_args)
        caller_node = self.ensure_caller_node(caller)
        caller_id = str(caller_node["node_id"])
        task_id = req["task_id"]

        t_row = self.store.conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if t_row is None:
            raise SideSessionError(ErrorCode.NOT_FOUND, f"Task not found: {task_id}")

        owner_id = str(t_row["owner_node_id"])
        origin_id = str(t_row["origin_node_id"])
        if (
            caller_id not in (owner_id, origin_id)
            and not self._is_ancestor_or_self(self.store.conn, caller_id, owner_id)
            and not self._is_ancestor_or_self(self.store.conn, caller_id, origin_id)
        ):
            raise _err(
                "PERMISSION_DENIED",
                "Caller is not authorized to read this task",
                {"task_id": task_id},
                aliases=(ErrorCode.FORBIDDEN, ErrorCode.NOT_FOUND_OR_FORBIDDEN),
            )
        return self._build_task_result(t_row)

    def list_tasks(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("list_tasks", raw_args)
        caller_node = self.ensure_caller_node(caller)
        target_id = str(caller_node["node_id"])
        if req["session_id"] is not None:
            target_node = self.resolve_target_node(caller, req["session_id"], require_manage=True)
            target_id = str(target_node["node_id"])

        rows = self.store.conn.execute(
            "SELECT * FROM tasks WHERE owner_node_id = ? OR origin_node_id = ? ORDER BY created_at ASC",
            (target_id, target_id),
        ).fetchall()
        items = [self._build_task_result(r) for r in rows]
        return {
            "ok": True,
            "session_id": target_id,
            "tasks": items,
            "items": items,
            "revision": self.store.get_revision(),
        }

    def _map_scope_for_handoff(
        self,
        source_scope: Mapping[str, Any],
        source_workspace: str,
        target_workspace: str,
        workspace_mode: str,
    ) -> dict[str, Any]:
        if workspace_mode == "inherit":
            return dict(source_scope)

        src_real = os.path.realpath(source_workspace) if os.path.exists(source_workspace) else source_workspace
        tgt_real = os.path.realpath(target_workspace) if os.path.exists(target_workspace) else target_workspace

        def _remap_paths(paths: list[str]) -> list[str]:
            mapped: list[str] = []
            for p in paths:
                norm_p = str(p).strip()
                if not norm_p:
                    continue
                if ".." in norm_p.split("/"):
                    raise SideSessionError(
                        ErrorCode.HANDOFF_SCOPE_UNSUPPORTED,
                        f"Task scope path contains parent traversal and cannot be relocated: {norm_p}",
                        {"path": norm_p},
                    )
                if norm_p.startswith("/"):
                    p_real = os.path.realpath(norm_p) if os.path.exists(norm_p) else norm_p
                    if p_real == src_real:
                        mapped.append(tgt_real)
                    elif p_real.startswith(src_real.rstrip("/") + "/"):
                        rel = p_real[len(src_real.rstrip("/")) + 1 :]
                        mapped.append(f"{tgt_real.rstrip('/')}/{rel}")
                    else:
                        raise SideSessionError(
                            ErrorCode.HANDOFF_SCOPE_UNSUPPORTED,
                            f"External absolute path '{norm_p}' outside source repository cannot be mapped to child worktree",
                            {"path": norm_p, "source_workspace": src_real},
                        )
                else:
                    mapped.append(norm_p)
            return mapped

        return {
            "resource_keys": list(source_scope.get("resource_keys") or []),
            "write_path_roots": _remap_paths(list(source_scope.get("write_path_roots") or [])),
            "artifact_source_roots": _remap_paths(list(source_scope.get("artifact_source_roots") or [])),
            "tool_profile_hash": str(source_scope.get("tool_profile_hash") or ""),
        }

    def hand_off_to_session(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Atomically hand off an active registered task to a new child session (Section 7.6 & R03/R07/R08)."""
        ctx = self._coerce_caller(caller)
        dirty_policy = str(kwargs.pop("dirty_policy", "reject"))
        approved_path_manifest = kwargs.pop("approved_path_manifest", None)
        raw_args = self._merge_args(args, kwargs)
        operation_id_override = raw_args.pop("operation_id", None)
        if "transfer_id" not in raw_args:
            raw_args["transfer_id"] = self._new_uuid()
        if "context_strategy" not in raw_args:
            raw_args["context_strategy"] = "summary_copy"

        req = normalize_request("hand_off_to_session", raw_args)
        parent_node = self.ensure_caller_node(ctx)
        parent_id = str(parent_node["node_id"])
        parent_sid = str(parent_node["runtime_session_id"] or ctx.runtime_sid)
        root_id = str(parent_node["root_node_id"])
        source_cwd = str(parent_node.get("canonical_workspace") or ctx.workspace_path or self.store.root)

        # 1. Idempotency check
        existing_res = self._check_idempotent_request(
            self.store.conn,
            parent_id,
            "hand_off_to_session",
            req.request_id,
            req.normalized_hash,
        )
        if existing_res is not None:
            if existing_res.get("status") in ("awaiting_context_approval", "awaiting_context_acceptance"):
                op_id = existing_res.get("operation_id")
                if op_id:
                    op_row = self.store.conn.execute(
                        "SELECT stage, context_acceptance_id FROM operations WHERE operation_id = ?",
                        (op_id,),
                    ).fetchone()
                    if op_row and (op_row["stage"] == "ready_for_admission" or op_row["context_acceptance_id"]):
                        operation_id_override = str(op_id)
                        existing_res = None
            if existing_res is not None:
                return existing_res

        self._assert_no_active_worktree_job(self.store.conn, parent_id)

        task_id = req["task_id"]
        transfer_id = req["transfer_id"]
        expected_rev = int(req["expected_task_revision"])
        title = req["title"]
        remaining_plan = req["remaining_plan"]
        task_kind = req["task_kind"]
        workspace_mode = req["workspace_mode"]
        context_strategy = req["context_strategy"]
        dispatch_group_id = req.get("dispatch_group_id")
        requested_name = req.get("name")

        # 2. Verify task exists, caller is owner, state is active, and revision matches
        t_row = self.store.conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if t_row is None:
            raise _err(
                ErrorCode.TASK_UNBOUND,
                f"Task not registered: {task_id}",
                {"task_id": task_id},
                aliases=(ErrorCode.NOT_FOUND,),
            )
        if str(t_row["owner_node_id"]) != parent_id:
            raise SideSessionError(
                ErrorCode.TASK_OWNER_CHANGED,
                "Caller is not the current owner of the task being handed off",
                {"task_id": task_id, "owner_node_id": t_row["owner_node_id"], "caller_node_id": parent_id},
            )
        if str(t_row["state"]) != "active":
            raise SideSessionError(
                ErrorCode.TASK_OWNER_CHANGED,
                f"Task is not active (state={t_row['state']})",
                {"task_id": task_id, "state": t_row["state"]},
            )
        if int(t_row["task_revision"]) != expected_rev:
            raise SideSessionError(
                ErrorCode.REVISION_CONFLICT,
                "Task revision does not match expected_task_revision",
                {"expected_task_revision": expected_rev, "actual_task_revision": t_row["task_revision"]},
            )

        source_scope = json.loads(t_row["scope_json"] or "{}")
        # Validate scope relocatability before any side effects
        self._map_scope_for_handoff(source_scope, source_cwd, source_cwd, workspace_mode)

        # 3. Check capabilities before any side effects
        caps = self._probe_capabilities()
        adapter = self.host_adapter
        if getattr(adapter, "supports_task_guard", True) is False or (
            getattr(self.driver, "supports_task_guard", None) is False
        ):
            raise SideSessionError(
                ErrorCode.HANDOFF_GUARD_UNAVAILABLE,
                "Host task guard capability is unavailable for hand_off_to_session",
                {"task_id": task_id},
            )
        if task_kind == "read_only" and not self._is_capability_supported(caps, "supports_tool_restrictions"):
            raise SideSessionError(
                ErrorCode.CAPABILITY_UNAVAILABLE,
                "Driver does not support tool restrictions required for read_only handoff",
            )
        if context_strategy == "native_fork":
            if workspace_mode == "branch":
                raise SideSessionError(
                    ErrorCode.UNSUPPORTED_CONTEXT_WORKSPACE,
                    "native_fork cannot be combined with branch worktree workspace",
                )
            if not self._is_capability_supported(caps, "supports_live_fork", require_integration_verified=True):
                raise SideSessionError(
                    ErrorCode.UNSUPPORTED_LIVE_FORK,
                    "native_fork handoff is not supported from a live parent turn",
                )

        # 5. Context preflight & R08 quality check (capacity is re-checked inside the admission transaction)
        operation_id = str(operation_id_override or self._new_uuid())
        prelim_brief = self._build_brief_markdown(
            title=title,
            prompt=remaining_plan,
            context_mode="summary_copy",
            background_sections={
                "overall_goal": title,
                "decisions": "承接父会话已登记任务进度",
                "constraints": "严格在交接任务作用域内完成剩余计划",
            },
            background_raw=None,
            history_summary=None,
            remaining_plan=remaining_plan,
            assignment_view={"node_id": "pending", "run_id": "pending", "turn_seq": 1, "worker_turn_id": "pending"},
        )
        prelim_brief_hash = sha256_hex(prelim_brief)

        existing_snap_row = self.store.conn.execute(
            "SELECT * FROM context_snapshots WHERE operation_id = ? ORDER BY created_at DESC LIMIT 1",
            (operation_id,),
        ).fetchone()
        if existing_snap_row is not None:
            snapshot_hash = str(existing_snap_row["snapshot_hash"])
            history_quality = str(existing_snap_row["history_quality"])
            anchor_obj: Any = json.loads(existing_snap_row["anchor_json"] or "{}")
            manifest_ref = existing_snap_row["projection_ref"]
            history_summary = f"Summary from snapshot {snapshot_hash}"
            prelim_brief_hash = str(existing_snap_row["brief_hash"])
            snapshot_id = str(existing_snap_row["snapshot_id"])
        else:
            proj, snapshot_id, manifest_ref = self._prepare_fork_context_snapshot(
                parent_node=parent_node,
                caller=ctx,
                request_id=req.request_id,
                operation_id=operation_id,
                kind="hand_off_to_session",
                title=title,
                prompt=remaining_plan,
                remaining_plan=remaining_plan,
                task_id=task_id,
                task_revision=expected_rev,
                requested_group_id=dispatch_group_id,
                brief_hash=prelim_brief_hash,
            )
            history_quality = proj.history_quality
            snapshot_hash = proj.snapshot_hash
            history_summary = proj.summary
            anchor_obj = proj.anchor

        if history_quality == "brief_only":
            with self.store.transaction("IMMEDIATE") as txn:
                acc = self._verify_existing_context_acceptance_in_conn(
                    txn.conn,
                    operation_id=operation_id,
                    snapshot_hash=snapshot_hash,
                    expected_brief_hash=prelim_brief_hash,
                    expected_task_revision=expected_rev,
                    anchor=anchor_obj,
                )
                if acc is None:
                    await_res = {
                        "ok": True,
                        "request_id": req.request_id,
                        "transfer_id": transfer_id,
                        "task_id": task_id,
                        "operation_id": operation_id,
                        "status": _AliasStr(
                            "awaiting_context_approval",
                            "awaiting_context_acceptance",
                            "CONTEXT_QUALITY_APPROVAL_REQUIRED",
                        ),
                        "code": ErrorCode.CONTEXT_QUALITY_APPROVAL_REQUIRED.value,
                        "context_requested": "fork",
                        "context_applied": "brief_only",
                        "history_quality": "brief_only",
                        "snapshot_hash": snapshot_hash,
                        "brief_hash": prelim_brief_hash,
                        "manifest_ref": manifest_ref,
                        "workspace_mode": workspace_mode,
                        "host_link_verified": False,
                        "revision": txn.revision,
                    }
                    self._record_idempotent_request(
                        txn.conn,
                        parent_id,
                        "hand_off_to_session",
                        req.request_id,
                        req.normalized_hash,
                        await_res,
                        operation_id=operation_id,
                    )
                    return await_res
                txn.execute(
                    "UPDATE context_acceptances SET state = 'used' WHERE acceptance_id = ?",
                    (acc["acceptance_id"],),
                )
                txn.execute(
                    "UPDATE context_snapshots SET state = 'authorized' WHERE snapshot_id = ?",
                    (snapshot_id,),
                )
            context_applied = "brief_only"
        else:
            if not self._driver_validate_anchor(anchor_obj):
                raise SideSessionError(
                    ErrorCode.SOURCE_SNAPSHOT_STALE,
                    "Source anchor is no longer valid for handoff",
                    {"operation_id": operation_id, "snapshot_hash": snapshot_hash},
                )
            context_applied = "summary_copy"

        # 6. Atomic reservation + transfer_preparing inside BEGIN IMMEDIATE (R07)
        node_id = self._new_uuid()
        child_runtime_sid = f"sess_{self._new_uuid()}"
        run_id = self._new_uuid()
        worker_turn_id = self._new_uuid()
        input_id = self._new_uuid()
        message_id = self._new_uuid()
        brief_id = self._new_uuid()
        fencing_token = f"fence:{node_id}:{uuid.uuid4().hex}"

        with self.store.transaction("IMMEDIATE") as txn:
            self._assert_no_active_worktree_job(txn.conn, parent_id)
            t_fresh = txn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
            if t_fresh is None or str(t_fresh["owner_node_id"]) != parent_id or str(t_fresh["state"]) != "active":
                raise SideSessionError(ErrorCode.TASK_OWNER_CHANGED, "Task owner or state changed before reservation")
            if int(t_fresh["task_revision"]) != expected_rev:
                raise SideSessionError(ErrorCode.REVISION_CONFLICT, "Task revision changed before reservation")

            child_name = self._allocate_child_short_name(txn.conn, parent_id, requested_name, node_id)
            slot_no = self.reserve_dispatch(txn, parent_id, node_id, operation_id=operation_id, run_id=run_id)
            eff_group_id, member_id, _ordinal = self._admit_dispatch_group_member_in_conn(
                txn.conn,
                parent_node_id=parent_id,
                child_node_id=node_id,
                message_id=message_id,
                operation_id=operation_id,
                run_id=run_id,
                dispatch_group_id=dispatch_group_id,
                batch_id=None,
                initial_state="queued",
            )

            now = self._now_iso()
            txn.execute(
                """
                UPDATE tasks
                SET state = 'transfer_preparing', current_transfer_id = ?, updated_at = ?
                WHERE task_id = ?
                """,
                (transfer_id, now, task_id),
            )
            txn.execute(
                """
                INSERT INTO transfers (
                    transfer_id, source_node_id, child_node_id, task_id, source_task_revision,
                    source_scope_json, target_scope_json, context_snapshot_id, state,
                    brief_id, brief_hash, operation_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'preparing', ?, ?, ?, ?, ?)
                """,
                (
                    transfer_id,
                    parent_id,
                    node_id,
                    task_id,
                    expected_rev,
                    canonical_json(source_scope),
                    canonical_json(source_scope),
                    snapshot_id,
                    brief_id,
                    prelim_brief_hash,
                    operation_id,
                    now,
                    now,
                ),
            )
            txn.execute(
                """
                INSERT INTO operations (
                    operation_id, request_id, node_id, actor_node_id, task_id, member_id, kind,
                    requested_group_id, stage, attempt, external_ids, expected_paths,
                    revision, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'hand_off_to_session', ?, 'reserved', 1, ?, '{}', 1, ?, ?)
                ON CONFLICT(operation_id) DO UPDATE SET
                    node_id = excluded.node_id,
                    task_id = excluded.task_id,
                    member_id = excluded.member_id,
                    stage = 'reserved',
                    external_ids = excluded.external_ids,
                    revision = operations.revision + 1,
                    updated_at = excluded.updated_at
                """,
                (
                    operation_id,
                    req.request_id,
                    node_id,
                    parent_id,
                    task_id,
                    member_id,
                    dispatch_group_id,
                    canonical_json({"transfer_id": transfer_id, "slot_no": slot_no, "run_id": run_id}),
                    now,
                    now,
                ),
            )

        # 7. Prepare task guard via host_adapter
        cutoff = SourceCutoff(
            source_node_id=parent_id,
            source_runtime_sid=parent_sid,
            trigger_runtime_turn_id=ctx.runtime_turn_id or "turn-0",
            trigger_request_id=req.request_id,
            owner_id=parent_id,
            accepted_input_high_watermark=req.request_id,
            source_revision=int(parent_node.get("revision") or 1),
            task_id=task_id,
        )
        guard_receipt: GuardReceipt | None = None
        try:
            guard_receipt = self._adapter_prepare_task_guard(
                task_id=task_id,
                expected_revision=expected_rev,
                transfer_id=transfer_id,
                source_cutoff=cutoff,
            )
            if guard_receipt.state != "prepared" or guard_receipt.inflight_action_ids:
                with self.store.transaction("IMMEDIATE") as rec_txn:
                    rec_txn.execute(
                        "UPDATE transfers SET guard_id = ?, state = 'reconciliation', updated_at = ? WHERE transfer_id = ?",
                        (guard_receipt.guard_id, self._now_iso(), transfer_id),
                    )
                    rec_txn.execute(
                        "UPDATE operations SET stage = 'reconciliation', updated_at = ? WHERE operation_id = ?",
                        (self._now_iso(), operation_id),
                    )
                raise SideSessionError(
                    ErrorCode.HANDOFF_GUARD_UNAVAILABLE,
                    f"Task guard is not prepared (state={guard_receipt.state}, inflight={guard_receipt.inflight_action_ids})",
                    {"guard_id": guard_receipt.guard_id, "state": guard_receipt.state},
                )

            with self.store.transaction("IMMEDIATE") as txn:
                t_chk = txn.execute("SELECT task_revision FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
                if int(t_chk["task_revision"]) != expected_rev:
                    raise SideSessionError(
                        ErrorCode.SOURCE_SNAPSHOT_STALE,
                        "Task revision advanced while preparing task guard",
                        {"task_id": task_id},
                    )
                now = self._now_iso()
                txn.execute(
                    "UPDATE tasks SET state = 'transferring', updated_at = ? WHERE task_id = ?",
                    (now, task_id),
                )
                txn.execute(
                    "UPDATE transfers SET guard_id = ?, state = 'transferring', updated_at = ? WHERE transfer_id = ?",
                    (guard_receipt.guard_id, now, transfer_id),
                )
                txn.execute(
                    "UPDATE task_turn_bindings SET state = 'frozen' WHERE task_id = ? AND node_id = ? AND state = 'active'",
                    (task_id, parent_id),
                )

            # 8. Prepare workspace & child brief
            ws_spec = WorkspaceSpec(
                node_id=node_id,
                workspace_mode=workspace_mode,
                source_cwd=source_cwd,
                dirty_policy=dirty_policy,
                approved_path_manifest=approved_path_manifest,
                name=child_name,
            )
            wt_record = _worktree_mod.prepare(
                ws_spec,
                operation_id=operation_id,
                worktrees_home=self.worktrees_home,
            )
            canonical_ws = wt_record.canonical_worktree_path
            target_scope = self._map_scope_for_handoff(source_scope, source_cwd, canonical_ws, workspace_mode)
            new_task_rev = expected_rev + 1

            assignment = RunAssignment(
                node_id=node_id,
                runtime_sid=child_runtime_sid,
                turn_seq=1,
                run_id=run_id,
                worker_turn_id=worker_turn_id,
                input_id=input_id,
                message_id=message_id,
                parent_node_id=parent_id,
                dispatch_group_id=eff_group_id,
                member_id=member_id,
                task_id=task_id,
                task_revision=new_task_rev,
                owner_epoch=1,
                fencing_token=fencing_token,
            )
            brief_content = self._build_brief_markdown(
                title=title,
                prompt=remaining_plan,
                context_mode=context_applied,
                background_sections={
                    "overall_goal": title,
                    "decisions": "承接父会话已登记任务进度",
                    "constraints": "严格在交接任务作用域内完成剩余计划",
                },
                background_raw=None,
                history_summary=history_summary,
                remaining_plan=remaining_plan,
                assignment_view=assignment.child_view(),
            )
            brief_hash = sha256_hex(brief_content)
            self.store.write_artifact_blob(f"artifacts/briefs/{node_id}/{brief_id}.md", brief_content.encode("utf-8"))
            self.store.export_child_brief(parent_id, node_id, brief_content)
            self.store.atomic_export(f"side-session-notes/{parent_id}/{child_name}-brief.md", brief_content)

            if self.runtime_execution == "deferred":
                with self.store.transaction("IMMEDIATE") as txn:
                    now = self._now_iso()
                    txn.execute(
                        """
                        INSERT INTO nodes (
                            node_id, runtime_session_id, parent_node_id, root_node_id, name, title,
                            node_status, pause_requested, task_kind, context_requested, context_applied,
                            workspace_mode, canonical_workspace, repo_root, base_commit,
                            host_link_verified, recovery_status, last_turn_report, last_turn_seq,
                            primary_task_id, brief_id, brief_revision, brief_hash, brief_content,
                            revision, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 'active', 0, ?, 'fork', ?, ?, ?, ?, ?, 0, 'topology_restored',
                                  '', 1, ?, ?, 1, ?, ?, 1, ?, ?)
                        """,
                        (
                            node_id,
                            child_runtime_sid,
                            parent_id,
                            root_id,
                            child_name,
                            title,
                            task_kind,
                            context_applied,
                            workspace_mode,
                            canonical_ws,
                            wt_record.repo_root,
                            wt_record.base_commit,
                            task_id,
                            brief_id,
                            brief_hash,
                            brief_content,
                            now,
                            now,
                        ),
                    )
                    txn.execute(
                        """
                        INSERT INTO bindings (
                            runtime_sid, node_id, schema_version, last_turn_id, cwd, last_seen_at, db_check_state
                        ) VALUES (?, ?, ?, NULL, ?, ?, 'pending')
                        """,
                        (child_runtime_sid, node_id, ENGINE_SCHEMA_VERSION, canonical_ws, now),
                    )
                    if workspace_mode == "branch":
                        txn.execute(
                            """
                            INSERT INTO worktrees (
                                worktree_id, node_id, operation_id, canonical_worktree_path,
                                worktrees_home, workspace_mode, repo_key, repo_root, base_commit,
                                branch, source_patch_hash, ownership_marker, state, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, 'branch', ?, ?, ?, ?, ?, ?, 'in_use', ?, ?)
                            """,
                            (
                                wt_record.worktree_id,
                                node_id,
                                operation_id,
                                wt_record.canonical_worktree_path,
                                wt_record.worktrees_home,
                                wt_record.repo_key,
                                wt_record.repo_root,
                                wt_record.base_commit,
                                wt_record.branch,
                                wt_record.source_patch_hash,
                                wt_record.ownership_marker,
                                now,
                                now,
                            ),
                        )
                    msg_envelope = (
                        f'<cross-session-message from="{parent_id}" name="{parent_node["name"]}">\n'
                        f"{brief_content}\n"
                        f"</cross-session-message>"
                    )
                    txn.execute(
                        """
                        INSERT INTO inbox_messages (
                            message_id, target_node_id, source_node_id, seq, delivery_kind,
                            dispatch_group_id, member_id, task_id, payload_hash, payload,
                            state, run_id, created_at, updated_at
                        ) VALUES (?, ?, ?, 1, 'managed_dispatch', ?, ?, ?, ?, ?, 'claimed', ?, ?, ?)
                        """,
                        (
                            message_id,
                            node_id,
                            parent_id,
                            eff_group_id,
                            member_id,
                            task_id,
                            sha256_hex(msg_envelope),
                            msg_envelope,
                            run_id,
                            now,
                            now,
                        ),
                    )
                    txn.execute(
                        """
                        INSERT INTO owners (
                            node_id, worker_id, owner_token, owner_epoch, fencing_token,
                            current_run_id, heartbeat, state
                        ) VALUES (?, ?, ?, 1, ?, ?, ?, 'active')
                        """,
                        (
                            node_id,
                            f"worker:{node_id[:8]}",
                            f"tok:{uuid.uuid4().hex}",
                            fencing_token,
                            run_id,
                            now,
                        ),
                    )
                    txn.execute(
                        """
                        INSERT INTO turns (
                            run_id, node_id, turn_seq, worker_turn_id, runtime_turn_id,
                            input_id, message_id, dispatch_group_id, member_id, task_id,
                            task_revision, owner_epoch, fencing_token, execution_state,
                            report_state, started_at
                        ) VALUES (?, ?, 1, ?, NULL, ?, ?, ?, ?, ?, ?, 1, ?, 'starting', 'none', ?)
                        """,
                        (
                            run_id,
                            node_id,
                            worker_turn_id,
                            input_id,
                            message_id,
                            eff_group_id,
                            member_id,
                            task_id,
                            new_task_rev,
                            fencing_token,
                            now,
                        ),
                    )
                    txn.execute(
                        "UPDATE parent_slots SET state = 'starting', updated_at = ? WHERE parent_node_id = ? AND node_id = ?",
                        (now, parent_id, node_id),
                    )
                    txn.execute(
                        "UPDATE dispatch_group_members SET state = 'starting', updated_at = ? WHERE member_id = ?",
                        (now, member_id),
                    )
                    txn.execute(
                        """
                        UPDATE transfers
                        SET child_node_id = ?,
                            target_scope_json = ?,
                            state = 'transferring',
                            brief_hash = ?,
                            updated_at = ?
                        WHERE transfer_id = ?
                        """,
                        (
                            node_id,
                            canonical_json(target_scope),
                            brief_hash,
                            now,
                            transfer_id,
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
                        (canonical_json({"workspace": canonical_ws, "branch": wt_record.branch}), now, operation_id),
                    )
                    transfer_res = {
                        "ok": True,
                        "request_id": req.request_id,
                        "transfer_id": transfer_id,
                        "operation_id": operation_id,
                        "task_id": task_id,
                        "task_revision": new_task_rev,
                        "owner_node_id": parent_id,
                        "node_id": node_id,
                        "child_node_id": node_id,
                        "runtime_session_id": child_runtime_sid,
                        "name": child_name,
                        "title": title,
                        "remaining_plan": remaining_plan,
                        "task_kind": task_kind,
                        "workspace_mode": workspace_mode,
                        "branch": wt_record.branch,
                        "worktree_path": canonical_ws,
                        "context_requested": "fork",
                        "context_applied": context_applied,
                        "history_quality": history_quality,
                        "snapshot_hash": snapshot_hash,
                        "guard_id": guard_receipt.guard_id,
                        "dispatch_group_id": eff_group_id,
                        "member_id": member_id,
                        "run_id": run_id,
                        "turn_seq": 1,
                        "worker_turn_id": worker_turn_id,
                        "status": "transfer_pending",
                        "execution_state": "starting",
                        "runtime_state": "queued_for_worker",
                        "host_link_verified": False,
                        "revision": txn.revision,
                    }
                    self._record_idempotent_request(
                        txn.conn,
                        parent_id,
                        "hand_off_to_session",
                        req.request_id,
                        req.normalized_hash,
                        transfer_res,
                        operation_id=operation_id,
                    )

                self.store.export_parent_notes(parent_id)
                self._notify_supervisor(
                    {
                        "event": "handoff_started",
                        "operation_id": operation_id,
                        "node_id": node_id,
                        "run_id": run_id,
                        "transfer_id": transfer_id,
                    }
                )
                return transfer_res

            prof = runtime_profile_for_task_kind(task_kind)
            create_spec = RuntimeCreateSpec(
                assignment=assignment,
                workspace_path=canonical_ws,
                parent_runtime_sid=parent_sid,
                mode=prof.mode,
                model={},
                tool_allowlist=list(prof.tool_allowlist or []),
                tool_denylist=list(prof.tool_denylist),
                additional_directories=[],
                persistence="immediate",
                preallocated_session_id=child_runtime_sid,
                brief_ref=f"side-session-notes/{parent_id}/{node_id}-brief.md",
                context_applied=context_applied,
            )
            handle = self._driver_create(create_spec)
            actual_sid = handle.runtime_sid or child_runtime_sid

            # 9. Brief accepted -> Atomically switch task owner to child_node_id & commit_task_guard
            with self.store.transaction("IMMEDIATE") as txn:
                now = self._now_iso()
                txn.execute(
                    """
                    INSERT INTO nodes (
                        node_id, runtime_session_id, parent_node_id, root_node_id, name, title,
                        node_status, pause_requested, task_kind, context_requested, context_applied,
                        workspace_mode, canonical_workspace, repo_root, base_commit,
                        host_link_verified, recovery_status, last_turn_report, last_turn_seq,
                        primary_task_id, brief_id, brief_revision, brief_hash, brief_content,
                        revision, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'active', 0, ?, 'fork', ?, ?, ?, ?, ?, 1, 'runtime_resumable',
                              '', 1, ?, ?, 1, ?, ?, 1, ?, ?)
                    """,
                    (
                        node_id,
                        actual_sid,
                        parent_id,
                        root_id,
                        child_name,
                        title,
                        task_kind,
                        context_applied,
                        workspace_mode,
                        canonical_ws,
                        wt_record.repo_root,
                        wt_record.base_commit,
                        task_id,
                        brief_id,
                        brief_hash,
                        brief_content,
                        now,
                        now,
                    ),
                )
                txn.execute(
                    """
                    INSERT INTO bindings (
                        runtime_sid, node_id, schema_version, last_turn_id, cwd, last_seen_at, db_check_state
                    ) VALUES (?, ?, ?, NULL, ?, ?, 'verified')
                    """,
                    (actual_sid, node_id, ENGINE_SCHEMA_VERSION, canonical_ws, now),
                )
                if workspace_mode == "branch":
                    txn.execute(
                        """
                        INSERT INTO worktrees (
                            worktree_id, node_id, operation_id, canonical_worktree_path,
                            worktrees_home, workspace_mode, repo_key, repo_root, base_commit,
                            branch, source_patch_hash, ownership_marker, state, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, 'branch', ?, ?, ?, ?, ?, ?, 'in_use', ?, ?)
                        """,
                        (
                            wt_record.worktree_id,
                            node_id,
                            operation_id,
                            wt_record.canonical_worktree_path,
                            wt_record.worktrees_home,
                            wt_record.repo_key,
                            wt_record.repo_root,
                            wt_record.base_commit,
                            wt_record.branch,
                            wt_record.source_patch_hash,
                            wt_record.ownership_marker,
                            now,
                            now,
                        ),
                    )
                msg_envelope = (
                    f'<cross-session-message from="{parent_id}" name="{parent_node["name"]}">\n'
                    f"{brief_content}\n"
                    f"</cross-session-message>"
                )
                txn.execute(
                    """
                    INSERT INTO inbox_messages (
                        message_id, target_node_id, source_node_id, seq, delivery_kind,
                        dispatch_group_id, member_id, task_id, payload_hash, payload,
                        state, run_id, created_at, updated_at
                    ) VALUES (?, ?, ?, 1, 'managed_dispatch', ?, ?, ?, ?, ?, 'running', ?, ?, ?)
                    """,
                    (
                        message_id,
                        node_id,
                        parent_id,
                        eff_group_id,
                        member_id,
                        task_id,
                        sha256_hex(msg_envelope),
                        msg_envelope,
                        run_id,
                        now,
                        now,
                    ),
                )
                txn.execute(
                    """
                    INSERT INTO owners (
                        node_id, worker_id, owner_token, owner_epoch, fencing_token,
                        runtime_instance_id, current_run_id, heartbeat, state
                    ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, 'active')
                    """,
                    (
                        node_id,
                        f"worker:{node_id[:8]}",
                        f"tok:{uuid.uuid4().hex}",
                        fencing_token,
                        handle.runtime_instance_id,
                        run_id,
                        now,
                    ),
                )
                txn.execute(
                    """
                    INSERT INTO turns (
                        run_id, node_id, turn_seq, worker_turn_id, runtime_turn_id,
                        input_id, message_id, dispatch_group_id, member_id, task_id,
                        task_revision, owner_epoch, fencing_token, execution_state,
                        report_state, started_at
                    ) VALUES (?, ?, 1, ?, NULL, ?, ?, ?, ?, ?, ?, 1, ?, 'starting', 'none', ?)
                    """,
                    (
                        run_id,
                        node_id,
                        worker_turn_id,
                        input_id,
                        message_id,
                        eff_group_id,
                        member_id,
                        task_id,
                        new_task_rev,
                        fencing_token,
                        now,
                    ),
                )
                txn.execute(
                    """
                    UPDATE tasks
                    SET owner_node_id = ?,
                        title = ?,
                        remaining_plan = ?,
                        task_kind = ?,
                        scope_json = ?,
                        state = 'active',
                        task_revision = ?,
                        current_transfer_id = ?,
                        updated_at = ?
                    WHERE task_id = ?
                    """,
                    (
                        node_id,
                        title,
                        remaining_plan,
                        task_kind,
                        canonical_json(target_scope),
                        new_task_rev,
                        transfer_id,
                        now,
                        task_id,
                    ),
                )
                txn.execute(
                    """
                    UPDATE transfers
                    SET child_node_id = ?,
                        target_scope_json = ?,
                        state = 'committed',
                        brief_hash = ?,
                        accepted_receipt = ?,
                        updated_at = ?
                    WHERE transfer_id = ?
                    """,
                    (
                        node_id,
                        canonical_json(target_scope),
                        brief_hash,
                        f"brief-accepted:{node_id}:{brief_id}",
                        now,
                        transfer_id,
                    ),
                )
                txn.execute("UPDATE task_turn_bindings SET state = 'released' WHERE task_id = ? AND state = 'frozen'", (task_id,))
                txn.execute(
                    """
                    UPDATE operations
                    SET stage = 'brief_accepted', revision = revision + 1, updated_at = ?
                    WHERE operation_id = ?
                    """,
                    (now, operation_id),
                )

            commit_rcpt = self._adapter_commit_task_guard(
                guard_id=guard_receipt.guard_id,
                child_node_id=node_id,
                new_task_revision=new_task_rev,
            )
            owner_now = self.store.conn.execute(
                "SELECT owner_node_id FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if getattr(commit_rcpt, "state", None) != "committed" or owner_now is None or str(owner_now["owner_node_id"]) != node_id:
                raise SideSessionError(
                    ErrorCode.HANDOFF_GUARD_UNAVAILABLE,
                    "commit_task_guard did not confirm committed ownership on the child before session/send",
                    {
                        "guard_id": getattr(commit_rcpt, "guard_id", None),
                        "commit_state": getattr(commit_rcpt, "state", None),
                        "owner_node_id": None if owner_now is None else owner_now["owner_node_id"],
                    },
                )
            send_rcpt = self._driver_send(
                handle,
                RuntimeInput(input_id=input_id, content=brief_content, origin="system/side_sessions"),
            )
            runtime_turn_id = send_rcpt.runtime_turn_id or f"rturn:{run_id[:8]}"

            with self.store.transaction("IMMEDIATE") as txn:
                now = self._now_iso()
                txn.execute(
                    "UPDATE turns SET runtime_turn_id = ?, execution_state = 'running' WHERE run_id = ?",
                    (runtime_turn_id, run_id),
                )
                txn.execute(
                    "UPDATE bindings SET last_turn_id = ?, last_seen_at = ? WHERE node_id = ?",
                    (runtime_turn_id, now, node_id),
                )
                txn.execute(
                    """
                    INSERT INTO task_turn_bindings (
                        binding_id, task_id, node_id, runtime_sid, runtime_turn_id,
                        task_revision, state, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
                    """,
                    (self._new_uuid(), task_id, node_id, actual_sid, runtime_turn_id, new_task_rev, now),
                )
                txn.execute(
                    "UPDATE parent_slots SET state = 'running', updated_at = ? WHERE parent_node_id = ? AND node_id = ?",
                    (now, parent_id, node_id),
                )
                txn.execute(
                    "UPDATE dispatch_group_members SET state = 'running', updated_at = ? WHERE member_id = ?",
                    (now, member_id),
                )
                txn.execute(
                    "UPDATE operations SET stage = 'running', result_state = 'committed', revision = revision + 1, updated_at = ? WHERE operation_id = ?",
                    (now, operation_id),
                )
                transfer_res = {
                    "ok": True,
                    "request_id": req.request_id,
                    "transfer_id": transfer_id,
                    "operation_id": operation_id,
                    "task_id": task_id,
                    "task_revision": new_task_rev,
                    "owner_node_id": node_id,
                    "node_id": node_id,
                    "child_node_id": node_id,
                    "runtime_session_id": actual_sid,
                    "name": child_name,
                    "title": title,
                    "remaining_plan": remaining_plan,
                    "task_kind": task_kind,
                    "workspace_mode": workspace_mode,
                    "branch": wt_record.branch,
                    "worktree_path": canonical_ws,
                    "context_requested": "fork",
                    "context_applied": context_applied,
                    "history_quality": history_quality,
                    "snapshot_hash": snapshot_hash,
                    "guard_id": commit_rcpt.guard_id,
                    "dispatch_group_id": eff_group_id,
                    "member_id": member_id,
                    "run_id": run_id,
                    "turn_seq": 1,
                    "worker_turn_id": worker_turn_id,
                    "status": "committed",
                    "execution_state": "running",
                    "host_link_verified": True,
                    "revision": txn.revision,
                }
                self._record_idempotent_request(
                    txn.conn,
                    parent_id,
                    "hand_off_to_session",
                    req.request_id,
                    req.normalized_hash,
                    transfer_res,
                    operation_id=operation_id,
                )

            self.store.export_parent_notes(parent_id)
            self._notify_supervisor(
                {
                    "event": "handoff_started",
                    "operation_id": operation_id,
                    "node_id": node_id,
                    "run_id": run_id,
                    "transfer_id": transfer_id,
                }
            )
            return transfer_res

        except Exception as exc:
            t_check = self.store.conn.execute("SELECT owner_node_id FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
            owner_is_parent = t_check is not None and str(t_check["owner_node_id"]) == parent_id
            transfer_row = self.store.conn.execute(
                "SELECT state FROM transfers WHERE transfer_id = ?",
                (transfer_id,),
            ).fetchone()
            transfer_committed = transfer_row is not None and str(transfer_row["state"]) == "committed"
            guard_state = getattr(guard_receipt, "state", None) if guard_receipt is not None else None

            if guard_state == "unknown":
                with self.store.transaction("IMMEDIATE") as rec_txn:
                    rec_txn.execute(
                        "UPDATE transfers SET state = 'reconciliation', updated_at = ? WHERE transfer_id = ?",
                        (self._now_iso(), transfer_id),
                    )
                    rec_txn.execute(
                        "UPDATE operations SET stage = 'reconciliation', error = ?, updated_at = ? WHERE operation_id = ?",
                        (str(exc), self._now_iso(), operation_id),
                    )
                raise

            if (not owner_is_parent) or transfer_committed:
                with self.store.transaction("IMMEDIATE") as rec_txn:
                    rec_txn.execute(
                        "UPDATE transfers SET state = 'reconciliation', updated_at = ? WHERE transfer_id = ?",
                        (self._now_iso(), transfer_id),
                    )
                    rec_txn.execute(
                        "UPDATE operations SET stage = 'reconciliation', error = ?, updated_at = ? WHERE operation_id = ?",
                        (str(exc), self._now_iso(), operation_id),
                    )
                    rec_txn.execute(
                        "UPDATE parent_slots SET state = 'reconciliation', updated_at = ? WHERE parent_node_id = ? AND node_id = ?",
                        (self._now_iso(), parent_id, node_id),
                    )
                raise

            resume_ok = False
            if guard_receipt is not None and guard_state in ("prepared", "requested"):
                resume_rcpt = self._adapter_resume_task_guard(
                    guard_id=guard_receipt.guard_id,
                    expected_task_revision=expected_rev,
                )
                resume_ok = getattr(resume_rcpt, "state", None) == "resumed"
            if not resume_ok:
                with self.store.transaction("IMMEDIATE") as rec_txn:
                    rec_txn.execute(
                        "UPDATE tasks SET state = 'paused', updated_at = ? WHERE task_id = ? AND owner_node_id = ?",
                        (self._now_iso(), task_id, parent_id),
                    )
                    rec_txn.execute(
                        "UPDATE transfers SET state = 'reconciliation', updated_at = ? WHERE transfer_id = ?",
                        (self._now_iso(), transfer_id),
                    )
                    rec_txn.execute(
                        "UPDATE operations SET stage = 'reconciliation', error = ?, updated_at = ? WHERE operation_id = ?",
                        (str(exc), self._now_iso(), operation_id),
                    )
                raise

            with self.store.transaction("IMMEDIATE") as comp_txn:
                now = self._now_iso()
                comp_txn.execute(
                    "UPDATE tasks SET state = 'active', current_transfer_id = NULL, updated_at = ? WHERE task_id = ? AND owner_node_id = ?",
                    (now, task_id, parent_id),
                )
                comp_txn.execute(
                    "UPDATE task_turn_bindings SET state = 'active' WHERE task_id = ? AND node_id = ? AND state = 'frozen'",
                    (task_id, parent_id),
                )
                comp_txn.execute(
                    "UPDATE transfers SET state = 'failed', updated_at = ? WHERE transfer_id = ?",
                    (now, transfer_id),
                )
                comp_txn.execute(
                    "UPDATE operations SET stage = 'failed', error = ?, updated_at = ? WHERE operation_id = ?",
                    (str(exc), now, operation_id),
                )
                comp_txn.execute(
                    "UPDATE parent_slots SET state = 'released', updated_at = ? WHERE parent_node_id = ? AND node_id = ?",
                    (now, parent_id, node_id),
                )
                comp_txn.execute(
                    """
                    UPDATE dispatch_group_members
                    SET state = 'terminal', outcome = 'failed', exit_confirmed = 'not_started_proven',
                        terminal_reason = ?, updated_at = ?
                    WHERE member_id = ?
                    """,
                    (str(exc), now, member_id),
                )
                self._maybe_finalize_dispatch_group_in_conn(comp_txn.conn, eff_group_id, comp_txn.store_instance_id)
            raise

    def complete_handoff_transfer(self, node_id: str) -> dict[str, Any] | None:
        """Complete a deferred handoff transfer once the worker has created the session and sent the brief."""
        tr_row = self.store.conn.execute(
            "SELECT * FROM transfers WHERE child_node_id = ? AND state IN ('preparing', 'transferring', 'brief_accepted') ORDER BY created_at DESC LIMIT 1",
            (node_id,),
        ).fetchone()
        if tr_row is None:
            return None

        transfer_id = str(tr_row["transfer_id"])
        task_id = str(tr_row["task_id"])
        guard_id = tr_row["guard_id"]
        new_task_rev = int(tr_row["source_task_revision"]) + 1
        node_row = self.store.conn.execute("SELECT * FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
        if node_row is None:
            return None

        with self.store.transaction("IMMEDIATE") as txn:
            now = self._now_iso()
            txn.execute(
                """
                UPDATE tasks
                SET owner_node_id = ?,
                    title = ?,
                    task_kind = ?,
                    scope_json = ?,
                    state = 'active',
                    task_revision = ?,
                    current_transfer_id = ?,
                    updated_at = ?
                WHERE task_id = ?
                """,
                (
                    node_id,
                    str(node_row["title"]),
                    str(node_row["task_kind"]),
                    str(tr_row["target_scope_json"] or "{}"),
                    new_task_rev,
                    transfer_id,
                    now,
                    task_id,
                ),
            )
            txn.execute(
                """
                UPDATE transfers
                SET state = 'committed',
                    accepted_receipt = ?,
                    updated_at = ?
                WHERE transfer_id = ?
                """,
                (f"brief-accepted:{node_id}:{tr_row['brief_id']}", now, transfer_id),
            )
            txn.execute("UPDATE task_turn_bindings SET state = 'released' WHERE task_id = ? AND state = 'frozen'", (task_id,))
            if tr_row["operation_id"]:
                txn.execute(
                    "UPDATE operations SET result_state = 'committed', revision = revision + 1, updated_at = ? WHERE operation_id = ?",
                    (now, tr_row["operation_id"]),
                )

        if guard_id:
            self._adapter_commit_task_guard(
                guard_id=str(guard_id),
                child_node_id=node_id,
                new_task_revision=new_task_rev,
            )
        return {"ok": True, "transfer_id": transfer_id, "task_id": task_id, "owner_node_id": node_id}

    def _adapter_prepare_task_guard(
        self,
        *,
        task_id: str,
        expected_revision: int,
        transfer_id: str,
        source_cutoff: SourceCutoff,
    ) -> GuardReceipt:
        adapter = self.host_adapter
        if hasattr(adapter, "prepare_task_guard") and callable(adapter.prepare_task_guard):
            res = adapter.prepare_task_guard(task_id, expected_revision, transfer_id, source_cutoff)
            if isinstance(res, GuardReceipt):
                return res
            if isinstance(res, Mapping):
                return GuardReceipt(**{k: v for k, v in res.items() if hasattr(GuardReceipt, k)})
        raise SideSessionError(ErrorCode.HANDOFF_GUARD_UNAVAILABLE, "prepare_task_guard is not available on host_adapter")

    def _adapter_commit_task_guard(
        self,
        *,
        guard_id: str,
        child_node_id: str,
        new_task_revision: int,
    ) -> GuardReceipt:
        adapter = self.host_adapter
        if hasattr(adapter, "commit_task_guard") and callable(adapter.commit_task_guard):
            res = adapter.commit_task_guard(guard_id, child_node_id, new_task_revision)
            if isinstance(res, GuardReceipt):
                return res
            if isinstance(res, Mapping):
                return GuardReceipt(**{k: v for k, v in res.items() if hasattr(GuardReceipt, k)})
        raise SideSessionError(ErrorCode.HANDOFF_GUARD_UNAVAILABLE, "commit_task_guard is not available on host_adapter")

    def _adapter_resume_task_guard(
        self,
        *,
        guard_id: str,
        expected_task_revision: int,
    ) -> GuardReceipt:
        adapter = self.host_adapter
        if hasattr(adapter, "resume_task_guard") and callable(adapter.resume_task_guard):
            res = adapter.resume_task_guard(guard_id, expected_task_revision)
            if isinstance(res, GuardReceipt):
                return res
            if isinstance(res, Mapping):
                return GuardReceipt(**{k: v for k, v in res.items() if hasattr(GuardReceipt, k)})
        raise SideSessionError(ErrorCode.HANDOFF_GUARD_UNAVAILABLE, "resume_task_guard is not available on host_adapter")

    # ------------------------------------------------------------------
    # 5. Turn Reporting, Outbox Events & R01 Read / ACK Loop (Section 6.5, 9, 10 & Prompt #5)
    # ------------------------------------------------------------------

    def _build_linked_sessions_summary_in_conn(self, conn: Any, parent_node_id: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT * FROM nodes WHERE parent_node_id = ? ORDER BY created_at ASC, node_id ASC",
            (parent_node_id,),
        ).fetchall()
        summaries: list[dict[str, Any]] = []
        for r in rows:
            enr = self._enrich_node_row(conn, r)
            summaries.append(
                {
                    "node_id": enr["node_id"],
                    "name": enr["name"],
                    "status": enr["status"],
                    "execution_state": enr["execution_state"],
                    "workspace_mode": enr["workspace_mode"],
                    "branch": enr["branch"],
                    "last_turn_report": enr["last_turn_report"],
                }
            )
        return summaries

    def _format_event_xml(self, event_payload: Mapping[str, Any]) -> str:
        ev_id = html.escape(str(event_payload.get("event_id") or ""), quote=True)
        kind = html.escape(str(event_payload.get("kind") or ""), quote=True)
        child_id = html.escape(str(event_payload.get("child_node_id") or ""), quote=True)
        child_name = html.escape(str(event_payload.get("child_name") or ""), quote=True)
        outcome = html.escape(str(event_payload.get("outcome") or ""), quote=True)
        recap = html.escape(str(event_payload.get("recap") or ""), quote=False)
        report_ref = html.escape(str(event_payload.get("report_ref") or ""), quote=True)
        manifest_ref = html.escape(str(event_payload.get("manifest_ref") or ""), quote=True)
        linked = event_payload.get("linked_sessions_now") or []
        linked_lines = ["Linked sessions now:"]
        for item in linked:
            linked_lines.append(
                f"- {item.get('name')} ({item.get('node_id')}): status={item.get('status')} exec={item.get('execution_state')}"
            )
        linked_str = html.escape("\n".join(linked_lines), quote=False)

        body_obj = {
            "event_id": event_payload.get("event_id"),
            "event_ref": event_payload.get("event_ref"),
            "event_seq": event_payload.get("event_seq"),
            "kind": event_payload.get("kind"),
            "dispatch_group_id": event_payload.get("dispatch_group_id"),
            "member_id": event_payload.get("member_id"),
            "child_node_id": event_payload.get("child_node_id"),
            "child_name": event_payload.get("child_name"),
            "run_id": event_payload.get("run_id"),
            "turn_seq": event_payload.get("turn_seq"),
            "outcome": event_payload.get("outcome"),
            "recap": recap,
            "report_ref": event_payload.get("report_ref"),
            "report_semantic_sha256": event_payload.get("report_semantic_sha256"),
            "manifest_ref": event_payload.get("manifest_ref"),
            "artifact_refs": event_payload.get("artifact_refs") or [],
        }
        return (
            f'<side-sessions-event event_id="{ev_id}" kind="{kind}" '
            f'child_node_id="{child_id}" child_name="{child_name}" outcome="{outcome}" '
            f'report_ref="{report_ref}" manifest_ref="{manifest_ref}">\n'
            f"{canonical_json(body_obj)}\n"
            f"{linked_str}\n"
            f"</side-sessions-event>"
        )

    def _insert_outbox_event_in_conn(
        self,
        conn: Any,
        *,
        store_instance_id: str,
        producer_key: str,
        parent_node_id: str,
        child_node_id: str | None,
        turn_seq: int | None,
        run_id: str | None,
        dispatch_group_id: str | None,
        member_id: str | None,
        kind: str,
        outcome: str | None,
        recap: str,
        report_ref: str | None,
        report_semantic_sha256: str | None,
        manifest_ref: str | None,
        artifact_refs: list[dict[str, Any]],
        child_turn_id: str | None = None,
    ) -> dict[str, Any]:
        existing = conn.execute(
            "SELECT * FROM outbox_events WHERE producer_key = ?",
            (producer_key,),
        ).fetchone()
        if existing is not None:
            return dict(existing)

        event_id = self._new_uuid()
        event_seq = int(
            conn.execute("SELECT COALESCE(MAX(event_seq), 0) + 1 AS next_seq FROM outbox_events").fetchone()["next_seq"]
        )
        event_ref = format_ssref(store_instance_id, "event", event_id)
        p_row = conn.execute("SELECT runtime_session_id FROM nodes WHERE node_id = ?", (parent_node_id,)).fetchone()
        parent_sid = str(p_row["runtime_session_id"]) if (p_row and p_row["runtime_session_id"]) else None

        child_sid: str | None = None
        child_name = ""
        if child_node_id:
            c_row = conn.execute("SELECT runtime_session_id, name FROM nodes WHERE node_id = ?", (child_node_id,)).fetchone()
            if c_row is not None:
                child_sid = str(c_row["runtime_session_id"]) if c_row["runtime_session_id"] else None
                child_name = str(c_row["name"] or "")

        linked_now = self._build_linked_sessions_summary_in_conn(conn, parent_node_id)
        payload_dict: dict[str, Any] = {
            "event_id": event_id,
            "event_ref": event_ref,
            "event_seq": event_seq,
            "producer_key": producer_key,
            "parent_node_id": parent_node_id,
            "parent_session_id": parent_sid,
            "child_node_id": child_node_id,
            "child_session_id": child_sid,
            "child_name": child_name,
            "child_turn_id": child_turn_id,
            "turn_seq": turn_seq,
            "run_id": run_id,
            "dispatch_group_id": dispatch_group_id,
            "member_id": member_id,
            "kind": kind,
            "outcome": outcome,
            "recap": format_recap_400(recap),
            "report_ref": report_ref,
            "report_semantic_sha256": report_semantic_sha256,
            "manifest_ref": manifest_ref,
            "artifact_refs": artifact_refs,
            "linked_sessions_now": linked_now,
        }
        payload_dict["formatted_event"] = self._format_event_xml(payload_dict)
        now = self._now_iso()

        conn.execute(
            """
            INSERT INTO outbox_events (
                event_id, event_seq, producer_key, parent_node_id, parent_session_id,
                child_node_id, child_session_id, child_turn_id, turn_seq, run_id,
                dispatch_group_id, member_id, kind, payload, state, attempt_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?)
            """,
            (
                event_id,
                event_seq,
                producer_key,
                parent_node_id,
                parent_sid,
                child_node_id,
                child_sid,
                child_turn_id,
                turn_seq,
                run_id,
                dispatch_group_id,
                member_id,
                kind,
                canonical_json(payload_dict),
                now,
            ),
        )
        row = conn.execute("SELECT * FROM outbox_events WHERE event_id = ?", (event_id,)).fetchone()
        return dict(row)

    def _has_external_live_worker(self, conn: Any, node_id: str, *, require_process: bool = False) -> bool:
        o_row = conn.execute("SELECT * FROM owners WHERE node_id = ?", (node_id,)).fetchone()
        if o_row is None:
            return False
        if o_row["pid"] is not None or o_row["model_pid"] is not None:
            return True
        if require_process:
            return False
        if o_row["current_run_id"]:
            return True
        if str(o_row["state"] or "") in ("active", "starting", "running", "running_external"):
            return True
        return False

    def _finalize_turn_core(
        self,
        *,
        child_node_id: str,
        run_id: str,
        turn_seq: int,
        worker_turn_id: str,
        phase: str,
        report_revision: int | None,
        outcome: str,
        recap: str,
        full_report: str,
        blocked: bool,
        block_reason: str | None,
        artifacts: list[dict[str, Any]],
        origin: str,
        request_id: str | None = None,
        normalized_hash: str | None = None,
        provided_fencing_token: str | None = None,
        provided_owner_epoch: int | None = None,
        caller_runtime_turn_id: str | None = None,
        exit_confirmed_override: bool | None = None,
    ) -> dict[str, Any]:
        t_pre = self.store.conn.execute(
            "SELECT * FROM turns WHERE node_id = ? AND turn_seq = ?",
            (child_node_id, turn_seq),
        ).fetchone()
        if t_pre is None or str(t_pre["run_id"]) != run_id or str(t_pre["worker_turn_id"]) != worker_turn_id:
            raise SideSessionError(
                ErrorCode.REPORT_TURN_UNBOUND,
                "Turn assignment (node_id, turn_seq, run_id, worker_turn_id) does not match active turn",
                {"node_id": child_node_id, "turn_seq": turn_seq, "run_id": run_id},
            )

        o_pre = self.store.conn.execute("SELECT * FROM owners WHERE node_id = ?", (child_node_id,)).fetchone()
        if provided_fencing_token is not None:
            if str(t_pre["fencing_token"]) != str(provided_fencing_token) or (
                o_pre is not None and str(o_pre["fencing_token"]) != str(provided_fencing_token)
            ):
                raise _err(
                    "STALE_FENCING_TOKEN",
                    "Provided fencing_token is stale or does not match current turn owner",
                    {"node_id": child_node_id, "run_id": run_id},
                    aliases=(ErrorCode.OWNERSHIP_CONFLICT, ErrorCode.FORBIDDEN),
                )
        if provided_owner_epoch is not None:
            if int(t_pre["owner_epoch"]) != int(provided_owner_epoch) or (
                o_pre is not None and int(o_pre["owner_epoch"]) != int(provided_owner_epoch)
            ):
                raise _err(
                    "STALE_FENCING_TOKEN",
                    "Provided owner_epoch is stale or does not match current turn owner",
                    {
                        "node_id": child_node_id,
                        "run_id": run_id,
                        "expected_epoch": o_pre["owner_epoch"] if o_pre else t_pre["owner_epoch"],
                        "provided_epoch": provided_owner_epoch,
                    },
                    aliases=(ErrorCode.OWNERSHIP_CONFLICT, ErrorCode.FORBIDDEN),
                )
        if o_pre is not None and int(o_pre["owner_epoch"]) > int(t_pre["owner_epoch"]):
            raise _err(
                "STALE_FENCING_TOKEN",
                "Turn owner_epoch has been superseded by a newer owner",
                {"node_id": child_node_id, "run_id": run_id},
                aliases=(ErrorCode.OWNERSHIP_CONFLICT, ErrorCode.FORBIDDEN),
            )

        bound_runtime_turn_id = t_pre["runtime_turn_id"]
        if (
            caller_runtime_turn_id
            and bound_runtime_turn_id
            and not str(bound_runtime_turn_id).startswith("rturn:")
            and str(caller_runtime_turn_id) != str(bound_runtime_turn_id)
        ):
            raise SideSessionError(
                ErrorCode.REPORT_TURN_UNBOUND,
                "Caller runtime_turn_id does not match turn assignment",
                {"caller_runtime_turn_id": caller_runtime_turn_id, "bound_runtime_turn_id": bound_runtime_turn_id},
            )
        eff_runtime_turn_id = (
            str(caller_runtime_turn_id or bound_runtime_turn_id or "")
            if (not bound_runtime_turn_id or str(bound_runtime_turn_id).startswith("rturn:"))
            else str(bound_runtime_turn_id)
        ) or None

        canon_report = CanonicalReport(
            node_id=child_node_id,
            run_id=run_id,
            turn_seq=turn_seq,
            worker_turn_id=worker_turn_id,
            runtime_turn_id=eff_runtime_turn_id,
            phase=phase,
            report_revision=None if phase == "final" else int(report_revision or 1),
            outcome=outcome,
            blocked=bool(blocked),
            block_reason=block_reason if blocked else None,
            recap=recap,
            full_report=full_report,
            artifacts=artifacts,
        )
        semantic_sha = canon_report.semantic_sha256()
        recap_400 = format_recap_400(canon_report.recap)

        # Pre-write full report markdown blob outside DB transaction (Section 4.3 & 9.2)
        candidate_report_id = self._new_uuid()
        candidate_full_art_id = self._new_uuid()
        rel_report_blob = f"artifacts/reports/{child_node_id}/{run_id}/{candidate_report_id}.md"
        blob_export = self.store.write_artifact_blob(rel_report_blob, canon_report.full_report.encode("utf-8"))

        parent_id_for_export: str | None = None

        with self.store.transaction("IMMEDIATE") as txn:
            c_node = txn.execute("SELECT * FROM nodes WHERE node_id = ?", (child_node_id,)).fetchone()
            if c_node is None or not c_node["parent_node_id"]:
                raise _err(
                    "PERMISSION_DENIED",
                    "Only a child session with a parent can submit turn reports",
                    {"node_id": child_node_id},
                    aliases=(ErrorCode.FORBIDDEN, ErrorCode.NO_PARENT),
                )
            parent_id = str(c_node["parent_node_id"])
            parent_id_for_export = parent_id

            # Validate and publish referenced artifacts
            published_art_refs: list[dict[str, Any]] = []
            for art in canon_report.artifacts:
                _, _, art_id = parse_ssref(
                    art["ref"],
                    expected_store_id=txn.store_instance_id,
                    expected_kind="artifact",
                )
                a_row = txn.execute("SELECT * FROM artifacts WHERE artifact_id = ?", (art_id,)).fetchone()
                if a_row is None or str(a_row["owner_node_id"]) != child_node_id:
                    raise SideSessionError(
                        ErrorCode.NOT_FOUND_OR_FORBIDDEN,
                        f"Referenced artifact does not exist or belong to child session: {art['ref']}",
                    )
                if a_row["run_id"] is not None and str(a_row["run_id"]) != run_id:
                    raise SideSessionError(
                        ErrorCode.NOT_FOUND_OR_FORBIDDEN,
                        f"Referenced artifact belongs to a different run: {art['ref']}",
                    )
                if str(a_row["sha256"]) != str(art["sha256"]) or int(a_row["byte_length"]) != int(art["byte_length"]):
                    raise SideSessionError(
                        ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                        f"Referenced artifact hash or byte_length mismatch: {art['ref']}",
                    )
                txn.execute("UPDATE artifacts SET state = 'published' WHERE artifact_id = ?", (art_id,))
                published_art_refs.append(dict(art))

            if phase == "checkpoint":
                existing_ckpt = txn.execute(
                    """
                    SELECT * FROM reports
                    WHERE node_id = ? AND turn_seq = ? AND phase = 'checkpoint' AND report_revision = ?
                    """,
                    (child_node_id, turn_seq, canon_report.report_revision),
                ).fetchone()
                if existing_ckpt is not None:
                    if str(existing_ckpt["semantic_sha256"]) == semantic_sha:
                        ev_row = txn.execute(
                            "SELECT event_id FROM outbox_events WHERE child_node_id = ? AND turn_seq = ? AND kind = ?",
                            (child_node_id, turn_seq, f"checkpoint:{canon_report.report_revision}"),
                        ).fetchone()
                        rcpt = ReportReceipt(
                            report_id=str(existing_ckpt["report_id"]),
                            event_id=str(ev_row["event_id"]) if ev_row else "",
                            node_id=child_node_id,
                            turn_seq=turn_seq,
                            run_id=run_id,
                            phase="checkpoint",
                            report_revision=canon_report.report_revision,
                            semantic_sha256=semantic_sha,
                            duplicate=True,
                            revision=txn.revision,
                        ).to_dict()
                        rcpt["ok"] = True
                        rcpt["report_ref"] = format_ssref(txn.store_instance_id, "report", str(existing_ckpt["report_id"]))
                        return rcpt
                    raise SideSessionError(
                        ErrorCode.REPORT_CONFLICT,
                        "Conflicting checkpoint report content for identical report_revision",
                        {"node_id": child_node_id, "turn_seq": turn_seq, "report_revision": canon_report.report_revision},
                    )

                max_rev_row = txn.execute(
                    """
                    SELECT MAX(report_revision) AS max_rev FROM reports
                    WHERE node_id = ? AND turn_seq = ? AND phase = 'checkpoint'
                    """,
                    (child_node_id, turn_seq),
                ).fetchone()
                if max_rev_row and max_rev_row["max_rev"] is not None:
                    if int(canon_report.report_revision or 0) <= int(max_rev_row["max_rev"]):
                        raise SideSessionError(
                            ErrorCode.REPORT_CONFLICT,
                            "Checkpoint report_revision must be strictly greater than previous revision",
                            {"report_revision": canon_report.report_revision, "max_revision": max_rev_row["max_rev"]},
                        )
            else:
                # phase == "final"
                existing_final = txn.execute(
                    "SELECT * FROM reports WHERE node_id = ? AND turn_seq = ? AND phase = 'final'",
                    (child_node_id, turn_seq),
                ).fetchone()
                if existing_final is not None:
                    ev_row = txn.execute(
                        "SELECT event_id FROM outbox_events WHERE child_node_id = ? AND turn_seq = ? AND kind = 'terminal'",
                        (child_node_id, turn_seq),
                    ).fetchone()
                    if origin == "runner" or str(existing_final["semantic_sha256"]) == semantic_sha:
                        rcpt = ReportReceipt(
                            report_id=str(existing_final["report_id"]),
                            event_id=str(ev_row["event_id"]) if ev_row else "",
                            node_id=child_node_id,
                            turn_seq=turn_seq,
                            run_id=run_id,
                            phase="final",
                            report_revision=None,
                            semantic_sha256=str(existing_final["semantic_sha256"]),
                            duplicate=True,
                            revision=txn.revision,
                        ).to_dict()
                        rcpt["ok"] = True
                        rcpt["report_ref"] = format_ssref(txn.store_instance_id, "report", str(existing_final["report_id"]))
                        if request_id and normalized_hash and origin == "child":
                            self._record_idempotent_request(
                                txn.conn,
                                child_node_id,
                                "report_child_turn",
                                request_id,
                                normalized_hash,
                                rcpt,
                            )
                        return rcpt
                    raise SideSessionError(
                        ErrorCode.REPORT_CONFLICT,
                        "Conflicting final report submitted for the same turn",
                        {"node_id": child_node_id, "turn_seq": turn_seq},
                    )

            # Insert new report & full_report artifact
            now = self._now_iso()
            txn.execute(
                """
                INSERT INTO artifacts (
                    artifact_id, owner_node_id, run_id, kind, storage_kind,
                    inline_bytes, relative_blob_path, sha256, byte_length,
                    media_type, state, created_at
                ) VALUES (?, ?, ?, 'report_markdown', 'blob', NULL, ?, ?, ?, 'text/markdown', 'published', ?)
                """,
                (
                    candidate_full_art_id,
                    child_node_id,
                    run_id,
                    blob_export.relative_path,
                    blob_export.sha256,
                    blob_export.byte_length,
                    now,
                ),
            )
            full_report_ref = format_ssref(txn.store_instance_id, "artifact", candidate_full_art_id)
            report_ref = format_ssref(txn.store_instance_id, "report", candidate_report_id)

            txn.execute(
                """
                INSERT INTO reports (
                    report_id, node_id, turn_seq, run_id, phase, report_revision,
                    canonical_json, semantic_sha256, full_report_ref, artifact_ref,
                    artifact_sha256, outcome, origin, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate_report_id,
                    child_node_id,
                    turn_seq,
                    run_id,
                    phase,
                    canon_report.report_revision,
                    canonical_json(canon_report.semantic_dict()),
                    semantic_sha,
                    full_report_ref,
                    published_art_refs[0]["ref"] if published_art_refs else None,
                    published_art_refs[0]["sha256"] if published_art_refs else None,
                    outcome,
                    origin,
                    now,
                ),
            )

            # Update nodes and turns
            if eff_runtime_turn_id and not str(eff_runtime_turn_id).startswith("rturn:"):
                self._upgrade_synthetic_turn_binding(
                    child_node_id,
                    str(c_node["runtime_session_id"] or ""),
                    eff_runtime_turn_id,
                    run_id=run_id,
                    conn=txn.conn,
                )
            txn.execute(
                """
                UPDATE nodes
                SET last_turn_report = ?,
                    last_turn_seq = CASE WHEN ? > last_turn_seq THEN ? ELSE last_turn_seq END,
                    revision = revision + 1,
                    updated_at = ?
                WHERE node_id = ?
                """,
                (recap_400, turn_seq, turn_seq, now, child_node_id),
            )
            new_rep_state = "final" if phase == "final" else "checkpointed"
            txn.execute(
                """
                UPDATE turns
                SET runtime_turn_id = CASE
                        WHEN runtime_turn_id IS NULL OR runtime_turn_id = '' OR runtime_turn_id LIKE 'rturn:%'
                        THEN COALESCE(?, runtime_turn_id)
                        ELSE runtime_turn_id
                    END,
                    report_state = CASE WHEN report_state = 'final' THEN 'final' ELSE ? END,
                    outcome = CASE WHEN ? = 'final' THEN ? ELSE COALESCE(outcome, ?) END
                WHERE run_id = ?
                """,
                (eff_runtime_turn_id, new_rep_state, phase, outcome, outcome, run_id),
            )

            t_row = txn.execute("SELECT * FROM turns WHERE run_id = ?", (run_id,)).fetchone()
            dispatch_group_id = t_row["dispatch_group_id"]
            member_id = t_row["member_id"]

            if canon_report.blocked:
                txn.execute(
                    "UPDATE nodes SET node_status = 'paused', updated_at = ? WHERE node_id = ?",
                    (now, child_node_id),
                )
                txn.execute(
                    "UPDATE turns SET execution_state = 'waiting_input' WHERE run_id = ?",
                    (run_id,),
                )
                txn.execute(
                    "UPDATE parent_slots SET state = 'waiting_input', updated_at = ? WHERE node_id = ? AND state != 'released'",
                    (now, child_node_id),
                )
                if member_id:
                    txn.execute(
                        """
                        UPDATE dispatch_group_members
                        SET state = 'waiting_input', outcome = 'blocked', report_id = ?, updated_at = ?
                        WHERE member_id = ?
                        """,
                        (candidate_report_id, now, member_id),
                    )
                existing_wait = txn.execute(
                    "SELECT wait_id FROM wait_requests WHERE run_id = ? AND state IN ('open', 'responding') LIMIT 1",
                    (run_id,),
                ).fetchone()
                if existing_wait is None:
                    wait_id = self._new_uuid()
                    o_cur = txn.execute("SELECT * FROM owners WHERE node_id = ?", (child_node_id,)).fetchone()
                    inst_id = str(o_cur["runtime_instance_id"] if (o_cur and o_cur["runtime_instance_id"]) else f"inst:{child_node_id}")
                    epoch_val = int(t_row["owner_epoch"])
                    txn.execute(
                        """
                        INSERT INTO wait_requests (
                            wait_id, node_id, run_id, runtime_turn_id, runtime_instance_id,
                            owner_epoch, host_request_id, kind, nonce, question, options,
                            required_authority, deadline_at, state, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'input', ?, ?, '[]', 'parent_agent_allowed', ?, 'open', ?, ?)
                        """,
                        (
                            wait_id,
                            child_node_id,
                            run_id,
                            eff_runtime_turn_id,
                            inst_id,
                            epoch_val,
                            f"block-wait:{run_id}:{turn_seq}",
                            self._new_uuid(),
                            canon_report.block_reason or recap_400,
                            self._future_iso(hours=24),
                            now,
                            now,
                        ),
                    )
            elif phase == "final":
                if member_id:
                    txn.execute(
                        "UPDATE dispatch_group_members SET outcome = ?, report_id = ?, updated_at = ? WHERE member_id = ?",
                        (outcome, candidate_report_id, now, member_id),
                    )
                should_complete_turn = exit_confirmed_override is True
                if should_complete_turn:
                    has_queued = txn.execute(
                        "SELECT 1 FROM inbox_messages WHERE target_node_id = ? AND state = 'queued' LIMIT 1",
                        (child_node_id,),
                    ).fetchone() is not None
                    pause_req = bool(c_node["pause_requested"])
                    if pause_req or outcome in ("failed", "cancelled", "blocked"):
                        next_node_status = "paused"
                    elif has_queued:
                        next_node_status = "active"
                    else:
                        next_node_status = "done"

                    next_exec_state = (
                        "exited"
                        if outcome == "success"
                        else ("cancelled" if outcome == "cancelled" else "failed")
                    )
                    txn.execute(
                        "UPDATE nodes SET node_status = ?, pause_requested = 0, updated_at = ? WHERE node_id = ?",
                        (next_node_status, now, child_node_id),
                    )
                    txn.execute(
                        "UPDATE turns SET execution_state = ?, ended_at = COALESCE(ended_at, ?) WHERE run_id = ?",
                        (next_exec_state, now, run_id),
                    )
                    txn.execute(
                        "UPDATE inbox_messages SET state = ?, updated_at = ? WHERE target_node_id = ? AND message_id = ?",
                        ("completed" if outcome == "success" else "failed", now, child_node_id, t_row["message_id"]),
                    )
                    if t_row["task_id"]:
                        next_task_state = "done" if next_node_status == "done" else ("paused" if next_node_status == "paused" else "active")
                        txn.execute(
                            """
                            UPDATE tasks
                            SET state = ?, task_revision = task_revision + 1, updated_at = ?
                            WHERE task_id = ? AND owner_node_id = ?
                            """,
                            (next_task_state, now, t_row["task_id"], child_node_id),
                        )
                        txn.execute(
                            "UPDATE task_turn_bindings SET state = 'released' WHERE task_id = ? AND node_id = ? AND state = 'active'",
                            (t_row["task_id"], child_node_id),
                        )
                    txn.execute(
                        "UPDATE parent_slots SET state = 'released', updated_at = ? WHERE node_id = ? AND state != 'released'",
                        (now, child_node_id),
                    )
                    txn.execute(
                        "UPDATE operations SET stage = 'finished', result_state = ?, updated_at = ? WHERE node_id = ? AND stage = 'running'",
                        (outcome, now, child_node_id),
                    )
                    if member_id:
                        txn.execute(
                            """
                            UPDATE dispatch_group_members
                            SET state = 'terminal',
                                outcome = ?,
                                exit_confirmed = 'confirmed',
                                report_id = ?,
                                updated_at = ?
                            WHERE member_id = ?
                            """,
                            (outcome, candidate_report_id, now, member_id),
                        )

            ev_kind = "terminal" if phase == "final" else f"checkpoint:{canon_report.report_revision}"
            producer_key = f"turn:{child_node_id}:{turn_seq}:{ev_kind}"
            ev_row = self._insert_outbox_event_in_conn(
                txn.conn,
                store_instance_id=txn.store_instance_id,
                producer_key=producer_key,
                parent_node_id=parent_id,
                child_node_id=child_node_id,
                turn_seq=turn_seq,
                run_id=run_id,
                dispatch_group_id=dispatch_group_id,
                member_id=member_id,
                kind=ev_kind,
                outcome=outcome,
                recap=recap_400,
                report_ref=report_ref,
                report_semantic_sha256=semantic_sha,
                manifest_ref=None,
                artifact_refs=published_art_refs,
                child_turn_id=eff_runtime_turn_id,
            )

            if dispatch_group_id and phase == "final" and not canon_report.blocked:
                self._maybe_finalize_dispatch_group_in_conn(txn.conn, str(dispatch_group_id), txn.store_instance_id)

            rcpt = ReportReceipt(
                report_id=candidate_report_id,
                event_id=str(ev_row["event_id"]),
                node_id=child_node_id,
                turn_seq=turn_seq,
                run_id=run_id,
                phase=phase,
                report_revision=canon_report.report_revision,
                semantic_sha256=semantic_sha,
                duplicate=False,
                revision=txn.revision,
            ).to_dict()
            rcpt["ok"] = True
            rcpt["report_ref"] = report_ref
            rcpt["full_report_ref"] = full_report_ref
            if request_id and normalized_hash and origin == "child":
                self._record_idempotent_request(
                    txn.conn,
                    child_node_id,
                    "report_child_turn",
                    request_id,
                    normalized_hash,
                    rcpt,
                )

        if parent_id_for_export:
            self.store.export_child_report(parent_id_for_export, child_node_id, canon_report.full_report)
            self.store.export_events(parent_id_for_export)
        return rcpt

    def report_child_turn(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Submit a checkpoint or final turn report from a child session."""
        ctx = self._coerce_caller(caller)
        internal_exit_confirmed = kwargs.pop("_internal_exit_confirmed", None)
        provided_fencing_token = kwargs.pop("_internal_fencing_token", None)
        provided_owner_epoch = kwargs.pop("_internal_owner_epoch", None)
        raw_args = self._merge_args(args, kwargs)
        exit_confirmed_override = internal_exit_confirmed

        child_node = self.ensure_caller_node(ctx)
        child_id = str(child_node["node_id"])

        # Allow convenience defaults if worker_turn_id / blocked are omitted in casual tests
        if "worker_turn_id" not in raw_args and "run_id" in raw_args:
            t_lookup = self.store.conn.execute(
                "SELECT worker_turn_id FROM turns WHERE run_id = ? AND node_id = ?",
                (str(raw_args["run_id"]), child_id),
            ).fetchone()
            if t_lookup is not None:
                raw_args["worker_turn_id"] = str(t_lookup["worker_turn_id"])

        req = normalize_request("report_child_turn", raw_args)

        if provided_fencing_token is None and provided_owner_epoch is None:
            cached = self._check_idempotent_request(
                self.store.conn,
                child_id,
                "report_child_turn",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

        return self._finalize_turn_core(
            child_node_id=child_id,
            run_id=req["run_id"],
            turn_seq=req["turn_seq"],
            worker_turn_id=req["worker_turn_id"],
            phase=req["phase"],
            report_revision=req["report_revision"],
            outcome=req["outcome"],
            recap=req["recap"],
            full_report=req["full_report"],
            blocked=req["blocked"],
            block_reason=req["block_reason"],
            artifacts=req["artifacts"],
            origin="child",
            request_id=req.request_id,
            normalized_hash=req.normalized_hash,
            provided_fencing_token=provided_fencing_token,
            provided_owner_epoch=provided_owner_epoch,
            caller_runtime_turn_id=ctx.runtime_turn_id,
            exit_confirmed_override=exit_confirmed_override,
        )

    def finalize_turn_from_worker(
        self,
        owner_context: Any,
        run_id: str,
        report: CanonicalReport | Mapping[str, Any],
        *,
        exit_receipt: ExitReceipt | Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Controlled internal entrypoint for worker_runner fallback finalization (Section 9.1 & Prompt #5)."""
        t_row = self.store.conn.execute("SELECT * FROM turns WHERE run_id = ?", (run_id,)).fetchone()
        if t_row is None:
            raise SideSessionError(ErrorCode.REPORT_TURN_UNBOUND, f"Run not found: {run_id}")

        child_node_id = str(t_row["node_id"])
        fencing_token: str | None = None
        owner_epoch: int | None = None
        if isinstance(owner_context, Mapping):
            fencing_token = owner_context.get("fencing_token")
            owner_epoch = owner_context.get("owner_epoch")
        else:
            fencing_token = getattr(owner_context, "fencing_token", None)
            owner_epoch = getattr(owner_context, "owner_epoch", None)

        if isinstance(report, CanonicalReport):
            rep_dict = report.to_dict()
        elif isinstance(report, Mapping):
            rep_dict = dict(report)
        else:
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "report must be CanonicalReport or Mapping")

        outcome = str(rep_dict.get("outcome", "success"))
        blocked = bool(rep_dict.get("blocked", outcome == "blocked"))
        block_reason = rep_dict.get("block_reason")
        recap = str(rep_dict.get("recap") or "Worker fallback turn completion")
        full_report = str(rep_dict.get("full_report") or recap)
        artifacts = list(rep_dict.get("artifacts") or [])

        exit_confirmed = True
        if isinstance(exit_receipt, ExitReceipt):
            exit_confirmed = bool(exit_receipt.exit_confirmed)
        elif isinstance(exit_receipt, Mapping):
            exit_confirmed = bool(exit_receipt.get("exit_confirmed", True))

        return self._finalize_turn_core(
            child_node_id=child_node_id,
            run_id=run_id,
            turn_seq=int(t_row["turn_seq"]),
            worker_turn_id=str(t_row["worker_turn_id"]),
            phase="final",
            report_revision=None,
            outcome=outcome,
            recap=recap,
            full_report=full_report,
            blocked=blocked,
            block_reason=block_reason,
            artifacts=artifacts,
            origin="runner",
            provided_fencing_token=fencing_token,
            provided_owner_epoch=owner_epoch,
            exit_confirmed_override=exit_confirmed,
        )

    finalize_from_owner = finalize_turn_from_worker

    def close_run(
        self,
        owner_context: Any,
        exit_receipt: ExitReceipt | Mapping[str, Any],
        fallback_report: CanonicalReport | Mapping[str, Any] | None = None,
        *,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        """Finalize run exit, emit execution_failure event if process failed after a success final, and release slot."""
        if isinstance(exit_receipt, ExitReceipt):
            rcpt = exit_receipt
        elif isinstance(exit_receipt, Mapping):
            rcpt = ExitReceipt(
                runtime_instance_id=str(exit_receipt.get("runtime_instance_id", "")),
                process_identity=dict(exit_receipt.get("process_identity") or {}),
                exit_confirmed=bool(exit_receipt.get("exit_confirmed", True)),
                runtime_outcome=str(exit_receipt.get("runtime_outcome", "success")),
                ended_at=str(exit_receipt.get("ended_at") or self._now_iso()),
                exit_code=exit_receipt.get("exit_code", 0),
                evidence_ref=str(exit_receipt.get("evidence_ref", "")),
            )
        else:
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "exit_receipt must be ExitReceipt or Mapping")

        eff_run_id = run_id or (
            owner_context.get("run_id") if isinstance(owner_context, Mapping) else getattr(owner_context, "run_id", None)
        )
        if not eff_run_id:
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "run_id is required for close_run")

        if not rcpt.exit_confirmed:
            return {"ok": False, "run_id": eff_run_id, "exit_confirmed": False, "slot_released": False}

        if fallback_report is not None:
            self.finalize_turn_from_worker(owner_context, eff_run_id, fallback_report, exit_receipt=rcpt)

        with self.store.transaction("IMMEDIATE") as txn:
            t_row = txn.execute("SELECT * FROM turns WHERE run_id = ?", (eff_run_id,)).fetchone()
            if t_row is None:
                raise SideSessionError(ErrorCode.NOT_FOUND, f"Run not found: {eff_run_id}")
            child_id = str(t_row["node_id"])
            turn_seq = int(t_row["turn_seq"])
            c_node = txn.execute("SELECT * FROM nodes WHERE node_id = ?", (child_id,)).fetchone()
            parent_id = str(c_node["parent_node_id"])
            now = self._now_iso()

            existing_final = txn.execute(
                "SELECT * FROM reports WHERE node_id = ? AND turn_seq = ? AND phase = 'final'",
                (child_id, turn_seq),
            ).fetchone()

            process_failed = rcpt.runtime_outcome in ("failed", "error") or (
                rcpt.exit_code is not None and int(rcpt.exit_code) != 0
            )
            if existing_final is not None and str(existing_final["outcome"]) == "success" and process_failed:
                # Emit unique execution_failure event without overwriting existing final report (Section 9.2 #5)
                self._insert_outbox_event_in_conn(
                    txn.conn,
                    store_instance_id=txn.store_instance_id,
                    producer_key=f"turn:{child_id}:{turn_seq}:execution_failure",
                    parent_node_id=parent_id,
                    child_node_id=child_id,
                    turn_seq=turn_seq,
                    run_id=eff_run_id,
                    dispatch_group_id=t_row["dispatch_group_id"],
                    member_id=t_row["member_id"],
                    kind="execution_failure",
                    outcome="failed",
                    recap=f"Process exited with code={rcpt.exit_code} outcome={rcpt.runtime_outcome} after final report",
                    report_ref=format_ssref(txn.store_instance_id, "report", str(existing_final["report_id"])),
                    report_semantic_sha256=str(existing_final["semantic_sha256"]),
                    manifest_ref=None,
                    artifact_refs=[],
                )

            final_outcome = (
                "failed"
                if process_failed
                else (str(existing_final["outcome"]) if existing_final else rcpt.runtime_outcome)
            )
            exec_state = (
                "exited"
                if final_outcome == "success"
                else ("cancelled" if final_outcome == "cancelled" else "failed")
            )
            txn.execute(
                """
                UPDATE turns
                SET execution_state = ?, outcome = ?, exit_code = ?, ended_at = ?
                WHERE run_id = ?
                """,
                (exec_state, final_outcome, rcpt.exit_code, rcpt.ended_at or now, eff_run_id),
            )
            txn.execute(
                "UPDATE wait_requests SET state = 'cancelled', updated_at = ? WHERE run_id = ? AND state IN ('open', 'responding')",
                (now, eff_run_id),
            )
            txn.execute(
                "UPDATE control_commands SET state = 'applied', updated_at = ? WHERE run_id = ? AND kind = 'cancel_run' AND state IN ('queued', 'claimed')",
                (now, eff_run_id),
            )
            txn.execute(
                "UPDATE parent_slots SET state = 'released', updated_at = ? WHERE node_id = ? AND state != 'released'",
                (now, child_id),
            )
            txn.execute(
                "UPDATE owners SET pid = NULL, model_pid = NULL, current_run_id = NULL, state = 'idle', heartbeat = ? WHERE node_id = ?",
                (now, child_id),
            )
            txn.execute(
                """
                UPDATE inbox_messages
                SET state = ?, updated_at = ?
                WHERE target_node_id = ? AND message_id = ? AND state IN ('claimed', 'running')
                """,
                (
                    "completed"
                    if final_outcome == "success"
                    else ("cancelled" if final_outcome == "cancelled" else "failed"),
                    now,
                    child_id,
                    t_row["message_id"],
                ),
            )
            txn.execute(
                """
                UPDATE operations
                SET stage = 'finished', result_state = ?, updated_at = ?
                WHERE node_id = ? AND stage = 'running'
                """,
                (final_outcome, now, child_id),
            )
            pause_req = bool(c_node["pause_requested"]) if c_node is not None else False
            has_queued = txn.execute(
                "SELECT 1 FROM inbox_messages WHERE target_node_id = ? AND state = 'queued' LIMIT 1",
                (child_id,),
            ).fetchone() is not None
            if pause_req or final_outcome in ("failed", "cancelled", "blocked"):
                next_node_status = "paused"
            elif has_queued:
                next_node_status = "active"
            else:
                next_node_status = "done"
            txn.execute(
                "UPDATE nodes SET node_status = ?, pause_requested = 0, revision = revision + 1, updated_at = ? WHERE node_id = ?",
                (next_node_status, now, child_id),
            )
            if t_row["task_id"]:
                next_task_state = "done" if next_node_status == "done" else ("paused" if next_node_status == "paused" else "active")
                txn.execute(
                    """
                    UPDATE tasks
                    SET state = ?, task_revision = task_revision + 1, updated_at = ?
                    WHERE task_id = ? AND owner_node_id = ?
                    """,
                    (next_task_state, now, t_row["task_id"], child_id),
                )
            if t_row["member_id"]:
                txn.execute(
                    """
                    UPDATE dispatch_group_members
                    SET state = 'terminal',
                        outcome = COALESCE(?, outcome),
                        exit_confirmed = 'confirmed',
                        updated_at = ?
                    WHERE member_id = ?
                    """,
                    (final_outcome, now, t_row["member_id"]),
                )
            if t_row["dispatch_group_id"]:
                self._maybe_finalize_dispatch_group_in_conn(txn.conn, str(t_row["dispatch_group_id"]), txn.store_instance_id)

            return {
                "ok": True,
                "run_id": eff_run_id,
                "node_id": child_id,
                "execution_state": exec_state,
                "outcome": final_outcome,
                "exit_confirmed": True,
                "slot_released": True,
                "revision": txn.revision,
            }

    # ------------------------------------------------------------------
    # R01 Event, Report & Artifact Read / ACK Methods (Section 6.5)
    # ------------------------------------------------------------------

    def _row_to_event_view(self, row: Mapping[str, Any], store_instance_id: str) -> dict[str, Any]:
        payload = json.loads(row["payload"] or "{}")
        ev_id = str(row["event_id"])
        ev_ref = payload.get("event_ref") or format_ssref(store_instance_id, "event", ev_id)
        view = EventView(
            event_id=ev_id,
            event_ref=ev_ref,
            event_seq=int(row["event_seq"]),
            kind=str(row["kind"]),
            state=str(row["state"]),
            dispatch_group_id=row["dispatch_group_id"],
            outcome=payload.get("outcome"),
            recap=str(payload.get("recap") or ""),
            artifact_refs=list(payload.get("artifact_refs") or []),
            member_id=row["member_id"],
            run_id=row["run_id"],
            report_ref=payload.get("report_ref"),
            report_semantic_sha256=payload.get("report_semantic_sha256"),
            manifest_ref=payload.get("manifest_ref"),
        ).to_dict()
        view["child_node_id"] = row["child_node_id"]
        view["parent_node_id"] = row["parent_node_id"]
        view["turn_seq"] = row["turn_seq"]
        view["formatted_event"] = payload.get("formatted_event")
        view["linked_sessions_now"] = payload.get("linked_sessions_now") or []
        return view

    def _encode_event_cursor(self, cursor_obj: Mapping[str, Any]) -> str:
        body = canonical_json(cursor_obj)
        sig = sha256_hex(f"{self.store.store_instance_id}:{body}")[:16]
        token = canonical_json({"b": cursor_obj, "s": sig})
        return base64.urlsafe_b64encode(token.encode("utf-8")).decode("ascii")

    def _decode_event_cursor(
        self,
        cursor_str: str,
        *,
        expected_actor_id: str,
        expected_states: list[str],
    ) -> dict[str, Any]:
        try:
            raw = base64.urlsafe_b64decode(cursor_str.encode("ascii")).decode("utf-8")
            parsed = json.loads(raw)
            body_obj = parsed["b"]
            sig = parsed["s"]
        except Exception as exc:
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "Malformed event pagination cursor") from exc

        expected_sig = sha256_hex(f"{self.store.store_instance_id}:{canonical_json(body_obj)}")[:16]
        if sig != expected_sig:
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "Event pagination cursor signature mismatch")
        if str(body_obj.get("actor_node_id")) != expected_actor_id:
            raise _err(
                ErrorCode.NOT_FOUND_OR_FORBIDDEN,
                "Event cursor belongs to a different caller node",
                aliases=("PERMISSION_DENIED", ErrorCode.FORBIDDEN),
            )
        if list(body_obj.get("states") or []) != list(expected_states):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "Event cursor state filter does not match request states",
            )
        if self._is_expired(body_obj.get("expires_at")):
            raise SideSessionError(ErrorCode.EXPIRED, "Event pagination cursor has expired")
        return dict(body_obj)

    def list_events(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """List outbox events where the caller is the direct parent recipient (without modifying state or ACKing)."""
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("list_events", raw_args)
        caller_node = self.ensure_caller_node(caller)
        caller_id = str(caller_node["node_id"])
        states = list(req["states"])
        limit = int(req["limit"])
        store_id = self.store.store_instance_id

        with self.store.transaction("READONLY") as txn:
            if req["cursor"] is not None:
                cur_data = self._decode_event_cursor(
                    req["cursor"],
                    expected_actor_id=caller_id,
                    expected_states=states,
                )
                last_seq = int(cur_data["last_seq"])
                high_watermark = int(cur_data["high_watermark"])
                as_of_rev = int(cur_data["as_of_revision"])
            else:
                last_seq = 0
                hw_row = txn.execute(
                    "SELECT COALESCE(MAX(event_seq), 0) AS hw FROM outbox_events WHERE parent_node_id = ?",
                    (caller_id,),
                ).fetchone()
                high_watermark = int(hw_row["hw"])
                as_of_rev = self.store.get_revision()

            placeholders = ", ".join("?" for _ in states)
            rows = txn.execute(
                f"""
                SELECT * FROM outbox_events
                WHERE parent_node_id = ?
                  AND state IN ({placeholders})
                  AND event_seq > ?
                  AND event_seq <= ?
                ORDER BY event_seq ASC
                LIMIT ?
                """,
                (caller_id, *states, last_seq, high_watermark, limit + 1),
            ).fetchall()

            has_more = len(rows) > limit
            page_rows = rows[:limit]
            items = [self._row_to_event_view(r, store_id) for r in page_rows]

            next_cursor: str | None = None
            if has_more and page_rows:
                next_cursor = self._encode_event_cursor(
                    {
                        "actor_node_id": caller_id,
                        "states": states,
                        "last_seq": int(page_rows[-1]["event_seq"]),
                        "high_watermark": high_watermark,
                        "as_of_revision": as_of_rev,
                        "expires_at": self._future_iso(minutes=10),
                    }
                )

            page = EventPage(
                items=items,
                next_cursor=next_cursor,
                as_of_revision=as_of_rev,
                high_watermark=high_watermark,
            ).to_dict()
            page["ok"] = True
            return page

    def get_event(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("get_event", raw_args)
        caller_node = self.ensure_caller_node(caller)
        caller_id = str(caller_node["node_id"])
        event_id = req["event_id"]

        ev_row = self.store.conn.execute(
            "SELECT * FROM outbox_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if ev_row is None:
            raise SideSessionError(ErrorCode.NOT_FOUND_OR_FORBIDDEN, f"Event not found: {event_id}")

        parent_id = str(ev_row["parent_node_id"])
        if not self._is_ancestor_or_self(self.store.conn, caller_id, parent_id):
            raise _err(
                ErrorCode.NOT_FOUND_OR_FORBIDDEN,
                "Caller is not authorized to read this event",
                {"event_id": event_id},
                aliases=("PERMISSION_DENIED", ErrorCode.FORBIDDEN),
            )

        view = self._row_to_event_view(ev_row, self.store.store_instance_id)
        view["ok"] = True
        return view

    def read_report(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Read a structured report by `report_ref`, verify its blob and semantic SHA-256 integrity."""
        raw_args = self._merge_args(args, kwargs)
        if "report_ref" not in raw_args and "report_id" in raw_args:
            raw_args["report_ref"] = format_ssref(
                self.store.store_instance_id,
                "report",
                str(raw_args.pop("report_id")),
            )
        req = normalize_request("read_report", raw_args)
        caller_node = self.ensure_caller_node(caller)
        caller_id = str(caller_node["node_id"])
        store_id = self.store.store_instance_id

        _, _, report_id = parse_ssref(
            req["report_ref"],
            expected_store_id=store_id,
            expected_kind="report",
        )
        r_row = self.store.conn.execute("SELECT * FROM reports WHERE report_id = ?", (report_id,)).fetchone()
        if r_row is None:
            raise SideSessionError(ErrorCode.NOT_FOUND_OR_FORBIDDEN, "Report not found or forbidden")

        author_id = str(r_row["node_id"])
        if not self._is_ancestor_or_self(self.store.conn, caller_id, author_id):
            raise _err(
                ErrorCode.NOT_FOUND_OR_FORBIDDEN,
                "Caller is not authorized to read this report",
                {"report_ref": req["report_ref"]},
                aliases=("PERMISSION_DENIED", ErrorCode.FORBIDDEN),
            )

        author_node = self.store.conn.execute("SELECT parent_node_id FROM nodes WHERE node_id = ?", (author_id,)).fetchone()
        parent_id = str(author_node["parent_node_id"] or "") if author_node else ""

        # Read full report blob and verify integrity
        _, _, full_art_id = parse_ssref(
            str(r_row["full_report_ref"]),
            expected_store_id=store_id,
            expected_kind="artifact",
        )
        full_art = self.store.conn.execute("SELECT * FROM artifacts WHERE artifact_id = ?", (full_art_id,)).fetchone()
        if full_art is None:
            raise SideSessionError(ErrorCode.ARTIFACT_INTEGRITY_ERROR, "Full report artifact record is missing")

        try:
            if full_art["storage_kind"] == "inline":
                raw_bytes = bytes(full_art["inline_bytes"])
            else:
                raw_bytes = self.store.read_safe_bytes(full_art["relative_blob_path"])
        except Exception as exc:
            raise SideSessionError(
                ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                f"Failed to read full report blob: {exc}",
            ) from exc

        if sha256_hex(raw_bytes) != str(full_art["sha256"]) or len(raw_bytes) != int(full_art["byte_length"]):
            raise SideSessionError(
                ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                "Full report blob SHA-256 or byte length mismatch",
            )

        full_report_text = raw_bytes.decode("utf-8")
        saved_semantic = json.loads(r_row["canonical_json"] or "{}")
        reconstructed = CanonicalReport(
            node_id=str(saved_semantic["node_id"]),
            run_id=str(saved_semantic["run_id"]),
            turn_seq=int(saved_semantic["turn_seq"]),
            worker_turn_id=str(saved_semantic["worker_turn_id"]),
            runtime_turn_id=saved_semantic.get("runtime_turn_id"),
            phase=str(saved_semantic["phase"]),
            report_revision=saved_semantic.get("report_revision"),
            outcome=str(saved_semantic["outcome"]),
            blocked=bool(saved_semantic["blocked"]),
            block_reason=saved_semantic.get("block_reason"),
            recap=str(saved_semantic["recap"]),
            full_report=full_report_text,
            artifacts=list(saved_semantic.get("artifacts") or []),
            schema_version=str(saved_semantic.get("schema_version", ENGINE_SCHEMA_VERSION)),
        )
        if reconstructed.semantic_sha256() != str(r_row["semantic_sha256"]):
            raise SideSessionError(
                ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                "Recomputed report semantic_sha256 does not match stored hash",
            )

        view = ReportView(
            report_ref=req["report_ref"],
            report_id=report_id,
            author_node_id=author_id,
            parent_node_id=parent_id,
            run_id=str(r_row["run_id"]),
            turn_seq=int(r_row["turn_seq"]),
            phase=str(r_row["phase"]),
            report_revision=r_row["report_revision"],
            semantic_fields=reconstructed.semantic_fields_without_full_report(),
            semantic_sha256=str(r_row["semantic_sha256"]),
            full_report_ref=str(r_row["full_report_ref"]),
            artifact_refs=list(saved_semantic.get("artifacts") or []),
            integrity_verified=True,
        ).to_dict()
        view["ok"] = True
        view["outcome"] = reconstructed.outcome
        view["recap"] = reconstructed.recap
        view["full_report"] = full_report_text
        return view

    def read_artifact(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Read an immutable artifact or report/manifest blob in paged Base64 byte chunks with SHA-256 verification."""
        raw_args = self._merge_args(args, kwargs)
        if "limit" in raw_args and "max_bytes" not in raw_args:
            raw_args["max_bytes"] = raw_args.pop("limit")
        req = normalize_request("read_artifact", raw_args)
        caller_node = self.ensure_caller_node(caller)
        caller_id = str(caller_node["node_id"])
        store_id = self.store.store_instance_id

        _, _, artifact_id = parse_ssref(
            req["artifact_ref"],
            expected_store_id=store_id,
            expected_kind="artifact",
        )
        a_row = self.store.conn.execute("SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,)).fetchone()
        if a_row is None or str(a_row["state"]) != "published":
            raise SideSessionError(
                ErrorCode.NOT_FOUND_OR_FORBIDDEN,
                "Artifact not found, unpublished, or forbidden",
                {"artifact_ref": req["artifact_ref"]},
            )

        owner_id = str(a_row["owner_node_id"])
        if not self._is_ancestor_or_self(self.store.conn, caller_id, owner_id):
            raise _err(
                ErrorCode.NOT_FOUND_OR_FORBIDDEN,
                "Caller is not authorized to read this artifact",
                {"artifact_ref": req["artifact_ref"]},
                aliases=("PERMISSION_DENIED", ErrorCode.FORBIDDEN),
            )

        offset = int(req["offset"])
        max_bytes = int(req["max_bytes"])
        cache_key = str(artifact_id)
        cached = self._artifact_identity_cache.get(cache_key)

        def _file_identity(path: Path) -> tuple[int | None, int, int | None]:
            st = os.lstat(path)
            return int(st.st_ino), int(st.st_size), int(st.st_mtime_ns) if hasattr(st, "st_mtime_ns") else int(st.st_mtime)

        try:
            if a_row["storage_kind"] == "inline":
                raw_bytes = bytes(a_row["inline_bytes"])
                ident = (None, len(raw_bytes), None, sha256_hex(raw_bytes))
                if cached and tuple(cached.get("ident") or ()) != ident:
                    raise SideSessionError(
                        ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                        "Inline artifact identity changed between pages",
                        {"artifact_ref": req["artifact_ref"]},
                    )
                self._artifact_identity_cache[cache_key] = {"ident": ident, "sha256": ident[3], "total": ident[1]}
                total_bytes = ident[1]
                full_sha = ident[3]
                chunk_bytes = raw_bytes[offset : offset + max_bytes]
            else:
                blob_path = self.store.safe_resolve(a_row["relative_blob_path"], mkdirs=False)
                ino, size, mtime = _file_identity(blob_path)
                if cached is None:
                    raw_bytes = self.store.read_safe_bytes(a_row["relative_blob_path"])
                    full_sha = sha256_hex(raw_bytes)
                    if full_sha != str(a_row["sha256"]) or len(raw_bytes) != int(a_row["byte_length"]):
                        raise SideSessionError(
                            ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                            "Artifact content SHA-256 or byte_length does not match recorded digest",
                            {"artifact_ref": req["artifact_ref"]},
                        )
                    self._artifact_identity_cache[cache_key] = {
                        "ident": (ino, size, mtime, full_sha),
                        "sha256": full_sha,
                        "total": size,
                    }
                    chunk_bytes = raw_bytes[offset : offset + max_bytes]
                    total_bytes = size
                else:
                    if tuple(cached.get("ident") or ())[:3] != (ino, size, mtime) or cached.get("sha256") != str(a_row["sha256"]):
                        raise SideSessionError(
                            ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                            "Artifact file identity changed; refusing to mix pages across versions",
                            {"artifact_ref": req["artifact_ref"]},
                        )
                    total_bytes = int(cached["total"])
                    full_sha = str(cached["sha256"])
                    with open(blob_path, "rb") as f:
                        f.seek(offset)
                        chunk_bytes = f.read(max_bytes)
        except SideSessionError:
            raise
        except Exception as exc:
            raise SideSessionError(
                ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                f"Failed to read artifact bytes: {exc}",
            ) from exc

        if offset > total_bytes:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"offset ({offset}) exceeds artifact total_bytes ({total_bytes})",
                {"offset": offset, "total_bytes": total_bytes},
            )
        next_offset = offset + len(chunk_bytes)
        eof = next_offset >= total_bytes
        chunk_sha = sha256_hex(chunk_bytes)
        b64_str = base64.b64encode(chunk_bytes).decode("ascii")

        chunk_res = ArtifactChunk(
            ref=req["artifact_ref"],
            offset=offset,
            returned_bytes=len(chunk_bytes),
            total_bytes=total_bytes,
            media_type=str(a_row["media_type"]),
            sha256=full_sha,
            chunk_sha256=chunk_sha,
            data_base64=b64_str,
            next_offset=next_offset,
            eof=eof,
        ).to_dict()
        chunk_res["ok"] = True
        return chunk_res

    def publish_artifact(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Snapshot a file from the child's approved workspace into a staged artifact for the current run."""
        ctx = self._coerce_caller(caller)
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("publish_artifact", raw_args)
        child_node = self.ensure_caller_node(ctx)
        child_id = str(child_node["node_id"])
        if ctx.runtime_turn_id and not str(ctx.runtime_turn_id).startswith("rturn:"):
            self._upgrade_synthetic_turn_binding(
                child_id,
                ctx.runtime_sid,
                ctx.runtime_turn_id,
                run_id=req["run_id"],
            )

        cached = self._check_idempotent_request(
            self.store.conn,
            child_id,
            "publish_artifact",
            req.request_id,
            req.normalized_hash,
        )
        if cached is not None:
            return cached

        t_row = self.store.conn.execute(
            "SELECT * FROM turns WHERE run_id = ? AND node_id = ?",
            (req["run_id"], child_id),
        ).fetchone()
        if t_row is None or t_row["execution_state"] not in ("starting", "running", "waiting_input"):
            raise SideSessionError(
                ErrorCode.NOT_FOUND_OR_FORBIDDEN,
                "Active run not found for caller in publish_artifact",
                {"run_id": req["run_id"]},
            )

        workspace = str(child_node.get("canonical_workspace") or "")
        if not workspace:
            raise SideSessionError(ErrorCode.UNSAFE_PATH, "Child session has no canonical_workspace")

        rel_path = req["relative_path"]
        if t_row["task_id"]:
            task_row = self.store.conn.execute("SELECT scope_json FROM tasks WHERE task_id = ?", (t_row["task_id"],)).fetchone()
            if task_row is not None:
                scope_obj = json.loads(task_row["scope_json"] or "{}")
                allowed_roots = list(scope_obj.get("artifact_source_roots") or [])
                if allowed_roots:
                    ws_real = os.path.realpath(workspace)
                    cand_target = safe_resolve_under(ws_real, rel_path, mkdirs=False)
                    allowed = False
                    for r_root in allowed_roots:
                        r_path = Path(r_root) if str(r_root).startswith("/") else (Path(ws_real) / str(r_root))
                        r_real = os.path.realpath(r_path) if r_path.exists() else str(r_path.resolve())
                        if str(cand_target) == r_real or str(cand_target).startswith(r_real.rstrip("/") + "/"):
                            allowed = True
                            break
                    if not allowed:
                        raise _err(
                            ErrorCode.FORBIDDEN,
                            f"relative_path '{rel_path}' is outside task approved artifact_source_roots",
                            {"relative_path": rel_path, "artifact_source_roots": allowed_roots},
                            aliases=("PERMISSION_DENIED", ErrorCode.NOT_FOUND_OR_FORBIDDEN),
                        )

        src_file = safe_resolve_under(workspace, rel_path, mkdirs=False)
        if not src_file.exists():
            raise SideSessionError(ErrorCode.NOT_FOUND, f"Artifact source file not found: {rel_path}")

        st_before = os.lstat(src_file)
        fd = os.open(str(src_file), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            with os.fdopen(fd, "rb", closefd=False) as f:
                data = f.read()
        finally:
            os.close(fd)
        st_after = os.lstat(src_file)

        if (
            st_before.st_ino != st_after.st_ino
            or st_before.st_mtime_ns != st_after.st_mtime_ns
            or st_before.st_size != st_after.st_size
            or len(data) != st_before.st_size
        ):
            raise SideSessionError(
                ErrorCode.SOURCE_CHANGED,
                "Artifact source file changed concurrently during snapshot",
                {"relative_path": rel_path},
            )

        actual_sha = sha256_hex(data)
        if actual_sha != req["expected_sha256"]:
            raise SideSessionError(
                ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                f"Artifact SHA-256 mismatch: expected {req['expected_sha256']}, got {actual_sha}",
                {"relative_path": rel_path, "expected_sha256": req["expected_sha256"], "actual_sha256": actual_sha},
            )

        artifact_id = self._new_uuid()
        blob_rel = f"artifacts/blobs/{child_id}/{artifact_id}"
        export_ref = self.store.write_artifact_blob(blob_rel, data)

        with self.store.transaction("IMMEDIATE") as txn:
            now = self._now_iso()
            txn.execute(
                """
                INSERT INTO artifacts (
                    artifact_id, owner_node_id, run_id, kind, storage_kind,
                    inline_bytes, relative_blob_path, sha256, byte_length,
                    media_type, state, source_manifest, created_at
                ) VALUES (?, ?, ?, 'blob', 'blob', NULL, ?, ?, ?, ?, 'staged', ?, ?)
                """,
                (
                    artifact_id,
                    child_id,
                    req["run_id"],
                    export_ref.relative_path,
                    actual_sha,
                    len(data),
                    req["media_type"],
                    canonical_json({"relative_path": rel_path, "ino": st_after.st_ino, "size": len(data)}),
                    now,
                ),
            )
            art_ref = ArtifactRef(
                ref=format_ssref(txn.store_instance_id, "artifact", artifact_id),
                sha256=actual_sha,
                byte_length=len(data),
                media_type=req["media_type"],
            ).to_dict()
            art_ref["ok"] = True
            art_ref["artifact_id"] = artifact_id
            art_ref["state"] = "staged"
            art_ref["request_id"] = req.request_id
            art_ref["revision"] = txn.revision
            self._record_idempotent_request(
                txn.conn,
                child_id,
                "publish_artifact",
                req.request_id,
                req.normalized_hash,
                art_ref,
            )
            return art_ref

    def ack_events(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Acknowledge outbox events as consumed by their direct parent session."""
        raw_args = self._merge_args(args, kwargs)
        if "request_id" not in raw_args:
            raw_args["request_id"] = self._new_uuid()
        req = normalize_request("ack_events", raw_args)
        caller_node = self.ensure_caller_node(caller)
        caller_id = str(caller_node["node_id"])
        event_ids = list(req["event_ids"])

        with self.store.transaction("IMMEDIATE") as txn:
            cached = self._check_idempotent_request(
                txn.conn,
                caller_id,
                "ack_events",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

            for eid in event_ids:
                ev_row = txn.execute(
                    "SELECT event_id, parent_node_id, state FROM outbox_events WHERE event_id = ?",
                    (eid,),
                ).fetchone()
                if ev_row is None or str(ev_row["parent_node_id"]) != caller_id:
                    raise _err(
                        ErrorCode.NOT_FOUND_OR_FORBIDDEN,
                        f"Event {eid} not found or caller is not its direct parent recipient",
                        {"event_id": eid, "caller_node_id": caller_id},
                        aliases=("PERMISSION_DENIED", ErrorCode.FORBIDDEN),
                    )

            now = self._now_iso()
            for eid in event_ids:
                txn.execute(
                    "UPDATE outbox_events SET state = 'acked', acked_at = COALESCE(acked_at, ?) WHERE event_id = ?",
                    (now, eid),
                )
                txn.execute(
                    """
                    INSERT OR IGNORE INTO event_acks (
                        event_id, consumer_parent_node_id, receipt_kind, receipt_ref, acked_at
                    ) VALUES (?, ?, 'explicit_ack', ?, ?)
                    """,
                    (eid, caller_id, f"ack:{req.request_id}:{eid}", now),
                )

            res = {
                "ok": True,
                "request_id": req.request_id,
                "acked_event_ids": event_ids,
                "acked_count": len(event_ids),
                "state": "acked",
                "revision": txn.revision,
            }
            self._record_idempotent_request(
                txn.conn,
                caller_id,
                "ack_events",
                req.request_id,
                req.normalized_hash,
                res,
            )

        self.store.export_events(caller_id)
        return res

    # ------------------------------------------------------------------
    # Notes & Shared Context (Section 4.4 & 6.3)
    # ------------------------------------------------------------------

    def read_brief(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("read_brief", raw_args)
        caller_node = self.ensure_caller_node(caller)
        target_node = (
            self.resolve_target_node(caller, req["session_id"], require_manage=True)
            if req["session_id"] is not None
            else caller_node
        )
        target_id = str(target_node["node_id"])

        latest_turn = self.store.conn.execute(
            "SELECT * FROM turns WHERE node_id = ? ORDER BY turn_seq DESC LIMIT 1",
            (target_id,),
        ).fetchone()
        if latest_turn is not None:
            assignment = RunAssignment(
                node_id=target_id,
                runtime_sid=str(target_node["runtime_session_id"] or ""),
                turn_seq=int(latest_turn["turn_seq"]),
                run_id=str(latest_turn["run_id"]),
                worker_turn_id=str(latest_turn["worker_turn_id"]),
                input_id=str(latest_turn["input_id"] or ""),
                message_id=str(latest_turn["message_id"]),
                parent_node_id=str(target_node["parent_node_id"] or ""),
                dispatch_group_id=str(latest_turn["dispatch_group_id"] or ""),
                member_id=str(latest_turn["member_id"] or ""),
                task_id=latest_turn["task_id"],
                task_revision=latest_turn["task_revision"],
                owner_epoch=int(latest_turn["owner_epoch"]),
                fencing_token=str(latest_turn["fencing_token"]),
            )
            assignment_view = assignment.child_view()
        else:
            assignment_view = {"node_id": target_id}

        snap = BriefSnapshot(
            node_id=target_id,
            brief_id=str(target_node["brief_id"] or ""),
            brief_revision=int(target_node["brief_revision"] or 0),
            brief_hash=str(target_node["brief_hash"] or ""),
            content=str(target_node["brief_content"] or ""),
            context_applied=str(target_node["context_applied"] or "fresh"),
            assignment_view=assignment_view,
            source_anchor=None,
        ).to_dict()
        snap["ok"] = True
        return snap

    def read_context(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("read_context", raw_args)
        caller_node = self.ensure_caller_node(caller)
        root_id = str(caller_node["root_node_id"])
        target_id = req["root"] or str(caller_node["parent_node_id"] or caller_node["node_id"])

        target_row = self.resolve_target_node(caller, target_id)
        entries = [
            dict(r)
            for r in self.store.conn.execute(
                "SELECT * FROM note_entries WHERE owner_node_id = ? ORDER BY revision ASC, created_at ASC",
                (target_row["node_id"],),
            ).fetchall()
        ]
        return {
            "ok": True,
            "node_id": str(target_row["node_id"]),
            "root_node_id": root_id,
            "shared_context_revision": int(target_row["shared_context_revision"] or 0),
            "content": str(target_row["shared_context_content"] or ""),
            "entries": entries,
            "revision": self.store.get_revision(),
        }

    def submit_note(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("submit_note", raw_args)
        caller_node = self.ensure_caller_node(caller)
        caller_id = str(caller_node["node_id"])
        owner_id = str(caller_node["parent_node_id"] or caller_id)

        entry_id = self._new_uuid()
        content = req["content"]
        content_sha = sha256_hex(content)
        rel_note = f"notes/{owner_id}/{entry_id}.md"
        self.store.write_artifact_blob(rel_note, content.encode("utf-8"))

        with self.store.transaction("IMMEDIATE") as txn:
            cached = self._check_idempotent_request(
                txn.conn,
                caller_id,
                "submit_note",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

            next_rev = int(
                txn.execute(
                    "SELECT COALESCE(MAX(revision), 0) + 1 AS nr FROM note_entries WHERE owner_node_id = ?",
                    (owner_id,),
                ).fetchone()["nr"]
            )
            now = self._now_iso()
            txn.execute(
                """
                INSERT INTO note_entries (
                    entry_id, owner_node_id, author_node_id, revision, content, content_sha256, artifact_ref, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (entry_id, owner_id, caller_id, next_rev, content, content_sha, rel_note, now),
            )
            res = {
                "ok": True,
                "request_id": req.request_id,
                "entry_id": entry_id,
                "owner_node_id": owner_id,
                "author_node_id": caller_id,
                "note_revision": next_rev,
                "content_sha256": content_sha,
                "revision": txn.revision,
            }
            self._record_idempotent_request(
                txn.conn,
                caller_id,
                "submit_note",
                req.request_id,
                req.normalized_hash,
                res,
            )
            return res

    def update_shared_context(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("update_shared_context", raw_args)
        caller_node = self.ensure_caller_node(caller)
        caller_id = str(caller_node["node_id"])

        with self.store.transaction("IMMEDIATE") as txn:
            cached = self._check_idempotent_request(
                txn.conn,
                caller_id,
                "update_shared_context",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

            fresh = txn.execute("SELECT * FROM nodes WHERE node_id = ?", (caller_id,)).fetchone()
            cur_rev = int(fresh["shared_context_revision"] or 0)
            if cur_rev != int(req["expected_revision"]):
                raise SideSessionError(
                    ErrorCode.REVISION_CONFLICT,
                    "shared_context_revision mismatch",
                    {"expected_revision": req["expected_revision"], "actual_revision": cur_rev},
                )
            new_rev = cur_rev + 1
            txn.execute(
                """
                UPDATE nodes
                SET shared_context_revision = ?, shared_context_content = ?, revision = revision + 1, updated_at = ?
                WHERE node_id = ?
                """,
                (new_rev, req["content"], self._now_iso(), caller_id),
            )
            res = {
                "ok": True,
                "request_id": req.request_id,
                "node_id": caller_id,
                "shared_context_revision": new_rev,
                "content": req["content"],
                "revision": txn.revision,
            }
            self._record_idempotent_request(
                txn.conn,
                caller_id,
                "update_shared_context",
                req.request_id,
                req.normalized_hash,
                res,
            )

        self.store.export_shared_context(caller_id, req["content"])
        return res

    # ------------------------------------------------------------------
    # 6. Cross-Session Messaging, Waits, Cancellation & Hook Engine
    # ------------------------------------------------------------------

    def _row_to_wait_dict(self, row: Mapping[str, Any]) -> dict[str, Any]:
        raw_opts = row["options"]
        if isinstance(raw_opts, str):
            try:
                opts = json.loads(raw_opts or "[]")
            except Exception:
                opts = []
        elif isinstance(raw_opts, list):
            opts = list(raw_opts)
        else:
            opts = []

        bound = BoundWait(
            wait_id=str(row["wait_id"]),
            node_id=str(row["node_id"]),
            run_id=str(row["run_id"]),
            runtime_turn_id=row["runtime_turn_id"],
            runtime_instance_id=str(row["runtime_instance_id"]),
            owner_epoch=int(row["owner_epoch"]),
            host_request_id=str(row["host_request_id"]),
            kind=str(row["kind"]),
            nonce=str(row["nonce"]),
            question=str(row["question"] or ""),
            options=opts,
            required_authority=str(row["required_authority"]),
            deadline_at=row["deadline_at"],
            state=str(row["state"]),
        ).to_dict()
        bound.update(
            {
                "session_id": str(row["node_id"]),
                "wait_kind": str(row["kind"]),
                "prompt_nonce": str(row["nonce"]),
                "response_hash": row["response_hash"],
                "receipt_ref": row["receipt_ref"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )
        return bound

    def _get_wait_summaries_in_conn(
        self,
        conn: Any,
        node_id: str,
        *,
        only_open: bool = True,
    ) -> list[dict[str, Any]]:
        if only_open:
            rows = conn.execute(
                """
                SELECT * FROM wait_requests
                WHERE node_id = ? AND state IN ('open', 'responding')
                ORDER BY created_at ASC, wait_id ASC
                """,
                (node_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM wait_requests
                WHERE node_id = ?
                ORDER BY created_at ASC, wait_id ASC
                """,
                (node_id,),
            ).fetchall()
        return [self._row_to_wait_dict(r) for r in rows]

    def send_message_to_session(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Enqueue a cross-session follow-up message into the target node's persistent FIFO inbox."""
        ctx = self._coerce_caller(caller)
        raw_args = self._merge_args(args, kwargs)

        if "session_id" not in raw_args:
            if "node_id" in raw_args:
                raw_args["session_id"] = raw_args.pop("node_id")
            elif "target" in raw_args:
                raw_args["session_id"] = raw_args.pop("target")

        if "request_id" not in raw_args:
            raw_args["request_id"] = self._new_uuid()
        if "message_id" not in raw_args:
            raw_args["message_id"] = str(
                uuid.uuid5(uuid.NAMESPACE_OID, f"msg:{raw_args['request_id']}")
            )

        raw_policy = raw_args.get("resume_policy", "active_only")
        if raw_policy == "auto":
            raw_args["resume_policy"] = "explicit"
            eff_resume_policy = "explicit"
        elif raw_policy == "reject_done":
            raw_args["resume_policy"] = "active_only"
            eff_resume_policy = "active_only"
        else:
            eff_resume_policy = str(raw_policy) if raw_policy is not None else "active_only"

        req = normalize_request("send_message_to_session", raw_args)
        caller_node = self.ensure_caller_node(ctx)
        caller_id = str(caller_node["node_id"])

        target_row = self.resolve_target_node(ctx, req["session_id"])
        target_id = str(target_row["node_id"])
        message_id = req["message_id"]
        msg_envelope = (
            f'<cross-session-message from="{caller_id}" name="{caller_node["name"]}">\n'
            f'{req["message"]}\n'
            f"</cross-session-message>"
        )
        payload_hash = sha256_hex(msg_envelope)

        with self.store.transaction("IMMEDIATE") as txn:
            cached = self._check_idempotent_request(
                txn.conn,
                caller_id,
                "send_message_to_session",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

            existing_msg = txn.execute(
                "SELECT * FROM inbox_messages WHERE message_id = ?",
                (message_id,),
            ).fetchone()
            if existing_msg is not None:
                if (
                    str(existing_msg["target_node_id"]) == target_id
                    and str(existing_msg["source_node_id"]) == caller_id
                    and str(existing_msg["payload_hash"]) == payload_hash
                ):
                    seq_val = int(existing_msg["seq"])
                    q_pos = int(
                        txn.execute(
                            "SELECT COUNT(*) AS cnt FROM inbox_messages WHERE target_node_id = ? AND state = 'queued' AND seq <= ?",
                            (target_id, seq_val),
                        ).fetchone()["cnt"]
                    )
                    wait_summaries = self._get_wait_summaries_in_conn(txn.conn, target_id, only_open=True)
                    dup_res = QueueResult(
                        message_id=message_id,
                        seq=seq_val,
                        status=str(existing_msg["state"]),
                        queue_position=max(1, q_pos),
                        node_id=target_id,
                        pending_owner=(target_row.get("parent_node_id") is None),
                        wait_summaries=wait_summaries,
                    ).to_dict()
                    dup_res.update(
                        {
                            "ok": True,
                            "request_id": req.request_id,
                            "node_id": target_id,
                            "session_id": target_id,
                            "runtime_session_id": target_row.get("runtime_session_id"),
                            "message_id": message_id,
                            "seq": seq_val,
                            "state": str(existing_msg["state"]),
                            "status": str(existing_msg["state"]),
                            "delivery": "queued",
                            "delivery_kind": str(existing_msg["delivery_kind"]),
                            "queue_position": max(1, q_pos),
                            "dispatch_group_id": existing_msg["dispatch_group_id"],
                            "member_id": existing_msg["member_id"],
                            "run_id": existing_msg["run_id"],
                            "duplicate": True,
                            "revision": txn.revision,
                        }
                    )
                    self._record_idempotent_request(
                        txn.conn,
                        caller_id,
                        "send_message_to_session",
                        req.request_id,
                        req.normalized_hash,
                        dup_res,
                    )
                    return dup_res
                raise SideSessionError(
                    ErrorCode.MESSAGE_ID_CONFLICT,
                    f"message_id '{message_id}' already exists with different target or payload",
                    {"message_id": message_id, "target_node_id": target_id},
                )

            fresh_target = txn.execute(
                "SELECT * FROM nodes WHERE node_id = ?",
                (target_id,),
            ).fetchone()
            if fresh_target is None:
                raise SideSessionError(ErrorCode.NOT_FOUND, f"Target session not found: {target_id}")

            node_status = str(fresh_target["node_status"])
            if node_status == "archived":
                raise SideSessionError(
                    ErrorCode.SESSION_ARCHIVED,
                    "Cannot send message to an archived session",
                    {"node_id": target_id, "session_id": target_id},
                )
            self._assert_no_active_worktree_job(txn.conn, target_id)

            latest_turn = txn.execute(
                "SELECT * FROM turns WHERE node_id = ? ORDER BY turn_seq DESC LIMIT 1",
                (target_id,),
            ).fetchone()
            open_wait = txn.execute(
                "SELECT * FROM wait_requests WHERE node_id = ? AND state IN ('open', 'responding') ORDER BY created_at ASC LIMIT 1",
                (target_id,),
            ).fetchone()
            exec_state = str(latest_turn["execution_state"]) if latest_turn is not None else "idle"
            waiting_input_now = exec_state == "waiting_input" or open_wait is not None

            if node_status == "done" and eff_resume_policy in ("reject_done", "active_only"):
                raise _err(
                    ErrorCode.SESSION_DONE,
                    "Target session is in 'done' status; pass resume_policy='explicit' to resume it",
                    {"node_id": target_id, "status": node_status, "resume_policy": eff_resume_policy},
                )
            if node_status == "paused" and eff_resume_policy == "active_only":
                raise _err(
                    ErrorCode.SESSION_PAUSED,
                    "Target session is in 'paused' status; pass resume_policy='explicit' to resume it",
                    {"node_id": target_id, "status": node_status, "resume_policy": eff_resume_policy},
                )

            primary_task_id = fresh_target["primary_task_id"]
            task_rev: int | None = None
            if primary_task_id:
                t_row = txn.execute(
                    "SELECT * FROM tasks WHERE task_id = ?",
                    (primary_task_id,),
                ).fetchone()
                if t_row is not None:
                    if str(t_row["owner_node_id"]) != target_id:
                        raise SideSessionError(
                            ErrorCode.TASK_OWNER_CHANGED,
                            "Target session's primary task ownership has been transferred to another session",
                            {
                                "node_id": target_id,
                                "task_id": primary_task_id,
                                "owner_node_id": t_row["owner_node_id"],
                            },
                        )
                    task_rev = int(t_row["task_revision"])

            now = self._now_iso()
            parent_id = str(fresh_target["parent_node_id"]) if fresh_target["parent_node_id"] else None
            delivery_kind = "managed_dispatch" if parent_id is not None else "owner_input"

            if node_status in ("paused", "done"):
                txn.execute(
                    """
                    UPDATE nodes
                    SET node_status = 'active', pause_requested = 0, revision = revision + 1, updated_at = ?
                    WHERE node_id = ?
                    """,
                    (now, target_id),
                )
                if primary_task_id and task_rev is not None:
                    task_rev = task_rev + 1
                    txn.execute(
                        """
                        UPDATE tasks
                        SET state = 'active', task_revision = ?, updated_at = ?
                        WHERE task_id = ? AND owner_node_id = ?
                        """,
                        (task_rev, now, primary_task_id, target_id),
                    )

            active_turn = txn.execute(
                """
                SELECT * FROM turns
                WHERE node_id = ?
                  AND execution_state IN ('queued', 'starting', 'running', 'waiting_input', 'stopping', 'reconciliation')
                ORDER BY turn_seq DESC LIMIT 1
                """,
                (target_id,),
            ).fetchone()

            created_run_id: str | None = str(active_turn["run_id"]) if active_turn is not None else None
            # Follow-up messages persist as queued inbox items. Worker claim later reserves a slot
            # and consumes turn_seq; enqueue must not reserve_dispatch or INSERT turns.
            need_new_turn = False

            if parent_id is not None:
                existing_slot = txn.execute(
                    "SELECT * FROM parent_slots WHERE parent_node_id = ? AND node_id = ? AND state != 'released'",
                    (parent_id, target_id),
                ).fetchone()
                if existing_slot is None and not waiting_input_now:
                    # Hint only: do not reserve here. Worker claim path reserves atomically.
                    pass

                eff_group_id, member_id, _ordinal = self._admit_dispatch_group_member_in_conn(
                    txn.conn,
                    parent_node_id=parent_id,
                    child_node_id=target_id,
                    message_id=message_id,
                    operation_id=None,
                    run_id=created_run_id if need_new_turn else None,
                    dispatch_group_id=req["dispatch_group_id"],
                    batch_id=None,
                    initial_state="queued",
                )
            else:
                if req["dispatch_group_id"] is not None:
                    raise SideSessionError(
                        ErrorCode.GROUP_NOT_APPLICABLE,
                        "dispatch_group_id is not applicable when sending a message to a root session",
                        {"node_id": target_id},
                    )
                eff_group_id = None
                member_id = None

            next_seq = int(
                txn.execute(
                    "SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM inbox_messages WHERE target_node_id = ?",
                    (target_id,),
                ).fetchone()["next_seq"]
            )

            txn.execute(
                """
                INSERT INTO inbox_messages (
                    message_id, target_node_id, source_node_id, seq, delivery_kind,
                    dispatch_group_id, member_id, task_id, payload_hash, payload,
                    state, run_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)
                """,
                (
                    message_id,
                    target_id,
                    caller_id,
                    next_seq,
                    delivery_kind,
                    eff_group_id,
                    member_id,
                    primary_task_id,
                    payload_hash,
                    msg_envelope,
                    created_run_id if need_new_turn else None,
                    now,
                    now,
                ),
            )

            if need_new_turn and created_run_id is not None:
                next_turn_seq = int(
                    txn.execute(
                        "SELECT COALESCE(MAX(turn_seq), 0) + 1 AS next_tseq FROM turns WHERE node_id = ?",
                        (target_id,),
                    ).fetchone()["next_tseq"]
                )
                o_row = txn.execute("SELECT * FROM owners WHERE node_id = ?", (target_id,)).fetchone()
                owner_epoch = (int(o_row["owner_epoch"]) + 1) if o_row is not None else 1
                fencing_token = f"fence:{target_id}:{uuid.uuid4().hex}"
                worker_turn_id = self._new_uuid()
                input_id = self._new_uuid()

                if o_row is not None:
                    txn.execute(
                        """
                        UPDATE owners
                        SET owner_epoch = ?, fencing_token = ?, current_run_id = ?, state = 'active', heartbeat = ?
                        WHERE node_id = ?
                        """,
                        (owner_epoch, fencing_token, created_run_id, now, target_id),
                    )
                else:
                    txn.execute(
                        """
                        INSERT INTO owners (
                            node_id, worker_id, owner_token, owner_epoch, fencing_token,
                            current_run_id, heartbeat, state
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
                        """,
                        (
                            target_id,
                            f"worker:{target_id[:8]}",
                            f"tok:{uuid.uuid4().hex}",
                            owner_epoch,
                            fencing_token,
                            created_run_id,
                            now,
                        ),
                    )

                txn.execute(
                    """
                    INSERT INTO turns (
                        run_id, node_id, turn_seq, worker_turn_id, runtime_turn_id,
                        input_id, message_id, dispatch_group_id, member_id, task_id,
                        task_revision, owner_epoch, fencing_token, execution_state,
                        report_state, started_at
                    ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', 'none', ?)
                    """,
                    (
                        created_run_id,
                        target_id,
                        next_turn_seq,
                        worker_turn_id,
                        input_id,
                        message_id,
                        eff_group_id,
                        member_id,
                        primary_task_id,
                        task_rev,
                        owner_epoch,
                        fencing_token,
                        now,
                    ),
                )

            queue_position = int(
                txn.execute(
                    "SELECT COUNT(*) AS cnt FROM inbox_messages WHERE target_node_id = ? AND state = 'queued' AND seq <= ?",
                    (target_id, next_seq),
                ).fetchone()["cnt"]
            )
            wait_summaries = self._get_wait_summaries_in_conn(txn.conn, target_id, only_open=True)

            res = QueueResult(
                message_id=message_id,
                seq=next_seq,
                status="queued",
                queue_position=queue_position,
                node_id=target_id,
                pending_owner=(parent_id is None),
                wait_summaries=wait_summaries,
            ).to_dict()
            res.update(
                {
                    "ok": True,
                    "request_id": req.request_id,
                    "node_id": target_id,
                    "session_id": target_id,
                    "runtime_session_id": fresh_target["runtime_session_id"],
                    "message_id": message_id,
                    "seq": next_seq,
                    "state": "queued",
                    "status": "queued",
                    "delivery": "queued",
                    "delivery_kind": delivery_kind,
                    "queue_position": queue_position,
                    "dispatch_group_id": eff_group_id,
                    "member_id": member_id,
                    "run_id": created_run_id,
                    "revision": txn.revision,
                }
            )
            self._record_idempotent_request(
                txn.conn,
                caller_id,
                "send_message_to_session",
                req.request_id,
                req.normalized_hash,
                res,
            )

        self._notify_supervisor(
            {
                "event": "message_queued",
                "node_id": target_id,
                "session_id": target_id,
                "message_id": message_id,
                "seq": next_seq,
                "run_id": created_run_id,
            }
        )
        return res

    def list_waits(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """List wait requests within the caller's authorized family."""
        ctx = self._coerce_caller(caller)
        raw_args = self._merge_args(args, kwargs)
        caller_node = self.ensure_caller_node(ctx)
        caller_id = str(caller_node["node_id"])
        root_id = str(caller_node["root_node_id"])

        include_resolved = False
        if "include_resolved" in raw_args:
            raw_inc = raw_args.pop("include_resolved")
            if raw_inc is not None:
                if type(raw_inc) is not bool:
                    raise SideSessionError(
                        ErrorCode.INVALID_REQUEST,
                        "include_resolved must be a boolean",
                        {"field": "include_resolved"},
                    )
                include_resolved = raw_inc

        if "node_id" in raw_args and "session_id" not in raw_args:
            raw_args["session_id"] = raw_args.pop("node_id")

        filter_node_id: str | None = None
        norm_args = dict(raw_args)
        if "session_id" not in norm_args or norm_args.get("session_id") is None:
            norm_args["session_id"] = caller_id
        else:
            raw_sid = norm_args["session_id"]
            if isinstance(raw_sid, str) and raw_sid.strip():
                target_node = self.resolve_target_node(ctx, raw_sid.strip())
                filter_node_id = str(target_node["node_id"])
                norm_args["session_id"] = filter_node_id

        normalize_request("list_waits", norm_args)

        conn = self.store.conn
        state_clause = "" if include_resolved else "AND w.state IN ('open', 'responding')"
        if filter_node_id is not None:
            rows = conn.execute(
                f"""
                SELECT w.* FROM wait_requests w
                JOIN nodes n ON n.node_id = w.node_id
                WHERE n.root_node_id = ? AND w.node_id = ? {state_clause}
                ORDER BY w.created_at ASC, w.wait_id ASC
                """,
                (root_id, filter_node_id),
            ).fetchall()
        else:
            rows = conn.execute(
                f"""
                SELECT w.* FROM wait_requests w
                JOIN nodes n ON n.node_id = w.node_id
                WHERE n.root_node_id = ? {state_clause}
                ORDER BY w.created_at ASC, w.wait_id ASC
                """,
                (root_id,),
            ).fetchall()

        waits = [self._row_to_wait_dict(r) for r in rows]
        return {
            "ok": True,
            "waits": waits,
            "items": waits,
            "session_id": filter_node_id,
            "include_resolved": include_resolved,
            "revision": self.store.get_revision(),
        }

    def respond_to_wait(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Respond to an open wait request on a child session via its control channel."""
        ctx = self._coerce_caller(caller)
        raw_args = self._merge_args(args, kwargs)

        if "prompt_nonce" in raw_args and "nonce" not in raw_args:
            raw_args["nonce"] = raw_args.pop("prompt_nonce")
        elif "prompt_nonce" in raw_args and raw_args.get("prompt_nonce") == raw_args.get("nonce"):
            raw_args.pop("prompt_nonce", None)

        if "request_id" not in raw_args:
            raw_args["request_id"] = self._new_uuid()

        evidence_arg = raw_args.pop("evidence", raw_args.pop("approval_evidence", None))
        extra_approval_fields: dict[str, Any] = {}
        for k in (
            "real_input_id",
            "input_id",
            "inputId",
            "command_id",
            "commandId",
            "interaction_token",
            "approval_token",
            "human_signature",
            "signature",
            "trusted_token",
            "origin",
            "source",
            "actor_kind",
            "from_model",
            "verified",
            "verified_human",
            "human_verified",
        ):
            if k in raw_args:
                extra_approval_fields[k] = raw_args.pop(k)

        raw_args.pop("session_id", None)
        raw_args.pop("node_id", None)

        raw_resp = raw_args.get("response")
        if isinstance(raw_resp, Mapping) and "kind" not in raw_resp:
            if "text" in raw_resp and set(raw_resp.keys()) <= {"text"}:
                raw_args["response"] = {"kind": "input", "text": raw_resp["text"]}
            elif "action" in raw_resp and set(raw_resp.keys()) <= {"action", "content"}:
                raw_args["response"] = {"kind": "elicitation", **dict(raw_resp)}
            elif "decision" in raw_resp and set(raw_resp.keys()) <= {"option_id", "decision"}:
                raw_args["response"] = {
                    "kind": "permission",
                    "option_id": raw_resp.get("option_id") or raw_resp["decision"],
                    "decision": raw_resp["decision"],
                }

        req = normalize_request("respond_to_wait", raw_args)
        caller_node = self.ensure_caller_node(ctx)
        caller_id = str(caller_node["node_id"])

        cached = self._check_idempotent_request(
            self.store.conn,
            caller_id,
            "respond_to_wait",
            req.request_id,
            req.normalized_hash,
        )
        if cached is not None:
            return cached

        wait_id = req["wait_id"]
        w_row = self.store.conn.execute(
            "SELECT * FROM wait_requests WHERE wait_id = ?",
            (wait_id,),
        ).fetchone()
        if w_row is None:
            raise SideSessionError(
                ErrorCode.NOT_FOUND,
                f"Wait request not found: {wait_id}",
                {"wait_id": wait_id},
            )

        target_node_id = str(w_row["node_id"])
        self.resolve_target_node(ctx, target_node_id, require_manage=True)
        self._assert_no_active_worktree_job(self.store.conn, target_node_id)

        w_state = str(w_row["state"])
        if w_state in ("responding", "resolved"):
            raise SideSessionError(
                ErrorCode.WAIT_ALREADY_RESPONDED,
                f"Wait request {wait_id} has already been responded to",
                {"wait_id": wait_id, "state": w_state},
            )
        if w_state != "open" or self._is_expired(w_row["deadline_at"]):
            if w_state == "open" and self._is_expired(w_row["deadline_at"]):
                with self.store.transaction("IMMEDIATE") as exp_txn:
                    exp_txn.execute(
                        "UPDATE wait_requests SET state = 'expired', updated_at = ? WHERE wait_id = ?",
                        (self._now_iso(), wait_id),
                    )
            raise _err(
                ErrorCode.WAIT_STALE,
                f"Wait request {wait_id} is no longer open (state={w_state})",
                {"wait_id": wait_id, "state": w_state},
                aliases=(ErrorCode.EXPIRED,),
            )

        if str(w_row["nonce"]) != req["nonce"]:
            raise _err(
                ErrorCode.WAIT_STALE,
                "Wait prompt_nonce / nonce does not match open wait request",
                {
                    "wait_id": wait_id,
                    "expected_nonce": w_row["nonce"],
                    "provided_nonce": req["nonce"],
                },
                aliases=(ErrorCode.INVALID_REQUEST, ErrorCode.VALIDATION_ERROR),
            )

        wait_kind = str(w_row["kind"])
        if req["response"]["kind"] != wait_kind:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"Response kind '{req['response']['kind']}' does not match wait kind '{wait_kind}'",
                {"wait_id": wait_id, "wait_kind": wait_kind, "response_kind": req["response"]["kind"]},
            )

        response_hash = canonical_json_sha256(req["response"])
        approval_evidence: ApprovalEvidence | None = None

        if wait_kind == "permission":
            raw_opts = json.loads(w_row["options"] or "[]") if isinstance(w_row["options"], str) else list(w_row["options"] or [])
            if raw_opts:
                allowed_tokens: set[str] = set()
                for opt in raw_opts:
                    if isinstance(opt, str):
                        allowed_tokens.add(opt)
                    elif isinstance(opt, Mapping):
                        for k_opt in ("option_id", "id", "decision", "value"):
                            if opt.get(k_opt) is not None:
                                allowed_tokens.add(str(opt[k_opt]))
                if allowed_tokens:
                    opt_id = str(req["response"]["option_id"])
                    dec_val = str(req["response"]["decision"])
                    if opt_id not in allowed_tokens and dec_val not in allowed_tokens:
                        raise SideSessionError(
                            ErrorCode.INVALID_REQUEST,
                            "Permission response option_id/decision is not in allowed wait options",
                            {"wait_id": wait_id, "allowed_options": sorted(allowed_tokens)},
                        )

        needs_human = (wait_kind == "permission") or (str(w_row["required_authority"]) == "human")

        control_id = self._new_uuid()
        run_id = str(w_row["run_id"])
        owner_epoch = int(w_row["owner_epoch"])
        cmd_payload_obj = {
            "command_kind": "respond_wait",
            "kind": "respond_wait",
            "wait_id": wait_id,
            "wait_kind": wait_kind,
            "nonce": req["nonce"],
            "response": req["response"],
            "response_hash": response_hash,
        }
        cmd_payload_json = canonical_json(cmd_payload_obj)
        cmd_payload_hash = sha256_hex(cmd_payload_json)

        with self.store.transaction("IMMEDIATE") as txn:
            self._assert_no_active_worktree_job(txn.conn, target_node_id)
            w_fresh = txn.execute(
                "SELECT * FROM wait_requests WHERE wait_id = ?",
                (wait_id,),
            ).fetchone()
            if w_fresh is None or str(w_fresh["state"]) != "open":
                raise SideSessionError(
                    ErrorCode.WAIT_ALREADY_RESPONDED,
                    f"Wait request {wait_id} is no longer open",
                    {"wait_id": wait_id},
                )

            now = self._now_iso()
            owner_row = txn.execute("SELECT * FROM owners WHERE node_id = ?", (target_node_id,)).fetchone()
            current_epoch = int(owner_row["owner_epoch"]) if owner_row is not None and owner_row["owner_epoch"] is not None else None
            if current_epoch is None or current_epoch != int(w_fresh["owner_epoch"]):
                raise _err(
                    ErrorCode.WAIT_STALE,
                    "Wait owner_epoch does not match current owner epoch",
                    {
                        "wait_id": wait_id,
                        "wait_owner_epoch": w_fresh["owner_epoch"],
                        "current_owner_epoch": current_epoch,
                    },
                )
            live_owner = self._has_external_live_worker(txn.conn, target_node_id, require_process=True)
            if not live_owner:
                raise _err(
                    ErrorCode.WAIT_RESPONSE_UNAVAILABLE,
                    "No live owner is available to consume the wait response over the original connection",
                    {"wait_id": wait_id, "node_id": target_node_id},
                    aliases=(ErrorCode.CANCEL_OWNER_UNAVAILABLE,),
                )

            if needs_human:
                allowed_ev_keys = (
                    "real_input_id",
                    "input_id",
                    "inputId",
                    "command_id",
                    "commandId",
                    "interaction_token",
                    "approval_token",
                    "human_signature",
                    "signature",
                    "trusted_token",
                    "origin",
                    "source",
                    "actor_kind",
                    "from_model",
                    "verified",
                )
                cred_fields: dict[str, Any] = {
                    k: v for k, v in extra_approval_fields.items() if k in allowed_ev_keys
                }
                if isinstance(evidence_arg, Mapping):
                    for k in allowed_ev_keys:
                        if k in evidence_arg and evidence_arg[k] is not None:
                            cred_fields[k] = evidence_arg[k]
                for tk in ("interaction_token", "approval_token", "human_signature", "signature", "trusted_token"):
                    cred_fields.pop(tk, None)

                has_explicit_inp = bool(
                    cred_fields.get("real_input_id")
                    or cred_fields.get("input_id")
                    or cred_fields.get("inputId")
                )
                has_token = any(
                    cred_fields.get(tk)
                    for tk in ("interaction_token", "approval_token", "human_signature", "signature", "trusted_token")
                )
                if not isinstance(evidence_arg, ApprovalEvidence) and not has_explicit_inp and not has_token and ctx.runtime_turn_id:
                    cand_rows = txn.execute(
                        "SELECT * FROM input_provenance WHERE input_id = ?",
                        (ctx.runtime_turn_id,),
                    ).fetchall()
                    for c_row in cand_rows:
                        c_dict = dict(c_row)
                        if not c_dict.get("verified"):
                            continue
                        c_sid = str(c_dict.get("runtime_session_id") or "").strip()
                        c_owner = str(c_dict.get("owner_id") or "")
                        if ctx.runtime_sid and not ctx.runtime_sid.startswith("sid:"):
                            if c_sid and c_sid != ctx.runtime_sid:
                                continue
                            if not c_sid and c_owner != f"host:{ctx.runtime_sid}":
                                continue
                        if (
                            str(c_dict.get("origin") or "") == "slash_command"
                            and str(c_dict.get("command_id") or "") == "/side-sessions:respond"
                        ):
                            cred_fields["real_input_id"] = ctx.runtime_turn_id
                            break

                eff_inp_id = str(
                    cred_fields.get("real_input_id")
                    or cred_fields.get("input_id")
                    or cred_fields.get("inputId")
                    or ""
                ).strip()
                if not isinstance(evidence_arg, ApprovalEvidence) and eff_inp_id and not has_token:
                    p_rows = txn.execute(
                        "SELECT origin, command_id, action_binding_json, verified FROM input_provenance WHERE input_id = ?",
                        (eff_inp_id,),
                    ).fetchall()
                    for p_r in p_rows:
                        p_d = dict(p_r)
                        if (
                            p_d.get("verified")
                            and str(p_d.get("origin") or "") in ("human_prompt", "real_user")
                            and not str(p_d.get("command_id") or "").strip()
                            and not str(p_d.get("action_binding_json") or "").strip()
                        ):
                            raise _err(
                                "USER_APPROVAL_REQUIRED",
                                "Ordinary human chat prompt cannot self-approve a permission wait without /side-sessions:respond",
                                {"wait_id": wait_id, "input_id": eff_inp_id},
                                aliases=(
                                    ErrorCode.USER_APPROVAL_UNAVAILABLE,
                                    ErrorCode.HUMAN_ACTION_REQUIRED,
                                    ErrorCode.FORBIDDEN,
                                ),
                            )

                approval_action: dict[str, Any] = {
                    **cred_fields,
                    "purpose": "wait_response",
                    "wait_id": wait_id,
                    "wait_nonce": req["nonce"],
                    "nonce": req["nonce"],
                    "host_request_id": str(w_row["host_request_id"]),
                    "run_id": str(w_row["run_id"]),
                    "parent_node_id": caller_id,
                    "runtime_sid": ctx.runtime_sid,
                    "response": req["response"],
                    "response_hash": response_hash,
                    "request_id": req.request_id,
                }

                adapter = self.host_adapter
                if adapter is None or not hasattr(adapter, "verify_approval"):
                    raise _err(
                        "USER_APPROVAL_REQUIRED",
                        "Host adapter verify_approval is unavailable for wait response",
                        {"wait_id": wait_id},
                        aliases=(ErrorCode.USER_APPROVAL_UNAVAILABLE, ErrorCode.HUMAN_ACTION_REQUIRED),
                    )
                try:
                    approval_evidence = self._obtain_or_verify_approval_evidence(
                        purpose="wait_response",
                        evidence=evidence_arg if isinstance(evidence_arg, ApprovalEvidence) else None,
                        action_dict=approval_action,
                        conn=txn.conn,
                        caller=ctx,
                    )
                except SideSessionError as exc:
                    raise _err(
                        "USER_APPROVAL_REQUIRED",
                        exc.message,
                        {"wait_id": wait_id, **exc.details},
                        aliases=(
                            ErrorCode.USER_APPROVAL_UNAVAILABLE,
                            ErrorCode.HUMAN_ACTION_REQUIRED,
                            ErrorCode.FORBIDDEN,
                            exc.code,
                        ),
                    ) from exc

                if self._is_expired(approval_evidence.expires_at):
                    raise _err(
                        "USER_APPROVAL_REQUIRED",
                        "Permission ApprovalEvidence has expired",
                        {"wait_id": wait_id},
                        aliases=(ErrorCode.EXPIRED, ErrorCode.USER_APPROVAL_UNAVAILABLE, ErrorCode.HUMAN_ACTION_REQUIRED),
                    )

            authority_ref = (
                approval_evidence.evidence_ref
                if approval_evidence is not None
                else f"caller:{caller_id}:{req.request_id}"
            )
            next_wait_state = "responding"
            cas = txn.execute(
                """
                UPDATE wait_requests
                SET state = ?,
                    response_hash = ?,
                    receipt_ref = ?,
                    updated_at = ?
                WHERE wait_id = ? AND state = 'open'
                """,
                (next_wait_state, response_hash, f"control:{control_id}", now, wait_id),
            )
            if cas.rowcount == 0:
                raise SideSessionError(
                    ErrorCode.WAIT_ALREADY_RESPONDED,
                    f"Wait request {wait_id} is no longer open",
                    {"wait_id": wait_id},
                )
            txn.execute(
                """
                INSERT INTO control_commands (
                    control_id, request_id, node_id, run_id, owner_epoch,
                    kind, wait_id, payload_hash, payload, authority_ref,
                    state, receipt_ref, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'respond_wait', ?, ?, ?, ?, 'queued', NULL, ?, ?)
                """,
                (
                    control_id,
                    req.request_id,
                    target_node_id,
                    run_id,
                    owner_epoch,
                    wait_id,
                    cmd_payload_hash,
                    cmd_payload_json,
                    authority_ref,
                    now,
                    now,
                ),
            )
            # Running/resolved is applied later by the owner after verify_consumption.

            res = ControlResult(
                control_id=control_id,
                node_id=target_node_id,
                status="responding",
                revision=txn.revision,
                run_id=run_id,
                wait_id=wait_id,
            ).to_dict()
            res.update(
                {
                    "ok": True,
                    "request_id": req.request_id,
                    "control_id": control_id,
                    "command_id": control_id,
                    "command_kind": "respond_wait",
                    "kind": "respond_wait",
                    "wait_id": wait_id,
                    "wait_kind": wait_kind,
                    "node_id": target_node_id,
                    "session_id": target_node_id,
                    "run_id": run_id,
                    "nonce": req["nonce"],
                    "prompt_nonce": req["nonce"],
                    "response": req["response"],
                    "response_hash": response_hash,
                    "state": _AliasStr(next_wait_state, "responding", "queued"),
                    "status": _AliasStr(next_wait_state, "responding", "queued"),
                    "wait_state": _AliasStr(next_wait_state, "responding"),
                    "command_state": "queued",
                    "node_status": "active",
                    "execution_state": "waiting_input",
                    "approval_id": approval_evidence.approval_id if approval_evidence else None,
                    "authority_ref": authority_ref,
                    "revision": txn.revision,
                }
            )
            self._record_idempotent_request(
                txn.conn,
                caller_id,
                "respond_to_wait",
                req.request_id,
                req.normalized_hash,
                res,
            )

        self._notify_supervisor(
            {
                "event": "respond_wait",
                "control_id": control_id,
                "wait_id": wait_id,
                "node_id": target_node_id,
                "run_id": run_id,
            }
        )
        return res

    def cancel_message(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Cancel a queued inbox message before it is claimed by a worker."""
        ctx = self._coerce_caller(caller)
        raw_args = self._merge_args(args, kwargs)

        if "request_id" not in raw_args:
            raw_args["request_id"] = self._new_uuid()
        if "reason" not in raw_args or raw_args.get("reason") is None:
            raw_args["reason"] = "Cancelled queued message"
        if "node_id" in raw_args and "session_id" not in raw_args:
            raw_args["session_id"] = raw_args.pop("node_id")

        if "session_id" not in raw_args or raw_args.get("session_id") is None:
            raw_mid = raw_args.get("message_id")
            if isinstance(raw_mid, str) and raw_mid.strip():
                m_lookup = self.store.conn.execute(
                    "SELECT target_node_id FROM inbox_messages WHERE message_id = ? LIMIT 1",
                    (raw_mid.strip(),),
                ).fetchone()
                if m_lookup is not None:
                    raw_args["session_id"] = str(m_lookup["target_node_id"])
                else:
                    raw_args["session_id"] = str(self.ensure_caller_node(ctx)["node_id"])
        else:
            raw_sid = raw_args["session_id"]
            if isinstance(raw_sid, str) and raw_sid.strip() and _try_parse_uuid(raw_sid) is None:
                t_node = self.resolve_target_node(ctx, raw_sid.strip(), require_manage=True)
                raw_args["session_id"] = str(t_node["node_id"])

        req = normalize_request("cancel_message", raw_args)
        caller_node = self.ensure_caller_node(ctx)
        caller_id = str(caller_node["node_id"])
        target_row = self.resolve_target_node(ctx, req["session_id"], require_manage=True)
        target_id = str(target_row["node_id"])
        message_id = req["message_id"]

        with self.store.transaction("IMMEDIATE") as txn:
            cached = self._check_idempotent_request(
                txn.conn,
                caller_id,
                "cancel_message",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

            m_row = txn.execute(
                "SELECT * FROM inbox_messages WHERE target_node_id = ? AND message_id = ?",
                (target_id, message_id),
            ).fetchone()
            if m_row is None:
                m_any = txn.execute(
                    "SELECT * FROM inbox_messages WHERE message_id = ?",
                    (message_id,),
                ).fetchone()
                if m_any is not None:
                    other_target = self.resolve_target_node(ctx, str(m_any["target_node_id"]), require_manage=True)
                    target_id = str(other_target["node_id"])
                    m_row = m_any

            if m_row is None:
                raise SideSessionError(
                    ErrorCode.NOT_FOUND,
                    f"Message not found: {message_id}",
                    {"message_id": message_id, "session_id": target_id},
                )

            m_state = str(m_row["state"])
            if m_state == "cancelled":
                res = {
                    "ok": True,
                    "request_id": req.request_id,
                    "node_id": target_id,
                    "session_id": target_id,
                    "message_id": message_id,
                    "seq": int(m_row["seq"]),
                    "state": "cancelled",
                    "status": "cancelled",
                    "member_state": _AliasStr("cancelled", "terminal"),
                    "exit_confirmed": "not_started_proven",
                    "slot_released": False,
                    "reason": req["reason"],
                    "revision": txn.revision,
                }
                self._record_idempotent_request(
                    txn.conn,
                    caller_id,
                    "cancel_message",
                    req.request_id,
                    req.normalized_hash,
                    res,
                )
                return res

            if m_state in ("claimed", "running", "completed", "failed", "reconciliation"):
                raise _err(
                    "MESSAGE_ALREADY_CLAIMED",
                    f"Message {message_id} is already in state '{m_state}'; use cancel_run to stop an active run",
                    {
                        "message_id": message_id,
                        "session_id": target_id,
                        "state": m_state,
                        "run_id": m_row["run_id"],
                        "hint": "Use cancel_run to cancel an already claimed or running turn",
                    },
                    aliases=(ErrorCode.MESSAGE_IN_FLIGHT, ErrorCode.SESSION_BUSY),
                )

            now = self._now_iso()
            txn.execute(
                "UPDATE inbox_messages SET state = 'cancelled', updated_at = ? WHERE target_node_id = ? AND message_id = ?",
                (now, target_id, message_id),
            )
            self._insert_outbox_event_in_conn(
                txn.conn,
                store_instance_id=txn.store_instance_id,
                producer_key=f"message:{message_id}:cancelled",
                parent_node_id=str(target_row.get("parent_node_id") or target_id),
                child_node_id=target_id,
                turn_seq=int(m_row["seq"] or 0),
                run_id=m_row["run_id"],
                dispatch_group_id=m_row["dispatch_group_id"],
                member_id=m_row["member_id"],
                kind="message_cancelled",
                outcome="cancelled",
                recap=req["reason"],
                report_ref=None,
                report_semantic_sha256=None,
                manifest_ref=None,
                artifact_refs=[],
            )

            associated_run_id = m_row["run_id"]
            if associated_run_id:
                txn.execute(
                    """
                    UPDATE turns
                    SET execution_state = 'cancelled',
                        outcome = 'cancelled',
                        cancel_requested_at = ?,
                        cancel_reason = ?,
                        ended_at = ?
                    WHERE run_id = ? AND execution_state = 'queued'
                    """,
                    (now, req["reason"], now, associated_run_id),
                )

            member_id = m_row["member_id"]
            dispatch_group_id = m_row["dispatch_group_id"]
            if member_id:
                txn.execute(
                    """
                    UPDATE dispatch_group_members
                    SET state = 'terminal',
                        outcome = 'cancelled',
                        exit_confirmed = 'not_started_proven',
                        terminal_reason = ?,
                        updated_at = ?
                    WHERE member_id = ?
                    """,
                    (req["reason"], now, member_id),
                )
            else:
                txn.execute(
                    """
                    UPDATE dispatch_group_members
                    SET state = 'terminal',
                        outcome = 'cancelled',
                        exit_confirmed = 'not_started_proven',
                        terminal_reason = ?,
                        updated_at = ?
                    WHERE message_id = ?
                    """,
                    (req["reason"], now, message_id),
                )

            other_active_msg = txn.execute(
                """
                SELECT 1 FROM inbox_messages
                WHERE target_node_id = ?
                  AND state IN ('queued', 'claimed', 'running', 'reconciliation')
                LIMIT 1
                """,
                (target_id,),
            ).fetchone()
            other_active_turn = txn.execute(
                """
                SELECT 1 FROM turns
                WHERE node_id = ?
                  AND execution_state IN ('starting', 'running', 'waiting_input', 'stopping', 'reconciliation')
                LIMIT 1
                """,
                (target_id,),
            ).fetchone()

            slot_released = False
            if other_active_msg is None and other_active_turn is None:
                reserved_slot = txn.execute(
                    """
                    SELECT * FROM parent_slots
                    WHERE node_id = ? AND state = 'reserved'
                    LIMIT 1
                    """,
                    (target_id,),
                ).fetchone()
                if reserved_slot is not None:
                    txn.execute(
                        "UPDATE parent_slots SET state = 'released', updated_at = ? WHERE node_id = ? AND state = 'reserved'",
                        (now, target_id),
                    )
                    slot_released = True

            if dispatch_group_id:
                self._maybe_finalize_dispatch_group_in_conn(
                    txn.conn,
                    str(dispatch_group_id),
                    txn.store_instance_id,
                )

            res = {
                "ok": True,
                "request_id": req.request_id,
                "node_id": target_id,
                "session_id": target_id,
                "message_id": message_id,
                "seq": int(m_row["seq"]),
                "state": "cancelled",
                "status": "cancelled",
                "member_state": _AliasStr("cancelled", "terminal"),
                "exit_confirmed": "not_started_proven",
                "slot_released": slot_released,
                "reason": req["reason"],
                "revision": txn.revision,
            }
            self._record_idempotent_request(
                txn.conn,
                caller_id,
                "cancel_message",
                req.request_id,
                req.normalized_hash,
                res,
            )
            return res

    def cancel_run(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        *,
        strict_node: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Request stop of an active run without releasing its parent slot until close_run confirms exit."""
        ctx = self._coerce_caller(caller)
        raw_args = self._merge_args(args, kwargs)

        if "request_id" not in raw_args:
            raw_args["request_id"] = self._new_uuid()
        if "reason" not in raw_args or raw_args.get("reason") is None:
            raw_args["reason"] = "User requested run cancellation"
        if "node_id" in raw_args and "session_id" not in raw_args:
            raw_args["session_id"] = raw_args.pop("node_id")

        if "session_id" not in raw_args or raw_args.get("session_id") is None or "run_id" not in raw_args or raw_args.get("run_id") is None:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "cancel_run requires exact session_id and run_id",
                {"fields": ["session_id", "run_id"]},
            )
        raw_sid = raw_args["session_id"]
        if isinstance(raw_sid, str) and raw_sid.strip() and _try_parse_uuid(raw_sid) is None:
            t_node = self.resolve_target_node(ctx, raw_sid.strip(), require_manage=True)
            raw_args["session_id"] = str(t_node["node_id"])

        req = normalize_request("cancel_run", raw_args)
        caller_node = self.ensure_caller_node(ctx)
        caller_id = str(caller_node["node_id"])
        target_row = self.resolve_target_node(ctx, req["session_id"], require_manage=True)
        target_id = str(target_row["node_id"])
        run_id = req["run_id"]

        with self.store.transaction("IMMEDIATE") as txn:
            cached = self._check_idempotent_request(
                txn.conn,
                caller_id,
                "cancel_run",
                req.request_id,
                req.normalized_hash,
            )
            if cached is not None:
                return cached

            t_row = txn.execute(
                "SELECT * FROM turns WHERE run_id = ? AND node_id = ?",
                (run_id, target_id),
            ).fetchone()
            if t_row is None and not strict_node:
                t_any = txn.execute(
                    "SELECT * FROM turns WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                if t_any is not None:
                    other_target = self.resolve_target_node(ctx, str(t_any["node_id"]), require_manage=True)
                    target_id = str(other_target["node_id"])
                    t_row = t_any

            if t_row is None:
                raise SideSessionError(
                    ErrorCode.NOT_FOUND,
                    f"Run not found: {run_id}",
                    {"run_id": run_id, "session_id": target_id},
                )

            cur_exec_state = str(t_row["execution_state"])
            now = self._now_iso()

            if cur_exec_state in ("exited", "failed", "cancelled"):
                res = {
                    "ok": True,
                    "request_id": req.request_id,
                    "node_id": target_id,
                    "session_id": target_id,
                    "run_id": run_id,
                    "state": "already_exited",
                    "status": "already_exited",
                    "execution_state": cur_exec_state,
                    "slot_released": True,
                    "reason": req["reason"],
                    "revision": txn.revision,
                }
                self._record_idempotent_request(
                    txn.conn,
                    caller_id,
                    "cancel_run",
                    req.request_id,
                    req.normalized_hash,
                    res,
                )
                return res

            control_id = self._new_uuid()
            owner_epoch = int(t_row["owner_epoch"])
            cmd_payload_obj = {
                "command_kind": "stop_run",
                "kind": "cancel_run",
                "run_id": run_id,
                "node_id": target_id,
                "reason": req["reason"],
            }
            cmd_payload_json = canonical_json(cmd_payload_obj)
            cmd_payload_hash = sha256_hex(cmd_payload_json)

            txn.execute(
                """
                UPDATE turns
                SET execution_state = 'stopping',
                    cancel_requested_at = COALESCE(cancel_requested_at, ?),
                    cancel_reason = COALESCE(cancel_reason, ?)
                WHERE run_id = ?
                """,
                (now, req["reason"], run_id),
            )
            txn.execute(
                """
                UPDATE nodes
                SET pause_requested = 1,
                    revision = revision + 1,
                    updated_at = ?
                WHERE node_id = ?
                """,
                (now, target_id),
            )
            # Never release parent_slots here; slot remains occupied in 'stopping' until close_run confirms exit
            txn.execute(
                """
                UPDATE parent_slots
                SET state = 'stopping',
                    updated_at = ?
                WHERE node_id = ? AND state != 'released'
                """,
                (now, target_id),
            )
            txn.execute(
                """
                INSERT INTO control_commands (
                    control_id, request_id, node_id, run_id, owner_epoch,
                    kind, wait_id, payload_hash, payload, authority_ref,
                    state, receipt_ref, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'cancel_run', NULL, ?, ?, ?, 'queued', NULL, ?, ?)
                """,
                (
                    control_id,
                    req.request_id,
                    target_id,
                    run_id,
                    owner_epoch,
                    cmd_payload_hash,
                    cmd_payload_json,
                    f"caller:{caller_id}:{req.request_id}",
                    now,
                    now,
                ),
            )

            res = ControlResult(
                control_id=control_id,
                node_id=target_id,
                status="stopping",
                revision=txn.revision,
                run_id=run_id,
            ).to_dict()
            res.update(
                {
                    "ok": True,
                    "request_id": req.request_id,
                    "control_id": control_id,
                    "command_id": control_id,
                    "command_kind": _AliasStr("stop_run", "cancel_run"),
                    "kind": _AliasStr("cancel_run", "stop_run"),
                    "node_id": target_id,
                    "session_id": target_id,
                    "run_id": run_id,
                    "state": "stopping",
                    "status": "stopping",
                    "execution_state": "stopping",
                    "command_state": "queued",
                    "slot_released": False,
                    "reason": req["reason"],
                    "revision": txn.revision,
                }
            )
            self._record_idempotent_request(
                txn.conn,
                caller_id,
                "cancel_run",
                req.request_id,
                req.normalized_hash,
                res,
            )

        self._notify_supervisor(
            {
                "event": "cancel_run",
                "control_id": control_id,
                "node_id": target_id,
                "run_id": run_id,
            }
        )
        return res

    def get_control(
        self,
        caller: CallerContext | Mapping[str, Any] | str,
        args: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Inspect status of a control command (`respond_wait` or `cancel_run`)."""
        ctx = self._coerce_caller(caller)
        raw_args = self._merge_args(args, kwargs)
        req = normalize_request("get_control", raw_args)
        caller_node = self.ensure_caller_node(ctx)
        caller_id = str(caller_node["node_id"])
        control_id = req["control_id"]

        c_row = self.store.conn.execute(
            "SELECT * FROM control_commands WHERE control_id = ?",
            (control_id,),
        ).fetchone()
        if c_row is None:
            raise SideSessionError(ErrorCode.NOT_FOUND, f"Control command not found: {control_id}")

        target_id = str(c_row["node_id"])
        if not self._is_ancestor_or_self(self.store.conn, caller_id, target_id):
            raise _err(
                ErrorCode.NOT_FOUND_OR_FORBIDDEN,
                "Caller is not authorized to read this control command",
                {"control_id": control_id},
                aliases=("PERMISSION_DENIED", ErrorCode.FORBIDDEN),
            )

        payload_obj = json.loads(c_row["payload"] or "{}")
        res = ControlResult(
            control_id=control_id,
            node_id=target_id,
            status=str(c_row["state"]),
            revision=self.store.get_revision(),
            run_id=c_row["run_id"],
            wait_id=c_row["wait_id"],
        ).to_dict()
        res.update(
            {
                "ok": True,
                "request_id": c_row["request_id"],
                "kind": c_row["kind"],
                "command_kind": payload_obj.get("command_kind", c_row["kind"]),
                "state": c_row["state"],
                "payload": payload_obj,
                "receipt_ref": c_row["receipt_ref"],
            }
        )
        return res

    def _build_hook_context_text(
        self,
        events: list[dict[str, Any]],
        linked_sessions: list[dict[str, Any]],
        *,
        include_event_tags: bool = True,
    ) -> str:
        summary_lines = ["Side-sessions updates:"]
        event_xml_blocks: list[str] = []

        for ev in events:
            payload = json.loads(ev["payload"] or "{}")
            ev_id = str(ev["event_id"])
            kind = str(ev["kind"])
            child_name = str(payload.get("child_name") or ev.get("child_node_id") or "group")
            child_id = str(ev.get("child_node_id") or "")
            outcome = str(payload.get("outcome") or "")
            recap = html.escape(str(payload.get("recap") or ""), quote=False)
            report_ref = str(payload.get("report_ref") or "")
            manifest_ref = str(payload.get("manifest_ref") or "")
            ref_part = f" report_ref={report_ref}" if report_ref else (f" manifest_ref={manifest_ref}" if manifest_ref else "")
            summary_lines.append(
                f"- [{kind}] {child_name} ({child_id}) event_id={ev_id} outcome={outcome}:{ref_part} {recap}".strip()
            )
            if include_event_tags:
                fmt_xml = payload.get("formatted_event") or self._format_event_xml(
                    {**payload, "linked_sessions_now": linked_sessions}
                )
                event_xml_blocks.append(str(fmt_xml))

        summary_lines.append("Linked sessions now:")
        if linked_sessions:
            for item in linked_sessions:
                summary_lines.append(
                    f"- {item.get('name')} ({item.get('node_id')}): status={item.get('status')} exec={item.get('execution_state')}"
                )
        else:
            summary_lines.append("- (none)")

        reminder_block = "<system-reminder>\n" + "\n".join(summary_lines) + "\n</system-reminder>"
        if include_event_tags and event_xml_blocks:
            full_text = reminder_block + "\n" + "\n".join(event_xml_blocks)
        else:
            full_text = reminder_block

        if len(full_text.encode("utf-8")) <= MAX_HOOK_CONTEXT_BYTES:
            return full_text

        # Compact fallback if payload exceeds 8192 bytes
        compact_xmls: list[str] = []
        for ev in events:
            payload = json.loads(ev["payload"] or "{}")
            ev_id = html.escape(str(ev["event_id"]), quote=True)
            kind = html.escape(str(ev["kind"]), quote=True)
            report_ref = html.escape(str(payload.get("report_ref") or ""), quote=True)
            manifest_ref = html.escape(str(payload.get("manifest_ref") or ""), quote=True)
            compact_xmls.append(
                f'<side-sessions-event event_id="{ev_id}" kind="{kind}" '
                f'report_ref="{report_ref}" manifest_ref="{manifest_ref}" truncated="true" />'
            )
        compact_text = reminder_block + ("\n" + "\n".join(compact_xmls) if include_event_tags and compact_xmls else "")
        if len(compact_text.encode("utf-8")) <= MAX_HOOK_CONTEXT_BYTES:
            return compact_text

        encoded = compact_text.encode("utf-8")[: MAX_HOOK_CONTEXT_BYTES - 32]
        return encoded.decode("utf-8", errors="ignore") + "\n</system-reminder>"

    @staticmethod
    def _extract_inbox_message_text(raw_payload: str) -> str:
        s = str(raw_payload or "")
        stripped = s.strip()
        if stripped.startswith("{"):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, Mapping):
                    for key in ("text", "message", "content"):
                        if key in parsed and parsed[key] is not None:
                            return str(parsed[key])
            except Exception:
                pass
        if "<cross-session-message" in s and "</cross-session-message>" in s:
            gt_idx = s.find(">")
            end_idx = s.rfind("</cross-session-message>")
            if 0 <= gt_idx < end_idx:
                return s[gt_idx + 1 : end_idx].strip("\n")
        return s

    @staticmethod
    def _parse_slash_command_from_prompt(prompt_text: str) -> tuple[str, str] | None:
        s = str(prompt_text or "").replace("\r\n", "\n").replace("\r", "\n").strip()
        if not s:
            return None
        if "\n" not in s:
            m = re.match(r"^/side-sessions:(approve|dismiss|respond|merge|cleanup)(?:\s+(.*))?$", s)
            if m:
                return m.group(1), (m.group(2) or "").strip()
            return None
        lines = s.splitlines()
        if len(lines) >= 2:
            m_exp = re.match(r"^Run custom command /side-sessions:(approve|dismiss|respond|merge|cleanup)\.$", lines[0].strip())
            if m_exp and lines[1].strip().startswith("Command source:"):
                cmd_name = m_exp.group(1)
                marker = "\n\nUser arguments:\n"
                if marker in s:
                    arg_tail = s.rsplit(marker, 1)[1].strip()
                    if "\n" in arg_tail:
                        return None
                    return cmd_name, arg_tail
                return cmd_name, ""
        return None

    def confirm_emitted(self, deliveries: list[tuple[str, str]] | None = None) -> int:
        """Confirm that child_hook inbox_deliveries were flushed to stdout."""
        items = list(self._pending_emit_deliveries if deliveries is None else deliveries)
        if not items:
            return 0
        now = self._now_iso()
        updated = 0
        with self.store.transaction("IMMEDIATE") as txn:
            for target_nid, msg_id in items:
                cur = txn.execute(
                    """
                    UPDATE inbox_deliveries
                    SET emitted_at = ?, updated_at = ?
                    WHERE target_node_id = ? AND message_id = ? AND channel = 'child_hook'
                    """,
                    (now, now, target_nid, msg_id),
                )
                updated += cur.rowcount
        if deliveries is None:
            self._pending_emit_deliveries.clear()
        return updated

    def handle_hook(
        self,
        ctx: HookContext | Mapping[str, Any],
        *,
        defer_emit_confirm: bool = False,
    ) -> dict[str, Any] | None:
        """Process synchronous lifecycle hooks (`SessionStart`, `UserPromptSubmit`, `PostToolUse`, `Stop`)."""
        self._pending_emit_deliveries = []
        if isinstance(ctx, Mapping):
            raw_in = dict(ctx.get("raw_input")) if isinstance(ctx.get("raw_input"), Mapping) else dict(ctx)
            event_name = str(
                ctx.get("event")
                or raw_in.get("hook_event_name")
                or raw_in.get("hookEventName")
                or raw_in.get("event")
                or "UserPromptSubmit"
            )
            runtime_sid = str(
                ctx.get("runtime_sid")
                or ctx.get("session_id")
                or ctx.get("sessionId")
                or raw_in.get("session_id")
                or raw_in.get("sessionId")
                or ""
            ).strip()
            cwd = str(ctx.get("cwd") or raw_in.get("cwd") or "")
            turn_id = (
                ctx.get("runtime_turn_id")
                or ctx.get("turn_id")
                or raw_in.get("turn_id")
                or raw_in.get("turnId")
            )
            stop_active = ctx.get("stop_hook_active")
            if stop_active is None and "stop_hook_active" in raw_in:
                stop_active = bool(raw_in["stop_hook_active"])
            ctx = HookContext(
                event=event_name,
                invocation_id=str(ctx.get("invocation_id") or self._new_uuid()),
                runtime_sid=runtime_sid,
                cwd=cwd,
                raw_input=raw_in,
                deadline_at=str(ctx.get("deadline_at") or self._future_iso(seconds=3)),
                runtime_turn_id=str(turn_id).strip() if turn_id else None,
                stop_hook_active=stop_active,
            )

        if ctx.event not in VALID_HOOK_EVENTS:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"Unsupported hook event: {ctx.event!r}",
                {"event": ctx.event},
            )

        node = self.ensure_caller_node(
            CallerContext(
                runtime_sid=ctx.runtime_sid,
                runtime_turn_id=ctx.runtime_turn_id,
                workspace_path=ctx.cwd,
            )
        )
        node_id = str(node["node_id"])
        now = self._now_iso()
        turn_marker = ctx.runtime_turn_id or ctx.invocation_id

        with self.store.transaction("IMMEDIATE") as txn:
            txn.execute(
                """
                UPDATE bindings
                SET last_turn_id = COALESCE(?, last_turn_id),
                    cwd = CASE WHEN ? != '' THEN ? ELSE cwd END,
                    last_seen_at = ?
                WHERE runtime_sid = ?
                """,
                (ctx.runtime_turn_id, ctx.cwd, ctx.cwd, now, ctx.runtime_sid),
            )
            presented_deliveries = txn.execute(
                """
                SELECT * FROM inbox_deliveries
                WHERE target_node_id = ? AND channel = 'child_hook' AND state = 'presented'
                """,
                (node_id,),
            ).fetchall()
            for d_row in presented_deliveries:
                d_dict = dict(d_row)
                prev_turn = str(d_row["presented_in_turn"] or "")
                if d_dict.get("emitted_at") is None:
                    if prev_turn != turn_marker:
                        txn.execute(
                            """
                            UPDATE inbox_messages
                            SET state = 'queued', updated_at = ?
                            WHERE target_node_id = ? AND message_id = ? AND state = 'claimed' AND run_id IS NULL
                            """,
                            (now, node_id, d_row["message_id"]),
                        )
                        txn.execute(
                            """
                            DELETE FROM inbox_deliveries
                            WHERE target_node_id = ? AND message_id = ? AND channel = 'child_hook'
                            """,
                            (node_id, d_row["message_id"]),
                        )
                else:
                    should_ack = (
                        (bool(ctx.runtime_turn_id) and prev_turn != ctx.runtime_turn_id)
                        or (
                            not ctx.runtime_turn_id
                            and ctx.event == "UserPromptSubmit"
                            and prev_turn != ctx.invocation_id
                        )
                    )
                    if should_ack:
                        txn.execute(
                            """
                            UPDATE inbox_deliveries
                            SET state = 'acked', updated_at = ?
                            WHERE target_node_id = ? AND message_id = ? AND channel = 'child_hook'
                            """,
                            (now, node_id, d_row["message_id"]),
                        )
                        txn.execute(
                            """
                            UPDATE inbox_messages
                            SET state = 'completed', updated_at = ?
                            WHERE target_node_id = ? AND message_id = ? AND state = 'claimed' AND run_id IS NULL
                            """,
                            (now, node_id, d_row["message_id"]),
                        )

        raw_in = dict(ctx.raw_input) if isinstance(ctx.raw_input, Mapping) else {}
        command_feedback: str | None = None

        # 1. UserPromptSubmit: observe human input provenance & reset wake budget on verified human turn
        if ctx.event == "UserPromptSubmit":
            obs_input: HookContext | dict[str, Any] = ctx
            active_t = self.store.conn.execute(
                """
                SELECT input_id FROM turns
                WHERE node_id = ? AND execution_state IN ('queued', 'starting', 'running', 'waiting_input')
                ORDER BY turn_seq DESC LIMIT 1
                """,
                (node_id,),
            ).fetchone()
            cand_inp_id = str(
                raw_in.get("input_id")
                or raw_in.get("inputId")
                or (active_t["input_id"] if (active_t and active_t["input_id"]) else "")
                or ctx.runtime_turn_id
                or ctx.invocation_id
            ).strip()
            if not raw_in.get("input_id") and not raw_in.get("inputId"):
                enriched_raw = dict(raw_in)
                enriched_raw["input_id"] = cand_inp_id
                obs_input = replace(ctx, raw_input=enriched_raw)

            # Intercept trusted human slash commands (/side-sessions:approve|dismiss|respond|merge)
            raw_origin = str(
                raw_in.get("origin")
                or raw_in.get("input_origin")
                or raw_in.get("source")
                or ""
            ).strip()
            non_human_origins = (
                "auto_continuation",
                "stop_continuation",
                "stop_hook",
                "system/side_sessions",
                "system",
                "managed_dispatch",
                "model",
                "agent",
            )
            prompt_text = str(raw_in.get("prompt") or raw_in.get("user_prompt") or raw_in.get("text") or "")
            parsed_slash = self._parse_slash_command_from_prompt(prompt_text)

            if (
                parsed_slash is not None
                and ctx.stop_hook_active is not True
                and active_t is None
                and raw_origin not in non_human_origins
                and raw_in.get("verified") is not False
                and not self._has_external_live_worker(self.store.conn, node_id)
            ):
                # Check that cand_inp_id is not already recorded as non-human in HostAdapter or DB
                pre_non_human = False
                if hasattr(self.host_adapter, "_provenance_records"):
                    cached_rec = self.host_adapter._provenance_records.get((ctx.runtime_sid, cand_inp_id))
                    if cached_rec is not None and not getattr(cached_rec, "verified", False):
                        pre_non_human = True
                if not pre_non_human:
                    bad_db_row = self.store.conn.execute(
                        """
                        SELECT 1 FROM input_provenance
                        WHERE input_id = ?
                          AND (verified = 0 OR origin IN ('system/side_sessions', 'auto_continuation', 'system'))
                        LIMIT 1
                        """,
                        (cand_inp_id,),
                    ).fetchone()
                    if bad_db_row is not None:
                        pre_non_human = True

                if not pre_non_human:
                    slash_cmd, slash_args = parsed_slash
                    caller_ctx = CallerContext(
                        runtime_sid=ctx.runtime_sid,
                        runtime_turn_id=ctx.runtime_turn_id,
                        workspace_path=ctx.cwd or str(node.get("canonical_workspace") or ""),
                        node_id=node_id,
                    )
                    try:
                        if slash_cmd == "approve":
                            a_tokens = slash_args.split()
                            if not a_tokens:
                                raise SideSessionError(
                                    ErrorCode.INVALID_REQUEST,
                                    "Usage: /side-sessions:approve <proposal-id> | /side-sessions:approve context <operation-id> <snapshot-hash>",
                                )
                            if a_tokens[0] == "context":
                                if len(a_tokens) != 3:
                                    raise SideSessionError(
                                        ErrorCode.INVALID_REQUEST,
                                        "Usage: /side-sessions:approve context <operation-id> <snapshot-hash>",
                                    )
                                op_id = validate_uuid(a_tokens[1], "operation_id")
                                snap_hash = a_tokens[2]
                                self.host_adapter.record_human_input(
                                    runtime_sid=ctx.runtime_sid,
                                    input_id=cand_inp_id,
                                    origin="slash_command",
                                    runtime_turn_id=ctx.runtime_turn_id,
                                    command_id="/side-sessions:approve",
                                    action_binding={
                                        "purpose": "context_quality",
                                        "target_id": op_id,
                                        "target_hash": snap_hash,
                                    },
                                )
                                res_ctx = self.approve_context(
                                    caller_ctx,
                                    {
                                        "operation_id": op_id,
                                        "snapshot_hash": snap_hash,
                                        "real_input_id": cand_inp_id,
                                        "command_id": "/side-sessions:approve",
                                        "origin": "slash_command",
                                    },
                                )
                                command_feedback = (
                                    f"[side-sessions:approve] Context snapshot {snap_hash[:12]} for operation {op_id} "
                                    f"was approved by Hook (stage={res_ctx.get('stage')}). Do NOT call approve_context again."
                                )
                            else:
                                if len(a_tokens) != 1:
                                    raise SideSessionError(
                                        ErrorCode.INVALID_REQUEST,
                                        "Usage: /side-sessions:approve <proposal-id> (unexpected extra arguments)",
                                    )
                                prop_ref = a_tokens[0]
                                p_row = self._resolve_proposal_row(self.store.conn, prop_ref)
                                if p_row is None:
                                    raise SideSessionError(ErrorCode.NOT_FOUND, f"Proposal not found: {prop_ref}")
                                p_id = str(p_row["proposal_id"])
                                p_hash = str(p_row["task_hash"])
                                self.host_adapter.record_human_input(
                                    runtime_sid=ctx.runtime_sid,
                                    input_id=cand_inp_id,
                                    origin="slash_command",
                                    runtime_turn_id=ctx.runtime_turn_id,
                                    command_id="/side-sessions:approve",
                                    action_binding={
                                        "purpose": "proposal",
                                        "target_id": p_id,
                                        "target_hash": p_hash,
                                    },
                                )
                                res_prop = self.approve_proposal(
                                    caller_ctx,
                                    {
                                        "proposal_id": p_id,
                                        "auto_claim": False,
                                        "real_input_id": cand_inp_id,
                                        "command_id": "/side-sessions:approve",
                                        "origin": "slash_command",
                                    },
                                )
                                if res_prop.get("state") == "approved":
                                    self._notify_supervisor(
                                        {"event": "proposal_claim_queued", "proposal_id": p_id}
                                    )
                                    command_feedback = (
                                        f"[side-sessions:approve] Proposal {p_id} was approved by Hook and queued in "
                                        f"proposal_claim_jobs for background worker startup. Do NOT call approve_proposal or start_session again."
                                    )
                                else:
                                    command_feedback = (
                                        f"[side-sessions:approve] Offer proposal {p_id} was approved by Hook "
                                        f"(state=awaiting_brief). Call start_session with proposal_id, prompt, and background to claim it."
                                    )

                        elif slash_cmd == "dismiss":
                            d_tokens = slash_args.split()
                            if len(d_tokens) != 1:
                                raise SideSessionError(
                                    ErrorCode.INVALID_REQUEST,
                                    "Usage: /side-sessions:dismiss <proposal-id>",
                                )
                            prop_ref = d_tokens[0]
                            self.host_adapter.record_human_input(
                                runtime_sid=ctx.runtime_sid,
                                input_id=cand_inp_id,
                                origin="slash_command",
                                runtime_turn_id=ctx.runtime_turn_id,
                                command_id="/side-sessions:dismiss",
                                action_binding={"purpose": "dismiss", "target_id": prop_ref},
                            )
                            res_dis = self.reject_proposal(caller_ctx, {"proposal_id": prop_ref})
                            command_feedback = (
                                f"[side-sessions:dismiss] Proposal {res_dis.get('proposal_id', prop_ref)} was dismissed by Hook "
                                f"(state={res_dis.get('state')}). Do NOT call dismiss_task again."
                            )

                        elif slash_cmd == "respond":
                            r_parts = slash_args.split(None, 1)
                            if len(r_parts) != 2 or not r_parts[0].strip() or not r_parts[1].strip():
                                raise SideSessionError(
                                    ErrorCode.INVALID_REQUEST,
                                    "Usage: /side-sessions:respond <wait-id> <answer>",
                                )
                            wait_id_arg, answer_str = r_parts[0].strip(), r_parts[1].strip()
                            w_row = self.store.conn.execute(
                                "SELECT * FROM wait_requests WHERE wait_id = ?",
                                (wait_id_arg,),
                            ).fetchone()
                            if w_row is None:
                                raise SideSessionError(ErrorCode.NOT_FOUND, f"Wait request not found: {wait_id_arg}")
                            w_kind = str(w_row["kind"])
                            w_nonce = str(w_row["nonce"])
                            if w_kind == "permission":
                                opt_id_val = answer_str
                                dec_val = answer_str
                                raw_opts = (
                                    json.loads(w_row["options"] or "[]")
                                    if isinstance(w_row["options"], str)
                                    else list(w_row["options"] or [])
                                )
                                for opt in raw_opts:
                                    if isinstance(opt, Mapping):
                                        cand_ids = {
                                            str(opt[k])
                                            for k in ("option_id", "id", "decision", "value")
                                            if opt.get(k) is not None
                                        }
                                        if answer_str in cand_ids:
                                            opt_id_val = str(
                                                opt.get("option_id")
                                                or opt.get("id")
                                                or opt.get("decision")
                                                or answer_str
                                            )
                                            dec_val = str(
                                                opt.get("decision")
                                                or opt.get("value")
                                                or opt.get("option_id")
                                                or answer_str
                                            )
                                            break
                                resp_obj: dict[str, Any] = {
                                    "kind": "permission",
                                    "option_id": opt_id_val,
                                    "decision": dec_val,
                                }
                            elif w_kind == "elicitation":
                                if answer_str in ("accept", "decline", "cancel"):
                                    resp_obj = {"kind": "elicitation", "action": answer_str}
                                else:
                                    resp_obj = {"kind": "elicitation", "action": "accept", "content": answer_str}
                            else:
                                resp_obj = {"kind": "input", "text": answer_str}

                            resp_hash = canonical_json_sha256(resp_obj)
                            target_hash = sha256_hex(f"{w_nonce}:{resp_hash}")
                            self.host_adapter.record_human_input(
                                runtime_sid=ctx.runtime_sid,
                                input_id=cand_inp_id,
                                origin="slash_command",
                                runtime_turn_id=ctx.runtime_turn_id,
                                command_id="/side-sessions:respond",
                                action_binding={
                                    "purpose": "wait_response",
                                    "target_id": str(w_row["wait_id"]),
                                    "target_hash": target_hash,
                                },
                            )
                            res_wait = self.respond_to_wait(
                                caller_ctx,
                                {
                                    "request_id": str(uuid.uuid5(uuid.NAMESPACE_OID, f"hook-respond:{cand_inp_id}")),
                                    "wait_id": str(w_row["wait_id"]),
                                    "nonce": w_nonce,
                                    "response": resp_obj,
                                    "real_input_id": cand_inp_id,
                                    "command_id": "/side-sessions:respond",
                                    "origin": "slash_command",
                                },
                            )
                            command_feedback = (
                                f"[side-sessions:respond] Wait {w_row['wait_id']} was responded to by Hook "
                                f"(control_id={res_wait.get('control_id')}, status={res_wait.get('status')}). Do NOT call respond_to_wait again."
                            )

                        elif slash_cmd == "merge":
                            m_tokens = slash_args.split()
                            if len(m_tokens) < 2:
                                raise SideSessionError(
                                    ErrorCode.INVALID_REQUEST,
                                    "Usage: /side-sessions:merge <session> <preview-hash> [ff-only|merge|squash] [--cleanup]",
                                )
                            sess_ref = m_tokens[0]
                            prev_hash = m_tokens[1].lower()
                            if not re.fullmatch(r"[0-9a-f]{64}", prev_hash):
                                raise SideSessionError(
                                    ErrorCode.INVALID_REQUEST,
                                    "preview_hash in /side-sessions:merge must be a 64-character hex SHA-256 string",
                                )
                            explicit_mode: str | None = None
                            cleanup_flag = False
                            for extra_tok in m_tokens[2:]:
                                if extra_tok == "--cleanup":
                                    if cleanup_flag:
                                        raise SideSessionError(
                                            ErrorCode.INVALID_REQUEST,
                                            "Duplicate --cleanup flag in /side-sessions:merge",
                                        )
                                    cleanup_flag = True
                                elif extra_tok in ("ff-only", "merge", "squash"):
                                    if explicit_mode is not None:
                                        raise SideSessionError(
                                            ErrorCode.INVALID_REQUEST,
                                            f"Conflicting or duplicate merge mode {extra_tok!r} in /side-sessions:merge",
                                        )
                                    explicit_mode = extra_tok
                                else:
                                    raise SideSessionError(
                                        ErrorCode.INVALID_REQUEST,
                                        f"Unknown argument or flag {extra_tok!r} in /side-sessions:merge; expected [ff-only|merge|squash] [--cleanup]",
                                    )
                            merge_mode = explicit_mode or "merge"
                            target_row = self.resolve_target_node(caller_ctx, sess_ref, require_manage=True)
                            target_nid = str(target_row["node_id"])
                            self.host_adapter.record_human_input(
                                runtime_sid=ctx.runtime_sid,
                                input_id=cand_inp_id,
                                origin="slash_command",
                                runtime_turn_id=ctx.runtime_turn_id,
                                command_id="/side-sessions:merge",
                                action_binding={
                                    "purpose": "worktree_merge",
                                    "target_id": target_nid,
                                    "target_hash": prev_hash,
                                },
                            )
                            res_m = self.enqueue_merge_worktree_job(
                                caller_ctx,
                                session_ref=target_nid,
                                preview_hash=prev_hash,
                                mode=merge_mode,
                                cleanup_after=cleanup_flag,
                                real_input_id=cand_inp_id,
                                command_id="/side-sessions:merge",
                            )
                            command_feedback = (
                                f"[side-sessions:merge] Worktree merge job {res_m['job_id']} queued by Hook "
                                f"(session={target_nid}, mode={merge_mode}, cleanup_after={cleanup_flag})."
                            )

                        elif slash_cmd == "cleanup":
                            c_tokens = slash_args.split()
                            if len(c_tokens) != 1:
                                raise SideSessionError(
                                    ErrorCode.INVALID_REQUEST,
                                    "Usage: /side-sessions:cleanup <session>",
                                )
                            sess_ref = c_tokens[0]
                            target_row = self._resolve_cleanup_target_node(caller_ctx, sess_ref)
                            target_nid = str(target_row["node_id"])
                            cleanup_hash = canonical_json_sha256({"cmd": "cleanup", "node_id": target_nid})
                            self.host_adapter.record_human_input(
                                runtime_sid=ctx.runtime_sid,
                                input_id=cand_inp_id,
                                origin="slash_command",
                                runtime_turn_id=ctx.runtime_turn_id,
                                command_id="/side-sessions:cleanup",
                                action_binding={
                                    "purpose": "worktree_merge",
                                    "cmd": "cleanup",
                                    "node_id": target_nid,
                                    "target_id": target_nid,
                                    "target_hash": cleanup_hash,
                                },
                            )
                            res_c = self.enqueue_cleanup_worktree_job(
                                caller_ctx,
                                {
                                    "session_id": target_nid,
                                    "real_input_id": cand_inp_id,
                                    "command_id": "/side-sessions:cleanup",
                                },
                            )
                            command_feedback = (
                                f"[side-sessions:cleanup] Worktree cleanup job {res_c['job_id']} queued by Hook "
                                f"(session={target_nid}). Do NOT call internal cleanup ports directly."
                            )
                    except SideSessionError as slash_exc:
                        command_feedback = f"[side-sessions:{slash_cmd}:error] [{slash_exc.code}] {slash_exc.message}"

            obs = self.host_adapter.observe_input(obs_input)
            prov = obs.to_dict() if hasattr(obs, "to_dict") else (dict(obs) if isinstance(obs, Mapping) else {})
            verified_human = bool(prov.get("verified_human") or getattr(obs, "verified", False)) and getattr(
                obs, "origin", prov.get("origin")
            ) in (
                "human_prompt",
                "slash_command",
            )
            if verified_human:
                inp_id = str(getattr(obs, "input_id", None) or ctx.runtime_turn_id or ctx.invocation_id)
                with self.store.transaction("IMMEDIATE") as txn:
                    txn.execute(
                        """
                        INSERT INTO wake_budget (
                            parent_node_id, user_epoch, last_verified_human_input_id,
                            wake_count, wake_inflight, parent_stop_state, updated_at
                        ) VALUES (?, 1, ?, 0, NULL, 'idle', ?)
                        ON CONFLICT(parent_node_id) DO UPDATE SET
                            user_epoch = CASE
                                WHEN wake_budget.last_verified_human_input_id IS NULL
                                  OR wake_budget.last_verified_human_input_id != excluded.last_verified_human_input_id
                                THEN wake_budget.user_epoch + 1
                                ELSE wake_budget.user_epoch
                            END,
                            last_verified_human_input_id = excluded.last_verified_human_input_id,
                            wake_count = CASE
                                WHEN wake_budget.last_verified_human_input_id IS NULL
                                  OR wake_budget.last_verified_human_input_id != excluded.last_verified_human_input_id
                                THEN 0
                                ELSE wake_budget.wake_count
                            END,
                            wake_inflight = CASE
                                WHEN wake_budget.last_verified_human_input_id IS NULL
                                  OR wake_budget.last_verified_human_input_id != excluded.last_verified_human_input_id
                                THEN NULL
                                ELSE wake_budget.wake_inflight
                            END,
                            parent_stop_state = CASE
                                WHEN wake_budget.last_verified_human_input_id IS NULL
                                  OR wake_budget.last_verified_human_input_id != excluded.last_verified_human_input_id
                                THEN 'idle'
                                ELSE wake_budget.parent_stop_state
                            END,
                            updated_at = excluded.updated_at
                        """,
                        (node_id, inp_id, now),
                    )

            is_human_child_prompt = bool(verified_human) and active_t is None
            if (
                node.get("parent_node_id")
                and str(node.get("node_status") or "") != "archived"
                and is_human_child_prompt
                and not self._has_external_live_worker(self.store.conn, node_id)
            ):
                with self.store.transaction("IMMEDIATE") as txn:
                    cur_node_row = txn.execute(
                        "SELECT node_status FROM nodes WHERE node_id = ?",
                        (node_id,),
                    ).fetchone()
                    if cur_node_row is not None and str(cur_node_row["node_status"]) != "archived":
                        self._assert_no_active_worktree_job(txn.conn, node_id)
                        txn.execute(
                            """
                            INSERT INTO interactive_leases (node_id, lease_until, source_turn_id)
                            VALUES (?, ?, ?)
                            ON CONFLICT(node_id) DO UPDATE SET
                                lease_until = excluded.lease_until,
                                source_turn_id = excluded.source_turn_id
                            """,
                            (node_id, self._future_iso(minutes=10), turn_marker),
                        )

        # 2. PostToolUse / PreToolUse: bind task action if active/frozen task turn binding exists
        if ctx.event in ("PostToolUse", "PreToolUse"):
            turn_key = ctx.runtime_turn_id or "turn-default"
            binding_row = self.store.conn.execute(
                """
                SELECT * FROM task_turn_bindings
                WHERE runtime_sid = ?
                  AND (runtime_turn_id IN (?, 'turn-default') OR state = 'frozen')
                  AND state IN ('active', 'frozen')
                ORDER BY CASE
                    WHEN runtime_turn_id = ? AND state = 'frozen' THEN 0
                    WHEN runtime_turn_id = ? AND state = 'active' THEN 1
                    WHEN state = 'frozen' THEN 2
                    ELSE 3
                END ASC
                LIMIT 1
                """,
                (ctx.runtime_sid, turn_key, turn_key, turn_key),
            ).fetchone()
            if binding_row is not None:
                tool_name_str = str(
                    raw_in.get("tool_name")
                    or raw_in.get("toolName")
                    or raw_in.get("tool")
                    or ""
                ).strip()
                tool_event = {
                    **raw_in,
                    "runtime_sid": ctx.runtime_sid,
                    "runtime_turn_id": str(binding_row["runtime_turn_id"]),
                    "tool_use_id": (
                        raw_in.get("tool_use_id")
                        or raw_in.get("toolUseId")
                        or raw_in.get("action_id")
                        or ctx.invocation_id
                    ),
                    "tool_name": tool_name_str,
                    "phase": "post" if ctx.event == "PostToolUse" else "pre",
                    "state": raw_in.get("state") or ("completed" if ctx.event == "PostToolUse" else "running"),
                }
                if ctx.event == "PreToolUse":
                    try:
                        self.host_adapter.bind_task_action(tool_event)
                    except SideSessionError as exc:
                        if exc.code in (ErrorCode.TASK_OWNER_CHANGED, ErrorCode.REVISION_CONFLICT):
                            return dict(
                                validate_hook_output(
                                    "PreToolUse",
                                    {
                                        "continue": False,
                                        "additionalContext": f"[{exc.code}] {exc.message}",
                                    },
                                )
                            )
                        raise
                    if str(binding_row["state"]) == "frozen":
                        return dict(
                            validate_hook_output(
                                "PreToolUse",
                                {
                                    "continue": False,
                                    "additionalContext": (
                                        f"[{ErrorCode.TASK_OWNER_CHANGED.value}] "
                                        f"Task {binding_row['task_id']} is frozen by task guard; tool action blocked."
                                    ),
                                },
                            )
                        )
                else:
                    self.host_adapter.bind_task_action(tool_event)
            if ctx.event == "PreToolUse":
                return None

        # 3. SessionStart / UserPromptSubmit / PostToolUse: present pending or lease-expired outbox_events & child_hook inbox_messages
        if ctx.event in ("SessionStart", "UserPromptSubmit", "PostToolUse"):
            child_msg_blocks: list[str] = []
            eligible: list[dict[str, Any]] = []
            eligible_text = ""
            with self.store.transaction("IMMEDIATE") as txn:
                cand_rows = txn.execute(
                    """
                    SELECT * FROM outbox_events
                    WHERE parent_node_id = ?
                      AND state IN ('pending', 'presented')
                    ORDER BY event_seq ASC
                    """,
                    (node_id,),
                ).fetchall()
                for r in cand_rows:
                    if str(r["state"]) == "pending" or self._is_expired(r["lease_until"]):
                        eligible.append(dict(r))
                    if len(eligible) >= MAX_HOOK_EVENTS:
                        break

                if eligible:
                    lease_until = self._future_iso(minutes=5)
                    for ev in eligible:
                        txn.execute(
                            """
                            UPDATE outbox_events
                            SET state = 'presented',
                                presented_in_turn = ?,
                                lease_owner = ?,
                                lease_until = ?,
                                attempt_count = attempt_count + 1
                            WHERE event_id = ?
                            """,
                            (turn_marker, ctx.invocation_id, lease_until, ev["event_id"]),
                        )
                    linked_now = self._build_linked_sessions_summary_in_conn(txn.conn, node_id)
                    eligible_text = self._build_hook_context_text(eligible, linked_now, include_event_tags=True)

                base_parts: list[str] = []
                if command_feedback:
                    base_parts.append(f"<system-reminder>\n{command_feedback}\n</system-reminder>")
                if eligible:
                    base_parts.append(eligible_text)
                used_bytes = len("\n".join(base_parts).encode("utf-8")) if base_parts else 0
                has_prior_part = bool(base_parts)

                if ctx.event in ("UserPromptSubmit", "PostToolUse") and node.get("parent_node_id"):
                    cur_node_st = txn.execute(
                        "SELECT node_status FROM nodes WHERE node_id = ?",
                        (node_id,),
                    ).fetchone()
                    lease_row = txn.execute(
                        "SELECT lease_until FROM interactive_leases WHERE node_id = ?",
                        (node_id,),
                    ).fetchone()
                    if (
                        cur_node_st is not None
                        and str(cur_node_st["node_status"]) != "archived"
                        and lease_row is not None
                        and not self._is_expired(lease_row["lease_until"])
                    ):
                        inbox_rows = txn.execute(
                            """
                            SELECT * FROM inbox_messages
                            WHERE target_node_id = ? AND state = 'queued' AND run_id IS NULL
                            ORDER BY seq ASC
                            LIMIT ?
                            """,
                            (node_id, MAX_HOOK_EVENTS),
                        ).fetchall()
                        for m_row in inbox_rows:
                            msg_text = self._extract_inbox_message_text(str(m_row["payload"]))
                            esc_mid = html.escape(str(m_row["message_id"]), quote=True)
                            esc_body = html.escape(msg_text, quote=False)
                            block = f'<side-sessions-message from="parent" message_id="{esc_mid}">{esc_body}</side-sessions-message>'
                            block_bytes = len(block.encode("utf-8"))
                            sep_bytes = 1 if (has_prior_part or child_msg_blocks) else 0
                            if used_bytes + sep_bytes + block_bytes > MAX_HOOK_CONTEXT_BYTES:
                                break
                            used_bytes += sep_bytes + block_bytes
                            child_msg_blocks.append(block)
                            txn.execute(
                                "UPDATE inbox_messages SET state = 'claimed', updated_at = ? WHERE target_node_id = ? AND message_id = ?",
                                (now, node_id, m_row["message_id"]),
                            )
                            emitted_val = None if defer_emit_confirm else now
                            txn.execute(
                                """
                                INSERT OR REPLACE INTO inbox_deliveries (
                                    message_id, target_node_id, channel, state,
                                    envelope_name, presented_in_turn, emitted_at, created_at, updated_at
                                ) VALUES (?, ?, 'child_hook', 'presented', NULL, ?, ?, ?, ?)
                                """,
                                (m_row["message_id"], node_id, turn_marker, emitted_val, now, now),
                            )
                            if defer_emit_confirm:
                                self._pending_emit_deliveries.append((node_id, str(m_row["message_id"])))

                if not eligible and not child_msg_blocks and not command_feedback:
                    return None

            parts_out = list(base_parts)
            if child_msg_blocks:
                parts_out.append("\n".join(child_msg_blocks))
            text = "\n".join(parts_out)
            if len(text.encode("utf-8")) > MAX_HOOK_CONTEXT_BYTES:
                text = text.encode("utf-8")[: MAX_HOOK_CONTEXT_BYTES - 32].decode("utf-8", errors="ignore")
            return dict(validate_hook_output(ctx.event, {"additionalContext": text}))

        # 4. Stop hook: child_user_turn report & group completion wake check & budget enforcement
        if ctx.event == "Stop":
            if ctx.stop_hook_active is not False:
                return None

            if node.get("parent_node_id") and not self._has_external_live_worker(self.store.conn, node_id):
                text = str(raw_in.get("last_assistant_message") or "").strip()
                if text:
                    with self.store.transaction("IMMEDIATE") as txn:
                        self._insert_outbox_event_in_conn(
                            txn.conn,
                            store_instance_id=txn.store_instance_id,
                            producer_key=f"user_turn:{ctx.runtime_sid}:{ctx.runtime_turn_id or ctx.invocation_id}",
                            parent_node_id=str(node["parent_node_id"]),
                            child_node_id=node_id,
                            turn_seq=None,
                            run_id=None,
                            dispatch_group_id=None,
                            member_id=None,
                            kind="child_user_turn",
                            outcome="success",
                            recap=text,
                            report_ref=None,
                            report_semantic_sha256=None,
                            manifest_ref=None,
                            artifact_refs=[],
                            child_turn_id=ctx.runtime_turn_id,
                        )
                    self.store.export_parent_notes(str(node["parent_node_id"]))

            with self.store.transaction("IMMEDIATE") as txn:
                txn.execute(
                    """
                    INSERT INTO wake_budget (
                        parent_node_id, user_epoch, last_verified_human_input_id,
                        wake_count, wake_inflight, parent_stop_state, updated_at
                    ) VALUES (?, 0, NULL, 0, NULL, 'idle', ?)
                    ON CONFLICT(parent_node_id) DO NOTHING
                    """,
                    (node_id, now),
                )
                wb_row = txn.execute(
                    "SELECT * FROM wake_budget WHERE parent_node_id = ?",
                    (node_id,),
                ).fetchone()
                user_epoch = int(wb_row["user_epoch"]) if wb_row is not None else 0
                if wb_row is not None and int(wb_row["wake_count"]) >= MAX_WAKE_BUDGET_PER_EPOCH:
                    return None
                if wb_row is not None and wb_row["wake_inflight"]:
                    return None

                unacked_rows = [
                    dict(r)
                    for r in txn.execute(
                        """
                        SELECT * FROM outbox_events
                        WHERE parent_node_id = ? AND state IN ('pending', 'presented')
                        ORDER BY event_seq ASC
                        """,
                        (node_id,),
                    ).fetchall()
                ]
                if not unacked_rows:
                    return None

                groups = [
                    dict(g)
                    for g in txn.execute(
                        "SELECT * FROM dispatch_groups WHERE parent_node_id = ? ORDER BY created_at ASC",
                        (node_id,),
                    ).fetchall()
                ]

                ready_group_ids: list[str] = []
                blocked_member_states = (
                    "waiting_input",
                    "stopping",
                    "reconciliation",
                    "admitted",
                    "queued",
                    "starting",
                    "running",
                    "preparing",
                    "open",
                    "incomplete",
                    "transfer",
                )
                for g in groups:
                    gid = str(g["dispatch_group_id"])
                    if str(g.get("assembly_state") or "") != "sealed":
                        continue
                    if str(g.get("integrity_state") or "ok") not in ("ok", "", "None"):
                        continue
                    if str(g.get("completion_state") or "") != "completed":
                        continue
                    already_woken = txn.execute(
                        "SELECT 1 FROM group_wakes WHERE parent_node_id = ? AND dispatch_group_id = ? LIMIT 1",
                        (node_id, gid),
                    ).fetchone()
                    if already_woken is not None:
                        continue

                    members = [
                        dict(m)
                        for m in txn.execute(
                            "SELECT * FROM dispatch_group_members WHERE dispatch_group_id = ? ORDER BY ordinal ASC",
                            (gid,),
                        ).fetchall()
                    ]
                    if not members:
                        continue
                    if any(str(m["state"]) in blocked_member_states for m in members):
                        continue

                    group_has_unacked = any(
                        str(ev.get("dispatch_group_id") or "") == gid
                        or (
                            ev.get("dispatch_group_id") is None
                            and any(str(m["node_id"]) == str(ev.get("child_node_id") or "") for m in members)
                        )
                        for ev in unacked_rows
                    )
                    if group_has_unacked:
                        ready_group_ids.append(gid)

                if not ready_group_ids:
                    return None

                chosen_gid = ready_group_ids[0]
                chosen_members = {
                    str(m["node_id"])
                    for m in txn.execute(
                        "SELECT node_id FROM dispatch_group_members WHERE dispatch_group_id = ?",
                        (chosen_gid,),
                    ).fetchall()
                }
                events_to_present = [
                    ev
                    for ev in unacked_rows
                    if str(ev.get("dispatch_group_id") or "") == chosen_gid
                    or (ev.get("dispatch_group_id") is None and str(ev.get("child_node_id") or "") in chosen_members)
                ][:MAX_HOOK_EVENTS]
                if not events_to_present:
                    return None
                linked_preview = self._build_linked_sessions_summary_in_conn(txn.conn, node_id)
                preview_text = self._build_hook_context_text(events_to_present, linked_preview, include_event_tags=True)
                if not isinstance(preview_text, str) or not preview_text.strip():
                    return None
                if len(preview_text.encode("utf-8")) > MAX_HOOK_CONTEXT_BYTES:
                    preview_text = preview_text.encode("utf-8")[: MAX_HOOK_CONTEXT_BYTES - 32].decode("utf-8", errors="ignore")
                validated_stop_out = dict(
                    validate_hook_output("Stop", {"continue": True, "additionalContext": preview_text})
                )

                reservation_id = self._new_uuid()
                cas = txn.execute(
                    """
                    UPDATE wake_budget
                    SET wake_count = wake_count + 1,
                        wake_inflight = ?,
                        parent_stop_state = 'waking',
                        updated_at = ?
                    WHERE parent_node_id = ?
                      AND wake_count < ?
                      AND wake_inflight IS NULL
                    """,
                    (reservation_id, now, node_id, MAX_WAKE_BUDGET_PER_EPOCH),
                )
                if cas.rowcount != 1:
                    return None
                txn.execute(
                    """
                    INSERT INTO group_wakes (
                        parent_node_id, user_epoch, dispatch_group_id, reservation_id,
                        state, host_input_id, created_at
                    ) VALUES (?, ?, ?, ?, 'woken', ?, ?)
                    """,
                    (node_id, user_epoch, chosen_gid, reservation_id, ctx.invocation_id, now),
                )

                lease_until = self._future_iso(minutes=5)
                turn_marker = ctx.runtime_turn_id or ctx.invocation_id
                for ev in events_to_present:
                    txn.execute(
                        """
                        UPDATE outbox_events
                        SET state = 'presented',
                            presented_in_turn = ?,
                            lease_owner = ?,
                            lease_until = ?,
                            attempt_count = attempt_count + 1
                        WHERE event_id = ?
                        """,
                        (turn_marker, ctx.invocation_id, lease_until, ev["event_id"]),
                    )

                txn.execute(
                    "UPDATE wake_budget SET wake_inflight = NULL, parent_stop_state = 'idle', updated_at = ? WHERE parent_node_id = ?",
                    (now, node_id),
                )

            return validated_stop_out

        return None



