"""Pluggable runtime driver layer (BaseDriver, ZCodeDriver, ScriptedFakeDriver, OrchestrateOnlyDriver)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import queue
import select
import shutil
import signal
import sqlite3
import subprocess
import threading
import time
from typing import Any, AsyncIterator, Callable, Iterator, Mapping
import uuid

try:
    from .contracts import (
        CLI_SESSION_MODES,
        DRIVER_API_VERSION,
        FORMATTER_VERSION,
        BoundWait,
        CapabilityStatus,
        ControlReceipt,
        DriverCapabilities,
        ErrorCode,
        ExitReceipt,
        HistoryProjection,
        RunAssignment,
        RuntimeCreateSpec,
        RuntimeHandle,
        RuntimeInput,
        RuntimeResumeSpec,
        RuntimeSnapshot,
        SendReceipt,
        SideSessionError,
        SourceAnchor,
        SourceCutoff,
        _SerializableMixin,
        _validate_wait_response,
        canonical_json,
        canonical_json_sha256,
        normalize_text,
        sha256_hex,
        utc_now_iso,
        validate_uuid,
    )
    from .host_adapter import DEFAULT_HOST_DB_PATH, get_process_lstart, verify_process_identity
except ImportError:  # pragma: no cover
    from contracts import (  # type: ignore
        CLI_SESSION_MODES,
        DRIVER_API_VERSION,
        FORMATTER_VERSION,
        BoundWait,
        CapabilityStatus,
        ControlReceipt,
        DriverCapabilities,
        ErrorCode,
        ExitReceipt,
        HistoryProjection,
        RunAssignment,
        RuntimeCreateSpec,
        RuntimeHandle,
        RuntimeInput,
        RuntimeResumeSpec,
        RuntimeSnapshot,
        SendReceipt,
        SideSessionError,
        SourceAnchor,
        SourceCutoff,
        _SerializableMixin,
        _validate_wait_response,
        canonical_json,
        canonical_json_sha256,
        normalize_text,
        sha256_hex,
        utc_now_iso,
        validate_uuid,
    )
    from host_adapter import DEFAULT_HOST_DB_PATH, get_process_lstart, verify_process_identity  # type: ignore


FORBIDDEN_INHERITED_SESSION_ENV_KEYS: tuple[str, ...] = (
    "CLAUDE_CODE_SESSION_ID",
    "CLAUDE_SESSION_ID",
    "CLAUDE_TURN_ID",
    "ZCODE_SESSION_ID",
)
FORBIDDEN_INHERITED_SESSION_ENV_PREFIXES: tuple[str, ...] = (
    "ZCODE_SESSION_",
    "ZCODE_TURN_",
    "ZCODE_TRACE_",
    "ZCODE_REQUEST_",
)


def _patch_capability_status_dunders() -> None:
    """Allow CapabilityStatus to be evaluated in boolean contexts and compared with bools."""
    def _cap_bool(self: CapabilityStatus) -> bool:
        return bool(self.source_supported and self.integration_verified)

    def _cap_eq(self: CapabilityStatus, other: object) -> bool:
        if isinstance(other, CapabilityStatus):
            return (
                self.source_supported == other.source_supported
                and self.integration_verified == other.integration_verified
            )
        if type(other) is bool:
            return bool(self.source_supported and self.integration_verified) is other
        return NotImplemented

    setattr(CapabilityStatus, "__bool__", _cap_bool)
    setattr(CapabilityStatus, "__eq__", _cap_eq)


_patch_capability_status_dunders()


def sanitize_subprocess_env(base_env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Strip inherited session/turn/trace/request IDs while preserving ZCODE_SIDE_SESSIONS_*."""
    src = os.environ if base_env is None else base_env
    env: dict[str, str] = {}
    for k, v in src.items():
        if k.startswith("ZCODE_SIDE_SESSIONS_"):
            env[k] = v
            continue
        if k in FORBIDDEN_INHERITED_SESSION_ENV_KEYS:
            continue
        if k.startswith(FORBIDDEN_INHERITED_SESSION_ENV_PREFIXES):
            continue
        env[k] = v
    return env


@dataclass(frozen=True)
class AnchorCheck(_SerializableMixin):
    """Validation result for a previously captured SourceAnchor."""

    ok: bool
    status: str
    source_session_id: str
    anchor_message_id: str | None = None
    sequence: int | None = None
    current_revision: int | None = None
    effective_chain_hash: str | None = None
    reverted: bool = False
    reason: str | None = None


@dataclass(frozen=True)
class RuntimeEvent(_SerializableMixin):
    """Normalized turn/status/wait event streamed from the runtime driver."""

    event_id: str
    runtime_sid: str
    kind: str
    runtime_turn_id: str | None = None
    input_id: str | None = None
    status: str | None = None
    outcome: str | None = None
    wait_request: dict[str, Any] | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""


@dataclass(frozen=True)
class WaitResponse(_SerializableMixin):
    """Structured response to a runtime wait_request (input / elicitation / permission)."""

    kind: str
    text: str | None = None
    action: str | None = None
    content: Any = None
    option_id: str | None = None
    decision: str | None = None

    def to_validated_dict(self) -> dict[str, Any]:
        raw: dict[str, Any] = {"kind": self.kind}
        if self.kind == "input":
            raw["text"] = self.text
        elif self.kind == "elicitation":
            raw["action"] = self.action
            if self.content is not None:
                raw["content"] = self.content
        elif self.kind == "permission":
            raw["option_id"] = self.option_id
            raw["decision"] = self.decision
        return _validate_wait_response(raw)


@dataclass(frozen=True)
class ForkReceipt(_SerializableMixin):
    """Receipt from an idle native fork operation (gated by supports_native_fork)."""

    runtime_sid: str
    parent_runtime_sid: str
    canonical_workspace: str
    snapshot_revision: int
    status: str = "forked"
    raw_response_ref: str = ""


class DualEventStream:
    """Iterator supporting both synchronous (`for ev in ...`) and async (`async for ev in ...`) iteration."""

    def __init__(self, items_or_supplier: list[RuntimeEvent] | Callable[[], RuntimeEvent | None]) -> None:
        if callable(items_or_supplier):
            self._supplier: Callable[[], RuntimeEvent | None] = items_or_supplier
        else:
            q: deque[RuntimeEvent] = deque(items_or_supplier)
            self._supplier = lambda: q.popleft() if q else None

    def __iter__(self) -> DualEventStream:
        return self

    def __next__(self) -> RuntimeEvent:
        item = self._supplier()
        if item is None:
            raise StopIteration
        return item

    def try_next(self) -> RuntimeEvent | None:
        """Return the next available event, or None if none is ready (does not end the stream)."""
        return self._supplier()

    def drain_available(self, timeout_ms: int = 250) -> list[RuntimeEvent]:
        collected: list[RuntimeEvent] = []
        deadline = time.monotonic() + max(0, int(timeout_ms)) / 1000.0
        while True:
            item = self._supplier()
            if item is None:
                break
            collected.append(item)
            if time.monotonic() >= deadline:
                break
        return collected

    def __aiter__(self) -> DualEventStream:
        return self

    async def __anext__(self) -> RuntimeEvent:
        item = self._supplier()
        if item is None:
            raise StopAsyncIteration
        return item


def _expand_tool_allowlist(allowlist: Any) -> list[str]:
    if not allowlist:
        return []
    out: list[str] = [str(t) for t in allowlist]
    for t in list(out):
        if t.startswith("mcp__side_sessions__"):
            alias = "mcp__plugin_side-sessions_side_sessions__" + t[len("mcp__side_sessions__") :]
            if alias not in out:
                out.append(alias)
        elif t.startswith("mcp__plugin_side-sessions_side_sessions__"):
            short = "mcp__side_sessions__" + t[len("mcp__plugin_side-sessions_side_sessions__") :]
            if short not in out:
                out.append(short)
    return out


def build_create_payload(spec: RuntimeCreateSpec) -> dict[str, Any]:
    """Build strict `session/create` JSON-RPC params per Section 7.4 (never includes `importedHistory`)."""
    if not isinstance(spec, RuntimeCreateSpec):
        raise SideSessionError(ErrorCode.INVALID_REQUEST, "spec must be a RuntimeCreateSpec")
    if not spec.workspace_path or not str(spec.workspace_path).strip():
        raise SideSessionError(ErrorCode.INVALID_REQUEST, "workspace_path cannot be empty")
    if not spec.parent_runtime_sid or not str(spec.parent_runtime_sid).strip():
        raise SideSessionError(ErrorCode.INVALID_REQUEST, "parent_runtime_sid cannot be empty")
    if spec.persistence != "immediate":
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"RuntimeCreateSpec.persistence must be 'immediate' (got {spec.persistence!r})",
        )

    ws_path = Path(spec.workspace_path).expanduser().absolute()
    if ws_path.is_symlink():
        raise SideSessionError(
            ErrorCode.SYMLINK_FORBIDDEN,
            f"Workspace path cannot be a symlink: {ws_path}",
            {"workspace_path": str(ws_path)},
        )
    canonical_ws = os.path.realpath(ws_path)
    session_id = (spec.preallocated_session_id or spec.assignment.runtime_sid).strip()
    if not session_id:
        raise SideSessionError(ErrorCode.INVALID_REQUEST, "sessionId cannot be empty")

    if spec.mode not in CLI_SESSION_MODES:
        raise SideSessionError(ErrorCode.INVALID_REQUEST, f"mode {spec.mode!r} not in CLI enum")

    model_dict = dict(spec.model) if isinstance(spec.model, Mapping) else {}
    if "importedHistory" in model_dict:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            "importedHistory is strictly forbidden in session/create",
        )

    payload: dict[str, Any] = {
        "sessionId": session_id,
        "workspace": {
            "workspacePath": canonical_ws,
            "workspaceKey": canonical_ws,
        },
        "parentSessionId": spec.parent_runtime_sid.strip(),
        "mode": spec.mode,
        "persistence": "immediate",
        "toolDenylist": list(spec.tool_denylist or ()),
    }
    if model_dict:
        payload["model"] = model_dict
    if spec.tool_allowlist:
        payload["toolAllowlist"] = _expand_tool_allowlist(spec.tool_allowlist)
    if spec.additional_directories:
        payload["additionalDirectories"] = [
            os.path.realpath(Path(d).expanduser().absolute()) for d in spec.additional_directories
        ]
    # Hard invariant: never allow importedHistory
    assert "importedHistory" not in payload
    return payload


def build_resume_payload(spec: RuntimeResumeSpec) -> dict[str, Any]:
    """Build strict `session/resume` JSON-RPC params per Section 3.3 & 7.4."""
    if not isinstance(spec, RuntimeResumeSpec):
        raise SideSessionError(ErrorCode.INVALID_REQUEST, "spec must be a RuntimeResumeSpec")
    if spec.mode not in CLI_SESSION_MODES:
        raise SideSessionError(ErrorCode.INVALID_REQUEST, f"mode {spec.mode!r} not in CLI enum")
    model_dict = dict(spec.model) if isinstance(spec.model, Mapping) else {}
    payload: dict[str, Any] = {
        "sessionId": spec.assignment.runtime_sid,
        "toolDenylist": list(spec.tool_denylist or ()),
    }
    if model_dict:
        payload["model"] = model_dict
    if spec.tool_allowlist:
        payload["toolAllowlist"] = _expand_tool_allowlist(spec.tool_allowlist)
    if spec.additional_directories:
        payload["additionalDirectories"] = [
            os.path.realpath(Path(d).expanduser().absolute()) for d in spec.additional_directories
        ]
    return payload


def extract_workspace_path(response: Mapping[str, Any], *, kind: str = "create") -> str:
    """Extract and validate `workspacePath` from `session/create` or `session/resume` / `session/fork` response.

    - `kind == "create"` reads `result.session.workspace.workspacePath`.
    - `kind in ("resume", "fork")` reads `result.snapshot.session.workspace.workspacePath`.
    - Explicitly rejects `snapshot.workspace` (Section 7.4 step 5).
    """
    if not isinstance(response, Mapping):
        raise SideSessionError(ErrorCode.WORKSPACE_MISMATCH, "Runtime response must be a mapping")

    body = response.get("result") if isinstance(response.get("result"), Mapping) else response
    assert isinstance(body, Mapping)

    if kind == "create":
        if "snapshot" in body and isinstance(body.get("snapshot"), Mapping):
            snap = body["snapshot"]
            if "workspace" in snap and "session" not in snap:
                raise SideSessionError(
                    ErrorCode.WORKSPACE_MISMATCH,
                    "snapshot.workspace is invalid; create requires session.workspace.workspacePath",
                )
        session_obj = body.get("session")
        if not isinstance(session_obj, Mapping):
            raise SideSessionError(
                ErrorCode.WORKSPACE_MISMATCH,
                "Missing 'session' object in session/create response",
            )
        ws_obj = session_obj.get("workspace")
        if not isinstance(ws_obj, Mapping) or not isinstance(ws_obj.get("workspacePath"), str):
            raise SideSessionError(
                ErrorCode.WORKSPACE_MISMATCH,
                "Missing 'session.workspace.workspacePath' in session/create response",
            )
        raw_path = ws_obj["workspacePath"].strip()
        if not raw_path:
            raise SideSessionError(ErrorCode.WORKSPACE_MISMATCH, "Empty session.workspace.workspacePath")
        return os.path.realpath(raw_path)

    if kind in ("resume", "fork"):
        snapshot_obj = body.get("snapshot")
        if isinstance(snapshot_obj, Mapping):
            if "workspace" in snapshot_obj and "session" not in snapshot_obj:
                raise SideSessionError(
                    ErrorCode.WORKSPACE_MISMATCH,
                    f"Invalid 'snapshot.workspace' in session/{kind} response; expected 'snapshot.session.workspace.workspacePath'",
                )
            session_obj = snapshot_obj.get("session")
        elif isinstance(body.get("session"), Mapping):
            session_obj = body.get("session")
        else:
            raise SideSessionError(
                ErrorCode.WORKSPACE_MISMATCH,
                f"Missing 'snapshot' object in session/{kind} response",
            )
        if not isinstance(session_obj, Mapping):
            raise SideSessionError(
                ErrorCode.WORKSPACE_MISMATCH,
                f"Missing 'snapshot.session' in session/{kind} response",
            )
        ws_obj = session_obj.get("workspace")
        if not isinstance(ws_obj, Mapping) or not isinstance(ws_obj.get("workspacePath"), str):
            raise SideSessionError(
                ErrorCode.WORKSPACE_MISMATCH,
                f"Missing 'snapshot.session.workspace.workspacePath' in session/{kind} response",
            )
        raw_path = ws_obj["workspacePath"].strip()
        if not raw_path:
            raise SideSessionError(ErrorCode.WORKSPACE_MISMATCH, "Empty snapshot.session.workspace.workspacePath")
        return os.path.realpath(raw_path)

    raise SideSessionError(ErrorCode.INVALID_REQUEST, f"Unsupported response kind: {kind!r}")


def _coerce_cutoff(source: SourceCutoff | Mapping[str, Any]) -> SourceCutoff:
    if isinstance(source, SourceCutoff):
        return source
    if isinstance(source, Mapping):
        return SourceCutoff(
            source_node_id=str(source.get("source_node_id") or source.get("node_id") or "node:source"),
            source_runtime_sid=str(source.get("source_runtime_sid") or source.get("runtime_sid") or ""),
            trigger_runtime_turn_id=str(source.get("trigger_runtime_turn_id") or source.get("runtime_turn_id") or ""),
            trigger_request_id=str(source.get("trigger_request_id") or source.get("request_id") or ""),
            owner_id=str(source.get("owner_id") or "owner:source"),
            accepted_input_high_watermark=str(source.get("accepted_input_high_watermark") or source.get("input_id") or ""),
            source_revision=source.get("source_revision"),
            task_id=source.get("task_id"),
        )
    raise SideSessionError(ErrorCode.INVALID_REQUEST, "source must be a SourceCutoff or Mapping")


def _coerce_anchor(anchor: SourceAnchor | Mapping[str, Any]) -> SourceAnchor:
    if isinstance(anchor, SourceAnchor):
        return anchor
    if isinstance(anchor, Mapping):
        raw_cutoff = anchor.get("cutoff")
        cutoff = (
            _coerce_cutoff(raw_cutoff)
            if isinstance(raw_cutoff, (SourceCutoff, Mapping))
            else SourceCutoff(
                source_node_id=str(anchor.get("source_node_id") or "node:source"),
                source_runtime_sid=str(anchor.get("source_session_id") or ""),
                trigger_runtime_turn_id=str(anchor.get("anchor_turn_id") or "turn-0"),
                trigger_request_id="",
                owner_id="owner:source",
                accepted_input_high_watermark="",
                source_revision=anchor.get("source_revision"),
            )
        )
        return SourceAnchor(
            status=str(anchor.get("status") or "unavailable"),
            source_session_id=str(anchor.get("source_session_id") or cutoff.source_runtime_sid),
            cutoff=cutoff,
            source_revision=anchor.get("source_revision"),
            anchor_message_id=anchor.get("anchor_message_id"),
            sequence=anchor.get("sequence"),
            anchor_turn_id=anchor.get("anchor_turn_id"),
            checkpoint_id=anchor.get("checkpoint_id"),
            effective_chain_hash=anchor.get("effective_chain_hash"),
            reason=anchor.get("reason"),
        )
    raise SideSessionError(ErrorCode.INVALID_REQUEST, "anchor must be a SourceAnchor or Mapping")


def _coerce_wait_response(response: WaitResponse | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(response, WaitResponse):
        return response.to_validated_dict()
    return _validate_wait_response(response)


def _has_incomplete_tool_parts(msg: Mapping[str, Any]) -> bool:
    """Return True if a message contains any incomplete/in-progress tool call parts."""
    if msg.get("has_incomplete_tool") is True or msg.get("incomplete") is True:
        return True
    if str(msg.get("status") or "").lower() in ("in_progress", "running", "streaming", "pending", "incomplete"):
        return True
    parts = msg.get("parts") or []
    if isinstance(parts, list):
        for part in parts:
            if not isinstance(part, Mapping):
                continue
            ptype = str(part.get("type") or part.get("kind") or "").lower()
            pstate = str(part.get("state") or part.get("status") or "").lower()
            if "tool" in ptype and pstate in (
                "pending",
                "running",
                "in_progress",
                "streaming",
                "call",
                "partial-call",
                "waiting",
                "started",
            ):
                return True
            if part.get("incomplete") is True:
                return True
    return False


def _filter_effective_chain_at_cutoff(
    messages: list[dict[str, Any]],
    cutoff: SourceCutoff,
    *,
    reverted_after_seq: int | None = None,
    reverted_message_ids: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None]:
    """Filter raw session messages into (safe_prefix, excluded_ranges, unavailable_reason).

    Implements R05 / Section 7.3:
    - Excludes messages reverted by `session.revert`.
    - Includes completed turns prior to the trigger turn, plus the trigger turn's user input message.
    - Excludes any assistant message in the trigger turn or any assistant message with incomplete tool calls.
    - Excludes any message arriving after the cutoff input/turn watermark.
    """
    if not messages:
        return [], [{"reason": "empty_session_history", "scope": "all"}], "empty_session_history"

    rev_ids = reverted_message_ids or set()
    ordered = sorted(
        (dict(m) for m in messages),
        key=lambda item: int(item.get("sequence", item.get("seq", 0))),
    )

    # Apply revert filtering first
    active_msgs: list[dict[str, Any]] = []
    excluded_ranges: list[dict[str, Any]] = []
    for idx, msg in enumerate(ordered):
        seq = int(msg.get("sequence", msg.get("seq", idx + 1)))
        msg_id = str(msg.get("id") or msg.get("message_id") or f"msg-{seq}")
        if msg.get("reverted") is True or msg_id in rev_ids or (
            reverted_after_seq is not None and seq > reverted_after_seq
        ):
            excluded_ranges.append({
                "message_id": msg_id,
                "sequence": seq,
                "reason": "reverted",
            })
            continue
        norm_msg = dict(msg)
        norm_msg["id"] = msg_id
        norm_msg["sequence"] = seq
        active_msgs.append(norm_msg)

    if not active_msgs:
        return [], excluded_ranges, "all_messages_reverted"

    # Locate cutoff boundary by accepted_input_high_watermark or trigger_runtime_turn_id
    watermark = cutoff.accepted_input_high_watermark.strip()
    trigger_turn = cutoff.trigger_runtime_turn_id.strip()

    cutoff_seq: int | None = None
    matched_boundary = False

    for msg in active_msgs:
        msg_input_id = str(msg.get("input_id") or msg.get("inputId") or "").strip()
        msg_id = str(msg["id"])
        msg_turn_id = str(msg.get("turn_id") or msg.get("turnId") or "").strip()
        role = str(msg.get("role") or "user").lower()

        if watermark and (msg_input_id == watermark or msg_id == watermark):
            matched_boundary = True
            if role == "user":
                cutoff_seq = int(msg["sequence"])
            elif cutoff_seq is None:
                cutoff_seq = int(msg["sequence"])

        if trigger_turn and msg_turn_id == trigger_turn:
            matched_boundary = True
            if role == "user":
                cutoff_seq = int(msg["sequence"])

    # If caller specified a non-wildcard watermark/turn that cannot be mapped when strict metadata exists
    has_any_turn_or_input_tags = any(
        bool(m.get("input_id") or m.get("inputId") or m.get("turn_id") or m.get("turnId"))
        for m in active_msgs
    )
    if not matched_boundary:
        if has_any_turn_or_input_tags and (watermark or trigger_turn):
            return [], excluded_ranges, "cutoff_watermark_not_found_in_session"
        # If untagged messages (e.g. legacy DB rows without turn/input tags), cannot safely map cutoff unless single turn
        return [], excluded_ranges, "unmapped_cutoff_in_session_history"

    safe_prefix: list[dict[str, Any]] = []
    for msg in active_msgs:
        seq = int(msg["sequence"])
        msg_id = str(msg["id"])
        msg_turn_id = str(msg.get("turn_id") or msg.get("turnId") or "").strip()
        role = str(msg.get("role") or "user").lower()

        if cutoff_seq is not None and seq > cutoff_seq:
            excluded_ranges.append({
                "message_id": msg_id,
                "sequence": seq,
                "reason": "after_cutoff",
            })
            continue

        if trigger_turn and msg_turn_id == trigger_turn and role != "user":
            excluded_ranges.append({
                "message_id": msg_id,
                "sequence": seq,
                "reason": "trigger_turn_incomplete_assistant",
            })
            continue

        if _has_incomplete_tool_parts(msg):
            excluded_ranges.append({
                "message_id": msg_id,
                "sequence": seq,
                "reason": "incomplete_tool_invocation",
            })
            continue

        safe_prefix.append(msg)

    if not safe_prefix:
        return [], excluded_ranges, "no_safe_prefix_before_cutoff"

    return safe_prefix, excluded_ranges, None


def _canonical_chain_digest(safe_prefix: list[dict[str, Any]]) -> str:
    chain_items = []
    for m in safe_prefix:
        chain_items.append({
            "id": str(m["id"]),
            "sequence": int(m["sequence"]),
            "role": str(m.get("role") or "user"),
            "turn_id": str(m.get("turn_id") or m.get("turnId") or ""),
            "input_id": str(m.get("input_id") or m.get("inputId") or ""),
            "content": str(m.get("content") or m.get("text") or ""),
        })
    return canonical_json_sha256(chain_items)


def _format_history_summary(anchor: SourceAnchor, safe_prefix: list[dict[str, Any]]) -> str:
    lines = [
        f"# Source History Projection ({anchor.source_session_id})",
        f"- Anchor Message ID: {anchor.anchor_message_id}",
        f"- Sequence Boundary: {anchor.sequence}",
        f"- Effective Chain Hash: {anchor.effective_chain_hash}",
        "",
        "## Safe Prefix Transcript Summary",
    ]
    for m in safe_prefix:
        role = str(m.get("role") or "user")
        seq = int(m["sequence"])
        msg_id = str(m["id"])
        content = normalize_text(str(m.get("content") or m.get("text") or ""), strip=True)
        lines.append(f"- [{seq}] ({role} / {msg_id}): {content}")
    return "\n".join(lines)


def build_driver_capabilities(
    *,
    host_version: str = "0.17.1",
    protocol_revision: str = "1.1",
    capability_fingerprint: str = "default-conservative-v1.1",
    verified_at: str = "",
    verification_test_id: str = "",
    integration_verified: bool | Mapping[str, bool] = False,
    capability_overrides: Mapping[str, bool | CapabilityStatus | Mapping[str, bool]] | None = None,
    summary_copy_verified_default: bool = True,
) -> DriverCapabilities:
    """Build DriverCapabilities adhering to Section 2.1 conservative baseline with optional overrides."""
    # Baseline source_supported flags per Section 2.1
    source_baseline: dict[str, bool] = {
        "supports_request_meta": True,
        "supports_async_command_hook": True,
        "async_output_applied": False,
        "supports_live_fork": False,
        "supports_fork_workspace": False,
        "supports_native_fork": True,
        "supports_history_import": False,
        "supports_summary_copy": True,
        "supports_tool_restrictions": True,
        "supports_workspace_write_scope": False,
        "supports_notes_grant": True,
        "supports_human_input_provenance": False,
        "supports_trusted_approval": False,
        "supports_idle_parent_wake": False,
        "supports_history_commit_receipt": False,
        "supports_supervised_survival": False,
        "supports_task_guard": False,
        "supports_wait_response": True,
        "supports_permission_response": True,
        "supports_cancel_run": True,
    }

    # Capabilities that must remain disabled unless explicitly overridden in capability_overrides
    strict_disabled = {
        "async_output_applied",
        "supports_live_fork",
        "supports_fork_workspace",
        "supports_history_import",
        "supports_native_fork",
        "supports_idle_parent_wake",
        "supports_history_commit_receipt",
    }

    statuses: dict[str, CapabilityStatus] = {}
    for cap_name, src_sup in source_baseline.items():
        if isinstance(integration_verified, bool):
            if cap_name in strict_disabled:
                int_ver = False
            elif cap_name == "supports_summary_copy":
                int_ver = bool(integration_verified or summary_copy_verified_default)
            else:
                int_ver = bool(integration_verified and src_sup)
        elif isinstance(integration_verified, Mapping):
            if cap_name in integration_verified:
                int_ver = bool(integration_verified[cap_name])
            elif cap_name == "supports_summary_copy":
                int_ver = summary_copy_verified_default
            else:
                int_ver = False
        else:
            int_ver = summary_copy_verified_default if cap_name == "supports_summary_copy" else False

        # Never allow supports_history_import / supports_live_fork / supports_fork_workspace to be enabled by blanket bool
        if cap_name in ("supports_live_fork", "supports_fork_workspace", "supports_history_import"):
            src_sup = False
            int_ver = False

        statuses[cap_name] = CapabilityStatus(
            source_supported=src_sup,
            integration_verified=int_ver,
        )

    if capability_overrides:
        for cap_name, override_val in capability_overrides.items():
            if cap_name not in statuses:
                continue
            if isinstance(override_val, CapabilityStatus):
                statuses[cap_name] = override_val
            elif isinstance(override_val, bool):
                base_src = statuses[cap_name].source_supported or override_val
                statuses[cap_name] = CapabilityStatus(
                    source_supported=base_src if override_val else statuses[cap_name].source_supported,
                    integration_verified=override_val,
                )
            elif isinstance(override_val, Mapping):
                statuses[cap_name] = CapabilityStatus(
                    source_supported=bool(override_val.get("source_supported", statuses[cap_name].source_supported)),
                    integration_verified=bool(override_val.get("integration_verified", statuses[cap_name].integration_verified)),
                )

    return DriverCapabilities(
        host_version=host_version,
        protocol_revision=protocol_revision,
        capability_fingerprint=capability_fingerprint,
        verified_at=verified_at,
        verification_test_id=verification_test_id,
        **statuses,
    )


class BaseDriver(ABC):
    """Abstract base class for side-sessions runtime drivers."""

    driver_kind: str = "base"
    driver_api_version: str = DRIVER_API_VERSION

    @abstractmethod
    def probe(self) -> DriverCapabilities:
        """Return DriverCapabilities for this runtime driver."""

    @abstractmethod
    def capture_anchor(self, source: SourceCutoff) -> SourceAnchor:
        """Capture a deterministic SourceAnchor from the source session up to `source` cutoff."""

    @abstractmethod
    def validate_anchor(self, anchor: SourceAnchor) -> AnchorCheck:
        """Validate that `anchor` has not been invalidated by a revert or deletion."""

    @abstractmethod
    def capture_history(self, anchor: SourceAnchor) -> HistoryProjection:
        """Generate a HistoryProjection (`stable_projection` or `brief_only`) for `anchor`."""

    @abstractmethod
    def create(self, spec: RuntimeCreateSpec) -> RuntimeHandle:
        """Create a new runtime session and return its RuntimeHandle on the open connection."""

    @abstractmethod
    def resume(self, spec: RuntimeResumeSpec) -> RuntimeHandle:
        """Resume an existing runtime session and verify its workspace and configuration."""

    @abstractmethod
    def send(self, handle: RuntimeHandle, input: RuntimeInput) -> SendReceipt:
        """Send input over the same app-server connection held by `handle`."""

    @abstractmethod
    def events(self, handle: RuntimeHandle) -> DualEventStream:
        """Stream turn, wait, and status events for `handle`."""

    @abstractmethod
    def inspect(self, handle: RuntimeHandle) -> RuntimeSnapshot:
        """Inspect process liveness, host DB state, and runtime configuration for `handle`."""

    @abstractmethod
    def respond_wait(
        self,
        handle: RuntimeHandle,
        request: BoundWait,
        response: WaitResponse | Mapping[str, Any],
        control_id: str,
    ) -> ControlReceipt:
        """Respond to a pending wait/permission request on the same connection held by `handle`."""

    @abstractmethod
    def stop_and_wait(self, handle: RuntimeHandle, deadline_ms: int = 5000) -> ExitReceipt:
        """Stop the runtime session and wait for confirmed process exit."""

    @abstractmethod
    def fork_idle(self, spec: Any) -> ForkReceipt:
        """Perform a native fork if capability gate and idle/inherit preconditions are met."""


class _HostSqliteHistoryMixin:
    """Shared read-only SQLite anchor and history inspection for host `db.sqlite`."""

    _host_db_path: Path | None
    _captured_chains: dict[tuple[str, str], tuple[list[dict[str, Any]], list[dict[str, Any]]]]
    _in_memory_source_sessions: dict[str, dict[str, Any]]
    _lock: threading.RLock

    def _resolve_host_db_path(self) -> Path:
        if self._host_db_path is not None:
            return self._host_db_path
        env_p = os.environ.get("ZCODE_HOST_DB_PATH")
        if env_p and env_p.strip():
            return Path(env_p.strip()).expanduser().absolute()
        return DEFAULT_HOST_DB_PATH.expanduser().absolute()

    def _read_source_session_from_sqlite(
        self,
        source_sid: str,
    ) -> tuple[dict[str, Any] | None, list[dict[str, Any]], str | None]:
        with self._lock:
            mem = self._in_memory_source_sessions.get(source_sid)
            if mem is not None:
                if mem.get("unavailable_reason"):
                    return dict(mem), [], str(mem["unavailable_reason"])
                return dict(mem), [dict(m) for m in mem.get("messages", [])], None

        db_path = self._resolve_host_db_path()
        if not db_path.exists() or db_path.is_symlink() or not db_path.is_file():
            return None, [], "host_sqlite_unavailable"

        uri = f"file:{db_path}?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=2.0, isolation_level=None)
        except sqlite3.Error as exc:
            return None, [], f"host_sqlite_open_failed:{exc}"

        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON;")
            conn.execute("BEGIN DEFERRED")
            try:
                s_cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(session)").fetchall()}
                if "id" not in s_cols:
                    return None, [], "session_table_missing"

                s_row = conn.execute("SELECT * FROM session WHERE id = ? LIMIT 1", (source_sid,)).fetchone()
                if s_row is None:
                    return None, [], "source_session_not_found"

                session_dict = dict(s_row)
                if session_dict.get("time_deleted") not in (None, 0, "", "0"):
                    return session_dict, [], "source_session_deleted"
                if session_dict.get("time_archived") not in (None, 0, "", "0"):
                    return session_dict, [], "source_session_archived"

                m_cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(message)").fetchall()}
                if not m_cols:
                    return session_dict, [], "message_table_missing"

                sid_col = "session_id" if "session_id" in m_cols else ("sessionId" if "sessionId" in m_cols else None)
                if sid_col is None:
                    return session_dict, [], "message_session_id_column_missing"

                order_col = "sequence" if "sequence" in m_cols else ("seq" if "seq" in m_cols else "rowid")
                m_rows = conn.execute(
                    f"SELECT * FROM message WHERE {sid_col} = ? ORDER BY {order_col} ASC",
                    (source_sid,),
                ).fetchall()

                p_cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(part)").fetchall()}
                parts_by_msg: dict[str, list[dict[str, Any]]] = {}
                if p_cols and m_rows:
                    p_msg_col = (
                        "message_id"
                        if "message_id" in p_cols
                        else ("messageId" if "messageId" in p_cols else None)
                    )
                    if p_msg_col is not None:
                        p_sid_col = (
                            "session_id"
                            if "session_id" in p_cols
                            else ("sessionId" if "sessionId" in p_cols else None)
                        )
                        if p_sid_col is not None:
                            p_rows = conn.execute(
                                f"SELECT * FROM part WHERE {p_sid_col} = ?",
                                (source_sid,),
                            ).fetchall()
                        else:
                            msg_ids = [str(r["id"]) for r in m_rows if "id" in r.keys()]
                            placeholders = ", ".join("?" for _ in msg_ids)
                            p_rows = (
                                conn.execute(
                                    f"SELECT * FROM part WHERE {p_msg_col} IN ({placeholders})",
                                    msg_ids,
                                ).fetchall()
                                if msg_ids
                                else []
                            )
                        for pr in p_rows:
                            pd = dict(pr)
                            if "data" in pd and isinstance(pd["data"], str):
                                try:
                                    pd.update(json.loads(pd["data"]))
                                except Exception:
                                    pass
                            mid = str(pd.get(p_msg_col) or "")
                            parts_by_msg.setdefault(mid, []).append(pd)

                messages: list[dict[str, Any]] = []
                for idx, mr in enumerate(m_rows):
                    md = dict(mr)
                    if "data" in md and isinstance(md["data"], str):
                        try:
                            parsed_data = json.loads(md["data"])
                            if isinstance(parsed_data, Mapping):
                                for k, v in parsed_data.items():
                                    md.setdefault(k, v)
                        except Exception:
                            pass
                    mid = str(md.get("id") or md.get("message_id") or f"msg-{idx + 1}")
                    seq = int(md.get("sequence", md.get("seq", idx + 1)))
                    md["id"] = mid
                    md["sequence"] = seq
                    if mid in parts_by_msg:
                        md["parts"] = parts_by_msg[mid]
                        if not md.get("content"):
                            text_chunks = [
                                str(p.get("text") or p.get("content") or "")
                                for p in parts_by_msg[mid]
                                if p.get("text") or p.get("content")
                            ]
                            if text_chunks:
                                md["content"] = "\n".join(text_chunks)
                    messages.append(md)

                return session_dict, messages, None
            finally:
                try:
                    conn.execute("COMMIT")
                except sqlite3.Error:
                    pass
        except sqlite3.Error as exc:
            return None, [], f"host_sqlite_query_failed:{exc}"
        finally:
            conn.close()

    def _get_source_session_data(
        self,
        source_sid: str,
    ) -> tuple[dict[str, Any] | None, list[dict[str, Any]], str | None]:
        with self._lock:
            mem = self._in_memory_source_sessions.get(source_sid)
            if mem is not None:
                if mem.get("unavailable_reason"):
                    return dict(mem), [], str(mem["unavailable_reason"])
                return dict(mem), [dict(m) for m in mem.get("messages", [])], None
        return self._read_source_session_from_sqlite(source_sid)

    def _extract_revert_info(self, session_dict: Mapping[str, Any]) -> tuple[int | None, set[str]]:
        reverted_after_seq: int | None = session_dict.get("reverted_after_seq")
        reverted_ids: set[str] = set(session_dict.get("reverted_message_ids") or [])
        raw_revert = session_dict.get("revert")
        if isinstance(raw_revert, str) and raw_revert.strip():
            try:
                raw_revert = json.loads(raw_revert)
            except Exception:
                reverted_ids.add(raw_revert.strip())
        if isinstance(raw_revert, Mapping):
            if raw_revert.get("sequence") is not None:
                reverted_after_seq = int(raw_revert["sequence"])
            if raw_revert.get("reverted_after_seq") is not None:
                reverted_after_seq = int(raw_revert["reverted_after_seq"])
            if raw_revert.get("message_id"):
                reverted_ids.add(str(raw_revert["message_id"]))
            if raw_revert.get("messageID"):
                reverted_ids.add(str(raw_revert["messageID"]))
            if isinstance(raw_revert.get("reverted_message_ids"), list):
                reverted_ids.update(str(x) for x in raw_revert["reverted_message_ids"])
        return reverted_after_seq, reverted_ids

    def capture_anchor(self, source: SourceCutoff) -> SourceAnchor:
        cutoff = _coerce_cutoff(source)
        source_sid = cutoff.source_runtime_sid.strip()
        if not source_sid:
            return SourceAnchor(
                status="unavailable",
                source_session_id="",
                cutoff=cutoff,
                source_revision=cutoff.source_revision,
                reason="empty_source_runtime_sid",
            )

        # Up to 3 attempts: read, close, read again, compare chain hash (Section 7.3).
        last_chain_hash: str | None = None
        stable_prefix: list[dict[str, Any]] = []
        excluded: list[dict[str, Any]] = []
        session_dict: dict[str, Any] | None = None
        err_reason: str | None = None

        for _attempt in range(3):
            first = self._get_source_session_data(source_sid)
            s_dict, msgs, reason = first
            if reason is not None or s_dict is None:
                err_reason = reason or "source_session_unavailable"
                break
            reverted_after_seq, reverted_ids = self._extract_revert_info(s_dict)
            prefix, excl, filter_reason = _filter_effective_chain_at_cutoff(
                msgs,
                cutoff,
                reverted_after_seq=reverted_after_seq,
                reverted_message_ids=reverted_ids,
            )
            if filter_reason is not None or not prefix:
                err_reason = filter_reason or "empty_safe_prefix"
                break
            first_hash = _canonical_chain_digest(prefix)
            second = self._get_source_session_data(source_sid)
            s_dict2, msgs2, reason2 = second
            if reason2 is not None or s_dict2 is None:
                err_reason = reason2 or "source_session_unavailable"
                break
            reverted_after_seq2, reverted_ids2 = self._extract_revert_info(s_dict2)
            prefix2, excl2, filter_reason2 = _filter_effective_chain_at_cutoff(
                msgs2,
                cutoff,
                reverted_after_seq=reverted_after_seq2,
                reverted_message_ids=reverted_ids2,
            )
            if filter_reason2 is not None or not prefix2:
                err_reason = filter_reason2 or "empty_safe_prefix"
                break
            second_hash = _canonical_chain_digest(prefix2)
            if first_hash == second_hash:
                last_chain_hash = second_hash
                stable_prefix = prefix2
                excluded = excl2
                session_dict = s_dict2
                err_reason = None
                break
            last_chain_hash = second_hash
            err_reason = "source_history_concurrently_changing"

        if err_reason is not None or not stable_prefix or last_chain_hash is None:
            return SourceAnchor(
                status="unavailable",
                source_session_id=source_sid,
                cutoff=cutoff,
                source_revision=cutoff.source_revision,
                anchor_message_id=None,
                sequence=None,
                anchor_turn_id=None,
                checkpoint_id=None,
                effective_chain_hash=None,
                reason=err_reason or "anchor_unavailable",
            )

        last_msg = stable_prefix[-1]
        anchor_msg_id = str(last_msg["id"])
        anchor_seq = int(last_msg["sequence"])
        anchor_turn_id = str(last_msg.get("turn_id") or last_msg.get("turnId") or cutoff.trigger_runtime_turn_id)
        rev = (
            int(session_dict["revision"])
            if session_dict and session_dict.get("revision") is not None
            else (cutoff.source_revision if cutoff.source_revision is not None else anchor_seq)
        )
        checkpoint_id = str(
            last_msg.get("checkpoint_id")
            or (session_dict.get("checkpoint_id") if session_dict else None)
            or f"chk:{source_sid}:{anchor_seq}"
        )

        with self._lock:
            self._captured_chains[(source_sid, last_chain_hash)] = (stable_prefix, excluded)

        return SourceAnchor(
            status="stable",
            source_session_id=source_sid,
            cutoff=cutoff,
            source_revision=rev,
            anchor_message_id=anchor_msg_id,
            sequence=anchor_seq,
            anchor_turn_id=anchor_turn_id,
            checkpoint_id=checkpoint_id,
            effective_chain_hash=last_chain_hash,
            reason=None,
        )

    def validate_anchor(self, anchor: SourceAnchor | Mapping[str, Any]) -> AnchorCheck:
        anchor = _coerce_anchor(anchor)
        if anchor.status != "stable" or not anchor.anchor_message_id or anchor.sequence is None:
            s_dict, _msgs, _reason = self._get_source_session_data(anchor.source_session_id)
            if s_dict is not None:
                rev_seq, rev_ids = self._extract_revert_info(s_dict)
                if rev_seq is not None or rev_ids:
                    return AnchorCheck(
                        ok=False,
                        status="stale",
                        source_session_id=anchor.source_session_id,
                        anchor_message_id=anchor.anchor_message_id,
                        sequence=anchor.sequence,
                        current_revision=s_dict.get("revision", anchor.source_revision),
                        effective_chain_hash=anchor.effective_chain_hash,
                        reverted=True,
                        reason="source_session_reverted",
                    )
            return AnchorCheck(
                ok=False,
                status="unavailable",
                source_session_id=anchor.source_session_id,
                anchor_message_id=anchor.anchor_message_id,
                sequence=anchor.sequence,
                current_revision=anchor.source_revision,
                effective_chain_hash=anchor.effective_chain_hash,
                reverted=False,
                reason=anchor.reason or "anchor_not_stable",
            )

        s_dict, msgs, reason = self._get_source_session_data(anchor.source_session_id)
        if reason is not None or s_dict is None:
            return AnchorCheck(
                ok=False,
                status="stale",
                source_session_id=anchor.source_session_id,
                anchor_message_id=anchor.anchor_message_id,
                sequence=anchor.sequence,
                current_revision=anchor.source_revision,
                effective_chain_hash=None,
                reverted=True,
                reason=reason or "source_session_missing",
            )

        reverted_after_seq, reverted_ids = self._extract_revert_info(s_dict)
        if (
            anchor.anchor_message_id in reverted_ids
            or (reverted_after_seq is not None and anchor.sequence > reverted_after_seq)
        ):
            return AnchorCheck(
                ok=False,
                status="stale",
                source_session_id=anchor.source_session_id,
                anchor_message_id=anchor.anchor_message_id,
                sequence=anchor.sequence,
                current_revision=s_dict.get("revision", anchor.source_revision),
                effective_chain_hash=None,
                reverted=True,
                reason="anchor_reverted",
            )

        prefix, _excl, filter_reason = _filter_effective_chain_at_cutoff(
            msgs,
            anchor.cutoff,
            reverted_after_seq=reverted_after_seq,
            reverted_message_ids=reverted_ids,
        )
        if filter_reason is not None or not prefix:
            return AnchorCheck(
                ok=False,
                status="stale",
                source_session_id=anchor.source_session_id,
                anchor_message_id=anchor.anchor_message_id,
                sequence=anchor.sequence,
                current_revision=s_dict.get("revision", anchor.source_revision),
                effective_chain_hash=None,
                reverted=True,
                reason=filter_reason or "prefix_invalidated",
            )

        current_hash = _canonical_chain_digest(prefix)
        last_msg = prefix[-1]
        if (
            str(last_msg["id"]) != anchor.anchor_message_id
            or int(last_msg["sequence"]) != anchor.sequence
            or (anchor.effective_chain_hash is not None and current_hash != anchor.effective_chain_hash)
        ):
            return AnchorCheck(
                ok=False,
                status="stale",
                source_session_id=anchor.source_session_id,
                anchor_message_id=anchor.anchor_message_id,
                sequence=anchor.sequence,
                current_revision=s_dict.get("revision", anchor.source_revision),
                effective_chain_hash=current_hash,
                reverted=True,
                reason="effective_chain_hash_mismatch",
            )

        return AnchorCheck(
            ok=True,
            status="valid",
            source_session_id=anchor.source_session_id,
            anchor_message_id=anchor.anchor_message_id,
            sequence=anchor.sequence,
            current_revision=s_dict.get("revision", anchor.source_revision),
            effective_chain_hash=current_hash,
            reverted=False,
            reason=None,
        )

    def capture_history(self, anchor: SourceAnchor) -> HistoryProjection:
        if not isinstance(anchor, SourceAnchor):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "anchor must be a SourceAnchor")

        if anchor.status == "stable" and anchor.anchor_message_id and anchor.sequence is not None:
            with self._lock:
                cached = self._captured_chains.get((anchor.source_session_id, anchor.effective_chain_hash or ""))

            if cached is not None:
                safe_prefix, excluded_ranges = cached
            else:
                chk = self.validate_anchor(anchor)
                if not chk.ok:
                    raise SideSessionError(
                        ErrorCode.SOURCE_SNAPSHOT_STALE,
                        f"Source anchor is stale or invalidated: {chk.reason}",
                        {"source_session_id": anchor.source_session_id, "reason": chk.reason},
                    )
                s_dict, msgs, _ = self._get_source_session_data(anchor.source_session_id)
                rev_seq, rev_ids = self._extract_revert_info(s_dict or {})
                safe_prefix, excluded_ranges, _ = _filter_effective_chain_at_cutoff(
                    msgs,
                    anchor.cutoff,
                    reverted_after_seq=rev_seq,
                    reverted_message_ids=rev_ids,
                )

            summary = _format_history_summary(anchor, safe_prefix)
            projection_sha256 = sha256_hex(summary)
            manifest = {
                "source_session_id": anchor.source_session_id,
                "cutoff": anchor.cutoff.to_dict(),
                "anchor": anchor.to_dict(),
                "history_quality": "stable_projection",
                "projection_sha256": projection_sha256,
                "excluded_ranges": excluded_ranges,
                "formatter_version": FORMATTER_VERSION,
            }
            snapshot_hash = canonical_json_sha256(manifest)
            return HistoryProjection(
                anchor=anchor,
                history_quality="stable_projection",
                summary=summary,
                excluded_ranges=excluded_ranges,
                snapshot_hash=snapshot_hash,
                formatter_version=FORMATTER_VERSION,
                effective_chain_ref=anchor.effective_chain_hash,
            )

        # Anchor is unavailable -> fallback to brief_only (requires explicit ContextAcceptance per R08)
        excluded_ranges = [
            {
                "scope": "full_source_history",
                "reason": anchor.reason or "anchor_unavailable",
            }
        ]
        summary = ""
        manifest = {
            "source_session_id": anchor.source_session_id,
            "cutoff": anchor.cutoff.to_dict(),
            "anchor": anchor.to_dict(),
            "history_quality": "brief_only",
            "projection_sha256": None,
            "excluded_ranges": excluded_ranges,
            "formatter_version": FORMATTER_VERSION,
        }
        snapshot_hash = canonical_json_sha256(manifest)
        return HistoryProjection(
            anchor=anchor,
            history_quality="brief_only",
            summary=summary,
            excluded_ranges=excluded_ranges,
            snapshot_hash=snapshot_hash,
            formatter_version=FORMATTER_VERSION,
            effective_chain_ref=None,
        )


@dataclass
class _AppServerConnection:
    """Active per-session `zcode app-server` subprocess and JSON-RPC pipe state."""

    runtime_sid: str
    runtime_instance_id: str
    owner_connection_id: str
    canonical_workspace: str
    parent_runtime_sid: str
    mode: str
    model: dict[str, Any]
    tool_allowlist: list[str]
    tool_denylist: list[str]
    additional_directories: list[str]
    proc: subprocess.Popen[bytes] | None
    pid: int | None
    process_started_at: str | None
    process_group: int | None
    revision: int = 1
    status: str = "idle"
    active_turn_id: str | None = None
    event_queue: deque[RuntimeEvent] = field(default_factory=deque)
    pending_waits: dict[str, dict[str, Any]] = field(default_factory=dict)
    sent_inputs: list[dict[str, Any]] = field(default_factory=list)
    closed: bool = False
    exit_code: int | None = None


class ZCodeDriver(_HostSqliteHistoryMixin, BaseDriver):
    """Production runtime driver targeting ZCode v0.17.1 `app-server` protocol."""

    driver_kind = "zcode"

    def __init__(
        self,
        *,
        zcode_bin: str | Path = "zcode",
        host_db_path: Path | str | None = None,
        host_version: str = "0.17.1",
        protocol_revision: str = "1.1",
        integration_verified: bool | Mapping[str, bool] = False,
        capability_overrides: Mapping[str, bool | CapabilityStatus | Mapping[str, bool]] | None = None,
        rpc_timeout_sec: float = 15.0,
    ) -> None:
        self.zcode_bin = str(zcode_bin)
        self._host_db_path = Path(host_db_path).expanduser().absolute() if host_db_path is not None else None
        self.host_version = host_version
        self.protocol_revision = protocol_revision
        self._integration_verified = integration_verified
        self._capability_overrides = dict(capability_overrides) if capability_overrides else {}
        self.rpc_timeout_sec = float(rpc_timeout_sec)

        self._lock = threading.RLock()
        self._connections: dict[str, _AppServerConnection] = {}
        self._stdout_queues: dict[int, queue.Queue[bytes | None]] = {}
        self._captured_chains: dict[tuple[str, str], tuple[list[dict[str, Any]], list[dict[str, Any]]]] = {}
        self._in_memory_source_sessions: dict[str, dict[str, Any]] = {}

    def probe(self) -> DriverCapabilities:
        return build_driver_capabilities(
            host_version=self.host_version,
            protocol_revision=self.protocol_revision,
            capability_fingerprint=f"zcode-{self.host_version}-v{self.protocol_revision}",
            integration_verified=self._integration_verified,
            capability_overrides=self._capability_overrides,
            summary_copy_verified_default=True,
        )

    def _spawn_app_server(self, cwd: str, base_env: Mapping[str, str] | None = None) -> subprocess.Popen[bytes]:
        clean_env = sanitize_subprocess_env(base_env)
        for forbidden_key in FORBIDDEN_INHERITED_SESSION_ENV_KEYS:
            assert forbidden_key not in clean_env

        node_dir = os.environ.get("ZCODE_SIDE_SESSIONS_NODE_DIR") or (
            str(Path(n).parent) if (n := shutil.which("node")) else None
        )
        if node_dir:
            existing_path = clean_env.get("PATH", "")
            clean_env["PATH"] = f"{node_dir}{os.pathsep}{existing_path}" if existing_path else node_dir
        clean_env["ZCODE_MESSAGE_ENABLED"] = "1"
        clean_env.setdefault("ZCODE_MAILBOX_ROOT", str(Path.home() / ".zcode" / "mailbox"))
        Path(clean_env["ZCODE_MAILBOX_ROOT"]).mkdir(mode=0o700, parents=True, exist_ok=True)

        cmd = [self.zcode_bin, "app-server"]
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                env=clean_env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )
            q: queue.Queue[bytes | None] = queue.Queue()
            self._stdout_queues[proc.pid] = q

            def _reader_loop() -> None:
                assert proc.stdout is not None
                try:
                    for raw_line in proc.stdout:
                        q.put(raw_line)
                except Exception:
                    pass
                finally:
                    q.put(None)

            threading.Thread(target=_reader_loop, daemon=True).start()
            return proc
        except FileNotFoundError as exc:
            raise SideSessionError(
                ErrorCode.CAPABILITY_UNAVAILABLE,
                f"zcode binary not found: {self.zcode_bin}",
                {"zcode_bin": self.zcode_bin},
            ) from exc
        except OSError as exc:
            raise SideSessionError(
                ErrorCode.CAPABILITY_UNAVAILABLE,
                f"Failed to launch zcode app-server: {exc}",
                {"zcode_bin": self.zcode_bin, "error": str(exc)},
            ) from exc

    def _maybe_reply_server_request(
        self,
        proc: subprocess.Popen[bytes],
        msg: Mapping[str, Any],
    ) -> bool:
        """Reply to reverse RPC requests (`id` starting with `'server'`) sent by `zcode app-server`."""
        mid = msg.get("id")
        method = msg.get("method")
        if mid is None or not isinstance(method, str) or not str(mid).startswith("server"):
            return False
        if method == "session/requestRuntimePreferences":
            result: dict[str, Any] = {
                "nativeSearchEnhancementsEnabled": False,
                "memoryEnabled": False,
                "askUserQuestionAutoResolutionEnabled": True,
            }
        else:
            result = {"headers": {}}
        if proc.stdin is not None:
            try:
                reply = (canonical_json({"id": mid, "result": result}) + "\n").encode("utf-8")
                proc.stdin.write(reply)
                proc.stdin.flush()
            except OSError:
                pass
        return True

    def _resolve_default_model_from_sqlite(self, parent_runtime_sid: str | None = None) -> dict[str, Any]:
        """Resolve non-account `modelSelection` from parent session (or latest session) in host `db.sqlite`."""
        db_path = self._resolve_host_db_path()
        if not db_path.exists() or db_path.is_symlink() or not db_path.is_file():
            return {}
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2.0)
        except sqlite3.Error:
            return {}
        try:
            conn.execute("PRAGMA query_only=ON;")
            candidates: list[dict[str, Any]] = []
            if parent_runtime_sid:
                rows = conn.execute(
                    """
                    SELECT json_extract(data, '$.modelSelection')
                    FROM message
                    WHERE session_id = ? AND json_extract(data, '$.modelSelection') IS NOT NULL
                    ORDER BY sequence DESC
                    LIMIT 20
                    """,
                    (parent_runtime_sid,),
                ).fetchall()
                for (raw_sel,) in rows:
                    if isinstance(raw_sel, str) and raw_sel.strip():
                        try:
                            parsed = json.loads(raw_sel)
                            if isinstance(parsed, Mapping):
                                candidates.append(dict(parsed))
                        except Exception:
                            pass
            if not candidates:
                rows = conn.execute(
                    """
                    SELECT json_extract(data, '$.modelSelection')
                    FROM message
                    WHERE json_extract(data, '$.modelSelection') IS NOT NULL
                    ORDER BY time_created DESC
                    LIMIT 20
                    """
                ).fetchall()
                for (raw_sel,) in rows:
                    if isinstance(raw_sel, str) and raw_sel.strip():
                        try:
                            parsed = json.loads(raw_sel)
                            if isinstance(parsed, Mapping):
                                candidates.append(dict(parsed))
                        except Exception:
                            pass

            chosen: dict[str, Any] | None = None
            for cand in candidates:
                pid = str(cand.get("providerId") or "")
                mid = str(cand.get("modelId") or "")
                if not pid or not mid or pid.startswith("account"):
                    continue
                chosen = dict(cand)
                break

            if not chosen:
                return {}

            opts = chosen.get("options")
            if not isinstance(opts, Mapping) or not opts.get("reasoningLevel"):
                for cand in candidates:
                    if (
                        cand.get("providerId") == chosen.get("providerId")
                        and cand.get("modelId") == chosen.get("modelId")
                        and isinstance(cand.get("options"), Mapping)
                        and cand["options"].get("reasoningLevel")
                    ):
                        chosen["options"] = dict(cand["options"])
                        break
            if str(chosen.get("modelId") or "") == "antigravity/gemini-4-argon":
                chosen["modelId"] = "ai-studio/gemini-4-argon"
            return chosen
        except sqlite3.Error:
            return {}
        finally:
            conn.close()

    def _rpc_call(
        self,
        proc: subprocess.Popen[bytes],
        method: str,
        params: Mapping[str, Any],
        *,
        event_sink: deque[RuntimeEvent] | None = None,
        runtime_sid: str = "",
    ) -> dict[str, Any]:
        if proc.stdin is None or proc.stdout is None:
            raise SideSessionError(ErrorCode.CAPABILITY_UNAVAILABLE, "app-server stdio pipes are closed")

        req_id = str(uuid.uuid4())
        rpc_msg = {
            "id": req_id,
            "method": method,
            "params": dict(params),
        }
        line = (canonical_json(rpc_msg) + "\n").encode("utf-8")
        try:
            proc.stdin.write(line)
            proc.stdin.flush()
        except OSError as exc:
            raise SideSessionError(
                ErrorCode.RETRY_LATER,
                f"Failed writing JSON-RPC request '{method}' to app-server: {exc}",
                {"method": method},
                retryable=False,
            ) from exc

        q = self._stdout_queues.get(proc.pid)
        deadline = time.monotonic() + max(5.0, self.rpc_timeout_sec)
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise SideSessionError(
                    ErrorCode.RETRY_LATER,
                    f"app-server timed out ({self.rpc_timeout_sec}s) waiting for '{method}'",
                    {"method": method},
                    retryable=True,
                )
            if q is not None:
                try:
                    raw_line = q.get(timeout=min(1.0, rem))
                except queue.Empty:
                    if proc.poll() is not None:
                        raise SideSessionError(
                            ErrorCode.CAPABILITY_UNAVAILABLE,
                            f"app-server exited ({proc.returncode}) before responding to '{method}'",
                            {"method": method, "returncode": proc.returncode},
                        )
                    continue
            else:
                raw_line = proc.stdout.readline()
            if not raw_line:
                raise SideSessionError(
                    ErrorCode.CAPABILITY_UNAVAILABLE,
                    f"app-server closed stdout before responding to '{method}'",
                    {"method": method},
                )
            try:
                msg = json.loads(raw_line.decode("utf-8", errors="replace"))
            except Exception:
                continue
            if not isinstance(msg, Mapping):
                continue
            if self._maybe_reply_server_request(proc, msg):
                continue
            msg_id = msg.get("id")
            if str(msg_id or "") == req_id or (msg_id is None and "error" in msg and msg["error"] is not None):
                if "error" in msg and msg["error"] is not None:
                    err_obj = msg["error"]
                    if isinstance(err_obj, Mapping):
                        err_data = err_obj.get("data") if isinstance(err_obj.get("data"), Mapping) else {}
                        err_msg = " | ".join(
                            filter(
                                None,
                                [
                                    str(err_obj.get("message") or ""),
                                    str(err_data.get("name") or ""),
                                    str(err_data.get("message") or ""),
                                ],
                            )
                        ) or str(err_obj)
                    else:
                        err_msg = str(err_obj)
                    raise SideSessionError(
                        ErrorCode.INVALID_REQUEST,
                        f"app-server error in '{method}': {err_msg}",
                        {"method": method, "rpc_error": err_obj},
                    )
                return dict(msg)
            if event_sink is not None:
                parsed_ev = self._parse_notification(msg, runtime_sid=runtime_sid)
                if parsed_ev is not None:
                    event_sink.append(parsed_ev)

    def _parse_notification(self, msg: Mapping[str, Any], *, runtime_sid: str) -> RuntimeEvent | None:
        method = str(msg.get("method") or msg.get("type") or "")
        params = msg.get("params") if isinstance(msg.get("params"), Mapping) else msg
        assert isinstance(params, Mapping)

        sid = str(params.get("sessionId") or params.get("session_id") or runtime_sid)
        now = utc_now_iso()

        if method == "session/event":
            ev_type = str(params.get("type") or params.get("event") or params.get("kind") or "")
            inner_payload = params.get("payload") if isinstance(params.get("payload"), Mapping) else {}
            merged_params: dict[str, Any] = dict(params)
            if isinstance(inner_payload, Mapping):
                for k, v in inner_payload.items():
                    merged_params.setdefault(k, v)
                if "turnId" in inner_payload or "runtime_turn_id" in inner_payload:
                    merged_params["turnId"] = inner_payload.get("turnId") or inner_payload.get("runtime_turn_id")
                if "inputId" in inner_payload or "input_id" in inner_payload:
                    merged_params["inputId"] = inner_payload.get("inputId") or inner_payload.get("input_id")
            sid = str(
                merged_params.get("sessionId")
                or merged_params.get("session_id")
                or runtime_sid
            )
            if ev_type in ("turn.started", "turn_started", "turn-started"):
                return RuntimeEvent(
                    event_id=str(merged_params.get("eventId") or merged_params.get("id") or uuid.uuid4()),
                    runtime_sid=sid,
                    kind="turn.started",
                    runtime_turn_id=str(merged_params.get("turnId") or merged_params.get("runtime_turn_id") or "") or None,
                    input_id=str(merged_params.get("inputId") or merged_params.get("input_id") or "") or None,
                    status="running",
                    payload=merged_params,
                    timestamp=now,
                )
            if ev_type in (
                "turn.terminal",
                "turn_terminal",
                "turn.completed",
                "turn-completed",
                "turn.failed",
                "turn-failed",
                "turn.cancelled",
                "turn.canceled",
                "turn.aborted",
            ):
                default_outcome = (
                    "failed"
                    if "failed" in ev_type
                    else ("cancelled" if ("cancel" in ev_type or "abort" in ev_type) else "success")
                )
                raw_outcome = str(
                    merged_params.get("outcome")
                    or merged_params.get("status")
                    or merged_params.get("resultType")
                    or default_outcome
                ).lower()
                if raw_outcome in ("success", "completed"):
                    norm_outcome = "success"
                elif raw_outcome in ("cancelled", "canceled", "aborted"):
                    norm_outcome = "cancelled"
                else:
                    norm_outcome = "failed"
                return RuntimeEvent(
                    event_id=str(merged_params.get("eventId") or merged_params.get("id") or uuid.uuid4()),
                    runtime_sid=sid,
                    kind="turn.terminal",
                    runtime_turn_id=str(merged_params.get("turnId") or merged_params.get("runtime_turn_id") or "") or None,
                    input_id=str(merged_params.get("inputId") or merged_params.get("input_id") or "") or None,
                    status="idle",
                    outcome=norm_outcome,
                    payload=merged_params,
                    timestamp=now,
                )
            if ev_type in (
                "wait.requested",
                "wait_request",
                "permission.requested",
                "permission_request",
                "elicitation.requested",
                "elicitation_request",
                "input.requested",
                "input_request",
            ) or "wait_request" in merged_params:
                w_obj = (
                    merged_params.get("wait_request")
                    if isinstance(merged_params.get("wait_request"), Mapping)
                    else (inner_payload if inner_payload else merged_params)
                )
                assert isinstance(w_obj, Mapping)
                w_dict = dict(w_obj)
                if "kind" not in w_dict:
                    if "permission" in ev_type:
                        w_dict["kind"] = "permission"
                    elif "elicitation" in ev_type:
                        w_dict["kind"] = "elicitation"
                    elif "input" in ev_type:
                        w_dict["kind"] = "input"
                return RuntimeEvent(
                    event_id=str(w_dict.get("wait_id") or merged_params.get("eventId") or uuid.uuid4()),
                    runtime_sid=sid,
                    kind="wait_request",
                    runtime_turn_id=str(
                        w_dict.get("turnId")
                        or w_dict.get("runtime_turn_id")
                        or merged_params.get("turnId")
                        or merged_params.get("runtime_turn_id")
                        or ""
                    )
                    or None,
                    status="waiting_input",
                    wait_request=w_dict,
                    payload=merged_params,
                    timestamp=now,
                )
            if ev_type in ("session/status", "session.status", "status_patch", "idle") or "status" in merged_params:
                st_val = str(merged_params.get("status") or ("idle" if ev_type == "idle" else "running"))
                return RuntimeEvent(
                    event_id=str(merged_params.get("eventId") or uuid.uuid4()),
                    runtime_sid=sid,
                    kind="idle" if st_val == "idle" else "status_patch",
                    runtime_turn_id=str(merged_params.get("turnId") or merged_params.get("runtime_turn_id") or "") or None,
                    status=st_val,
                    payload=merged_params,
                    timestamp=now,
                )
            return None

        if method == "v4/telemetry/event" or "event" in params:
            ev_name = str(params.get("event") or params.get("name") or params.get("kind") or method)
            if ev_name in (
                "turn.terminal",
                "turn_terminal",
                "turn.completed",
                "turn-completed",
                "turn.failed",
                "turn-failed",
                "turn.cancelled",
                "turn.canceled",
                "turn.aborted",
            ):
                default_outcome = (
                    "failed"
                    if "failed" in ev_name
                    else ("cancelled" if ("cancel" in ev_name or "abort" in ev_name) else "success")
                )
                raw_outcome = str(
                    params.get("outcome") or params.get("status") or params.get("resultType") or default_outcome
                ).lower()
                if raw_outcome in ("success", "completed"):
                    norm_outcome = "success"
                elif raw_outcome in ("cancelled", "canceled", "aborted"):
                    norm_outcome = "cancelled"
                else:
                    norm_outcome = "failed"
                return RuntimeEvent(
                    event_id=str(params.get("eventId") or uuid.uuid4()),
                    runtime_sid=sid,
                    kind="turn.terminal",
                    runtime_turn_id=str(params.get("turnId") or params.get("runtime_turn_id") or "") or None,
                    input_id=str(params.get("inputId") or params.get("input_id") or "") or None,
                    status="idle",
                    outcome=norm_outcome,
                    payload=dict(params),
                    timestamp=now,
                )
            if ev_name in ("turn.started", "turn_started", "turn-started"):
                return RuntimeEvent(
                    event_id=str(params.get("eventId") or uuid.uuid4()),
                    runtime_sid=sid,
                    kind="turn.started",
                    runtime_turn_id=str(params.get("turnId") or params.get("runtime_turn_id") or "") or None,
                    input_id=str(params.get("inputId") or params.get("input_id") or "") or None,
                    status="running",
                    payload=dict(params),
                    timestamp=now,
                )
            if ev_name in ("wait.requested", "wait_request", "permission.requested", "permission_request"):
                w_obj = params.get("wait_request") if isinstance(params.get("wait_request"), Mapping) else params
                assert isinstance(w_obj, Mapping)
                return RuntimeEvent(
                    event_id=str(w_obj.get("wait_id") or params.get("eventId") or uuid.uuid4()),
                    runtime_sid=sid,
                    kind="wait_request",
                    runtime_turn_id=str(w_obj.get("turnId") or w_obj.get("runtime_turn_id") or "") or None,
                    status="waiting_input",
                    wait_request=dict(w_obj),
                    payload=dict(params),
                    timestamp=now,
                )
            if method == "v4/telemetry/event":
                return None

        if method in ("wait.requested", "wait_request", "permission_request", "elicitation_request", "input_request") or "wait_request" in params:
            w_obj = params.get("wait_request") if isinstance(params.get("wait_request"), Mapping) else params
            assert isinstance(w_obj, Mapping)
            return RuntimeEvent(
                event_id=str(w_obj.get("wait_id") or uuid.uuid4()),
                runtime_sid=sid,
                kind="wait_request",
                runtime_turn_id=str(w_obj.get("turnId") or w_obj.get("runtime_turn_id") or "") or None,
                status="waiting_input",
                wait_request=dict(w_obj),
                payload=dict(params),
                timestamp=now,
            )

        if method in ("session/status", "status_patch", "idle") or (
            method not in ("v4/telemetry/event", "computer-use/operation-event", "process/mcpTelemetry")
            and "status" in params
        ):
            st_val = str(params.get("status") or ("idle" if method == "idle" else "running"))
            return RuntimeEvent(
                event_id=str(uuid.uuid4()),
                runtime_sid=sid,
                kind="idle" if st_val == "idle" else "status_patch",
                runtime_turn_id=str(params.get("turnId") or "") or None,
                status=st_val,
                payload=dict(params),
                timestamp=now,
            )

        return None

    def _verify_runtime_config(
        self,
        sess_obj: Mapping[str, Any],
        spec: RuntimeCreateSpec | RuntimeResumeSpec,
        *,
        actual_ws: str,
        expected_ws: str,
    ) -> None:
        if os.path.realpath(actual_ws) != os.path.realpath(expected_ws):
            raise SideSessionError(
                ErrorCode.RUNTIME_CONFIG_MISMATCH,
                f"workspacePath realpath mismatch: {actual_ws} != {expected_ws}",
                {"expected_workspace": expected_ws, "actual_workspace": actual_ws},
            )
        returned_mode = sess_obj.get("mode")
        if returned_mode not in (None, spec.mode) and not (
            spec.mode == "plan" and (sess_obj.get("planEnabled") is True or returned_mode == "build")
        ):
            raise SideSessionError(
                ErrorCode.RUNTIME_CONFIG_MISMATCH,
                f"runtime mode ({returned_mode}) != expected ({spec.mode})",
            )
        returned_model = sess_obj.get("model")
        if isinstance(returned_model, Mapping) and spec.model:
            for k in ("providerId", "modelId"):
                if k in spec.model and k in returned_model and returned_model[k] != spec.model[k]:
                    raise SideSessionError(
                        ErrorCode.RUNTIME_CONFIG_MISMATCH,
                        f"model.{k} ({returned_model[k]}) != expected ({spec.model[k]})",
                    )
            exp_opts = spec.model.get("options") if isinstance(spec.model.get("options"), Mapping) else {}
            act_opts = returned_model.get("options") if isinstance(returned_model.get("options"), Mapping) else {}
            if exp_opts and "reasoningLevel" in exp_opts and act_opts.get("reasoningLevel") not in (None, exp_opts.get("reasoningLevel")):
                if act_opts.get("reasoningLevel") != exp_opts.get("reasoningLevel"):
                    raise SideSessionError(
                        ErrorCode.RUNTIME_CONFIG_MISMATCH,
                        "model.options.reasoningLevel mismatch",
                    )
        for field_name, expected in (("toolAllowlist", spec.tool_allowlist), ("toolDenylist", spec.tool_denylist)):
            actual = sess_obj.get(field_name) or sess_obj.get(field_name.replace("Allow", "allow").replace("Deny", "deny"))
            if actual is None:
                continue
            actual_list = list(actual)
            expected_list = list(expected or ())
            if field_name == "toolAllowlist":
                expanded_expected = _expand_tool_allowlist(expected_list)
                if actual_list not in (expected_list, expanded_expected):
                    raise SideSessionError(
                        ErrorCode.RUNTIME_CONFIG_MISMATCH,
                        f"{field_name} mismatch",
                        {"expected": expanded_expected, "actual": actual_list},
                    )
            elif actual_list != expected_list:
                raise SideSessionError(
                    ErrorCode.RUNTIME_CONFIG_MISMATCH,
                    f"{field_name} mismatch",
                    {"expected": expected_list, "actual": actual_list},
                )

    def create(self, spec: RuntimeCreateSpec) -> RuntimeHandle:
        payload = build_create_payload(spec)
        if not payload.get("model"):
            default_model = self._resolve_default_model_from_sqlite(spec.parent_runtime_sid)
            if default_model:
                payload["model"] = default_model
        expected_ws = payload["workspace"]["workspacePath"]
        proc = self._spawn_app_server(cwd=expected_ws)
        pid = proc.pid
        lstart = get_process_lstart(pid)
        try:
            pgid = os.getpgid(pid)
        except OSError:
            pgid = pid

        event_q: deque[RuntimeEvent] = deque()
        try:
            try:
                resp = self._rpc_call(
                    proc,
                    "session/create",
                    payload,
                    event_sink=event_q,
                    runtime_sid=payload["sessionId"],
                )
            except SideSessionError as create_exc:
                if payload.get("model") and (
                    "ModelProtocolError" in create_exc.message
                    or "model_not_found" in str(create_exc.details)
                    or "不存在 Model" in create_exc.message
                ):
                    try:
                        proc.terminate()
                        proc.wait(timeout=2.0)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                    payload["model"] = {
                        "providerId": "magpie",
                        "modelId": "ai-studio/gemini-4-argon",
                        "options": {"reasoningLevel": "high"},
                    }
                    proc = self._spawn_app_server(cwd=expected_ws)
                    pid = proc.pid
                    lstart = get_process_lstart(pid)
                    try:
                        pgid = os.getpgid(pid)
                    except OSError:
                        pgid = pid
                    event_q.clear()
                    resp = self._rpc_call(
                        proc,
                        "session/create",
                        payload,
                        event_sink=event_q,
                        runtime_sid=payload["sessionId"],
                    )
                else:
                    raise
            actual_ws = extract_workspace_path(resp, kind="create")
            if actual_ws != expected_ws:
                raise SideSessionError(
                    ErrorCode.WORKSPACE_MISMATCH,
                    f"session/create returned workspacePath ({actual_ws}) != expected ({expected_ws})",
                    {"expected_workspace": expected_ws, "actual_workspace": actual_ws},
                )
            res_body = resp.get("result") if isinstance(resp.get("result"), Mapping) else resp
            sess_obj = res_body.get("session") if isinstance(res_body, Mapping) else {}
            if not isinstance(sess_obj, Mapping):
                sess_obj = {}
            returned_sid = str(sess_obj.get("id") or sess_obj.get("sessionId") or payload["sessionId"])
            self._verify_runtime_config(sess_obj, spec, actual_ws=actual_ws, expected_ws=expected_ws)
            returned_parent = sess_obj.get("parentSessionId") or sess_obj.get("parent_id")
            if returned_parent is not None and str(returned_parent) != spec.parent_runtime_sid:
                raise SideSessionError(
                    ErrorCode.HOST_PARENT_MISMATCH,
                    f"session/create returned parentSessionId ({returned_parent}) != expected ({spec.parent_runtime_sid})",
                )
            if payload.get("model"):
                try:
                    self._rpc_call(
                        proc,
                        "session/setModel",
                        {"sessionId": returned_sid, "model": payload["model"]},
                        event_sink=event_q,
                        runtime_sid=returned_sid,
                    )
                except SideSessionError:
                    pass
            revision = int(
                sess_obj.get("revision")
                or (res_body.get("runtime", {}).get("stateRevision") if isinstance(res_body.get("runtime"), Mapping) else None)
                or res_body.get("revision")
                or 1
            )
        except Exception:
            try:
                proc.terminate()
                proc.wait(timeout=2.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            raise

        instance_id = str(uuid.uuid4())
        conn_id = f"conn:{instance_id}"
        conn_state = _AppServerConnection(
            runtime_sid=returned_sid,
            runtime_instance_id=instance_id,
            owner_connection_id=conn_id,
            canonical_workspace=actual_ws,
            parent_runtime_sid=spec.parent_runtime_sid,
            mode=spec.mode,
            model=dict(payload.get("model") or spec.model),
            tool_allowlist=list(spec.tool_allowlist),
            tool_denylist=list(spec.tool_denylist),
            additional_directories=list(spec.additional_directories),
            proc=proc,
            pid=pid,
            process_started_at=lstart,
            process_group=pgid,
            revision=revision,
            status="idle",
            event_queue=event_q,
        )
        with self._lock:
            self._connections[instance_id] = conn_state

        return RuntimeHandle(
            runtime_sid=returned_sid,
            runtime_instance_id=instance_id,
            owner_connection_id=conn_id,
            snapshot_revision=revision,
            canonical_workspace=actual_ws,
            process_identity={
                "pid": pid,
                "process_started_at": lstart,
                "process_group": pgid,
            },
        )

    def resume(self, spec: RuntimeResumeSpec) -> RuntimeHandle:
        if not isinstance(spec, RuntimeResumeSpec):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "spec must be a RuntimeResumeSpec")
        expected_ws = os.path.realpath(Path(spec.expected_workspace).expanduser().absolute())
        payload = build_resume_payload(spec)
        if not payload.get("model"):
            default_model = self._resolve_default_model_from_sqlite(spec.expected_parent_runtime_sid)
            if default_model:
                payload["model"] = default_model
        proc = self._spawn_app_server(cwd=expected_ws)
        pid = proc.pid
        lstart = get_process_lstart(pid)
        try:
            pgid = os.getpgid(pid)
        except OSError:
            pgid = pid

        event_q: deque[RuntimeEvent] = deque()
        try:
            resp = self._rpc_call(
                proc,
                "session/resume",
                payload,
                event_sink=event_q,
                runtime_sid=spec.assignment.runtime_sid,
            )
            actual_ws = extract_workspace_path(resp, kind="resume")
            if actual_ws != expected_ws:
                raise SideSessionError(
                    ErrorCode.WORKSPACE_MISMATCH,
                    f"session/resume workspacePath ({actual_ws}) != expected ({expected_ws})",
                    {"expected_workspace": expected_ws, "actual_workspace": actual_ws},
                )
            res_body = resp.get("result") if isinstance(resp.get("result"), Mapping) else resp
            snap_obj = res_body.get("snapshot") if isinstance(res_body, Mapping) else {}
            sess_obj = (
                snap_obj.get("session")
                if isinstance(snap_obj, Mapping) and isinstance(snap_obj.get("session"), Mapping)
                else (res_body.get("session") if isinstance(res_body, Mapping) else {})
            )
            if not isinstance(sess_obj, Mapping):
                sess_obj = {}

            returned_parent = sess_obj.get("parentSessionId") or sess_obj.get("parent_id")
            if (
                spec.expected_parent_runtime_sid
                and returned_parent is not None
                and str(returned_parent) != spec.expected_parent_runtime_sid
            ):
                raise SideSessionError(
                    ErrorCode.HOST_PARENT_MISMATCH,
                    f"session/resume parentSessionId ({returned_parent}) != expected ({spec.expected_parent_runtime_sid})",
                )

            self._verify_runtime_config(sess_obj, spec, actual_ws=actual_ws, expected_ws=expected_ws)

            if payload.get("model"):
                try:
                    self._rpc_call(
                        proc,
                        "session/setModel",
                        {"sessionId": spec.assignment.runtime_sid, "model": payload["model"]},
                        event_sink=event_q,
                        runtime_sid=spec.assignment.runtime_sid,
                    )
                except SideSessionError:
                    pass

            revision = int(
                (snap_obj.get("revision") if isinstance(snap_obj, Mapping) else None)
                or sess_obj.get("revision")
                or (res_body.get("runtime", {}).get("stateRevision") if isinstance(res_body.get("runtime"), Mapping) else None)
                or 1
            )
        except Exception:
            try:
                proc.terminate()
                proc.wait(timeout=2.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            raise

        instance_id = str(uuid.uuid4())
        conn_id = f"conn:{instance_id}"
        conn_state = _AppServerConnection(
            runtime_sid=spec.assignment.runtime_sid,
            runtime_instance_id=instance_id,
            owner_connection_id=conn_id,
            canonical_workspace=actual_ws,
            parent_runtime_sid=spec.expected_parent_runtime_sid,
            mode=spec.mode,
            model=dict(payload.get("model") or spec.model),
            tool_allowlist=list(spec.tool_allowlist),
            tool_denylist=list(spec.tool_denylist),
            additional_directories=list(spec.additional_directories),
            proc=proc,
            pid=pid,
            process_started_at=lstart,
            process_group=pgid,
            revision=revision,
            status="idle",
            event_queue=event_q,
        )
        with self._lock:
            self._connections[instance_id] = conn_state

        return RuntimeHandle(
            runtime_sid=spec.assignment.runtime_sid,
            runtime_instance_id=instance_id,
            owner_connection_id=conn_id,
            snapshot_revision=revision,
            canonical_workspace=actual_ws,
            process_identity={
                "pid": pid,
                "process_started_at": lstart,
                "process_group": pgid,
            },
        )

    def _require_open_connection(self, handle: RuntimeHandle) -> _AppServerConnection:
        if not isinstance(handle, RuntimeHandle):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "handle must be a RuntimeHandle")
        with self._lock:
            conn = self._connections.get(handle.runtime_instance_id)
        if conn is None or conn.closed or conn.owner_connection_id != handle.owner_connection_id:
            raise SideSessionError(
                ErrorCode.CANCEL_OWNER_UNAVAILABLE,
                f"No active app-server connection for runtime_instance_id={handle.runtime_instance_id}",
                {"runtime_instance_id": handle.runtime_instance_id},
            )
        return conn

    def send(self, handle: RuntimeHandle, input: RuntimeInput) -> SendReceipt:
        conn = self._require_open_connection(handle)
        if not isinstance(input, RuntimeInput):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "input must be a RuntimeInput")
        assert conn.proc is not None

        params: dict[str, Any] = {
            "sessionId": handle.runtime_sid,
            "inputId": input.input_id,
            "content": input.content,
        }
        if input.expected_revision is not None:
            params["expectedRevision"] = input.expected_revision

        pre_q_len = len(conn.event_queue)
        try:
            resp = self._rpc_call(
                conn.proc,
                "session/send",
                params,
                event_sink=conn.event_queue,
                runtime_sid=handle.runtime_sid,
            )
        except SideSessionError as exc:
            if "Reasoning level is required" in exc.message and conn.model:
                fallback_model = dict(conn.model)
                fallback_model["options"] = {"reasoningLevel": "enabled"}
                try:
                    self._rpc_call(
                        conn.proc,
                        "session/setModel",
                        {"sessionId": handle.runtime_sid, "model": fallback_model},
                        event_sink=conn.event_queue,
                        runtime_sid=handle.runtime_sid,
                    )
                    conn.model = fallback_model
                except SideSessionError:
                    pass
                pre_q_len = len(conn.event_queue)
                resp = self._rpc_call(
                    conn.proc,
                    "session/send",
                    params,
                    event_sink=conn.event_queue,
                    runtime_sid=handle.runtime_sid,
                )
            else:
                raise
        res_body = resp.get("result") if isinstance(resp.get("result"), Mapping) else resp
        assert isinstance(res_body, Mapping)
        if "status" in res_body and res_body.get("status") is not None:
            status = str(res_body["status"])
        elif res_body.get("accepted") is False:
            status = "rejected"
        else:
            status = "accepted"
        turn_id = res_body.get("turnId") or res_body.get("runtime_turn_id")
        if turn_id is not None:
            turn_id = str(turn_id)
        if not turn_id and len(conn.event_queue) > pre_q_len:
            for ev in list(conn.event_queue)[pre_q_len:]:
                if ev.kind in ("turn.started", "turn.terminal") and ev.runtime_turn_id:
                    if ev.input_id in (None, input.input_id):
                        turn_id = str(ev.runtime_turn_id)
                        break
        rev = res_body.get("revision") if res_body.get("revision") is not None else res_body.get("stateRevision")
        if rev is not None:
            conn.revision = int(rev)
        conn.status = "running" if status == "accepted" else conn.status
        conn.active_turn_id = turn_id

        return SendReceipt(
            input_id=input.input_id,
            status=status,
            runtime_turn_id=turn_id,
            response_revision=conn.revision,
            evidence_ref=f"send:{handle.runtime_instance_id}:{input.input_id}",
        )

    def events(self, handle: RuntimeHandle) -> DualEventStream:
        conn = self._require_open_connection(handle)

        def _next_event() -> RuntimeEvent | None:
            if conn.event_queue:
                return conn.event_queue.popleft()
            if conn.proc is None or conn.proc.stdout is None or conn.closed:
                return None
            q = self._stdout_queues.get(conn.proc.pid)
            deadline = time.monotonic() + 0.25
            first_wait = 0.1
            while time.monotonic() < deadline:
                if conn.proc.poll() is not None and (q is None or q.empty()):
                    return None
                wait_sec = first_wait if first_wait > 0 else max(0.0, min(0.02, deadline - time.monotonic()))
                first_wait = 0.0
                if q is not None:
                    try:
                        raw_line = q.get(timeout=wait_sec)
                    except queue.Empty:
                        return None
                else:
                    try:
                        ready, _, _ = select.select([conn.proc.stdout], [], [], wait_sec)
                    except (ValueError, OSError):
                        return None
                    if not ready:
                        return None
                    raw_line = conn.proc.stdout.readline()
                if not raw_line:
                    return None
                try:
                    msg = json.loads(raw_line.decode("utf-8", errors="replace"))
                except Exception:
                    continue
                if not isinstance(msg, Mapping):
                    continue
                if self._maybe_reply_server_request(conn.proc, msg):
                    continue
                ev = self._parse_notification(msg, runtime_sid=handle.runtime_sid)
                if ev is None:
                    continue
                if ev.kind == "turn.terminal":
                    conn.status = "idle"
                elif ev.kind == "wait_request":
                    conn.status = "waiting_input"
                return ev
            return None

        return DualEventStream(_next_event)

    def inspect(self, handle: RuntimeHandle) -> RuntimeSnapshot:
        if not isinstance(handle, RuntimeHandle):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "handle must be a RuntimeHandle")
        with self._lock:
            conn = self._connections.get(handle.runtime_instance_id)

        pid = handle.process_identity.get("pid") if isinstance(handle.process_identity, Mapping) else None
        exp_lstart = (
            handle.process_identity.get("process_started_at")
            if isinstance(handle.process_identity, Mapping)
            else None
        )
        proc_alive = verify_process_identity(pid, exp_lstart) if pid else (conn is not None and not conn.closed)

        s_dict, _msgs, _reason = self._read_source_session_from_sqlite(handle.runtime_sid)
        db_dir = s_dict.get("directory") if s_dict else None
        db_parent = (s_dict.get("parent_id") or s_dict.get("parent_session_id")) if s_dict else None

        canonical_ws = (
            os.path.realpath(db_dir)
            if (isinstance(db_dir, str) and db_dir and os.path.exists(db_dir))
            else handle.canonical_workspace
        )
        parent_sid = str(db_parent) if db_parent is not None else (conn.parent_runtime_sid if conn else None)

        if not proc_alive:
            status = "exited"
        elif conn is not None:
            status = conn.status
        else:
            status = "unknown"

        return RuntimeSnapshot(
            runtime_sid=handle.runtime_sid,
            canonical_workspace=canonical_ws,
            model=dict(conn.model) if conn else {},
            mode=conn.mode if conn else "default",
            status=status,
            tool_profile_check="verified" if conn is not None else "unknown",
            notes_access_check="verified" if conn is not None else "unknown",
            revision=conn.revision if conn else handle.snapshot_revision,
            raw_response_ref=f"inspect:{handle.runtime_instance_id}",
            parent_runtime_sid=parent_sid,
        )

    def respond_wait(
        self,
        handle: RuntimeHandle,
        request: BoundWait,
        response: WaitResponse | Mapping[str, Any],
        control_id: str,
    ) -> ControlReceipt:
        conn = self._require_open_connection(handle)
        if not isinstance(request, BoundWait):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "request must be a BoundWait")
        if request.runtime_instance_id != handle.runtime_instance_id:
            raise SideSessionError(
                ErrorCode.WAIT_STALE,
                "BoundWait runtime_instance_id does not match RuntimeHandle",
                {
                    "expected_instance_id": handle.runtime_instance_id,
                    "wait_instance_id": request.runtime_instance_id,
                },
            )
        val_resp = _coerce_wait_response(response)
        if val_resp["kind"] != request.kind:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"WaitResponse kind ({val_resp['kind']!r}) does not match BoundWait kind ({request.kind!r})",
            )

        if request.kind == "permission":
            method = "respond_permission"
        elif request.kind == "elicitation":
            method = "respond_elicitation"
        else:
            method = "session/respond_input"

        assert conn.proc is not None
        rpc_params = {
            "sessionId": handle.runtime_sid,
            "requestId": request.host_request_id,
            "nonce": request.nonce,
            "controlId": str(control_id),
            "response": val_resp,
        }
        resp = self._rpc_call(
            conn.proc,
            method,
            rpc_params,
            event_sink=conn.event_queue,
            runtime_sid=handle.runtime_sid,
        )
        res_body = resp.get("result") if isinstance(resp.get("result"), Mapping) else resp
        assert isinstance(res_body, Mapping)
        conn.status = "running"

        return ControlReceipt(
            control_id=str(control_id),
            status=str(res_body.get("status") or "applied"),
            runtime_instance_id=handle.runtime_instance_id,
            owner_epoch=request.owner_epoch,
            observed_wait_state=str(res_body.get("observed_wait_state") or "resolved"),
            host_receipt_id=str(res_body.get("receiptId") or f"wait-rcpt:{control_id}"),
        )

    def stop_and_wait(self, handle: RuntimeHandle, deadline_ms: int = 5000) -> ExitReceipt:
        if not isinstance(handle, RuntimeHandle):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "handle must be a RuntimeHandle")
        with self._lock:
            conn = self._connections.get(handle.runtime_instance_id)

        if conn is None or conn.owner_connection_id != handle.owner_connection_id:
            raise SideSessionError(
                ErrorCode.CANCEL_OWNER_UNAVAILABLE,
                f"Cannot stop session: runtime_instance_id={handle.runtime_instance_id} is not owned by this driver",
                {"runtime_instance_id": handle.runtime_instance_id},
            )

        proc = conn.proc
        pid = conn.pid
        exp_lstart = conn.process_started_at
        pgid = conn.process_group
        timeout_sec = max(0.05, float(deadline_ms) / 1000.0)

        if proc is None:
            conn.closed = True
            conn.status = "exited"
            with self._lock:
                self._connections.pop(handle.runtime_instance_id, None)
                if pid is not None:
                    self._stdout_queues.pop(pid, None)
            return ExitReceipt(
                runtime_instance_id=handle.runtime_instance_id,
                process_identity=dict(handle.process_identity),
                exit_confirmed=True,
                runtime_outcome="cancelled",
                ended_at=utc_now_iso(),
                exit_code=0,
                evidence_ref=f"exit:{handle.runtime_instance_id}:no_proc",
            )

        # Step 1: Protocol session/stop + SIGINT
        if proc.poll() is None and verify_process_identity(pid, exp_lstart):
            try:
                if proc.stdin is not None:
                    stop_msg = canonical_json({
                        "id": str(uuid.uuid4()),
                        "method": "session/stop",
                        "params": {"sessionId": handle.runtime_sid},
                    }) + "\n"
                    proc.stdin.write(stop_msg.encode("utf-8"))
                    proc.stdin.flush()
            except Exception:
                pass
            try:
                if pgid:
                    os.killpg(pgid, signal.SIGINT)
                elif pid:
                    os.kill(pid, signal.SIGINT)
            except OSError:
                pass
            try:
                proc.wait(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                pass

        # Step 2: SIGTERM after verifying PID + lstart still belong to this owner
        if proc.poll() is None and verify_process_identity(pid, exp_lstart):
            try:
                if pgid:
                    os.killpg(pgid, signal.SIGTERM)
                else:
                    proc.terminate()
            except OSError:
                pass
            try:
                proc.wait(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                pass

        # Step 3: SIGKILL after verifying PID + lstart still belong to this owner
        if proc.poll() is None and verify_process_identity(pid, exp_lstart):
            try:
                if pgid:
                    os.killpg(pgid, signal.SIGKILL)
                else:
                    proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                pass

        exit_code = proc.poll()
        still_alive = verify_process_identity(pid, exp_lstart) if exit_code is None else False
        exit_confirmed = not still_alive

        if exit_confirmed:
            conn.closed = True
            conn.status = "exited"
            conn.exit_code = exit_code if exit_code is not None else -signal.SIGTERM
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except Exception:
                        pass
            with self._lock:
                self._connections.pop(handle.runtime_instance_id, None)
                if pid is not None:
                    self._stdout_queues.pop(pid, None)

        return ExitReceipt(
            runtime_instance_id=handle.runtime_instance_id,
            process_identity=dict(handle.process_identity),
            exit_confirmed=exit_confirmed,
            runtime_outcome="cancelled" if exit_confirmed else "cancel_unknown",
            ended_at=utc_now_iso(),
            exit_code=conn.exit_code if exit_confirmed else None,
            evidence_ref=f"exit:{handle.runtime_instance_id}:{'confirmed' if exit_confirmed else 'unknown'}",
        )

    def fork_idle(self, spec: Any) -> ForkReceipt:
        spec_dict = spec.to_dict() if hasattr(spec, "to_dict") else (dict(spec) if isinstance(spec, Mapping) else {})
        workspace_mode = str(spec_dict.get("workspace_mode") or "inherit")
        source_ws = spec_dict.get("source_workspace")
        target_ws = spec_dict.get("target_workspace") or spec_dict.get("workspace_path")

        if workspace_mode == "branch" or (
            source_ws and target_ws and os.path.realpath(str(source_ws)) != os.path.realpath(str(target_ws))
        ):
            raise SideSessionError(
                ErrorCode.UNSUPPORTED_CONTEXT_WORKSPACE,
                "native_fork is not supported with branch worktree or cross-directory workspace",
                {"workspace_mode": workspace_mode},
            )

        if (
            spec_dict.get("parent_busy") is True
            or spec_dict.get("parent_active") is True
            or spec_dict.get("live_fork") is True
            or spec_dict.get("in_active_turn") is True
        ):
            raise SideSessionError(
                ErrorCode.UNSUPPORTED_LIVE_FORK,
                "native_fork is not supported while the parent session is active",
            )

        raise SideSessionError(
            ErrorCode.CAPABILITY_UNAVAILABLE,
            "native_fork is disabled and not implemented by ZCodeDriver; use summary_copy",
        )


class ScriptedFakeDriver(_HostSqliteHistoryMixin, BaseDriver):
    """Deterministic scripted fake driver for unit testing, fault injection, and crash recovery."""

    driver_kind = "fake"

    def __init__(
        self,
        *,
        host_db_path: Path | str | None = None,
        sync_to_host_db: bool = True,
        integration_verified: bool | Mapping[str, bool] = True,
        capability_overrides: Mapping[str, bool | CapabilityStatus | Mapping[str, bool]] | None = None,
    ) -> None:
        self._host_db_path = Path(host_db_path).expanduser().absolute() if host_db_path is not None else None
        self.sync_to_host_db = bool(sync_to_host_db)
        self._integration_verified = integration_verified
        self._capability_overrides = dict(capability_overrides) if capability_overrides else {}

        self._lock = threading.RLock()
        self._connections: dict[str, _AppServerConnection] = {}
        self._sessions_by_sid: dict[str, dict[str, Any]] = {}
        self._captured_chains: dict[tuple[str, str], tuple[list[dict[str, Any]], list[dict[str, Any]]]] = {}
        self._in_memory_source_sessions: dict[str, dict[str, Any]] = {}
        self._faults: dict[str, list[Exception | Callable[..., Any]]] = {}
        self._prequeued_events: dict[str, list[RuntimeEvent]] = {}

        # Inspection logs for assertions in tests
        self.call_log: list[dict[str, Any]] = []
        self.create_payloads: list[dict[str, Any]] = []
        self.resume_payloads: list[dict[str, Any]] = []
        self.sent_inputs: list[dict[str, Any]] = []
        self.wait_responses: list[dict[str, Any]] = []
        self.stopped_handles: list[str] = []
        self.last_sanitized_env: dict[str, str] = sanitize_subprocess_env()

    def probe(self) -> DriverCapabilities:
        default_fake_overrides: dict[str, Any] = {
            "supports_request_meta": CapabilityStatus(True, True),
            "supports_summary_copy": CapabilityStatus(True, True),
            "supports_tool_restrictions": CapabilityStatus(True, True),
            "supports_workspace_write_scope": CapabilityStatus(True, True),
            "supports_notes_grant": CapabilityStatus(True, True),
            "supports_human_input_provenance": CapabilityStatus(True, True),
            "supports_trusted_approval": CapabilityStatus(True, True),
            "supports_task_guard": CapabilityStatus(True, True),
            "supports_wait_response": CapabilityStatus(True, True),
            "supports_permission_response": CapabilityStatus(True, True),
            "supports_cancel_run": CapabilityStatus(True, True),
            # Conservative gates that stay False unless explicitly overridden by test
            "supports_live_fork": CapabilityStatus(False, False),
            "supports_fork_workspace": CapabilityStatus(False, False),
            "supports_history_import": CapabilityStatus(False, False),
            "supports_native_fork": CapabilityStatus(True, False),
            "async_output_applied": CapabilityStatus(False, False),
            "supports_idle_parent_wake": CapabilityStatus(False, False),
            "supports_history_commit_receipt": CapabilityStatus(False, False),
        }
        if isinstance(self._integration_verified, bool) and not self._integration_verified:
            for k, v in list(default_fake_overrides.items()):
                if isinstance(v, CapabilityStatus) and k != "supports_summary_copy":
                    default_fake_overrides[k] = CapabilityStatus(v.source_supported, False)
        elif isinstance(self._integration_verified, Mapping):
            for k, val in self._integration_verified.items():
                if k in default_fake_overrides:
                    src = default_fake_overrides[k].source_supported
                    default_fake_overrides[k] = CapabilityStatus(src or bool(val), bool(val))

        default_fake_overrides.update(self._capability_overrides)
        return build_driver_capabilities(
            host_version="0.17.1",
            protocol_revision="1.1",
            capability_fingerprint="scripted-fake-v1.1",
            integration_verified=self._integration_verified,
            capability_overrides=default_fake_overrides,
            summary_copy_verified_default=True,
        )

    # ------------------------------------------------------------------
    # Scripting & Fault Injection Helpers for Tests
    # ------------------------------------------------------------------

    def inject_fault(self, method_name: str, fault: Exception | Callable[..., Any]) -> None:
        """Queue a one-shot fault (Exception or callable) for `method_name`."""
        with self._lock:
            self._faults.setdefault(method_name, []).append(fault)

    def _check_fault(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            q = self._faults.get(method_name)
            if not q:
                return None
            fault = q.pop(0)
        if isinstance(fault, Exception):
            raise fault
        if callable(fault):
            return fault(*args, **kwargs)
        return None

    def seed_source_session(
        self,
        runtime_sid: str,
        messages: list[dict[str, Any]],
        *,
        directory: str | None = None,
        parent_id: str | None = None,
        revision: int = 1,
        reverted_after_seq: int | None = None,
        reverted_message_ids: list[str] | None = None,
        unavailable_reason: str | None = None,
    ) -> None:
        """Seed in-memory source session history for `capture_anchor` / `validate_anchor` / `capture_history`."""
        with self._lock:
            self._in_memory_source_sessions[runtime_sid] = {
                "id": runtime_sid,
                "directory": directory or os.getcwd(),
                "parent_id": parent_id,
                "revision": revision,
                "reverted_after_seq": reverted_after_seq,
                "reverted_message_ids": list(reverted_message_ids or []),
                "unavailable_reason": unavailable_reason,
                "messages": [dict(m) for m in messages],
            }

    def revert_source_session(
        self,
        runtime_sid: str,
        *,
        reverted_after_seq: int | None = None,
        reverted_message_ids: list[str] | None = None,
    ) -> None:
        """Simulate a user revert on a seeded source session."""
        with self._lock:
            sess = self._in_memory_source_sessions.get(runtime_sid)
            if sess is None:
                raise SideSessionError(ErrorCode.NOT_FOUND, f"Source session not seeded: {runtime_sid}")
            if reverted_after_seq is not None:
                sess["reverted_after_seq"] = reverted_after_seq
            if reverted_message_ids is not None:
                existing = set(sess.get("reverted_message_ids") or [])
                existing.update(reverted_message_ids)
                sess["reverted_message_ids"] = sorted(existing)
            sess["revision"] = int(sess.get("revision", 1)) + 1

    def append_source_message(self, runtime_sid: str, message: Mapping[str, Any]) -> None:
        """Append a new message to a seeded source session (e.g. post-cutoff message)."""
        with self._lock:
            sess = self._in_memory_source_sessions.get(runtime_sid)
            if sess is None:
                raise SideSessionError(ErrorCode.NOT_FOUND, f"Source session not seeded: {runtime_sid}")
            msgs = sess.setdefault("messages", [])
            next_seq = max((int(m.get("sequence", m.get("seq", 0))) for m in msgs), default=0) + 1
            m_copy = dict(message)
            m_copy.setdefault("sequence", next_seq)
            m_copy.setdefault("id", f"msg-{next_seq}")
            msgs.append(m_copy)
            sess["revision"] = int(sess.get("revision", 1)) + 1

    def queue_event(self, runtime_sid: str, event: RuntimeEvent | Mapping[str, Any]) -> RuntimeEvent:
        """Enqueue a scripted RuntimeEvent for any active connection matching `runtime_sid`."""
        if isinstance(event, RuntimeEvent):
            ev = event
        elif isinstance(event, Mapping):
            ev = RuntimeEvent(
                event_id=str(event.get("event_id") or uuid.uuid4()),
                runtime_sid=runtime_sid,
                kind=str(event.get("kind") or "status_patch"),
                runtime_turn_id=event.get("runtime_turn_id"),
                input_id=event.get("input_id"),
                status=event.get("status"),
                outcome=event.get("outcome"),
                wait_request=dict(event["wait_request"]) if isinstance(event.get("wait_request"), Mapping) else None,
                payload=dict(event.get("payload") or {}),
                timestamp=str(event.get("timestamp") or utc_now_iso()),
            )
        else:
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "event must be RuntimeEvent or Mapping")

        with self._lock:
            matched = False
            for conn in self._connections.values():
                if conn.runtime_sid == runtime_sid and not conn.closed:
                    matched = True
                    conn.event_queue.append(ev)
                    if ev.kind == "wait_request" and ev.wait_request:
                        conn.status = "waiting_input"
                        req_id = str(ev.wait_request.get("host_request_id") or ev.wait_request.get("requestId") or ev.event_id)
                        conn.pending_waits[req_id] = dict(ev.wait_request)
                    elif ev.kind in ("turn.terminal", "idle"):
                        conn.status = "idle"
            if not matched:
                self._prequeued_events.setdefault(runtime_sid, []).append(ev)
        return ev

    def queue_wait_request(
        self,
        runtime_sid: str,
        *,
        host_request_id: str | None = None,
        kind: str = "permission",
        nonce: str | None = None,
        question: str = "Allow tool execution?",
        options: list[Any] | None = None,
        runtime_turn_id: str | None = None,
    ) -> RuntimeEvent:
        """Convenience helper to script a `wait_request` event on `runtime_sid`."""
        req_id = host_request_id or f"host-wait-{uuid.uuid4().hex[:8]}"
        wait_nonce = nonce or f"nonce-{uuid.uuid4().hex[:8]}"
        wait_payload = {
            "host_request_id": req_id,
            "kind": kind,
            "nonce": wait_nonce,
            "question": question,
            "options": options if options is not None else ["allow", "deny"],
            "runtime_turn_id": runtime_turn_id,
        }
        return self.queue_event(
            runtime_sid,
            RuntimeEvent(
                event_id=str(uuid.uuid4()),
                runtime_sid=runtime_sid,
                kind="wait_request",
                runtime_turn_id=runtime_turn_id,
                status="waiting_input",
                wait_request=wait_payload,
                payload=wait_payload,
                timestamp=utc_now_iso(),
            ),
        )

    def _sync_session_to_mock_host_db(
        self,
        runtime_sid: str,
        directory: str,
        parent_sid: str | None,
    ) -> None:
        if not self.sync_to_host_db or self._host_db_path is None:
            return
        db_path = self._host_db_path
        resolved_db = os.path.realpath(os.path.expanduser(str(db_path)))
        prod_db = os.path.realpath(os.path.expanduser("~/.zcode/cli/db/db.sqlite"))
        if resolved_db == prod_db:
            raise SideSessionError(
                ErrorCode.FORBIDDEN,
                f"ScriptedFakeDriver refuses to sync mock session to production host DB: {resolved_db}",
                {"db_path": resolved_db},
            )
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), timeout=2.0)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session (
                    id TEXT PRIMARY KEY,
                    directory TEXT,
                    parent_id TEXT,
                    time_archived INTEGER,
                    time_deleted INTEGER,
                    revert TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS message (
                    id TEXT PRIMARY KEY,
                    session_id TEXT,
                    sequence INTEGER,
                    role TEXT,
                    turn_id TEXT,
                    input_id TEXT,
                    content TEXT,
                    data TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS part (
                    id TEXT PRIMARY KEY,
                    session_id TEXT,
                    message_id TEXT,
                    data TEXT
                )
                """
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO session (id, directory, parent_id, time_archived, time_deleted, revert)
                VALUES (?, ?, ?, NULL, NULL, NULL)
                """,
                (runtime_sid, directory, parent_sid),
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # BaseDriver Implementation
    # ------------------------------------------------------------------

    def create(self, spec: RuntimeCreateSpec) -> RuntimeHandle:
        self.last_sanitized_env = sanitize_subprocess_env()
        for key in FORBIDDEN_INHERITED_SESSION_ENV_KEYS:
            assert key not in self.last_sanitized_env

        payload = build_create_payload(spec)
        assert "importedHistory" not in payload

        override_resp = self._check_fault("create", spec, payload)
        expected_ws = payload["workspace"]["workspacePath"]

        if isinstance(override_resp, Mapping):
            actual_ws = extract_workspace_path(override_resp, kind="create")
        else:
            sim_resp = {
                "result": {
                    "session": {
                        "id": payload["sessionId"],
                        "parentSessionId": payload["parentSessionId"],
                        "workspace": {
                            "workspacePath": expected_ws,
                            "workspaceKey": expected_ws,
                        },
                        "mode": payload["mode"],
                        "model": payload.get("model", {}),
                        "revision": 1,
                    }
                }
            }
            actual_ws = extract_workspace_path(sim_resp, kind="create")

        if actual_ws != expected_ws:
            raise SideSessionError(
                ErrorCode.WORKSPACE_MISMATCH,
                f"Workspace mismatch in create: expected {expected_ws}, got {actual_ws}",
                {"expected_workspace": expected_ws, "actual_workspace": actual_ws},
            )

        sid = payload["sessionId"]
        instance_id = str(uuid.uuid4())
        conn_id = f"fake-conn:{instance_id}"
        pid = os.getpid()
        lstart = get_process_lstart(pid) or f"test:{pid}"
        try:
            pgid = os.getpgid(pid)
        except OSError:
            pgid = pid

        conn_state = _AppServerConnection(
            runtime_sid=sid,
            runtime_instance_id=instance_id,
            owner_connection_id=conn_id,
            canonical_workspace=actual_ws,
            parent_runtime_sid=spec.parent_runtime_sid,
            mode=spec.mode,
            model=dict(spec.model or {}),
            tool_allowlist=list(spec.tool_allowlist or ()),
            tool_denylist=list(spec.tool_denylist or ()),
            additional_directories=list(spec.additional_directories),
            proc=None,
            pid=pid,
            process_started_at=lstart,
            process_group=pgid,
            revision=1,
            status="idle",
        )

        with self._lock:
            for pq_ev in self._prequeued_events.pop(sid, []):
                conn_state.event_queue.append(pq_ev)
                if pq_ev.kind == "wait_request" and pq_ev.wait_request:
                    conn_state.status = "waiting_input"
                    req_id = str(pq_ev.wait_request.get("host_request_id") or pq_ev.wait_request.get("requestId") or pq_ev.event_id)
                    conn_state.pending_waits[req_id] = dict(pq_ev.wait_request)
            self.create_payloads.append(payload)
            self.call_log.append({"method": "create", "runtime_sid": sid, "payload": payload})
            self._connections[instance_id] = conn_state
            self._sessions_by_sid[sid] = {
                "runtime_sid": sid,
                "canonical_workspace": actual_ws,
                "parent_runtime_sid": spec.parent_runtime_sid,
                "mode": spec.mode,
                "model": dict(spec.model or {}),
                "tool_allowlist": list(spec.tool_allowlist or ()),
                "tool_denylist": list(spec.tool_denylist or ()),
                "additional_directories": list(spec.additional_directories),
                "revision": 1,
            }

        self._sync_session_to_mock_host_db(sid, actual_ws, spec.parent_runtime_sid)

        return RuntimeHandle(
            runtime_sid=sid,
            runtime_instance_id=instance_id,
            owner_connection_id=conn_id,
            snapshot_revision=1,
            canonical_workspace=actual_ws,
            process_identity={
                "pid": pid,
                "process_started_at": lstart,
                "process_group": pgid,
            },
        )

    def resume(self, spec: RuntimeResumeSpec) -> RuntimeHandle:
        self.last_sanitized_env = sanitize_subprocess_env()
        for key in FORBIDDEN_INHERITED_SESSION_ENV_KEYS:
            assert key not in self.last_sanitized_env

        if not isinstance(spec, RuntimeResumeSpec):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "spec must be a RuntimeResumeSpec")

        expected_ws = os.path.realpath(Path(spec.expected_workspace).expanduser().absolute())
        payload = build_resume_payload(spec)
        sid = spec.assignment.runtime_sid

        override_resp = self._check_fault("resume", spec, payload)
        with self._lock:
            stored = self._sessions_by_sid.get(sid)

        if isinstance(override_resp, Mapping):
            actual_ws = extract_workspace_path(override_resp, kind="resume")
            res_body = override_resp.get("result") if isinstance(override_resp.get("result"), Mapping) else override_resp
            snap_obj = res_body.get("snapshot") if isinstance(res_body, Mapping) else {}
            sess_obj = snap_obj.get("session") if isinstance(snap_obj, Mapping) else {}
            if not isinstance(sess_obj, Mapping):
                sess_obj = {}
            returned_parent = sess_obj.get("parentSessionId") or sess_obj.get("parent_id")
            returned_mode = sess_obj.get("mode", spec.mode)
            returned_model = sess_obj.get("model", spec.model)
            revision = int(sess_obj.get("revision") or 1)
        elif stored is not None:
            sim_resp = {
                "result": {
                    "snapshot": {
                        "session": {
                            "id": sid,
                            "parentSessionId": stored["parent_runtime_sid"],
                            "workspace": {
                                "workspacePath": stored["canonical_workspace"],
                                "workspaceKey": stored["canonical_workspace"],
                            },
                            "mode": stored["mode"],
                            "model": stored["model"],
                            "revision": stored["revision"],
                        }
                    }
                }
            }
            actual_ws = extract_workspace_path(sim_resp, kind="resume")
            returned_parent = stored["parent_runtime_sid"]
            returned_mode = stored["mode"]
            returned_model = stored["model"]
            revision = int(stored["revision"])
        else:
            sim_resp = {
                "result": {
                    "snapshot": {
                        "session": {
                            "id": sid,
                            "parentSessionId": spec.expected_parent_runtime_sid,
                            "workspace": {
                                "workspacePath": expected_ws,
                                "workspaceKey": expected_ws,
                            },
                            "mode": spec.mode,
                            "model": dict(spec.model),
                            "revision": 1,
                        }
                    }
                }
            }
            actual_ws = extract_workspace_path(sim_resp, kind="resume")
            returned_parent = spec.expected_parent_runtime_sid
            returned_mode = spec.mode
            returned_model = dict(spec.model)
            revision = 1

        if actual_ws != expected_ws:
            raise SideSessionError(
                ErrorCode.WORKSPACE_MISMATCH,
                f"Workspace mismatch on resume: expected {expected_ws}, got {actual_ws}",
                {"expected_workspace": expected_ws, "actual_workspace": actual_ws},
            )
        if spec.expected_parent_runtime_sid and returned_parent and str(returned_parent) != spec.expected_parent_runtime_sid:
            raise SideSessionError(
                ErrorCode.HOST_PARENT_MISMATCH,
                f"Parent runtime SID mismatch on resume: expected {spec.expected_parent_runtime_sid}, got {returned_parent}",
            )
        if returned_mode != spec.mode or (spec.model and returned_model != spec.model):
            raise SideSessionError(
                ErrorCode.RUNTIME_CONFIG_MISMATCH,
                "Runtime mode or model mismatch on resume",
                {"expected_mode": spec.mode, "actual_mode": returned_mode},
            )

        instance_id = str(uuid.uuid4())
        conn_id = f"fake-conn:{instance_id}"
        pid = os.getpid()
        lstart = get_process_lstart(pid) or f"test:{pid}"
        try:
            pgid = os.getpgid(pid)
        except OSError:
            pgid = pid

        conn_state = _AppServerConnection(
            runtime_sid=sid,
            runtime_instance_id=instance_id,
            owner_connection_id=conn_id,
            canonical_workspace=actual_ws,
            parent_runtime_sid=spec.expected_parent_runtime_sid,
            mode=spec.mode,
            model=dict(spec.model or {}),
            tool_allowlist=list(spec.tool_allowlist or ()),
            tool_denylist=list(spec.tool_denylist or ()),
            additional_directories=list(spec.additional_directories),
            proc=None,
            pid=pid,
            process_started_at=lstart,
            process_group=pgid,
            revision=revision,
            status="idle",
        )
        with self._lock:
            for pq_ev in self._prequeued_events.pop(sid, []):
                conn_state.event_queue.append(pq_ev)
                if pq_ev.kind == "wait_request" and pq_ev.wait_request:
                    conn_state.status = "waiting_input"
                    req_id = str(pq_ev.wait_request.get("host_request_id") or pq_ev.wait_request.get("requestId") or pq_ev.event_id)
                    conn_state.pending_waits[req_id] = dict(pq_ev.wait_request)
            self.resume_payloads.append(payload)
            self.call_log.append({"method": "resume", "runtime_sid": sid, "payload": payload})
            self._connections[instance_id] = conn_state
            self._sessions_by_sid[sid] = {
                "runtime_sid": sid,
                "canonical_workspace": actual_ws,
                "parent_runtime_sid": spec.expected_parent_runtime_sid,
                "mode": spec.mode,
                "model": dict(spec.model or {}),
                "tool_allowlist": list(spec.tool_allowlist or ()),
                "tool_denylist": list(spec.tool_denylist or ()),
                "additional_directories": list(spec.additional_directories),
                "revision": revision,
            }

        return RuntimeHandle(
            runtime_sid=sid,
            runtime_instance_id=instance_id,
            owner_connection_id=conn_id,
            snapshot_revision=revision,
            canonical_workspace=actual_ws,
            process_identity={
                "pid": pid,
                "process_started_at": lstart,
                "process_group": pgid,
            },
        )

    def _require_fake_connection(self, handle: RuntimeHandle) -> _AppServerConnection:
        if not isinstance(handle, RuntimeHandle):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "handle must be a RuntimeHandle")
        with self._lock:
            conn = self._connections.get(handle.runtime_instance_id)
        if conn is None or conn.closed or conn.owner_connection_id != handle.owner_connection_id:
            raise SideSessionError(
                ErrorCode.CANCEL_OWNER_UNAVAILABLE,
                f"Connection is not open or not owned for runtime_instance_id={handle.runtime_instance_id}",
                {"runtime_instance_id": handle.runtime_instance_id},
            )
        return conn

    def send(self, handle: RuntimeHandle, input: RuntimeInput) -> SendReceipt:
        conn = self._require_fake_connection(handle)
        if not isinstance(input, RuntimeInput):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "input must be a RuntimeInput")

        fault_res = self._check_fault("send", handle, input)
        if isinstance(fault_res, SendReceipt):
            return fault_res

        if input.expected_revision is not None and input.expected_revision != conn.revision:
            return SendReceipt(
                input_id=input.input_id,
                status="rejected",
                runtime_turn_id=None,
                response_revision=conn.revision,
                evidence_ref=f"fake-send-rejected:{input.input_id}",
            )

        turn_id = f"turn-{uuid.uuid4().hex[:12]}"
        with self._lock:
            conn.revision += 1
            conn.status = "running"
            conn.active_turn_id = turn_id
            rec = {
                "runtime_sid": handle.runtime_sid,
                "runtime_instance_id": handle.runtime_instance_id,
                "owner_connection_id": handle.owner_connection_id,
                "input_id": input.input_id,
                "content": input.content,
                "origin": input.origin,
                "runtime_turn_id": turn_id,
                "revision": conn.revision,
            }
            conn.sent_inputs.append(rec)
            self.sent_inputs.append(rec)
            self.call_log.append({"method": "send", **rec})
            if handle.runtime_sid in self._sessions_by_sid:
                self._sessions_by_sid[handle.runtime_sid]["revision"] = conn.revision

            conn.event_queue.append(
                RuntimeEvent(
                    event_id=str(uuid.uuid4()),
                    runtime_sid=handle.runtime_sid,
                    kind="turn.started",
                    runtime_turn_id=turn_id,
                    input_id=input.input_id,
                    status="running",
                    payload={"turnId": turn_id, "inputId": input.input_id},
                    timestamp=utc_now_iso(),
                )
            )

        return SendReceipt(
            input_id=input.input_id,
            status="accepted",
            runtime_turn_id=turn_id,
            response_revision=conn.revision,
            evidence_ref=f"fake-send:{handle.runtime_instance_id}:{input.input_id}",
        )

    def events(self, handle: RuntimeHandle) -> DualEventStream:
        conn = self._require_fake_connection(handle)

        def _pop_next() -> RuntimeEvent | None:
            with self._lock:
                if not conn.event_queue:
                    return None
                ev = conn.event_queue.popleft()
                if ev.kind == "wait_request":
                    conn.status = "waiting_input"
                elif ev.kind in ("turn.terminal", "idle"):
                    conn.status = "idle"
                return ev

        return DualEventStream(_pop_next)

    def inspect(self, handle: RuntimeHandle) -> RuntimeSnapshot:
        if not isinstance(handle, RuntimeHandle):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "handle must be a RuntimeHandle")
        self._check_fault("inspect", handle)
        with self._lock:
            conn = self._connections.get(handle.runtime_instance_id)

        pid = handle.process_identity.get("pid") if isinstance(handle.process_identity, Mapping) else None
        exp_lstart = (
            handle.process_identity.get("process_started_at")
            if isinstance(handle.process_identity, Mapping)
            else None
        )
        proc_alive = verify_process_identity(pid, exp_lstart) if pid else (conn is not None and not conn.closed)
        if conn is not None and conn.closed:
            proc_alive = False

        status = conn.status if (conn is not None and proc_alive) else "exited"
        return RuntimeSnapshot(
            runtime_sid=handle.runtime_sid,
            canonical_workspace=conn.canonical_workspace if conn else handle.canonical_workspace,
            model=dict(conn.model) if conn else {},
            mode=conn.mode if conn else "default",
            status=status,
            tool_profile_check="verified" if conn is not None else "unknown",
            notes_access_check="verified" if conn is not None else "unknown",
            revision=conn.revision if conn else handle.snapshot_revision,
            raw_response_ref=f"fake-inspect:{handle.runtime_instance_id}",
            parent_runtime_sid=conn.parent_runtime_sid if conn else None,
        )

    def respond_wait(
        self,
        handle: RuntimeHandle,
        request: BoundWait,
        response: WaitResponse | Mapping[str, Any],
        control_id: str,
    ) -> ControlReceipt:
        conn = self._require_fake_connection(handle)
        if not isinstance(request, BoundWait):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "request must be a BoundWait")
        if request.runtime_instance_id != handle.runtime_instance_id:
            raise SideSessionError(
                ErrorCode.WAIT_STALE,
                "BoundWait runtime_instance_id does not match RuntimeHandle",
            )

        fault_res = self._check_fault("respond_wait", handle, request, response, control_id)
        if isinstance(fault_res, ControlReceipt):
            return fault_res

        val_resp = _coerce_wait_response(response)
        if val_resp["kind"] != request.kind:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"WaitResponse kind ({val_resp['kind']!r}) != BoundWait kind ({request.kind!r})",
            )

        if request.kind == "permission" and request.options:
            allowed_decisions = {
                str(opt.get("id") or opt.get("decision") or opt) if isinstance(opt, Mapping) else str(opt)
                for opt in request.options
            }
            if allowed_decisions and val_resp["decision"] not in allowed_decisions and val_resp["option_id"] not in allowed_decisions:
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    f"Permission decision {val_resp['decision']!r} is not in allowed options {sorted(allowed_decisions)}",
                )

        with self._lock:
            conn.pending_waits.pop(request.host_request_id, None)
            conn.status = "running"
            rec = {
                "control_id": str(control_id),
                "runtime_sid": handle.runtime_sid,
                "runtime_instance_id": handle.runtime_instance_id,
                "owner_connection_id": handle.owner_connection_id,
                "wait_id": request.wait_id,
                "host_request_id": request.host_request_id,
                "nonce": request.nonce,
                "response": val_resp,
            }
            self.wait_responses.append(rec)
            self.call_log.append({"method": "respond_wait", **rec})
            conn.event_queue.append(
                RuntimeEvent(
                    event_id=str(uuid.uuid4()),
                    runtime_sid=handle.runtime_sid,
                    kind="turn.terminal",
                    runtime_turn_id=request.runtime_turn_id or conn.active_turn_id,
                    status="idle",
                    outcome="success",
                    payload={"event": "turn.terminal", "resolvedWaitId": request.wait_id},
                    timestamp=utc_now_iso(),
                )
            )

        return ControlReceipt(
            control_id=str(control_id),
            status="applied",
            runtime_instance_id=handle.runtime_instance_id,
            owner_epoch=request.owner_epoch,
            observed_wait_state="resolved",
            host_receipt_id=f"fake-wait-rcpt:{control_id}",
        )

    def stop_and_wait(self, handle: RuntimeHandle, deadline_ms: int = 5000) -> ExitReceipt:
        if not isinstance(handle, RuntimeHandle):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "handle must be a RuntimeHandle")

        fault_res = self._check_fault("stop_and_wait", handle, deadline_ms)
        if isinstance(fault_res, ExitReceipt):
            return fault_res

        with self._lock:
            conn = self._connections.get(handle.runtime_instance_id)
            if conn is None or conn.owner_connection_id != handle.owner_connection_id:
                raise SideSessionError(
                    ErrorCode.CANCEL_OWNER_UNAVAILABLE,
                    f"Cannot stop session: runtime_instance_id={handle.runtime_instance_id} is not owned by this driver",
                )
            conn.closed = True
            conn.status = "exited"
            conn.exit_code = 0
            self.stopped_handles.append(handle.runtime_instance_id)
            self.call_log.append({
                "method": "stop_and_wait",
                "runtime_sid": handle.runtime_sid,
                "runtime_instance_id": handle.runtime_instance_id,
                "deadline_ms": deadline_ms,
            })

        return ExitReceipt(
            runtime_instance_id=handle.runtime_instance_id,
            process_identity=dict(handle.process_identity),
            exit_confirmed=True,
            runtime_outcome="cancelled",
            ended_at=utc_now_iso(),
            exit_code=0,
            evidence_ref=f"fake-exit:{handle.runtime_instance_id}",
        )

    def fork_idle(self, spec: Any) -> ForkReceipt:
        spec_dict = spec.to_dict() if hasattr(spec, "to_dict") else (dict(spec) if isinstance(spec, Mapping) else {})
        workspace_mode = str(spec_dict.get("workspace_mode") or "inherit")
        source_ws = spec_dict.get("source_workspace")
        target_ws = spec_dict.get("target_workspace") or spec_dict.get("workspace_path")

        if workspace_mode == "branch" or (
            source_ws and target_ws and os.path.realpath(str(source_ws)) != os.path.realpath(str(target_ws))
        ):
            raise SideSessionError(
                ErrorCode.UNSUPPORTED_CONTEXT_WORKSPACE,
                "native_fork cannot be combined with branch worktree or cross-directory workspace",
            )

        if (
            spec_dict.get("parent_busy") is True
            or spec_dict.get("parent_active") is True
            or spec_dict.get("live_fork") is True
            or spec_dict.get("in_active_turn") is True
        ):
            raise SideSessionError(
                ErrorCode.UNSUPPORTED_LIVE_FORK,
                "native_fork cannot be performed while parent session is active",
            )

        if not self.probe().supports_native_fork.enabled:
            raise SideSessionError(
                ErrorCode.CAPABILITY_UNAVAILABLE,
                "supports_native_fork is disabled by capability gate",
            )

        parent_sid = str(spec_dict.get("parent_runtime_sid") or spec_dict.get("source_runtime_sid") or "")
        new_sid = str(spec_dict.get("runtime_sid") or spec_dict.get("preallocated_session_id") or uuid.uuid4())
        canonical_ws = os.path.realpath(str(target_ws or source_ws or os.getcwd()))
        return ForkReceipt(
            runtime_sid=new_sid,
            parent_runtime_sid=parent_sid,
            canonical_workspace=canonical_ws,
            snapshot_revision=int(spec_dict.get("snapshot_revision", 1)),
            status="forked",
            raw_response_ref=f"fake-fork:{parent_sid}:{new_sid}",
        )


FakeDriver = ScriptedFakeDriver


class OrchestrateOnlyDriver(_HostSqliteHistoryMixin, BaseDriver):
    """Offline / orchestration-only driver that supports anchor inspection but rejects live runtime execution."""

    driver_kind = "orchestrate_only"

    def __init__(self, *, host_db_path: Path | str | None = None) -> None:
        self._host_db_path = Path(host_db_path).expanduser().absolute() if host_db_path is not None else None
        self._lock = threading.RLock()
        self._captured_chains: dict[tuple[str, str], tuple[list[dict[str, Any]], list[dict[str, Any]]]] = {}
        self._in_memory_source_sessions: dict[str, dict[str, Any]] = {}

    def probe(self) -> DriverCapabilities:
        return build_driver_capabilities(
            host_version="0.17.1",
            protocol_revision="1.1",
            capability_fingerprint="orchestrate-only-v1.1",
            integration_verified=False,
            summary_copy_verified_default=False,
        )

    def create(self, spec: RuntimeCreateSpec) -> RuntimeHandle:
        raise SideSessionError(
            ErrorCode.CAPABILITY_UNAVAILABLE,
            "OrchestrateOnlyDriver does not support creating live runtime sessions",
        )

    def resume(self, spec: RuntimeResumeSpec) -> RuntimeHandle:
        raise SideSessionError(
            ErrorCode.CAPABILITY_UNAVAILABLE,
            "OrchestrateOnlyDriver does not support resuming live runtime sessions",
        )

    def send(self, handle: RuntimeHandle, input: RuntimeInput) -> SendReceipt:
        raise SideSessionError(
            ErrorCode.CAPABILITY_UNAVAILABLE,
            "OrchestrateOnlyDriver does not support sending runtime inputs",
        )

    def events(self, handle: RuntimeHandle) -> DualEventStream:
        return DualEventStream([])

    def inspect(self, handle: RuntimeHandle) -> RuntimeSnapshot:
        return RuntimeSnapshot(
            runtime_sid=handle.runtime_sid,
            canonical_workspace=handle.canonical_workspace,
            model={},
            mode="orchestrate_only",
            status="unknown",
            tool_profile_check="unknown",
            notes_access_check="unknown",
            revision=handle.snapshot_revision,
        )

    def respond_wait(
        self,
        handle: RuntimeHandle,
        request: BoundWait,
        response: WaitResponse | Mapping[str, Any],
        control_id: str,
    ) -> ControlReceipt:
        raise SideSessionError(
            ErrorCode.WAIT_RESPONSE_UNAVAILABLE,
            "OrchestrateOnlyDriver cannot respond to runtime waits",
        )

    def stop_and_wait(self, handle: RuntimeHandle, deadline_ms: int = 5000) -> ExitReceipt:
        raise SideSessionError(
            ErrorCode.CANCEL_OWNER_UNAVAILABLE,
            "OrchestrateOnlyDriver does not own live runtime processes",
        )

    def fork_idle(self, spec: Any) -> ForkReceipt:
        raise SideSessionError(
            ErrorCode.CAPABILITY_UNAVAILABLE,
            "OrchestrateOnlyDriver does not support fork_idle",
        )


# ------------------------------------------------------------------
# Default Driver Instance & Module-Level Convenience Functions
# ------------------------------------------------------------------

_DEFAULT_DRIVER: BaseDriver = ZCodeDriver()


def get_default_driver() -> BaseDriver:
    return _DEFAULT_DRIVER


def set_default_driver(driver: BaseDriver) -> BaseDriver:
    global _DEFAULT_DRIVER
    _DEFAULT_DRIVER = driver
    return _DEFAULT_DRIVER


def probe(*, driver: BaseDriver | None = None) -> DriverCapabilities:
    return (driver or _DEFAULT_DRIVER).probe()


def capture_anchor(source: SourceCutoff, *, driver: BaseDriver | None = None) -> SourceAnchor:
    return (driver or _DEFAULT_DRIVER).capture_anchor(source)


def validate_anchor(anchor: SourceAnchor, *, driver: BaseDriver | None = None) -> AnchorCheck:
    return (driver or _DEFAULT_DRIVER).validate_anchor(anchor)


def capture_history(anchor: SourceAnchor, *, driver: BaseDriver | None = None) -> HistoryProjection:
    return (driver or _DEFAULT_DRIVER).capture_history(anchor)


def create(spec: RuntimeCreateSpec, *, driver: BaseDriver | None = None) -> RuntimeHandle:
    return (driver or _DEFAULT_DRIVER).create(spec)


def resume(spec: RuntimeResumeSpec, *, driver: BaseDriver | None = None) -> RuntimeHandle:
    return (driver or _DEFAULT_DRIVER).resume(spec)


def send(handle: RuntimeHandle, input: RuntimeInput, *, driver: BaseDriver | None = None) -> SendReceipt:
    return (driver or _DEFAULT_DRIVER).send(handle, input)


def events(handle: RuntimeHandle, *, driver: BaseDriver | None = None) -> DualEventStream:
    return (driver or _DEFAULT_DRIVER).events(handle)


def inspect(handle: RuntimeHandle, *, driver: BaseDriver | None = None) -> RuntimeSnapshot:
    return (driver or _DEFAULT_DRIVER).inspect(handle)


def respond_wait(
    handle: RuntimeHandle,
    request: BoundWait,
    response: WaitResponse | Mapping[str, Any],
    control_id: str,
    *,
    driver: BaseDriver | None = None,
) -> ControlReceipt:
    return (driver or _DEFAULT_DRIVER).respond_wait(handle, request, response, control_id)


def stop_and_wait(
    handle: RuntimeHandle,
    deadline_ms: int = 5000,
    *,
    driver: BaseDriver | None = None,
) -> ExitReceipt:
    return (driver or _DEFAULT_DRIVER).stop_and_wait(handle, deadline_ms=deadline_ms)


def fork_idle(spec: Any, *, driver: BaseDriver | None = None) -> ForkReceipt:
    return (driver or _DEFAULT_DRIVER).fork_idle(spec)


__all__ = [
    "AnchorCheck",
    "BaseDriver",
    "BoundWait",
    "CapabilityStatus",
    "ControlReceipt",
    "DRIVER_API_VERSION",
    "DriverCapabilities",
    "DualEventStream",
    "ExitReceipt",
    "FORBIDDEN_INHERITED_SESSION_ENV_KEYS",
    "FakeDriver",
    "ForkReceipt",
    "HistoryProjection",
    "OrchestrateOnlyDriver",
    "RunAssignment",
    "RuntimeCreateSpec",
    "RuntimeEvent",
    "RuntimeHandle",
    "RuntimeInput",
    "RuntimeResumeSpec",
    "RuntimeSnapshot",
    "ScriptedFakeDriver",
    "SendReceipt",
    "SourceAnchor",
    "SourceCutoff",
    "WaitResponse",
    "ZCodeDriver",
    "build_create_payload",
    "build_driver_capabilities",
    "build_resume_payload",
    "capture_anchor",
    "capture_history",
    "create",
    "events",
    "extract_workspace_path",
    "fork_idle",
    "get_default_driver",
    "inspect",
    "probe",
    "respond_wait",
    "resume",
    "sanitize_subprocess_env",
    "send",
    "set_default_driver",
    "stop_and_wait",
    "validate_anchor",
]
