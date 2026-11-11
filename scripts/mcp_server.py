"""Standard-library stdio JSON-RPC 2.0 MCP server for side-sessions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, BinaryIO, Iterable, Mapping, TextIO
import uuid

try:
    from .contracts import (
        DRIVER_API_VERSION,
        ENGINE_SCHEMA_VERSION,
        FORBIDDEN_CALLER_OVERRIDE_FIELDS,
        CallerContext,
        ErrorCode,
        SideSessionError,
        normalize_text,
    )
    from .driver import ZCodeDriver, sanitize_subprocess_env
    from .state import Store, open_store, resolve_state_root
except ImportError:  # pragma: no cover
    _script_dir = str(Path(__file__).resolve().parent)
    if _script_dir not in sys.path:
        sys.path.insert(0, _script_dir)
    from contracts import (  # type: ignore
        DRIVER_API_VERSION,
        ENGINE_SCHEMA_VERSION,
        FORBIDDEN_CALLER_OVERRIDE_FIELDS,
        CallerContext,
        ErrorCode,
        SideSessionError,
        normalize_text,
    )
    from driver import ZCodeDriver, sanitize_subprocess_env  # type: ignore
    from state import Store, open_store, resolve_state_root  # type: ignore


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


SERVER_NAME = "side-sessions"
SERVER_VERSION = "0.2.1"
DEFAULT_MCP_PROTOCOL_VERSION = "2024-11-05"
REQUEST_CONTEXT_NAMESPACE = "com.zcode/request-context"


class _AliasStr(str):
    """String subclass matching both primary error code and compatibility aliases."""

    def __new__(cls, primary: str, *aliases: str) -> _AliasStr:
        obj = super().__new__(cls, primary)
        obj._aliases = frozenset({primary, *(str(a) for a in aliases if a)})
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


def _install_contract_compat() -> None:
    """Ensure compatibility aliases on ErrorCode and CallerContext."""
    if not hasattr(ErrorCode, "CALLER_IDENTITY_CONFLICT"):
        try:
            setattr(ErrorCode, "CALLER_IDENTITY_CONFLICT", ErrorCode.CALLER_CONTEXT_CONFLICT)
        except Exception:
            pass

    if not hasattr(CallerContext, "runtime_session_id"):
        setattr(CallerContext, "runtime_session_id", property(lambda self: self.runtime_sid))
    if not hasattr(CallerContext, "session_id"):
        setattr(CallerContext, "session_id", property(lambda self: self.runtime_sid))
    if not hasattr(CallerContext, "turn_id"):
        setattr(CallerContext, "turn_id", property(lambda self: self.runtime_turn_id))


_install_contract_compat()


def _make_error(
    code: str | ErrorCode,
    message: str,
    details: Mapping[str, Any] | None = None,
    *,
    retryable: bool = False,
    aliases: Iterable[str | ErrorCode] = (),
) -> SideSessionError:
    primary = code.value if isinstance(code, Enum) else str(code)
    alias_strs = [a.value if isinstance(a, Enum) else str(a) for a in aliases if a]
    det = dict(details) if details else {}
    if alias_strs:
        det.setdefault("alias_codes", alias_strs)
    exc = SideSessionError(primary, message, det, retryable=retryable)
    if alias_strs:
        exc.code = _AliasStr(primary, *alias_strs)
    return exc


@dataclass
class TrustedConnection:
    """Represents a trusted local host stdio MCP connection."""

    connection_id: str = field(default_factory=lambda: f"stdio:{uuid.uuid4().hex[:12]}")
    trusted: bool = True
    initialized: bool = False
    transport: str = "stdio"
    client_info: dict[str, Any] = field(default_factory=dict)
    protocol_version: str = DEFAULT_MCP_PROTOCOL_VERSION


ALLOWED_ENGINE_TOOLS: tuple[str, ...] = (
    "start_session",
    "list_sessions",
    "get_session",
    "hand_off_to_session",
    "report_child_turn",
    "send_message_to_session",
    "dismiss_task",
    "set_session_status",
    "archive_session",
    "list_events",
    "get_event",
    "ack_events",
    "read_report",
    "read_brief",
    "read_context",
    "publish_artifact",
    "read_artifact",
    "submit_note",
    "update_shared_context",
    "register_task",
    "get_task",
    "list_tasks",
    "bind_current_task",
    "get_current_task",
    "create_dispatch_group",
    "seal_dispatch_group",
    "get_dispatch_group",
    "close_dispatch_group",
    "list_waits",
    "get_control",
    "respond_to_wait",
    "cancel_run",
    "cancel_message",
    "get_operation",
    "diff_worktree",
)


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "start_session",
        "description": "Start a controlled child side-session, create an offer/own_initiative proposal, or claim an approved proposal.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "initiation": {"type": "string", "enum": ["user_asked", "own_initiative", "offer"]},
                "proposal_id": {"type": "string"},
                "request_id": {"type": "string"},
                "title": {"type": "string"},
                "prompt": {"type": "string"},
                "context": {"type": "string", "enum": ["fresh", "fork"]},
                "background": {"type": "string"},
                "task_kind": {"type": "string", "enum": ["read_only", "write_code"]},
                "use_worktree": {"type": "boolean"},
                "context_strategy": {"type": "string", "enum": ["native_fork", "summary_copy"]},
                "name": {"type": "string"},
                "dispatch_group_id": {"type": "string"},
                "batch_id": {"type": "string"},
            },
            "required": ["request_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_sessions",
        "description": "List sessions in the caller's authorized family tree.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "linked": {"type": "boolean", "default": True},
                "include_archived": {"type": "boolean", "default": False},
                "parent_session_id": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_session",
        "description": "Get detailed status, active runs, waits, and recent report references for a session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target_kind": {"type": "string", "enum": ["node", "runtime"], "default": "node"},
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "send_message_to_session",
        "description": "Enqueue a follow-up message to an existing session in the same family.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "message_id": {"type": "string"},
                "session_id": {"type": "string"},
                "message": {"type": "string"},
                "resume_policy": {"type": "string", "enum": ["active_only", "explicit"], "default": "active_only"},
                "dispatch_group_id": {"type": "string"},
            },
            "required": ["request_id", "message_id", "session_id", "message"],
            "additionalProperties": False,
        },
    },
    {
        "name": "hand_off_to_session",
        "description": "Perform a two-phase guarded task handoff from the current parent session to a child session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "transfer_id": {"type": "string"},
                "task_id": {"type": "string"},
                "title": {"type": "string"},
                "remaining_plan": {"type": "string"},
                "task_kind": {"type": "string", "enum": ["read_only", "write_code"]},
                "use_worktree": {"type": "boolean"},
                "context": {"type": "string", "enum": ["fork"], "default": "fork"},
                "context_strategy": {"type": "string", "enum": ["summary_copy", "native_fork"]},
                "expected_task_revision": {"type": "integer"},
                "dispatch_group_id": {"type": "string"},
            },
            "required": [
                "request_id",
                "transfer_id",
                "task_id",
                "title",
                "remaining_plan",
                "task_kind",
                "use_worktree",
                "context_strategy",
                "expected_task_revision",
            ],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_operation",
        "description": "Inspect an asynchronous startup or handoff operation and its context snapshot candidate.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "operation_id": {"type": "string"},
            },
            "required": ["operation_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "create_dispatch_group",
        "description": "Create an explicit dispatch group for up to 4 parallel child dispatches.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "expected_members": {"type": "integer", "minimum": 1, "maximum": 4},
                "batch_id": {"type": "string"},
            },
            "required": ["request_id", "expected_members"],
            "additionalProperties": False,
        },
    },
    {
        "name": "seal_dispatch_group",
        "description": "Seal an open dispatch group once all expected members have been admitted.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "dispatch_group_id": {"type": "string"},
                "expected_revision": {"type": "integer"},
            },
            "required": ["request_id", "dispatch_group_id", "expected_revision"],
            "additionalProperties": False,
        },
    },
    {
        "name": "close_dispatch_group",
        "description": "Close an incomplete dispatch group and acknowledge that no further members will be added.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "dispatch_group_id": {"type": "string"},
                "expected_revision": {"type": "integer"},
            },
            "required": ["request_id", "dispatch_group_id", "expected_revision"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_dispatch_group",
        "description": "Get the status, member list, and manifest reference of a dispatch group.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "dispatch_group_id": {"type": "string"},
            },
            "required": ["dispatch_group_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "register_task",
        "description": "Register a new task owned by the caller and bind it to the current runtime turn.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "title": {"type": "string"},
                "remaining_plan": {"type": "string"},
                "task_kind": {"type": "string", "enum": ["read_only", "write_code"]},
                "scope": {"type": "object"},
            },
            "required": ["request_id", "title", "remaining_plan", "task_kind", "scope"],
            "additionalProperties": False,
        },
    },
    {
        "name": "bind_current_task",
        "description": "Bind an existing task owned by the caller to the current runtime turn.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "task_id": {"type": "string"},
                "expected_task_revision": {"type": "integer"},
            },
            "required": ["request_id", "task_id", "expected_task_revision"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_current_task",
        "description": "Get the task bound to the caller's current runtime turn.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "get_task",
        "description": "Get details of a specific task by task_id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
            },
            "required": ["task_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_tasks",
        "description": "List tasks owned by the caller or a managed descendant session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "list_waits",
        "description": "List wait requests (input, elicitation, permission) for a session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_control",
        "description": "Get the status of a control command (respond_wait or cancel_run).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "control_id": {"type": "string"},
            },
            "required": ["control_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "respond_to_wait",
        "description": "Submit a response to an open wait request over the owner's active runtime connection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "wait_id": {"type": "string"},
                "nonce": {"type": "string"},
                "response": {"type": "object"},
            },
            "required": ["request_id", "wait_id", "nonce", "response"],
            "additionalProperties": False,
        },
    },
    {
        "name": "cancel_run",
        "description": "Request cancellation of an active or starting run.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "session_id": {"type": "string"},
                "run_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["request_id", "session_id", "run_id", "reason"],
            "additionalProperties": False,
        },
    },
    {
        "name": "cancel_message",
        "description": "Cancel a queued message that has not yet been claimed by a worker.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "session_id": {"type": "string"},
                "message_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["request_id", "session_id", "message_id", "reason"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_events",
        "description": "List outbox events addressed to the caller as direct parent.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "states": {"type": "array", "items": {"type": "string", "enum": ["pending", "presented", "acked"]}},
                "cursor": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 64},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_event",
        "description": "Get a single outbox event by event_id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string"},
            },
            "required": ["event_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "read_report",
        "description": "Read a child turn report by logical ssref and verify its semantic SHA-256 digest.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "report_ref": {"type": "string"},
            },
            "required": ["report_ref"],
            "additionalProperties": False,
        },
    },
    {
        "name": "read_artifact",
        "description": "Read an immutable artifact or manifest in Base64 byte chunks with SHA-256 verification.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "artifact_ref": {"type": "string"},
                "offset": {"type": "integer", "minimum": 0},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": 65536},
            },
            "required": ["artifact_ref"],
            "additionalProperties": False,
        },
    },
    {
        "name": "publish_artifact",
        "description": "Snapshot a file from the child's approved workspace into a staged artifact for the active run.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "run_id": {"type": "string"},
                "relative_path": {"type": "string"},
                "expected_sha256": {"type": "string"},
                "media_type": {"type": "string"},
            },
            "required": ["request_id", "run_id", "relative_path", "expected_sha256", "media_type"],
            "additionalProperties": False,
        },
    },
    {
        "name": "report_child_turn",
        "description": "Submit a checkpoint or final turn report from a child session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "run_id": {"type": "string"},
                "turn_seq": {"type": "integer"},
                "worker_turn_id": {"type": "string"},
                "phase": {"type": "string", "enum": ["checkpoint", "final"]},
                "report_revision": {"type": ["integer", "null"]},
                "outcome": {"type": "string", "enum": ["success", "failed", "cancelled", "blocked"]},
                "recap": {"type": "string"},
                "full_report": {"type": "string"},
                "blocked": {"type": "boolean"},
                "block_reason": {"type": ["string", "null"]},
                "artifacts": {"type": "array", "items": {"type": "object"}},
            },
            "required": [
                "request_id",
                "run_id",
                "turn_seq",
                "worker_turn_id",
                "phase",
                "outcome",
                "recap",
                "full_report",
                "blocked",
            ],
            "additionalProperties": False,
        },
    },
    {
        "name": "ack_events",
        "description": "Acknowledge outbox events as consumed by their direct parent session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "event_ids": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["request_id", "event_ids"],
            "additionalProperties": False,
        },
    },
    {
        "name": "read_brief",
        "description": "Read the structured brief and assignment view for the caller or a managed child session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "read_context",
        "description": "Read the shared context snapshot and note entries for the family.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "revision": {"type": "integer"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "submit_note",
        "description": "Submit an immutable note entry to the parent's shared notes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["request_id", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "update_shared_context",
        "description": "Update the parent's shared context markdown using optimistic concurrency (expected_revision).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "expected_revision": {"type": "integer"},
                "content": {"type": "string"},
            },
            "required": ["request_id", "expected_revision", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "dismiss_task",
        "description": "Dismiss a pending proposal that has not yet been started.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "proposal_id": {"type": "string"},
            },
            "required": ["request_id", "proposal_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "set_session_status",
        "description": "Transition a session's logical node_status between active, paused, and done.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "session_id": {"type": "string"},
                "status": {"type": "string", "enum": ["active", "paused", "done"]},
                "expected_revision": {"type": "integer"},
            },
            "required": ["request_id", "session_id", "status", "expected_revision"],
            "additionalProperties": False,
        },
    },
    {
        "name": "archive_session",
        "description": "Archive an idle session node with no active executor or pending startup.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "session_id": {"type": "string"},
                "expected_revision": {"type": "integer"},
            },
            "required": ["request_id", "session_id", "expected_revision"],
            "additionalProperties": False,
        },
    },
    {
        "name": "diff_worktree",
        "description": "Read-only diff and merge-eligibility preview for an owned branch worktree.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": 262144, "default": 65536},
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
    },
]


_CONTEXT_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "session_id": ("session_id", "sessionId", "runtime_sid", "runtime_session_id"),
    "turn_id": ("turn_id", "turnId", "runtime_turn_id"),
    "runtime_scope": ("runtime_scope", "runtimeScope"),
    "workspace_path": ("workspace_path", "workspacePath", "cwd"),
    "trace_id": ("trace_id", "traceId"),
}


def _extract_single_field_from_mapping(
    obj: Mapping[str, Any],
    canonical_name: str,
    aliases: tuple[str, ...],
    *,
    source_label: str,
) -> tuple[bool, str | None]:
    """Extract a context field from a mapping, checking internal alias consistency and string type."""
    found_any = False
    resolved_val: str | None = None

    for key in aliases:
        if key not in obj:
            continue
        found_any = True
        raw_val = obj[key]
        if raw_val is None:
            norm_val: str | None = None
        elif isinstance(raw_val, str):
            stripped = normalize_text(raw_val, strip=True)
            if not stripped and canonical_name == "session_id":
                raise _make_error(
                    ErrorCode.CALLER_UNBOUND,
                    f"{source_label}.{key} cannot be empty",
                    {"field": key, "source": source_label},
                )
            norm_val = stripped if stripped else None
        else:
            raise _make_error(
                ErrorCode.CALLER_CONTEXT_CONFLICT,
                f"{source_label}.{key} must be a string (got {type(raw_val).__name__})",
                {"field": key, "source": source_label, "actual_type": type(raw_val).__name__},
                aliases=("CALLER_IDENTITY_CONFLICT", ErrorCode.INVALID_REQUEST),
            )

        if resolved_val is not None and norm_val is not None and resolved_val != norm_val:
            raise _make_error(
                ErrorCode.CALLER_CONTEXT_CONFLICT,
                f"Conflicting values for {canonical_name} within {source_label}",
                {
                    "field": canonical_name,
                    "source": source_label,
                    "first": resolved_val,
                    "second": norm_val,
                },
                aliases=("CALLER_IDENTITY_CONFLICT",),
            )
        if norm_val is not None:
            resolved_val = norm_val

    return found_any, resolved_val


def _validate_connection(connection: Any) -> str:
    """Validate that `connection` represents a trusted local host stdio connection and return its ID."""
    if connection is None:
        raise _make_error(
            ErrorCode.CALLER_UNBOUND,
            "MCP connection is required; tests must pass an explicit TrustedConnection",
        )
    if isinstance(connection, TrustedConnection):
        if not connection.trusted or not connection.initialized:
            raise _make_error(
                ErrorCode.CALLER_UNBOUND,
                "MCP connection is untrusted or not initialized",
                {"connection_id": connection.connection_id},
            )
        if connection.transport not in ("stdio", "local", "in_memory", "test"):
            raise _make_error(
                ErrorCode.CALLER_UNBOUND,
                f"Unsupported or untrusted MCP transport: {connection.transport}",
                {"transport": connection.transport},
            )
        return connection.connection_id
    if isinstance(connection, Mapping):
        if connection.get("trusted") is False or connection.get("initialized") is False:
            raise _make_error(
                ErrorCode.CALLER_UNBOUND,
                "MCP connection mapping marked untrusted or uninitialized",
            )
        transport = str(connection.get("transport", "stdio"))
        if transport not in ("stdio", "local", "in_memory", "test"):
            raise _make_error(
                ErrorCode.CALLER_UNBOUND,
                f"Unsupported MCP transport: {transport}",
                {"transport": transport},
            )
        return str(connection.get("connection_id") or connection.get("id") or "stdio:mapping")
    if isinstance(connection, str) and connection.strip():
        return connection.strip()
    if getattr(connection, "trusted", True) is False or getattr(connection, "initialized", True) is False:
        raise _make_error(
            ErrorCode.CALLER_UNBOUND,
            "MCP connection object marked untrusted or uninitialized",
        )
    return str(getattr(connection, "connection_id", None) or "stdio:custom")


def caller_from_meta(
    meta: Mapping[str, Any] | None,
    connection: Any = None,
) -> CallerContext:
    """Construct an immutable request-local `CallerContext` strictly from MCP `_meta`.

    Follows Section 5.1 (G01 / G12):
    - Prioritizes `meta["com.zcode/request-context"]`; if the key is present, it MUST be a valid Mapping
      with a non-empty string `session_id` (never falls back to top-level flat fields if the namespace
      entry is malformed or missing `session_id`).
    - If both `com.zcode/request-context` and top-level `meta` provide `session_id`, `turn_id`,
      `runtime_scope`, `workspace_path`, or `trace_id`, their values MUST match; any mismatch raises
      `SideSessionError(CALLER_CONTEXT_CONFLICT / CALLER_IDENTITY_CONFLICT)`.
    - If `session_id` is missing or empty, raises `SideSessionError(ErrorCode.CALLER_UNBOUND)`.
    - Strictly forbids inferring or overriding `runtime_sid` from tool arguments, environment variables, or cwd.
    """
    conn_id = _validate_connection(connection)

    if meta is None or not isinstance(meta, Mapping):
        raise _make_error(
            ErrorCode.CALLER_UNBOUND,
            "Missing or invalid MCP request _meta; cannot bind caller identity",
        )

    # Unwrap outer `{"_meta": ...}` only if someone passed `params` directly and no context keys are at top level
    effective_meta: Mapping[str, Any] = meta
    if (
        REQUEST_CONTEXT_NAMESPACE not in effective_meta
        and not any(k in effective_meta for aliases in _CONTEXT_FIELD_ALIASES.values() for k in aliases)
        and isinstance(effective_meta.get("_meta"), Mapping)
    ):
        effective_meta = effective_meta["_meta"]

    has_ns = REQUEST_CONTEXT_NAMESPACE in effective_meta
    ns_obj: Mapping[str, Any] | None = None

    if has_ns:
        raw_ns = effective_meta[REQUEST_CONTEXT_NAMESPACE]
        if not isinstance(raw_ns, Mapping):
            raise _make_error(
                ErrorCode.CALLER_CONTEXT_CONFLICT,
                f"'{REQUEST_CONTEXT_NAMESPACE}' in _meta must be a JSON object",
                {"namespace": REQUEST_CONTEXT_NAMESPACE, "actual_type": type(raw_ns).__name__},
                aliases=("CALLER_IDENTITY_CONFLICT", ErrorCode.CALLER_UNBOUND, ErrorCode.INVALID_REQUEST),
            )
        ns_obj = raw_ns

    top_values: dict[str, tuple[bool, str | None]] = {}
    ns_values: dict[str, tuple[bool, str | None]] = {}

    for field_name, aliases in _CONTEXT_FIELD_ALIASES.items():
        top_values[field_name] = _extract_single_field_from_mapping(
            effective_meta,
            field_name,
            aliases,
            source_label="_meta",
        )
        if ns_obj is not None:
            ns_values[field_name] = _extract_single_field_from_mapping(
                ns_obj,
                field_name,
                aliases,
                source_label=f"_meta['{REQUEST_CONTEXT_NAMESPACE}']",
            )

    if ns_obj is not None:
        # Namespace is present: Check conflicts between namespace and top-level fields first
        for field_name in _CONTEXT_FIELD_ALIASES:
            top_present, top_val = top_values[field_name]
            ns_present, ns_val = ns_values[field_name]
            if top_present and ns_present and top_val != ns_val:
                raise _make_error(
                    ErrorCode.CALLER_CONTEXT_CONFLICT,
                    f"Caller context conflict on '{field_name}' between '{REQUEST_CONTEXT_NAMESPACE}' ({ns_val!r}) and top-level _meta ({top_val!r})",
                    {
                        "field": field_name,
                        "namespace_value": ns_val,
                        "top_level_value": top_val,
                    },
                    aliases=("CALLER_IDENTITY_CONFLICT",),
                )

        # Namespace is primary and must contain a valid non-empty session_id (no fallback to flat if missing)
        _ns_sid_present, ns_sid = ns_values["session_id"]
        if not ns_sid:
            top_sid_present, top_sid = top_values["session_id"]
            if top_sid_present and top_sid:
                raise _make_error(
                    ErrorCode.CALLER_CONTEXT_CONFLICT,
                    f"'{REQUEST_CONTEXT_NAMESPACE}' is present but missing 'session_id'; refusing to fall back to flat _meta",
                    {"namespace": REQUEST_CONTEXT_NAMESPACE, "top_level_session_id": top_sid},
                    aliases=("CALLER_IDENTITY_CONFLICT", ErrorCode.CALLER_UNBOUND),
                )
            raise _make_error(
                ErrorCode.CALLER_UNBOUND,
                f"Missing required 'session_id' in _meta['{REQUEST_CONTEXT_NAMESPACE}']",
                {"namespace": REQUEST_CONTEXT_NAMESPACE},
            )

        session_id = ns_sid
        turn_id = ns_values["turn_id"][1] if ns_values["turn_id"][0] else top_values["turn_id"][1]
        runtime_scope = (
            ns_values["runtime_scope"][1]
            if ns_values["runtime_scope"][0]
            else top_values["runtime_scope"][1]
        )
        workspace_path = (
            ns_values["workspace_path"][1]
            if ns_values["workspace_path"][0]
            else top_values["workspace_path"][1]
        )
        trace_id = ns_values["trace_id"][1] if ns_values["trace_id"][0] else top_values["trace_id"][1]
    else:
        _top_sid_present, top_sid = top_values["session_id"]
        if not top_sid:
            raise _make_error(
                ErrorCode.CALLER_UNBOUND,
                "Missing required 'session_id' in MCP _meta",
            )
        session_id = top_sid
        turn_id = top_values["turn_id"][1]
        runtime_scope = top_values["runtime_scope"][1]
        workspace_path = top_values["workspace_path"][1]
        trace_id = top_values["trace_id"][1]

    return CallerContext(
        runtime_sid=session_id,
        runtime_turn_id=turn_id,
        runtime_scope=runtime_scope,
        workspace_path=workspace_path,
        trace_id=trace_id,
        connection_id=conn_id,
        node_id=None,
    )


def _format_mcp_tool_response(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Wrap an Engine response or structured error dict into an MCP `tools/call` result."""
    norm_payload = dict(payload)
    is_ok = bool(norm_payload.get("ok", True))
    norm_payload["ok"] = is_ok

    serialized = json.dumps(norm_payload, ensure_ascii=False, sort_keys=True)
    mcp_content = [{"type": "text", "text": serialized}]

    out: dict[str, Any] = {}
    for k, v in norm_payload.items():
        if k == "content":
            # Preserve string content under `text` as well as inside `structuredContent["content"]`
            if isinstance(v, str) and "text" not in norm_payload:
                out["text"] = v
            continue
        out[k] = v

    out["content"] = mcp_content
    out["structuredContent"] = norm_payload
    out["isError"] = not is_ok
    return out


def _extract_tool_invocation(
    raw_request: Mapping[str, Any],
) -> tuple[str, Mapping[str, Any], Mapping[str, Any] | None]:
    """Extract `(tool_name, arguments, meta)` from either a full JSON-RPC request or a `params` dict."""
    if not isinstance(raw_request, Mapping):
        raise _make_error(ErrorCode.INVALID_REQUEST, "MCP tool call request must be a JSON object")

    params_obj = raw_request.get("params")
    if isinstance(params_obj, Mapping):
        container: Mapping[str, Any] = params_obj
        top_meta = raw_request.get("_meta")
    else:
        container = raw_request
        top_meta = None

    raw_name = container.get("name") if "name" in container else container.get("tool")
    if not isinstance(raw_name, str) or not raw_name.strip():
        raise _make_error(
            ErrorCode.INVALID_REQUEST,
            "Tool call requires a non-empty string 'name'",
            {"field": "name"},
        )
    tool_name = raw_name.strip()

    raw_args = container.get("arguments") if "arguments" in container else container.get("args")
    if raw_args is None:
        arguments: Mapping[str, Any] = {}
    elif isinstance(raw_args, Mapping):
        arguments = raw_args
    else:
        raise _make_error(
            ErrorCode.INVALID_REQUEST,
            "Tool 'arguments' must be a JSON object",
            {"field": "arguments", "actual_type": type(raw_args).__name__},
        )

    # Check if arguments contain forbidden caller identity override fields before routing
    for forbidden_field in FORBIDDEN_CALLER_OVERRIDE_FIELDS:
        if forbidden_field in arguments:
            raise _make_error(
                ErrorCode.UNKNOWN_FIELD,
                f"Caller identity override field '{forbidden_field}' is forbidden in tool arguments",
                {"field": forbidden_field, "tool": tool_name},
            )

    param_meta = container.get("_meta")
    if param_meta is not None and not isinstance(param_meta, Mapping):
        raise _make_error(
            ErrorCode.CALLER_UNBOUND,
            "params._meta must be a JSON object when provided",
            {"actual_type": type(param_meta).__name__},
        )
    if top_meta is not None and not isinstance(top_meta, Mapping):
        raise _make_error(
            ErrorCode.CALLER_UNBOUND,
            "top-level _meta must be a JSON object when provided",
            {"actual_type": type(top_meta).__name__},
        )

    if isinstance(param_meta, Mapping) and isinstance(top_meta, Mapping):
        # Verify no conflict between top-level _meta and params._meta
        merged_meta = dict(top_meta)
        for k, v in param_meta.items():
            if k in merged_meta and merged_meta[k] != v:
                raise _make_error(
                    ErrorCode.CALLER_CONTEXT_CONFLICT,
                    f"Conflicting _meta key '{k}' between top-level request and params._meta",
                    {"key": k},
                    aliases=("CALLER_IDENTITY_CONFLICT",),
                )
            merged_meta[k] = v
        meta: Mapping[str, Any] | None = merged_meta
    elif isinstance(param_meta, Mapping):
        meta = param_meta
    elif isinstance(top_meta, Mapping):
        meta = top_meta
    elif isinstance(arguments.get("_meta"), Mapping):
        # Never allow caller identity to be smuggled inside tool `arguments._meta`
        raise _make_error(
            ErrorCode.UNKNOWN_FIELD,
            "Field '_meta' is not allowed inside tool arguments; pass '_meta' on params",
            {"field": "_meta", "tool": tool_name},
            aliases=(ErrorCode.CALLER_UNBOUND,),
        )
    else:
        meta = None

    return tool_name, arguments, meta


try:
    from .worker_kick import WorkerKicker
except ImportError:  # pragma: no cover
    from worker_kick import WorkerKicker  # type: ignore


def _get_or_create_engine(engine: Any = None) -> tuple[Any, bool]:
    if engine is not None:
        _ensure_compat_row_factory(engine)
        return engine, False
    try:
        from .engine import Engine
    except ImportError:  # pragma: no cover
        from engine import Engine  # type: ignore
    root = resolve_state_root()
    store = open_store(root, writable=True)
    _ensure_compat_row_factory(store)
    return Engine(
        store,
        runtime_execution="deferred",
        driver=ZCodeDriver(),
        supervisor_port=WorkerKicker(root),
    ), True


def handle_tool_call(
    raw_request: Mapping[str, Any],
    connection: Any = None,
    *,
    engine: Any = None,
) -> dict[str, Any]:
    """Handle an MCP `tools/call` request, bind `CallerContext` from `_meta`, and invoke `Engine`."""
    eng = None
    should_close = False
    try:
        tool_name, arguments, meta = _extract_tool_invocation(raw_request)
        caller = caller_from_meta(meta, connection=connection)

        if tool_name not in ALLOWED_ENGINE_TOOLS:
            raise _make_error(
                ErrorCode.INVALID_REQUEST,
                f"Unknown or unexposed MCP tool: {tool_name}",
                {"tool": tool_name},
            )

        eng, should_close = _get_or_create_engine(engine)
        handler = getattr(eng, tool_name, None)
        if not callable(handler):
            raise _make_error(
                ErrorCode.CAPABILITY_UNAVAILABLE,
                f"Engine method '{tool_name}' is not available",
                {"tool": tool_name},
            )

        raw_result = handler(caller, dict(arguments))
        if hasattr(raw_result, "to_dict") and callable(raw_result.to_dict):
            payload = dict(raw_result.to_dict())
        elif isinstance(raw_result, Mapping):
            payload = dict(raw_result)
        else:
            payload = {"ok": True, "result": raw_result}

        payload.setdefault("ok", True)
        return _format_mcp_tool_response(payload)

    except SideSessionError as exc:
        err_payload = exc.to_dict()
        return _format_mcp_tool_response(err_payload)
    except Exception as exc:
        fallback_err = SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"Unhandled error in tool call: {exc}",
            {"exception_type": type(exc).__name__},
            retryable=False,
        )
        return _format_mcp_tool_response(fallback_err.to_dict())
    finally:
        if should_close and eng is not None and hasattr(eng, "store"):
            try:
                eng.store.close()
            except Exception:
                pass


def handle_rpc_message(
    message: Mapping[str, Any],
    connection: TrustedConnection | Any = None,
    *,
    engine: Any = None,
) -> dict[str, Any] | None:
    """Process a single JSON-RPC 2.0 request or notification and return the response dict (or None)."""
    if not isinstance(message, Mapping):
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32600, "message": "Invalid Request: expected JSON object"},
        }

    has_id = "id" in message and message.get("id") is not None
    req_id = message.get("id")
    method = message.get("method")
    params = message.get("params") if isinstance(message.get("params"), Mapping) else {}

    if not isinstance(method, str) or not method.strip():
        if not has_id:
            return None
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32600, "message": "Invalid Request: missing method"},
        }

    method_name = method.strip()

    if method_name == "initialize":
        req_proto = params.get("protocolVersion")
        proto_ver = str(req_proto) if isinstance(req_proto, str) and req_proto.strip() else DEFAULT_MCP_PROTOCOL_VERSION
        if isinstance(connection, TrustedConnection):
            connection.protocol_version = proto_ver
            if isinstance(params.get("clientInfo"), Mapping):
                connection.client_info = dict(params["clientInfo"])
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": proto_ver,
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                    "engineSchemaVersion": ENGINE_SCHEMA_VERSION,
                    "driverApiVersion": DRIVER_API_VERSION,
                },
            },
        }

    if method_name in ("notifications/initialized", "initialized"):
        if isinstance(connection, TrustedConnection):
            connection.initialized = True
        if has_id:
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}
        return None

    if method_name == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method_name in ("tools/call", "tools/list"):
        if isinstance(connection, TrustedConnection) and not connection.initialized:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32600, "message": "MCP connection is not initialized"},
            }

    if method_name == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": TOOL_DEFINITIONS,
            },
        }

    if method_name == "tools/call":
        tool_res = handle_tool_call(message, connection=connection, engine=engine)
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": tool_res,
        }

    if method_name.startswith("notifications/"):
        return None

    if not has_id:
        return None

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {
            "code": -32601,
            "message": f"Method not found: {method_name}",
        },
    }


class _StdioParseError(ValueError):
    def __init__(self, message: str, *, framing: str | None = None) -> None:
        super().__init__(message)
        self.framing = framing


def _read_next_stdio_frame(stream: Any) -> tuple[dict[str, Any] | None, str]:
    """Read a single JSON-RPC message supporting both line-delimited JSON and `Content-Length` headers.

    Returns `(parsed_dict_or_none, framing_mode)` where `framing_mode` is `'line'` or `'content-length'`.
    """
    while True:
        raw_line = stream.readline()
        if not raw_line:
            return None, "line"

        line_str = raw_line.decode("utf-8", errors="replace") if isinstance(raw_line, (bytes, bytearray)) else str(raw_line)
        stripped = line_str.strip()
        if not stripped:
            continue

        if stripped.startswith("{") or stripped.startswith("["):
            try:
                parsed = json.loads(stripped)
            except Exception as exc:
                raise _StdioParseError(f"Invalid JSON line: {exc}", framing="line") from exc
            if not isinstance(parsed, Mapping):
                raise _StdioParseError("JSON-RPC message must be a JSON object", framing="line")
            return dict(parsed), "line"

        # Parse HTTP-like headers (Content-Length: <N>)
        headers: dict[str, str] = {}
        if ":" in stripped:
            k, v = stripped.split(":", 1)
            headers[k.strip().lower()] = v.strip()

        while True:
            hdr_line = stream.readline()
            if not hdr_line:
                break
            hdr_str = hdr_line.decode("utf-8", errors="replace") if isinstance(hdr_line, (bytes, bytearray)) else str(hdr_line)
            hdr_stripped = hdr_str.strip()
            if not hdr_stripped:
                break
            if ":" in hdr_stripped:
                hk, hv = hdr_stripped.split(":", 1)
                headers[hk.strip().lower()] = hv.strip()

        if "content-length" not in headers:
            raise ValueError(f"Unrecognized MCP stdio frame header: {stripped!r}")

        content_length = int(headers["content-length"])
        if content_length < 0:
            raise ValueError(f"Invalid Content-Length: {content_length}")

        chunks: list[bytes] = []
        remaining = content_length
        while remaining > 0:
            chunk = stream.read(remaining)
            if not chunk:
                break
            if isinstance(chunk, str):
                chunk_bytes = chunk.encode("utf-8")
            else:
                chunk_bytes = bytes(chunk)
            chunks.append(chunk_bytes)
            remaining -= len(chunk_bytes)

        body_bytes = b"".join(chunks)
        if remaining > 0:
            raise _StdioParseError(
                f"Incomplete Content-Length body: expected {content_length} bytes",
                framing="content-length",
            )
        try:
            parsed = json.loads(body_bytes.decode("utf-8", errors="replace"))
        except Exception as exc:
            raise _StdioParseError(f"Invalid JSON body: {exc}", framing="content-length") from exc
        if not isinstance(parsed, Mapping):
            raise _StdioParseError("JSON-RPC message body must be a JSON object", framing="content-length")
        return dict(parsed), "content-length"


def _write_stdio_frame(stream: Any, payload: Mapping[str, Any], *, framing: str = "line") -> None:
    """Write a JSON-RPC response using either line-delimited JSON or `Content-Length` framing."""
    body_str = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    body_bytes = body_str.encode("utf-8")

    if framing == "content-length":
        header_str = f"Content-Length: {len(body_bytes)}\r\n\r\n"
        frame_bytes = header_str.encode("ascii") + body_bytes
        frame_str = header_str + body_str
    else:
        frame_bytes = body_bytes + b"\n"
        frame_str = body_str + "\n"

    if isinstance(stream, io.TextIOBase) and not hasattr(stream, "buffer"):
        stream.write(frame_str)
        stream.flush()
        return

    target = getattr(stream, "buffer", stream)
    try:
        target.write(frame_bytes)
    except TypeError:
        stream.write(frame_str)
    target.flush()
    if target is not stream:
        try:
            stream.flush()
        except Exception:
            pass


class MCPServer:
    """Stdio MCP server instance binding an `Engine` and `TrustedConnection`."""

    def __init__(
        self,
        engine: Any = None,
        *,
        connection: TrustedConnection | None = None,
    ) -> None:
        self.engine = engine
        self.connection = connection or TrustedConnection()

    def handle_tool_call(self, raw_request: Mapping[str, Any]) -> dict[str, Any]:
        return handle_tool_call(raw_request, connection=self.connection, engine=self.engine)

    def handle_message(self, message: Mapping[str, Any]) -> dict[str, Any] | None:
        return handle_rpc_message(message, connection=self.connection, engine=self.engine)

    def serve_stdio(
        self,
        stdin: BinaryIO | TextIO | None = None,
        stdout: BinaryIO | TextIO | None = None,
        stderr: TextIO | None = None,
    ) -> None:
        serve_stdio(stdin=stdin, stdout=stdout, stderr=stderr, engine=self.engine, connection=self.connection)


def serve_stdio(
    stdin: BinaryIO | TextIO | None = None,
    stdout: BinaryIO | TextIO | None = None,
    stderr: TextIO | None = None,
    *,
    engine: Any = None,
    connection: TrustedConnection | None = None,
) -> None:
    """Run the synchronous MCP JSON-RPC 2.0 server loop over stdio."""
    raw_stdin = sys.stdin if stdin is None else stdin
    raw_stdout = sys.stdout if stdout is None else stdout
    err_stream = sys.stderr if stderr is None else stderr

    in_stream = getattr(raw_stdin, "buffer", raw_stdin)
    conn = connection or TrustedConnection()
    eng, should_close = _get_or_create_engine(engine)

    try:
        while True:
            identified_framing: str | None = None
            try:
                msg, framing = _read_next_stdio_frame(in_stream)
                identified_framing = framing
            except Exception as exc:
                identified_framing = getattr(exc, "framing", None)
                try:
                    err_stream.write(f"[side-sessions mcp_server] Frame parse error: {exc}\n")
                    err_stream.flush()
                except Exception:
                    pass
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
                if identified_framing in ("line", "content-length"):
                    _write_stdio_frame(raw_stdout, err_resp, framing=identified_framing)
                continue

            if msg is None:
                break

            resp = handle_rpc_message(msg, connection=conn, engine=eng)
            if resp is not None:
                _write_stdio_frame(raw_stdout, resp, framing=framing)
    finally:
        if should_close and eng is not None and hasattr(eng, "store"):
            try:
                eng.store.close()
            except Exception:
                pass


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `mcp_server.py`."""
    _ = argv
    serve_stdio()
    return 0


__all__ = [
    "ALLOWED_ENGINE_TOOLS",
    "DEFAULT_MCP_PROTOCOL_VERSION",
    "MCPServer",
    "REQUEST_CONTEXT_NAMESPACE",
    "SERVER_NAME",
    "SERVER_VERSION",
    "TOOL_DEFINITIONS",
    "TrustedConnection",
    "caller_from_meta",
    "handle_rpc_message",
    "handle_tool_call",
    "main",
    "serve_stdio",
]


if __name__ == "__main__":
    raise SystemExit(main())
