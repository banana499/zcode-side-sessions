"""Data contracts, strict schema validation, normalization, and error types for side-sessions."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Iterator, Mapping
import unicodedata
import uuid

ENGINE_SCHEMA_VERSION = "1.2"
DRIVER_API_VERSION = "1.1"
EXPORT_SCHEMA_VERSION = "1.1"
FORMATTER_VERSION = "1.1"
SSREF_PREFIX = "ssref:v1"

MAX_PROMPT_CHARS = 65536
MAX_BACKGROUND_CHARS = 32768
MIN_FRESH_BACKGROUND_CHARS = 80
MAX_TITLE_CHARS = 160
MAX_RECAP_CHARS = 400
MAX_HOOK_CONTEXT_BYTES = 8192
MAX_HOOK_EVENTS = 16
MAX_ACK_EVENTS = 64
MAX_EVENT_PAGE_LIMIT = 64
MAX_ARTIFACT_CHUNK_BYTES = 65536
DEFAULT_ARTIFACT_CHUNK_BYTES = 32768
MAX_SLOTS_PER_PARENT = 4
MAX_WAKE_BUDGET_PER_EPOCH = 10

SHORT_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
NAME_DISPLAY_MAX_CODEPOINTS = 24
RESERVED_NAMES = frozenset({"parent", "root", "self", "none"})
VALID_SSREF_KINDS = frozenset({"report", "artifact", "event", "context_snapshot"})
VALID_HOOK_EVENTS = frozenset({
    "SessionStart",
    "UserPromptSubmit",
    "PostToolUse",
    "PreToolUse",
    "Stop",
})
FORBIDDEN_CALLER_OVERRIDE_FIELDS = frozenset({
    "caller_sid",
    "caller_session_id",
    "caller_node_id",
    "actor_node_id",
    "parent_runtime_sid",
    "parent_sid",
})

READ_ONLY_CONTROL_ALLOWLIST = frozenset({
    "read_brief",
    "read_context",
    "list_events",
    "get_event",
    "read_report",
    "read_artifact",
    "get_session",
    "get_operation",
    "get_task",
    "get_current_task",
    "list_tasks",
    "list_waits",
    "get_control",
    "get_dispatch_group",
    "report_child_turn",
    "ack_events",
    "publish_artifact",
    "diff_worktree",
})

CLI_SESSION_MODES = frozenset({"plan", "build", "edit", "yolo", "guarded", "auto"})
MCP_TOOL_PREFIX = "mcp__side_sessions__"
MCP_PLUGIN_TOOL_PREFIX = "mcp__plugin_side-sessions_side_sessions__"
READ_ONLY_BUILTIN_TOOLS = ("Read", "Glob", "Grep")
READ_ONLY_DENYLIST = (
    "Write",
    "Edit",
    "Bash",
    "Agent",
    "Task",
    "CreateWorkflow",
    "AmendWorkflow",
    "ApplyPatch",
    "NotebookEdit",
    "CronCreate",
    "ExitPlanMode",
)
MAX_FULL_REPORT_CHARS = 32768
MAX_FALLBACK_LAST_TEXT_CHARS = 32768


@dataclass(frozen=True)
class RuntimeProfile:
    mode: str
    tool_allowlist: tuple[str, ...] | None
    tool_denylist: tuple[str, ...]
    require_branch_worktree: bool


def runtime_profile_for_task_kind(task_kind: str) -> RuntimeProfile:
    if task_kind == "read_only":
        sorted_ctrl = sorted(READ_ONLY_CONTROL_ALLOWLIST)
        allow = (
            READ_ONLY_BUILTIN_TOOLS
            + tuple(MCP_TOOL_PREFIX + t for t in sorted_ctrl)
            + tuple(MCP_PLUGIN_TOOL_PREFIX + t for t in sorted_ctrl)
        )
        return RuntimeProfile("plan", allow, READ_ONLY_DENYLIST, False)
    if task_kind == "write_code":
        return RuntimeProfile("build", None, ("CreateWorkflow", "AmendWorkflow"), True)
    raise SideSessionError(ErrorCode.INVALID_REQUEST, f"unknown task_kind {task_kind!r}")


class ErrorCode(str, Enum):
    """Canonical error codes for side-sessions."""

    INVALID_REQUEST = "INVALID_REQUEST"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    SCHEMA_ERROR = "SCHEMA_ERROR"
    INVALID_NAME = "INVALID_NAME"
    RESERVED_NAME = "RESERVED_NAME"
    BACKGROUND_TOO_SHORT = "BACKGROUND_TOO_SHORT"
    INVALID_BACKGROUND = "INVALID_BACKGROUND"
    INVALID_TASK_WORKSPACE = "INVALID_TASK_WORKSPACE"
    CALLER_UNBOUND = "CALLER_UNBOUND"
    CALLER_CONTEXT_CONFLICT = "CALLER_CONTEXT_CONFLICT"
    STATE_ROOT_MISMATCH = "STATE_ROOT_MISMATCH"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    READ_ONLY_STORE = "READ_ONLY_STORE"
    RETRY_LATER = "RETRY_LATER"
    REVISION_CONFLICT = "REVISION_CONFLICT"
    REQUEST_ID_CONFLICT = "REQUEST_ID_CONFLICT"
    MESSAGE_ID_CONFLICT = "MESSAGE_ID_CONFLICT"
    NO_PARENT = "NO_PARENT"
    AMBIGUOUS_SESSION = "AMBIGUOUS_SESSION"
    TOPOLOGY_CORRUPT = "TOPOLOGY_CORRUPT"
    NOT_FOUND = "NOT_FOUND"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND_OR_FORBIDDEN = "NOT_FOUND_OR_FORBIDDEN"
    CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
    USER_INTENT_UNVERIFIED = "USER_INTENT_UNVERIFIED"
    USER_APPROVAL_UNAVAILABLE = "USER_APPROVAL_UNAVAILABLE"
    HUMAN_ACTION_REQUIRED = "HUMAN_ACTION_REQUIRED"
    ALREADY_STARTED = "ALREADY_STARTED"
    ALREADY_DISMISSED = "ALREADY_DISMISSED"
    PROPOSAL_EXPIRED = "PROPOSAL_EXPIRED"
    EXPIRED = "EXPIRED"
    SPAWN_IN_FLIGHT = "SPAWN_IN_FLIGHT"
    SESSION_PAUSED = "SESSION_PAUSED"
    SESSION_DONE = "SESSION_DONE"
    SESSION_ARCHIVED = "SESSION_ARCHIVED"
    SESSION_BUSY = "SESSION_BUSY"
    TASK_OWNER_CHANGED = "TASK_OWNER_CHANGED"
    TASK_UNBOUND = "TASK_UNBOUND"
    TURN_ALREADY_BOUND = "TURN_ALREADY_BOUND"
    HANDOFF_GUARD_UNAVAILABLE = "HANDOFF_GUARD_UNAVAILABLE"
    HANDOFF_SCOPE_UNSUPPORTED = "HANDOFF_SCOPE_UNSUPPORTED"
    ARTIFACT_INTEGRITY_ERROR = "ARTIFACT_INTEGRITY_ERROR"
    SOURCE_CHANGED = "SOURCE_CHANGED"
    UNSUPPORTED_CONTEXT_WORKSPACE = "UNSUPPORTED_CONTEXT_WORKSPACE"
    UNSUPPORTED_LIVE_FORK = "UNSUPPORTED_LIVE_FORK"
    CONTEXT_DOWNGRADE_REQUIRES_ACCEPTANCE = "CONTEXT_DOWNGRADE_REQUIRES_ACCEPTANCE"
    CONTEXT_QUALITY_APPROVAL_REQUIRED = "CONTEXT_QUALITY_APPROVAL_REQUIRED"
    CONTEXT_ACCEPTANCE_STALE = "CONTEXT_ACCEPTANCE_STALE"
    SOURCE_SNAPSHOT_STALE = "SOURCE_SNAPSHOT_STALE"
    NOT_GIT_REPO = "NOT_GIT_REPO"
    GIT_HEAD_UNAVAILABLE = "GIT_HEAD_UNAVAILABLE"
    DIRTY_SOURCE = "DIRTY_SOURCE"
    WORKTREE_HOME_INSIDE_SOURCE = "WORKTREE_HOME_INSIDE_SOURCE"
    WORKSPACE_MISMATCH = "WORKSPACE_MISMATCH"
    HOST_PARENT_MISMATCH = "HOST_PARENT_MISMATCH"
    RUNTIME_CONFIG_MISMATCH = "RUNTIME_CONFIG_MISMATCH"
    CAPACITY_EXCEEDED = "CAPACITY_EXCEEDED"
    GROUP_NOT_APPLICABLE = "GROUP_NOT_APPLICABLE"
    GROUP_NOT_OPEN = "GROUP_NOT_OPEN"
    GROUP_SCOPE_MISMATCH = "GROUP_SCOPE_MISMATCH"
    GROUP_FULL = "GROUP_FULL"
    GROUP_INCOMPLETE = "GROUP_INCOMPLETE"
    OWNER_UNCERTAIN = "OWNER_UNCERTAIN"
    OWNERSHIP_CONFLICT = "OWNERSHIP_CONFLICT"
    WAIT_ALREADY_RESPONDED = "WAIT_ALREADY_RESPONDED"
    WAIT_STALE = "WAIT_STALE"
    WAIT_RESPONSE_UNAVAILABLE = "WAIT_RESPONSE_UNAVAILABLE"
    CANCEL_OWNER_UNAVAILABLE = "CANCEL_OWNER_UNAVAILABLE"
    MESSAGE_IN_FLIGHT = "MESSAGE_IN_FLIGHT"
    REPORT_TURN_UNBOUND = "REPORT_TURN_UNBOUND"
    REPORT_CONFLICT = "REPORT_CONFLICT"
    UNSAFE_PATH = "UNSAFE_PATH"
    SYMLINK_FORBIDDEN = "SYMLINK_FORBIDDEN"
    PATH_ESCAPE = "PATH_ESCAPE"
    LOCK_BUSY = "LOCK_BUSY"
    LOCK_REPLACED = "LOCK_REPLACED"
    APPROVAL_REPLAYED = "APPROVAL_REPLAYED"
    STALE_PREVIEW = "STALE_PREVIEW"
    BASELINE_UNAVAILABLE = "BASELINE_UNAVAILABLE"


_DEFAULT_CODE_ALIASES: dict[str, tuple[str, ...]] = {
    "SYMLINK_FORBIDDEN": ("PATH_SECURITY_VIOLATION", "UNSAFE_PATH"),
    "PATH_ESCAPE": ("PATH_SECURITY_VIOLATION", "UNSAFE_PATH"),
    "UNSAFE_PATH": ("PATH_SECURITY_VIOLATION",),
    "CALLER_CONTEXT_CONFLICT": ("CALLER_IDENTITY_CONFLICT",),
    "HOOK_IDENTITY_MISMATCH": ("CALLER_CONTEXT_CONFLICT", "CALLER_IDENTITY_CONFLICT", "INVALID_REQUEST"),
    "BACKGROUND_TOO_SHORT": ("INVALID_ARGUMENT", "INVALID_BACKGROUND"),
    "INVALID_BACKGROUND": ("INVALID_ARGUMENT",),
    "INVALID_REQUEST": ("INVALID_ARGUMENT",),
    "VALIDATION_ERROR": ("INVALID_ARGUMENT",),
    "PROPOSAL_EXPIRED": ("EXPIRED",),
}


class _ErrorCodeStr(str):
    """String subclass matching primary error code and standard compatibility aliases."""

    def __new__(cls, primary: str, *extra_aliases: str) -> _ErrorCodeStr:
        obj = super().__new__(cls, primary)
        defaults = _DEFAULT_CODE_ALIASES.get(primary, ())
        obj._aliases = frozenset({primary, *defaults, *(str(a) for a in extra_aliases if a)})
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


for _alias_name, _target in (
    ("CALLER_IDENTITY_CONFLICT", ErrorCode.CALLER_CONTEXT_CONFLICT),
    ("PATH_SECURITY_VIOLATION", ErrorCode.SYMLINK_FORBIDDEN),
    ("INVALID_ARGUMENT", ErrorCode.INVALID_REQUEST),
):
    if not hasattr(ErrorCode, _alias_name):
        try:
            setattr(ErrorCode, _alias_name, _target)
        except Exception:
            pass


class SideSessionError(Exception):
    """Structured error adhering to section 2.1 error contract."""

    def __init__(
        self,
        code: str | ErrorCode,
        message: str,
        details: Mapping[str, Any] | None = None,
        retryable: bool = False,
    ) -> None:
        code_str = code.value if isinstance(code, Enum) else str(code)
        super().__init__(f"[{code_str}] {message}")
        self.code: str = _ErrorCodeStr(code_str)
        self.message: str = message
        self.details: dict[str, Any] = dict(details) if details else {}
        self.retryable: bool = bool(retryable)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details,
            },
            "retryable": self.retryable,
        }


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_text(text: str, *, strip: bool = True) -> str:
    """Normalize string to Unicode NFC, unify line endings to LF, and optionally strip."""
    if not isinstance(text, str):
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"Expected string, got {type(text).__name__}",
        )
    s = unicodedata.normalize("NFC", text)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    return s.strip() if strip else s


def _normalize_json_value(val: Any) -> Any:
    if isinstance(val, str):
        return normalize_text(val, strip=False)
    if isinstance(val, Mapping):
        return {normalize_text(str(k), strip=False): _normalize_json_value(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [_normalize_json_value(v) for v in val]
    if dataclasses.is_dataclass(val) and not isinstance(val, type):
        return _normalize_json_value(dataclasses.asdict(val))
    if isinstance(val, Enum):
        return val.value
    return val


def canonical_json(obj: Any) -> str:
    """Serialize object to deterministic canonical JSON (UTF-8, sorted keys, no extra spaces)."""
    normalized = _normalize_json_value(obj)
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize object to deterministic canonical JSON UTF-8 bytes."""
    return canonical_json(obj).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    """Compute hex SHA-256 of bytes or UTF-8 string."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def canonical_json_sha256(obj: Any) -> str:
    """Compute hex SHA-256 of canonical JSON representation."""
    return sha256_hex(canonical_json_bytes(obj))


def format_recap_400(text: str) -> str:
    """Format recap into at most 400 Unicode code points with newlines replaced by ' ⏎ '."""
    normalized = normalize_text(text, strip=True)
    single_line = normalized.replace("\n", " ⏎ ")
    return single_line[:MAX_RECAP_CHARS]


def validate_uuid(value: Any, field_name: str = "id") -> str:
    """Validate that value is a non-empty string UUID (or canonicalize UUID string)."""
    if not isinstance(value, str) or not value.strip():
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"{field_name} must be a non-empty UUID string",
            {"field": field_name},
        )
    raw = value.strip()
    try:
        parsed = uuid.UUID(raw)
    except ValueError as exc:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"{field_name} is not a valid UUID: {raw}",
            {"field": field_name, "value": raw},
        ) from exc
    return str(parsed)


def validate_short_name(name: Any, *, allow_extended: bool = False) -> str:
    """Validate short session name against `[a-z][a-z0-9-]{0,47}` and reserved names.

    `allow_extended` is accepted for compatibility but no longer selects a different pattern.
    The 24-code-point bound is only a display truncation hint (`NAME_DISPLAY_MAX_CODEPOINTS`).
    """
    if not isinstance(name, str):
        raise SideSessionError(
            ErrorCode.INVALID_NAME,
            "Session name must be a string",
            {"name": name},
        )
    cleaned = normalize_text(name, strip=True)
    if not cleaned:
        raise SideSessionError(
            ErrorCode.INVALID_NAME,
            "Session name cannot be empty",
            {"name": name},
        )
    if cleaned in RESERVED_NAMES:
        raise SideSessionError(
            ErrorCode.RESERVED_NAME,
            f"Session name '{cleaned}' is reserved",
            {"name": cleaned, "reserved": sorted(RESERVED_NAMES)},
        )
    if not SHORT_NAME_RE.match(cleaned):
        raise SideSessionError(
            ErrorCode.INVALID_NAME,
            f"Session name '{cleaned}' does not match pattern {SHORT_NAME_RE.pattern}",
            {"name": cleaned, "pattern": SHORT_NAME_RE.pattern},
        )
    return cleaned


_SECTION_HEADER_PATTERNS = {
    "overall_goal": re.compile(r"(?:^|\n)\s*总体目标[：:]\s*", re.MULTILINE),
    "decisions": re.compile(r"(?:^|\n)\s*已有决策[：:]\s*", re.MULTILINE),
    "constraints": re.compile(r"(?:^|\n)\s*约束[：:]\s*", re.MULTILINE),
}


def validate_fresh_background(
    background: Any,
    *,
    require_sections: bool = True,
) -> tuple[str, dict[str, str]]:
    """Validate fresh background (>= 80 code points after NFC + strip, <= 32768, and section check)."""
    if not isinstance(background, str):
        raise SideSessionError(
            ErrorCode.INVALID_BACKGROUND,
            "fresh context requires a string background",
            {"field": "background"},
        )
    normalized = normalize_text(background, strip=True)
    code_points = len(normalized)
    if code_points < MIN_FRESH_BACKGROUND_CHARS:
        raise SideSessionError(
            ErrorCode.BACKGROUND_TOO_SHORT,
            f"fresh context background must be at least {MIN_FRESH_BACKGROUND_CHARS} characters after normalization (got {code_points})",
            {"field": "background", "length": code_points, "min_length": MIN_FRESH_BACKGROUND_CHARS},
        )
    if code_points > MAX_BACKGROUND_CHARS:
        raise SideSessionError(
            ErrorCode.INVALID_BACKGROUND,
            f"background exceeds maximum length of {MAX_BACKGROUND_CHARS} characters",
            {"field": "background", "length": code_points, "max_length": MAX_BACKGROUND_CHARS},
        )

    matches = {key: pat.search(normalized) for key, pat in _SECTION_HEADER_PATTERNS.items()}
    has_any_header = any(m is not None for m in matches.values())

    if require_sections or has_any_header:
        missing = [key for key, m in matches.items() if m is None]
        if missing:
            raise SideSessionError(
                ErrorCode.INVALID_BACKGROUND,
                "fresh structured background must contain non-empty '总体目标：', '已有决策：', and '约束：' sections",
                {"missing_sections": missing},
            )
        ordered = sorted(
            ((key, m.start(), m.end()) for key, m in matches.items() if m is not None),
            key=lambda item: item[1],
        )
        sections: dict[str, str] = {}
        for idx, (key, _start, end) in enumerate(ordered):
            next_start = ordered[idx + 1][1] if idx + 1 < len(ordered) else len(normalized)
            body = normalized[end:next_start].strip()
            if not body:
                raise SideSessionError(
                    ErrorCode.INVALID_BACKGROUND,
                    f"fresh structured background section '{key}' cannot be empty",
                    {"empty_section": key},
                )
            sections[key] = body
        return normalized, sections

    raise SideSessionError(
        ErrorCode.INVALID_BACKGROUND,
        "fresh structured background must contain non-empty '总体目标：', '已有决策：', and '约束：' sections",
        {"missing_sections": ["overall_goal", "decisions", "constraints"]},
    )


def format_ssref(store_instance_id: str, kind: str, object_id: str) -> str:
    """Format a logical reference string `ssref:v1:<store_instance_uuid>:<kind>:<object_uuid>`."""
    store_uuid = validate_uuid(store_instance_id, "store_instance_id")
    obj_uuid = validate_uuid(object_id, "object_id")
    if kind not in VALID_SSREF_KINDS:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"Invalid ssref kind: {kind}",
            {"kind": kind},
        )
    return f"{SSREF_PREFIX}:{store_uuid}:{kind}:{obj_uuid}"


def parse_ssref(
    ref: str,
    *,
    expected_store_id: str | None = None,
    expected_kind: str | None = None,
) -> tuple[str, str, str]:
    """Parse and validate `ssref:v1:<store_instance_uuid>:<kind>:<object_uuid>`."""
    if not isinstance(ref, str) or "/" in ref or "\\" in ref or ".." in ref or "?" in ref:
        raise SideSessionError(
            ErrorCode.NOT_FOUND_OR_FORBIDDEN,
            "Invalid or forbidden logical reference",
            {"ref": str(ref)},
        )
    parts = ref.split(":")
    if len(parts) != 5 or f"{parts[0]}:{parts[1]}" != SSREF_PREFIX:
        raise SideSessionError(
            ErrorCode.NOT_FOUND_OR_FORBIDDEN,
            "Malformed logical reference",
            {"ref": ref},
        )
    _, _, store_id, kind, object_id = parts
    try:
        store_uuid = validate_uuid(store_id, "store_instance_id")
        obj_uuid = validate_uuid(object_id, "object_id")
    except SideSessionError as exc:
        raise SideSessionError(
            ErrorCode.NOT_FOUND_OR_FORBIDDEN,
            "Logical reference has invalid UUID component",
            {"ref": ref},
        ) from exc
    if kind not in VALID_SSREF_KINDS:
        raise SideSessionError(
            ErrorCode.NOT_FOUND_OR_FORBIDDEN,
            "Logical reference has unsupported kind",
            {"ref": ref, "kind": kind},
        )
    if expected_store_id is not None and store_uuid != validate_uuid(expected_store_id, "expected_store_id"):
        raise SideSessionError(
            ErrorCode.NOT_FOUND_OR_FORBIDDEN,
            "Logical reference belongs to a different store instance",
            {"ref": ref},
        )
    if expected_kind is not None and kind != expected_kind:
        raise SideSessionError(
            ErrorCode.NOT_FOUND_OR_FORBIDDEN,
            f"Logical reference kind mismatch (expected {expected_kind}, got {kind})",
            {"ref": ref, "expected_kind": expected_kind, "actual_kind": kind},
        )
    return store_uuid, kind, obj_uuid


class _SerializableMixin:
    def to_dict(self) -> dict[str, Any]:
        return _normalize_json_value(dataclasses.asdict(self))


@dataclass(frozen=True)
class CallerContext(_SerializableMixin):
    runtime_sid: str
    runtime_turn_id: str | None = None
    runtime_scope: str | None = None
    workspace_path: str | None = None
    trace_id: str | None = None
    connection_id: str | None = None
    node_id: str | None = None


@dataclass(frozen=True)
class HookContext(_SerializableMixin):
    event: str
    invocation_id: str
    runtime_sid: str
    cwd: str
    raw_input: dict[str, Any] = field(default_factory=dict)
    deadline_at: str = ""
    runtime_turn_id: str | None = None
    stop_hook_active: bool | None = None


class HookOutputDict(dict):
    """Dict subclass supporting both dict key lookup and HookOutput attribute access."""

    @property
    def continue_(self) -> bool | None:
        return self.get("continue")

    @property
    def additionalContext(self) -> str | None:
        return self.get("additionalContext")

    @property
    def hookSpecificOutput(self) -> dict[str, Any] | None:
        return self.get("hookSpecificOutput")

    def to_dict(self) -> dict[str, Any]:
        return dict(self)


@dataclass(frozen=True)
class HookOutput:
    continue_: bool | None = None
    additionalContext: str | None = None
    hookSpecificOutput: dict[str, Any] | None = None

    def to_dict(self) -> HookOutputDict:
        out: dict[str, Any] = {}
        if self.continue_ is not None:
            out["continue"] = self.continue_
        if self.additionalContext is not None:
            out["additionalContext"] = self.additionalContext
        if self.hookSpecificOutput is not None:
            out["hookSpecificOutput"] = self.hookSpecificOutput
        return HookOutputDict(out)


@dataclass(frozen=True)
class WorkspaceSpec(_SerializableMixin):
    node_id: str
    workspace_mode: str
    source_cwd: str
    repo_root: str | None = None
    base_commit: str | None = None
    target_path: str | None = None
    branch: str | None = None
    dirty_policy: str = "reject"
    approved_path_manifest: list[str] | None = None
    name: str | None = None


@dataclass(frozen=True)
class RepoSnapshot(_SerializableMixin):
    source_cwd: str
    is_git_repo: bool
    repo_root: str | None = None
    git_common_dir: str | None = None
    repo_key: str | None = None
    head_commit: str | None = None
    is_dirty: bool = False
    dirty_entries: list[str] = field(default_factory=list)
    porcelain_output: str = ""


@dataclass(frozen=True)
class WorktreeRecord(_SerializableMixin):
    worktree_id: str
    node_id: str
    operation_id: str
    canonical_worktree_path: str
    worktrees_home: str
    workspace_mode: str = "branch"
    repo_key: str | None = None
    repo_root: str | None = None
    base_commit: str | None = None
    branch: str | None = None
    source_patch_hash: str | None = None
    ownership_marker: str | None = None
    state: str = "created"
    last_known_tip: str | None = None
    merged_into_ref: str | None = None
    merged_commit: str | None = None
    merged_tree: str | None = None
    merge_mode: str | None = None
    pre_parent_head: str | None = None
    cleaned_at: str | None = None


@dataclass(frozen=True)
class WorkspaceCheck(_SerializableMixin):
    ok: bool
    canonical_path: str
    workspace_mode: str
    branch: str | None = None
    head_commit: str | None = None
    is_clean: bool = True
    ownership_verified: bool = True
    reason: str | None = None


@dataclass(frozen=True)
class CleanupResult(_SerializableMixin):
    cleaned: bool
    state: str
    canonical_path: str
    branch_removed: bool = False
    reason: str | None = None


@dataclass(frozen=True)
class SourceCutoff(_SerializableMixin):
    source_node_id: str
    source_runtime_sid: str
    trigger_runtime_turn_id: str
    trigger_request_id: str
    owner_id: str
    accepted_input_high_watermark: str
    source_revision: int | None = None
    task_id: str | None = None


@dataclass(frozen=True)
class SourceAnchor(_SerializableMixin):
    status: str
    source_session_id: str
    cutoff: SourceCutoff
    source_revision: int | None = None
    anchor_message_id: str | None = None
    sequence: int | None = None
    anchor_turn_id: str | None = None
    checkpoint_id: str | None = None
    effective_chain_hash: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class HistoryProjection(_SerializableMixin):
    anchor: SourceAnchor
    history_quality: str
    summary: str
    excluded_ranges: list[dict[str, Any]]
    snapshot_hash: str
    formatter_version: str = FORMATTER_VERSION
    effective_chain_ref: str | None = None


@dataclass(frozen=True)
class RunAssignment(_SerializableMixin):
    node_id: str
    runtime_sid: str
    turn_seq: int
    run_id: str
    worker_turn_id: str
    input_id: str
    message_id: str
    parent_node_id: str
    dispatch_group_id: str
    member_id: str
    task_id: str | None
    task_revision: int | None
    owner_epoch: int
    fencing_token: str

    def child_view(self) -> dict[str, Any]:
        """Return view safe for child exposure without fencing_token or owner secret."""
        d = self.to_dict()
        d.pop("fencing_token", None)
        return d


@dataclass(frozen=True)
class RuntimeCreateSpec(_SerializableMixin):
    assignment: RunAssignment
    workspace_path: str
    parent_runtime_sid: str
    mode: str
    model: dict[str, Any]
    tool_allowlist: list[str]
    tool_denylist: list[str]
    additional_directories: list[str] = field(default_factory=list)
    persistence: str = "immediate"
    preallocated_session_id: str = ""
    brief_ref: str = ""
    context_applied: str = "fresh"


@dataclass(frozen=True)
class RuntimeResumeSpec(_SerializableMixin):
    assignment: RunAssignment
    expected_workspace: str
    expected_parent_runtime_sid: str
    mode: str
    model: dict[str, Any]
    tool_allowlist: list[str]
    tool_denylist: list[str]
    additional_directories: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RuntimeHandle(_SerializableMixin):
    runtime_sid: str
    runtime_instance_id: str
    owner_connection_id: str
    snapshot_revision: int
    canonical_workspace: str
    process_identity: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuntimeInput(_SerializableMixin):
    input_id: str
    content: str
    origin: str = "system/side_sessions"
    expected_revision: int | None = None


@dataclass(frozen=True)
class SendReceipt(_SerializableMixin):
    input_id: str
    status: str
    runtime_turn_id: str | None = None
    response_revision: int | None = None
    evidence_ref: str | None = None


@dataclass(frozen=True)
class RuntimeSnapshot(_SerializableMixin):
    runtime_sid: str
    canonical_workspace: str
    model: dict[str, Any]
    mode: str
    status: str
    tool_profile_check: str
    notes_access_check: str
    revision: int
    raw_response_ref: str = ""
    parent_runtime_sid: str | None = None


@dataclass(frozen=True)
class ExitReceipt(_SerializableMixin):
    runtime_instance_id: str
    process_identity: dict[str, Any]
    exit_confirmed: bool
    runtime_outcome: str
    ended_at: str
    exit_code: int | None = None
    evidence_ref: str = ""


@dataclass(frozen=True)
class CapabilityStatus(_SerializableMixin):
    source_supported: bool = False
    integration_verified: bool = False

    @property
    def enabled(self) -> bool:
        return bool(self.source_supported and self.integration_verified)


@dataclass(frozen=True)
class DriverCapabilities(_SerializableMixin):
    host_version: str = "0.17.1"
    protocol_revision: str = "1.1"
    capability_fingerprint: str = "default-conservative-v1.1"
    verified_at: str = ""
    verification_test_id: str = ""
    supports_request_meta: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=True, integration_verified=False)
    )
    supports_async_command_hook: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=True, integration_verified=False)
    )
    async_output_applied: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=False, integration_verified=False)
    )
    supports_live_fork: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=False, integration_verified=False)
    )
    supports_fork_workspace: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=False, integration_verified=False)
    )
    supports_native_fork: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=True, integration_verified=False)
    )
    supports_history_import: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=False, integration_verified=False)
    )
    supports_summary_copy: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=True, integration_verified=False)
    )
    supports_tool_restrictions: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=True, integration_verified=False)
    )
    supports_workspace_write_scope: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=False, integration_verified=False)
    )
    supports_notes_grant: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=True, integration_verified=False)
    )
    supports_human_input_provenance: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=False, integration_verified=False)
    )
    supports_trusted_approval: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=False, integration_verified=False)
    )
    supports_idle_parent_wake: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=False, integration_verified=False)
    )
    supports_history_commit_receipt: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=False, integration_verified=False)
    )
    supports_supervised_survival: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=False, integration_verified=False)
    )
    supports_task_guard: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=False, integration_verified=False)
    )
    supports_wait_response: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=True, integration_verified=False)
    )
    supports_permission_response: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=True, integration_verified=False)
    )
    supports_cancel_run: CapabilityStatus = field(
        default_factory=lambda: CapabilityStatus(source_supported=True, integration_verified=False)
    )

    def is_enabled(self, capability_name: str) -> bool:
        cap = getattr(self, capability_name, None)
        if isinstance(cap, CapabilityStatus):
            return cap.enabled
        if isinstance(cap, bool):
            return cap
        return False


@dataclass(frozen=True)
class StartResult(_SerializableMixin):
    request_id: str
    status: str
    host_link_verified: bool
    revision: int
    proposal_id: str | None = None
    node_id: str | None = None
    runtime_session_id: str | None = None
    operation_id: str | None = None
    context_requested: str | None = None
    context_applied: str | None = None
    history_quality: str | None = None
    snapshot_hash: str | None = None
    workspace_mode: str | None = None


@dataclass(frozen=True)
class ReportReceipt(_SerializableMixin):
    report_id: str
    event_id: str
    node_id: str
    turn_seq: int
    run_id: str
    phase: str
    semantic_sha256: str
    duplicate: bool
    revision: int
    report_revision: int | None = None


@dataclass(frozen=True)
class BriefSnapshot(_SerializableMixin):
    node_id: str
    brief_id: str
    brief_revision: int
    brief_hash: str
    content: str
    context_applied: str
    assignment_view: dict[str, Any]
    source_anchor: dict[str, Any] | None = None


@dataclass(frozen=True)
class ApprovalEvidence(_SerializableMixin):
    approval_id: str
    parent_node_id: str
    real_input_id: str
    purpose: str
    task_hash: str
    approved_at: str
    expires_at: str
    verifier: str
    evidence_ref: str
    command_id: str | None = None
    accepted_context_strategy: str | None = None
    operation_id: str | None = None
    snapshot_hash: str | None = None
    history_quality: str | None = None
    brief_hash: str | None = None
    task_revision: int | None = None
    wait_id: str | None = None
    wait_nonce: str | None = None
    host_request_id: str | None = None
    run_id: str | None = None
    response_hash: str | None = None
    target_id: str | None = None
    target_hash: str | None = None
    preview_hash: str | None = None
    _trusted_token: str = field(default="host_adapter_verified", repr=False)


@dataclass(frozen=True)
class GuardReceipt(_SerializableMixin):
    guard_id: str
    transfer_id: str
    task_id: str
    task_revision: int
    source_runtime_sid: str
    source_runtime_turn_ids: list[str]
    owner_id: str
    scope_digest: str
    state: str
    inflight_action_ids: list[str]
    stable_anchor: dict[str, Any] | None
    host_receipt_id: str
    verified_at: str


@dataclass(frozen=True)
class BoundWait(_SerializableMixin):
    wait_id: str
    node_id: str
    run_id: str
    runtime_turn_id: str | None
    runtime_instance_id: str
    owner_epoch: int
    host_request_id: str
    kind: str
    nonce: str
    question: str
    options: list[Any]
    required_authority: str
    deadline_at: str | None
    state: str


@dataclass(frozen=True)
class ControlReceipt(_SerializableMixin):
    control_id: str
    status: str
    runtime_instance_id: str
    owner_epoch: int
    observed_wait_state: str
    host_receipt_id: str | None = None


@dataclass(frozen=True)
class ArtifactRef(_SerializableMixin):
    ref: str
    sha256: str
    byte_length: int
    media_type: str


@dataclass(frozen=True)
class ExportRef(_SerializableMixin):
    relative_path: str
    absolute_path: str
    sha256: str
    byte_length: int
    revision: int


@dataclass(frozen=True)
class SessionResult(_SerializableMixin):
    node: dict[str, Any]
    revision: int
    current_task_ids: list[str]
    wait_summaries: list[dict[str, Any]]
    pending_event_count: int
    recent_report_refs: list[str]
    operation_summaries: list[dict[str, Any]]
    dispatch_group_summaries: list[dict[str, Any]]
    active_run_id: str | None = None
    latest_report_ref: str | None = None


@dataclass(frozen=True)
class WakeReceipt(_SerializableMixin):
    reservation_id: str
    parent_runtime_sid: str
    actual_owner_id: str
    status: str
    input_id: str | None = None
    runtime_turn_id: str | None = None
    history_receipt: str | None = None


@dataclass(frozen=True)
class TaskScope(_SerializableMixin):
    resource_keys: list[str] = field(default_factory=list)
    write_path_roots: list[str] = field(default_factory=list)
    artifact_source_roots: list[str] = field(default_factory=list)
    tool_profile_hash: str = ""


@dataclass(frozen=True)
class TaskResult(_SerializableMixin):
    task_id: str
    owner_node_id: str
    state: str
    task_revision: int
    title: str
    remaining_plan: str
    task_kind: str
    scope: dict[str, Any]
    last_stable_anchor: dict[str, Any] | None = None
    current_transfer_id: str | None = None


@dataclass(frozen=True)
class DispatchGroupResult(_SerializableMixin):
    dispatch_group_id: str
    parent_node_id: str
    assembly_state: str
    completion_state: str
    expected_members: int
    member_count: int
    revision: int
    members: list[dict[str, Any]]
    preparing_operation_ids: list[str] = field(default_factory=list)
    manifest_ref: str | None = None


@dataclass(frozen=True)
class QueueResult(_SerializableMixin):
    message_id: str
    seq: int
    status: str
    queue_position: int
    node_id: str
    pending_owner: bool = False
    wait_summaries: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class ControlResult(_SerializableMixin):
    control_id: str
    node_id: str
    status: str
    revision: int
    run_id: str | None = None
    wait_id: str | None = None
    error: dict[str, Any] | None = None


@dataclass(frozen=True)
class EventView(_SerializableMixin):
    event_id: str
    event_ref: str
    event_seq: int
    kind: str
    state: str
    dispatch_group_id: str | None
    outcome: str | None
    recap: str
    artifact_refs: list[dict[str, Any]] = field(default_factory=list)
    member_id: str | None = None
    run_id: str | None = None
    report_ref: str | None = None
    report_semantic_sha256: str | None = None
    manifest_ref: str | None = None


@dataclass(frozen=True)
class EventPage(_SerializableMixin):
    items: list[dict[str, Any]]
    next_cursor: str | None
    as_of_revision: int
    high_watermark: int


@dataclass(frozen=True)
class ReportView(_SerializableMixin):
    report_ref: str
    report_id: str
    author_node_id: str
    parent_node_id: str
    run_id: str
    turn_seq: int
    phase: str
    report_revision: int | None
    semantic_fields: dict[str, Any]
    semantic_sha256: str
    full_report_ref: str
    artifact_refs: list[dict[str, Any]]
    integrity_verified: bool = True


@dataclass(frozen=True)
class ArtifactChunk(_SerializableMixin):
    ref: str
    offset: int
    returned_bytes: int
    total_bytes: int
    media_type: str
    sha256: str
    chunk_sha256: str
    data_base64: str
    next_offset: int
    eof: bool


@dataclass(frozen=True)
class CanonicalReport(_SerializableMixin):
    node_id: str
    run_id: str
    turn_seq: int
    worker_turn_id: str
    runtime_turn_id: str | None
    phase: str
    report_revision: int | None
    outcome: str
    blocked: bool
    block_reason: str | None
    recap: str
    full_report: str
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    schema_version: str = ENGINE_SCHEMA_VERSION

    def semantic_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "node_id": self.node_id,
            "run_id": self.run_id,
            "turn_seq": self.turn_seq,
            "worker_turn_id": self.worker_turn_id,
            "runtime_turn_id": self.runtime_turn_id,
            "phase": self.phase,
            "report_revision": None if self.phase == "final" else self.report_revision,
            "outcome": self.outcome,
            "blocked": self.blocked,
            "block_reason": self.block_reason if self.blocked else None,
            "recap": normalize_text(self.recap, strip=True),
            "full_report": normalize_text(self.full_report, strip=True),
            "artifacts": [
                a.to_dict() if hasattr(a, "to_dict") else dict(a)
                for a in self.artifacts
            ],
        }

    def semantic_fields_without_full_report(self) -> dict[str, Any]:
        d = self.semantic_dict()
        d.pop("full_report", None)
        return d

    def semantic_sha256(self) -> str:
        return canonical_json_sha256(self.semantic_dict())


@dataclass(frozen=True)
class CanonicalRequest(_SerializableMixin):
    tool: str
    variant: str
    request_id: str | None
    payload: dict[str, Any]
    normalized_hash: str

    @property
    def kind(self) -> str:
        return self.variant

    @property
    def branch(self) -> str:
        return self.variant

    @property
    def args(self) -> dict[str, Any]:
        return self.payload

    @property
    def data(self) -> dict[str, Any]:
        return self.payload

    def __getitem__(self, key: str) -> Any:
        return self.payload[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.payload.get(key, default)

    def __contains__(self, key: object) -> bool:
        return key in self.payload

    def keys(self) -> Iterator[str]:
        return iter(self.payload.keys())


def _reject_unknown_fields(args: Mapping[str, Any], allowed: set[str] | frozenset[str], context_label: str) -> None:
    for key in args:
        if key in FORBIDDEN_CALLER_OVERRIDE_FIELDS:
            raise SideSessionError(
                ErrorCode.UNKNOWN_FIELD,
                f"Caller identity override field '{key}' is forbidden in {context_label}",
                {"field": key, "context": context_label},
            )
    unknown = sorted(set(args.keys()) - set(allowed))
    if unknown:
        raise SideSessionError(
            ErrorCode.UNKNOWN_FIELD,
            f"Unknown or disallowed field(s) in {context_label}: {', '.join(unknown)}",
            {"unknown_fields": unknown, "context": context_label},
        )


def _require_non_empty_str(
    value: Any,
    field_name: str,
    *,
    max_len: int | None = None,
) -> str:
    if not isinstance(value, str):
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"{field_name} must be a string",
            {"field": field_name},
        )
    normalized = normalize_text(value, strip=True)
    if not normalized:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"{field_name} cannot be empty",
            {"field": field_name},
        )
    if max_len is not None and len(normalized) > max_len:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"{field_name} exceeds maximum length of {max_len} characters",
            {"field": field_name, "length": len(normalized), "max_length": max_len},
        )
    return normalized


def _require_bool(value: Any, field_name: str) -> bool:
    if type(value) is not bool:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"{field_name} must be a boolean",
            {"field": field_name, "actual_type": type(value).__name__},
        )
    return value


def _require_int(
    value: Any,
    field_name: str,
    *,
    min_value: int | None = None,
    max_value: int | None = None,
) -> int:
    if type(value) is not int:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"{field_name} must be an integer",
            {"field": field_name, "actual_type": type(value).__name__},
        )
    if min_value is not None and value < min_value:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"{field_name} must be >= {min_value}",
            {"field": field_name, "value": value, "min_value": min_value},
        )
    if max_value is not None and value > max_value:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"{field_name} must be <= {max_value}",
            {"field": field_name, "value": value, "max_value": max_value},
        )
    return value


def _validate_task_workspace_pair(task_kind: Any, use_worktree: Any) -> tuple[str, bool, str]:
    if task_kind not in ("read_only", "write_code"):
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            "task_kind must be 'read_only' or 'write_code'",
            {"field": "task_kind", "value": task_kind},
        )
    use_wt = _require_bool(use_worktree, "use_worktree")
    if task_kind == "read_only" and use_wt is not False:
        raise SideSessionError(
            ErrorCode.INVALID_TASK_WORKSPACE,
            "task_kind='read_only' requires use_worktree=False (workspace_mode='inherit')",
            {"task_kind": task_kind, "use_worktree": use_wt},
        )
    if task_kind == "write_code" and use_wt is not True:
        raise SideSessionError(
            ErrorCode.INVALID_TASK_WORKSPACE,
            "task_kind='write_code' requires use_worktree=True (workspace_mode='branch')",
            {"task_kind": task_kind, "use_worktree": use_wt},
        )
    workspace_mode = "branch" if use_wt else "inherit"
    return task_kind, use_wt, workspace_mode


def _normalize_start_session(args: Mapping[str, Any]) -> tuple[str, str, dict[str, Any]]:
    has_proposal = "proposal_id" in args
    has_initiation = "initiation" in args

    if has_proposal and has_initiation:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            "start_session cannot specify both 'proposal_id' and 'initiation'",
        )
    if not has_proposal and not has_initiation:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            "start_session requires either 'initiation' or 'proposal_id'",
        )

    if has_proposal:
        # Either ClaimOffer or ClaimFullProposal
        if "prompt" in args or "background" in args:
            _reject_unknown_fields(
                args,
                {"proposal_id", "request_id", "prompt", "background"},
                "start_session(ClaimOffer)",
            )
            if "prompt" not in args or "background" not in args:
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    "ClaimOffer requires both 'prompt' and 'background'",
                )
            proposal_id = validate_uuid(args.get("proposal_id"), "proposal_id")
            request_id = validate_uuid(args.get("request_id"), "request_id")
            prompt = _require_non_empty_str(args.get("prompt"), "prompt", max_len=MAX_PROMPT_CHARS)
            background, background_sections = validate_fresh_background(args.get("background"))
            payload = {
                "proposal_id": proposal_id,
                "request_id": request_id,
                "prompt": prompt,
                "background": background,
                "background_sections": background_sections,
                "context": "fresh",
                "task_kind": "read_only",
                "use_worktree": False,
                "workspace_mode": "inherit",
            }
            return "claim_offer", request_id, payload
        else:
            _reject_unknown_fields(
                args,
                {"proposal_id", "request_id"},
                "start_session(ClaimFullProposal)",
            )
            proposal_id = validate_uuid(args.get("proposal_id"), "proposal_id")
            request_id = validate_uuid(args.get("request_id"), "request_id")
            payload = {
                "proposal_id": proposal_id,
                "request_id": request_id,
            }
            return "claim_full_proposal", request_id, payload

    initiation = args.get("initiation")
    if initiation == "offer":
        _reject_unknown_fields(
            args,
            {"initiation", "request_id", "title"},
            "start_session(Offer)",
        )
        request_id = validate_uuid(args.get("request_id"), "request_id")
        title = _require_non_empty_str(args.get("title"), "title", max_len=MAX_TITLE_CHARS)
        payload = {
            "initiation": "offer",
            "request_id": request_id,
            "title": title,
            "context": "fresh",
            "task_kind": "read_only",
            "use_worktree": False,
            "workspace_mode": "inherit",
        }
        return "offer", request_id, payload

    if initiation in ("user_asked", "own_initiative"):
        allowed = {
            "initiation",
            "request_id",
            "title",
            "prompt",
            "context",
            "background",
            "task_kind",
            "use_worktree",
            "context_strategy",
            "name",
            "dispatch_group_id",
            "batch_id",
        }
        _reject_unknown_fields(args, allowed, f"start_session({initiation})")
        request_id = validate_uuid(args.get("request_id"), "request_id")
        title = _require_non_empty_str(args.get("title"), "title", max_len=MAX_TITLE_CHARS)
        prompt = _require_non_empty_str(args.get("prompt"), "prompt", max_len=MAX_PROMPT_CHARS)
        task_kind, use_worktree, workspace_mode = _validate_task_workspace_pair(
            args.get("task_kind"),
            args.get("use_worktree"),
        )

        if "context" in args and args.get("context") is None:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "context cannot be null; omit the field to use the default 'fresh'",
                {"field": "context"},
            )
        raw_context = args.get("context", "fresh")
        if raw_context not in ("fresh", "fork"):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "context must be 'fresh' or 'fork'",
                {"field": "context", "value": raw_context},
            )

        context_strategy = args.get("context_strategy")
        if raw_context == "fresh":
            if context_strategy is not None:
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    "context_strategy is only allowed when context='fork'",
                    {"context": raw_context, "context_strategy": context_strategy},
                )
            if "background" not in args or args.get("background") is None:
                raise SideSessionError(
                    ErrorCode.BACKGROUND_TOO_SHORT,
                    "background is required when context='fresh'",
                    {"field": "background"},
                )
            background, background_sections = validate_fresh_background(args.get("background"))
        else:
            if context_strategy is not None and context_strategy not in ("native_fork", "summary_copy"):
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    "context_strategy must be 'native_fork' or 'summary_copy'",
                    {"field": "context_strategy", "value": context_strategy},
                )
            if context_strategy == "native_fork" and workspace_mode == "branch":
                raise SideSessionError(
                    ErrorCode.UNSUPPORTED_CONTEXT_WORKSPACE,
                    "native_fork cannot be combined with branch worktree workspace",
                    {"context_strategy": context_strategy, "workspace_mode": workspace_mode},
                )
            raw_bg = args.get("background")
            if raw_bg is not None:
                background = normalize_text(raw_bg, strip=True)
                if len(background) > MAX_BACKGROUND_CHARS:
                    raise SideSessionError(
                        ErrorCode.INVALID_BACKGROUND,
                        f"background exceeds maximum length of {MAX_BACKGROUND_CHARS} characters",
                    )
            else:
                background = None
            background_sections = {}

        name = validate_short_name(args["name"]) if args.get("name") is not None else None
        dispatch_group_id = (
            validate_uuid(args["dispatch_group_id"], "dispatch_group_id")
            if args.get("dispatch_group_id") is not None
            else None
        )
        batch_id = (
            validate_uuid(args["batch_id"], "batch_id")
            if args.get("batch_id") is not None
            else None
        )

        payload = {
            "initiation": initiation,
            "request_id": request_id,
            "title": title,
            "prompt": prompt,
            "context": raw_context,
            "background": background,
            "background_sections": background_sections,
            "task_kind": task_kind,
            "use_worktree": use_worktree,
            "workspace_mode": workspace_mode,
            "context_strategy": context_strategy,
            "name": name,
            "dispatch_group_id": dispatch_group_id,
            "batch_id": batch_id,
        }
        return initiation, request_id, payload

    raise SideSessionError(
        ErrorCode.INVALID_REQUEST,
        f"Invalid initiation value: {initiation!r}",
        {"field": "initiation", "value": initiation},
    )


def _validate_wait_response(resp: Any) -> dict[str, Any]:
    if not isinstance(resp, Mapping):
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            "response must be an object",
            {"field": "response"},
        )
    kind = resp.get("kind")
    if kind == "input":
        _reject_unknown_fields(resp, {"kind", "text"}, "WaitResponse(input)")
        text = _require_non_empty_str(resp.get("text"), "response.text", max_len=MAX_PROMPT_CHARS)
        return {"kind": "input", "text": text}
    if kind == "elicitation":
        _reject_unknown_fields(resp, {"kind", "action", "content", "reason"}, "WaitResponse(elicitation)")
        action = resp.get("action")
        if action not in ("accept", "decline", "cancel"):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "elicitation action must be 'accept', 'decline', or 'cancel'",
                {"field": "response.action", "value": action},
            )
        content = resp.get("content")
        if content is not None and not isinstance(content, Mapping):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "elicitation content must be a JSON object",
                {"field": "response.content", "actual_type": type(content).__name__},
            )
        out_el: dict[str, Any] = {
            "kind": "elicitation",
            "action": action,
            "content": _normalize_json_value(content),
        }
        if "reason" in resp and resp.get("reason") is not None:
            reason_val = _require_non_empty_str(resp.get("reason"), "response.reason", max_len=4096)
            out_el["reason"] = reason_val
        return out_el
    if kind == "permission":
        _reject_unknown_fields(resp, {"kind", "option_id", "decision"}, "WaitResponse(permission)")
        option_id = _require_non_empty_str(resp.get("option_id"), "response.option_id", max_len=128)
        decision = _require_non_empty_str(resp.get("decision"), "response.decision", max_len=128)
        return {"kind": "permission", "option_id": option_id, "decision": decision}
    raise SideSessionError(
        ErrorCode.INVALID_REQUEST,
        f"Unsupported WaitResponse kind: {kind!r}",
        {"field": "response.kind", "value": kind},
    )


def normalize_request(tool: str, args: Mapping[str, Any]) -> CanonicalRequest:
    """Validate and normalize MCP tool request into a deterministic CanonicalRequest."""
    if not isinstance(tool, str) or not tool.strip():
        raise SideSessionError(ErrorCode.INVALID_REQUEST, "tool name must be a non-empty string")
    if not isinstance(args, Mapping):
        raise SideSessionError(ErrorCode.INVALID_REQUEST, "tool arguments must be a JSON object")

    tool_name = tool.strip()

    if tool_name == "start_session":
        variant, request_id, payload = _normalize_start_session(args)
        norm_hash = canonical_json_sha256({"tool": tool_name, "variant": variant, "payload": payload})
        return CanonicalRequest(
            tool=tool_name,
            variant=variant,
            request_id=request_id,
            payload=payload,
            normalized_hash=norm_hash,
        )

    if tool_name == "list_sessions":
        _reject_unknown_fields(
            args,
            {"linked", "include_archived", "parent_session_id"},
            tool_name,
        )
        linked = _require_bool(args.get("linked", True), "linked")
        include_archived = _require_bool(args.get("include_archived", False), "include_archived")
        parent_session_id = (
            validate_uuid(args["parent_session_id"], "parent_session_id")
            if args.get("parent_session_id") is not None
            else None
        )
        payload = {
            "linked": linked,
            "include_archived": include_archived,
            "parent_session_id": parent_session_id,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "get_session":
        _reject_unknown_fields(args, {"session_id", "target_kind"}, tool_name)
        if "target_kind" in args and args.get("target_kind") is None:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "target_kind cannot be null; omit the field to use the default 'node'",
                {"field": "target_kind"},
            )
        target_kind = args.get("target_kind", "node")
        if target_kind not in ("node", "runtime"):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "target_kind must be 'node' or 'runtime'",
            )
        if target_kind == "node":
            raw_sid = args.get("session_id")
            if isinstance(raw_sid, str) and raw_sid.strip() in ("parent", "self"):
                session_id = raw_sid.strip()
            else:
                session_id = validate_uuid(raw_sid, "session_id")
        else:
            session_id = _require_non_empty_str(args.get("session_id"), "session_id", max_len=128)
        payload = {"session_id": session_id, "target_kind": target_kind}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "send_message_to_session":
        _reject_unknown_fields(
            args,
            {"request_id", "message_id", "session_id", "message", "resume_policy", "dispatch_group_id"},
            tool_name,
        )
        request_id = validate_uuid(args.get("request_id"), "request_id")
        message_id = validate_uuid(args.get("message_id"), "message_id")
        session_id = _require_non_empty_str(args.get("session_id"), "session_id", max_len=128)
        message = _require_non_empty_str(args.get("message"), "message", max_len=MAX_PROMPT_CHARS)
        resume_policy = args.get("resume_policy", "active_only")
        if resume_policy not in ("active_only", "explicit"):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "resume_policy must be 'active_only' or 'explicit'",
            )
        dispatch_group_id = (
            validate_uuid(args["dispatch_group_id"], "dispatch_group_id")
            if args.get("dispatch_group_id") is not None
            else None
        )
        payload = {
            "request_id": request_id,
            "message_id": message_id,
            "session_id": session_id,
            "message": message,
            "resume_policy": resume_policy,
            "dispatch_group_id": dispatch_group_id,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "hand_off_to_session":
        _reject_unknown_fields(
            args,
            {
                "request_id",
                "transfer_id",
                "task_id",
                "title",
                "remaining_plan",
                "task_kind",
                "use_worktree",
                "context",
                "context_strategy",
                "expected_task_revision",
                "dispatch_group_id",
            },
            tool_name,
        )
        request_id = validate_uuid(args.get("request_id"), "request_id")
        transfer_id = validate_uuid(args.get("transfer_id"), "transfer_id")
        task_id = validate_uuid(args.get("task_id"), "task_id")
        title = _require_non_empty_str(args.get("title"), "title", max_len=MAX_TITLE_CHARS)
        remaining_plan = _require_non_empty_str(
            args.get("remaining_plan"),
            "remaining_plan",
            max_len=MAX_PROMPT_CHARS,
        )
        task_kind, use_worktree, workspace_mode = _validate_task_workspace_pair(
            args.get("task_kind"),
            args.get("use_worktree"),
        )
        if "context" in args and args.get("context") is None:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "context cannot be null; omit the field to use the default 'fork'",
                {"field": "context"},
            )
        context = args.get("context", "fork")
        if context != "fork":
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "hand_off_to_session requires context='fork'",
            )
        context_strategy = args.get("context_strategy")
        if context_strategy not in ("summary_copy", "native_fork"):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "hand_off_to_session requires context_strategy in ('summary_copy', 'native_fork')",
            )
        if context_strategy == "native_fork" and workspace_mode == "branch":
            raise SideSessionError(
                ErrorCode.UNSUPPORTED_CONTEXT_WORKSPACE,
                "native_fork cannot be combined with branch worktree workspace",
            )
        expected_task_revision = _require_int(
            args.get("expected_task_revision"),
            "expected_task_revision",
            min_value=1,
        )
        dispatch_group_id = (
            validate_uuid(args["dispatch_group_id"], "dispatch_group_id")
            if args.get("dispatch_group_id") is not None
            else None
        )
        payload = {
            "request_id": request_id,
            "transfer_id": transfer_id,
            "task_id": task_id,
            "title": title,
            "remaining_plan": remaining_plan,
            "task_kind": task_kind,
            "use_worktree": use_worktree,
            "workspace_mode": workspace_mode,
            "context": "fork",
            "context_strategy": context_strategy,
            "expected_task_revision": expected_task_revision,
            "dispatch_group_id": dispatch_group_id,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "get_operation":
        _reject_unknown_fields(args, {"operation_id"}, tool_name)
        operation_id = validate_uuid(args.get("operation_id"), "operation_id")
        payload = {"operation_id": operation_id}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "create_dispatch_group":
        _reject_unknown_fields(args, {"request_id", "expected_members", "batch_id"}, tool_name)
        request_id = validate_uuid(args.get("request_id"), "request_id")
        expected_members = _require_int(
            args.get("expected_members"),
            "expected_members",
            min_value=1,
            max_value=MAX_SLOTS_PER_PARENT,
        )
        batch_id = (
            validate_uuid(args["batch_id"], "batch_id")
            if args.get("batch_id") is not None
            else None
        )
        payload = {
            "request_id": request_id,
            "expected_members": expected_members,
            "batch_id": batch_id,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name in ("seal_dispatch_group", "close_dispatch_group"):
        _reject_unknown_fields(
            args,
            {"request_id", "dispatch_group_id", "expected_revision"},
            tool_name,
        )
        request_id = validate_uuid(args.get("request_id"), "request_id")
        dispatch_group_id = validate_uuid(args.get("dispatch_group_id"), "dispatch_group_id")
        expected_revision = _require_int(args.get("expected_revision"), "expected_revision", min_value=1)
        payload = {
            "request_id": request_id,
            "dispatch_group_id": dispatch_group_id,
            "expected_revision": expected_revision,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "get_dispatch_group":
        _reject_unknown_fields(args, {"dispatch_group_id"}, tool_name)
        dispatch_group_id = validate_uuid(args.get("dispatch_group_id"), "dispatch_group_id")
        payload = {"dispatch_group_id": dispatch_group_id}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "register_task":
        _reject_unknown_fields(
            args,
            {"request_id", "title", "remaining_plan", "task_kind", "scope"},
            tool_name,
        )
        request_id = validate_uuid(args.get("request_id"), "request_id")
        title = _require_non_empty_str(args.get("title"), "title", max_len=MAX_TITLE_CHARS)
        remaining_plan = _require_non_empty_str(
            args.get("remaining_plan"),
            "remaining_plan",
            max_len=MAX_PROMPT_CHARS,
        )
        task_kind = args.get("task_kind")
        if task_kind not in ("read_only", "write_code"):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "task_kind must be 'read_only' or 'write_code'",
            )
        raw_scope = args.get("scope")
        if not isinstance(raw_scope, Mapping):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "scope must be an object")
        _reject_unknown_fields(
            raw_scope,
            {"resource_keys", "write_path_roots", "artifact_source_roots", "tool_profile_hash"},
            "register_task.scope",
        )
        scope = {
            "resource_keys": [ _require_non_empty_str(x, "scope.resource_keys[]") for x in raw_scope.get("resource_keys", []) ],
            "write_path_roots": [ _require_non_empty_str(x, "scope.write_path_roots[]") for x in raw_scope.get("write_path_roots", []) ],
            "artifact_source_roots": [ _require_non_empty_str(x, "scope.artifact_source_roots[]") for x in raw_scope.get("artifact_source_roots", []) ],
            "tool_profile_hash": normalize_text(str(raw_scope.get("tool_profile_hash", "")), strip=True),
        }
        payload = {
            "request_id": request_id,
            "title": title,
            "remaining_plan": remaining_plan,
            "task_kind": task_kind,
            "scope": scope,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "bind_current_task":
        _reject_unknown_fields(args, {"request_id", "task_id", "expected_task_revision"}, tool_name)
        request_id = validate_uuid(args.get("request_id"), "request_id")
        task_id = validate_uuid(args.get("task_id"), "task_id")
        expected_task_revision = _require_int(
            args.get("expected_task_revision"),
            "expected_task_revision",
            min_value=1,
        )
        payload = {
            "request_id": request_id,
            "task_id": task_id,
            "expected_task_revision": expected_task_revision,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "get_current_task":
        _reject_unknown_fields(args, set(), tool_name)
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload={},
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": {}}),
        )

    if tool_name == "get_task":
        _reject_unknown_fields(args, {"task_id"}, tool_name)
        task_id = validate_uuid(args.get("task_id"), "task_id")
        payload = {"task_id": task_id}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "list_tasks":
        _reject_unknown_fields(args, {"session_id"}, tool_name)
        session_id = (
            validate_uuid(args["session_id"], "session_id")
            if args.get("session_id") is not None
            else None
        )
        payload = {"session_id": session_id}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "list_waits":
        _reject_unknown_fields(args, {"session_id"}, tool_name)
        session_id = validate_uuid(args.get("session_id"), "session_id")
        payload = {"session_id": session_id}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "get_control":
        _reject_unknown_fields(args, {"control_id"}, tool_name)
        control_id = validate_uuid(args.get("control_id"), "control_id")
        payload = {"control_id": control_id}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "respond_to_wait":
        _reject_unknown_fields(args, {"request_id", "wait_id", "nonce", "response"}, tool_name)
        request_id = validate_uuid(args.get("request_id"), "request_id")
        wait_id = validate_uuid(args.get("wait_id"), "wait_id")
        nonce = _require_non_empty_str(args.get("nonce"), "nonce", max_len=256)
        response = _validate_wait_response(args.get("response"))
        payload = {
            "request_id": request_id,
            "wait_id": wait_id,
            "nonce": nonce,
            "response": response,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "cancel_run":
        _reject_unknown_fields(args, {"request_id", "session_id", "run_id", "reason"}, tool_name)
        request_id = validate_uuid(args.get("request_id"), "request_id")
        session_id = validate_uuid(args.get("session_id"), "session_id")
        run_id = validate_uuid(args.get("run_id"), "run_id")
        reason = _require_non_empty_str(args.get("reason"), "reason", max_len=1024)
        payload = {
            "request_id": request_id,
            "session_id": session_id,
            "run_id": run_id,
            "reason": reason,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "cancel_message":
        _reject_unknown_fields(args, {"request_id", "session_id", "message_id", "reason"}, tool_name)
        request_id = validate_uuid(args.get("request_id"), "request_id")
        session_id = validate_uuid(args.get("session_id"), "session_id")
        message_id = validate_uuid(args.get("message_id"), "message_id")
        reason = _require_non_empty_str(args.get("reason"), "reason", max_len=1024)
        payload = {
            "request_id": request_id,
            "session_id": session_id,
            "message_id": message_id,
            "reason": reason,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "list_events":
        _reject_unknown_fields(args, {"states", "cursor", "limit"}, tool_name)
        raw_states = args.get("states", ["pending", "presented"])
        if not isinstance(raw_states, list) or not raw_states:
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "states must be a non-empty list")
        for st in raw_states:
            if st not in ("pending", "presented", "acked"):
                raise SideSessionError(ErrorCode.INVALID_REQUEST, f"Invalid event state: {st!r}")
        cursor = _require_non_empty_str(args["cursor"], "cursor", max_len=2048) if args.get("cursor") is not None else None
        limit = _require_int(args.get("limit", 32), "limit", min_value=1, max_value=MAX_EVENT_PAGE_LIMIT)
        payload = {"states": list(raw_states), "cursor": cursor, "limit": limit}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "get_event":
        _reject_unknown_fields(args, {"event_id"}, tool_name)
        event_id = validate_uuid(args.get("event_id"), "event_id")
        payload = {"event_id": event_id}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "read_report":
        _reject_unknown_fields(args, {"report_ref"}, tool_name)
        report_ref = _require_non_empty_str(args.get("report_ref"), "report_ref", max_len=256)
        parse_ssref(report_ref, expected_kind="report")
        payload = {"report_ref": report_ref}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "read_artifact":
        _reject_unknown_fields(args, {"artifact_ref", "offset", "max_bytes"}, tool_name)
        artifact_ref = _require_non_empty_str(args.get("artifact_ref"), "artifact_ref", max_len=256)
        parse_ssref(artifact_ref, expected_kind="artifact")
        offset = _require_int(args.get("offset", 0), "offset", min_value=0)
        max_bytes = _require_int(
            args.get("max_bytes", DEFAULT_ARTIFACT_CHUNK_BYTES),
            "max_bytes",
            min_value=1,
            max_value=MAX_ARTIFACT_CHUNK_BYTES,
        )
        payload = {"artifact_ref": artifact_ref, "offset": offset, "max_bytes": max_bytes}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "publish_artifact":
        _reject_unknown_fields(
            args,
            {"request_id", "run_id", "relative_path", "expected_sha256", "media_type"},
            tool_name,
        )
        request_id = validate_uuid(args.get("request_id"), "request_id")
        run_id = validate_uuid(args.get("run_id"), "run_id")
        relative_path = _require_non_empty_str(args.get("relative_path"), "relative_path", max_len=1024)
        if relative_path.startswith("/") or ".." in relative_path.split("/"):
            raise SideSessionError(ErrorCode.PATH_ESCAPE, "relative_path must be a safe relative path")
        expected_sha256 = _require_non_empty_str(args.get("expected_sha256"), "expected_sha256", max_len=64).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "expected_sha256 must be 64 hex chars")
        media_type = _require_non_empty_str(args.get("media_type"), "media_type", max_len=128)
        payload = {
            "request_id": request_id,
            "run_id": run_id,
            "relative_path": relative_path,
            "expected_sha256": expected_sha256,
            "media_type": media_type,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "report_child_turn":
        _reject_unknown_fields(
            args,
            {
                "request_id",
                "run_id",
                "turn_seq",
                "worker_turn_id",
                "phase",
                "report_revision",
                "outcome",
                "recap",
                "full_report",
                "blocked",
                "block_reason",
                "artifacts",
            },
            tool_name,
        )
        request_id = validate_uuid(args.get("request_id"), "request_id")
        run_id = validate_uuid(args.get("run_id"), "run_id")
        turn_seq = _require_int(args.get("turn_seq"), "turn_seq", min_value=1)
        worker_turn_id = validate_uuid(args.get("worker_turn_id"), "worker_turn_id")
        phase = args.get("phase")
        if phase not in ("checkpoint", "final"):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "phase must be 'checkpoint' or 'final'")
        raw_rev = args.get("report_revision")
        if phase == "final":
            if raw_rev is not None:
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    "report_revision must be null when phase='final'",
                )
            report_revision = None
        else:
            report_revision = _require_int(raw_rev, "report_revision", min_value=1)

        outcome = args.get("outcome")
        if outcome not in ("success", "failed", "cancelled", "blocked"):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "outcome must be 'success', 'failed', 'cancelled', or 'blocked'",
            )
        blocked = _require_bool(args.get("blocked"), "blocked")
        raw_block_reason = args.get("block_reason")
        if blocked:
            if outcome != "blocked":
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    "blocked=True requires outcome='blocked'",
                )
            block_reason = _require_non_empty_str(raw_block_reason, "block_reason", max_len=4096)
        else:
            if outcome == "blocked":
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    "outcome='blocked' requires blocked=True",
                )
            if raw_block_reason is not None:
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    "block_reason must be null when blocked=False",
                )
            block_reason = None

        recap = _require_non_empty_str(args.get("recap"), "recap", max_len=4096)
        full_report = _require_non_empty_str(args.get("full_report"), "full_report", max_len=MAX_PROMPT_CHARS * 4)
        raw_artifacts = args.get("artifacts", [])
        if not isinstance(raw_artifacts, list):
            raise SideSessionError(ErrorCode.INVALID_REQUEST, "artifacts must be a list")
        artifacts: list[dict[str, Any]] = []
        for idx, item in enumerate(raw_artifacts):
            if hasattr(item, "to_dict"):
                item = item.to_dict()
            if not isinstance(item, Mapping):
                raise SideSessionError(ErrorCode.INVALID_REQUEST, f"artifacts[{idx}] must be an object")
            _reject_unknown_fields(item, {"ref", "sha256", "byte_length", "media_type"}, f"artifacts[{idx}]")
            ref_str = _require_non_empty_str(item.get("ref"), f"artifacts[{idx}].ref")
            parse_ssref(ref_str, expected_kind="artifact")
            sha_str = _require_non_empty_str(item.get("sha256"), f"artifacts[{idx}].sha256").lower()
            blen = _require_int(item.get("byte_length"), f"artifacts[{idx}].byte_length", min_value=0)
            mtype = _require_non_empty_str(item.get("media_type"), f"artifacts[{idx}].media_type")
            artifacts.append({
                "ref": ref_str,
                "sha256": sha_str,
                "byte_length": blen,
                "media_type": mtype,
            })

        payload = {
            "request_id": request_id,
            "run_id": run_id,
            "turn_seq": turn_seq,
            "worker_turn_id": worker_turn_id,
            "phase": phase,
            "report_revision": report_revision,
            "outcome": outcome,
            "recap": recap,
            "last_turn_report": format_recap_400(recap),
            "full_report": full_report,
            "blocked": blocked,
            "block_reason": block_reason,
            "artifacts": artifacts,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=phase,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "ack_events":
        _reject_unknown_fields(args, {"request_id", "event_ids"}, tool_name)
        request_id = validate_uuid(args.get("request_id"), "request_id")
        raw_ids = args.get("event_ids")
        if not isinstance(raw_ids, list) or not (1 <= len(raw_ids) <= MAX_ACK_EVENTS):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"event_ids must be a list of 1..{MAX_ACK_EVENTS} UUIDs",
            )
        event_ids = [validate_uuid(eid, "event_ids[]") for eid in raw_ids]
        payload = {"request_id": request_id, "event_ids": event_ids}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "read_brief":
        _reject_unknown_fields(args, {"session_id"}, tool_name)
        session_id = (
            validate_uuid(args["session_id"], "session_id")
            if args.get("session_id") is not None
            else None
        )
        payload = {"session_id": session_id}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "read_context":
        _reject_unknown_fields(args, {"root", "revision"}, tool_name)
        root = validate_uuid(args["root"], "root") if args.get("root") is not None else None
        revision = (
            _require_int(args["revision"], "revision", min_value=0)
            if args.get("revision") is not None
            else None
        )
        payload = {"root": root, "revision": revision}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "submit_note":
        _reject_unknown_fields(args, {"request_id", "content"}, tool_name)
        request_id = validate_uuid(args.get("request_id"), "request_id")
        content = _require_non_empty_str(args.get("content"), "content", max_len=MAX_PROMPT_CHARS)
        payload = {"request_id": request_id, "content": content}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "update_shared_context":
        _reject_unknown_fields(args, {"request_id", "expected_revision", "content"}, tool_name)
        request_id = validate_uuid(args.get("request_id"), "request_id")
        expected_revision = _require_int(args.get("expected_revision"), "expected_revision", min_value=0)
        content = _require_non_empty_str(args.get("content"), "content", max_len=MAX_PROMPT_CHARS)
        payload = {
            "request_id": request_id,
            "expected_revision": expected_revision,
            "content": content,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "dismiss_task":
        _reject_unknown_fields(args, {"request_id", "proposal_id"}, tool_name)
        request_id = validate_uuid(args.get("request_id"), "request_id")
        proposal_id = validate_uuid(args.get("proposal_id"), "proposal_id")
        payload = {"request_id": request_id, "proposal_id": proposal_id}
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "set_session_status":
        _reject_unknown_fields(args, {"request_id", "session_id", "status", "expected_revision"}, tool_name)
        request_id = validate_uuid(args.get("request_id"), "request_id")
        session_id = validate_uuid(args.get("session_id"), "session_id")
        status = args.get("status")
        if status not in ("active", "paused", "done"):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "status must be 'active', 'paused', or 'done'",
            )
        expected_revision = _require_int(args.get("expected_revision"), "expected_revision", min_value=1)
        payload = {
            "request_id": request_id,
            "session_id": session_id,
            "status": status,
            "expected_revision": expected_revision,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "archive_session":
        _reject_unknown_fields(args, {"request_id", "session_id", "expected_revision"}, tool_name)
        request_id = validate_uuid(args.get("request_id"), "request_id")
        session_id = validate_uuid(args.get("session_id"), "session_id")
        expected_revision = _require_int(args.get("expected_revision"), "expected_revision", min_value=1)
        payload = {
            "request_id": request_id,
            "session_id": session_id,
            "expected_revision": expected_revision,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=request_id,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    if tool_name == "diff_worktree":
        _reject_unknown_fields(args, {"session_id", "max_bytes"}, tool_name)
        session_id = _require_non_empty_str(args.get("session_id"), "session_id", max_len=256)
        max_bytes = _require_int(
            args.get("max_bytes", 65536),
            "max_bytes",
            min_value=1,
            max_value=262144,
        )
        payload = {
            "session_id": session_id,
            "max_bytes": max_bytes,
        }
        return CanonicalRequest(
            tool=tool_name,
            variant=tool_name,
            request_id=None,
            payload=payload,
            normalized_hash=canonical_json_sha256({"tool": tool_name, "payload": payload}),
        )

    raise SideSessionError(
        ErrorCode.INVALID_REQUEST,
        f"Unknown tool: {tool_name}",
        {"tool": tool_name},
    )


def validate_hook_output(event: str, output: Mapping[str, Any] | HookOutput) -> HookOutputDict:
    """Strictly validate Hook stdout payload before emission."""
    if event not in VALID_HOOK_EVENTS:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"Unsupported hook event: {event!r}",
            {"event": event},
        )
    if isinstance(output, HookOutput):
        raw = output.to_dict()
    elif isinstance(output, Mapping):
        raw = dict(output)
    else:
        raise SideSessionError(
            ErrorCode.SCHEMA_ERROR,
            "Hook output must be a dict",
            {"event": event, "actual_type": type(output).__name__},
        )

    allowed_keys = {"continue", "additionalContext", "hookSpecificOutput"}
    unknown = sorted(set(raw.keys()) - allowed_keys)
    if unknown:
        raise SideSessionError(
            ErrorCode.UNKNOWN_FIELD,
            f"Unknown key(s) in hook output for {event}: {', '.join(unknown)}",
            {"event": event, "unknown_keys": unknown},
        )

    validated: dict[str, Any] = {}

    if "continue" in raw and raw["continue"] is not None:
        if type(raw["continue"]) is not bool:
            raise SideSessionError(
                ErrorCode.SCHEMA_ERROR,
                "'continue' in hook output must be a boolean",
                {"event": event, "value": raw["continue"]},
            )
        if event in ("SessionStart", "UserPromptSubmit", "PostToolUse", "PreToolUse") and raw["continue"] is True:
            raise SideSessionError(
                ErrorCode.SCHEMA_ERROR,
                f"{event} hook cannot request continue=True",
                {"event": event},
            )
        if event != "Stop" and raw["continue"] is True:
            raise SideSessionError(
                ErrorCode.SCHEMA_ERROR,
                f"{event} hook cannot request continue=True; only Stop may continue",
                {"event": event},
            )
        validated["continue"] = raw["continue"]

    if "additionalContext" in raw and raw["additionalContext"] is not None:
        if not isinstance(raw["additionalContext"], str):
            raise SideSessionError(
                ErrorCode.SCHEMA_ERROR,
                "'additionalContext' in hook output must be a string",
                {"event": event},
            )
        ctx_str = raw["additionalContext"]
        ctx_bytes = len(ctx_str.encode("utf-8"))
        if ctx_bytes > MAX_HOOK_CONTEXT_BYTES:
            raise SideSessionError(
                ErrorCode.SCHEMA_ERROR,
                f"'additionalContext' exceeds {MAX_HOOK_CONTEXT_BYTES} UTF-8 bytes (got {ctx_bytes})",
                {"event": event, "byte_length": ctx_bytes},
            )
        validated["additionalContext"] = ctx_str

    if validated.get("continue") is True:
        ctx = validated.get("additionalContext", "")
        if not isinstance(ctx, str) or not ctx.strip():
            raise SideSessionError(
                ErrorCode.SCHEMA_ERROR,
                f"{event} hook with continue=True requires non-empty additionalContext",
                {"event": event},
            )

    if "hookSpecificOutput" in raw and raw["hookSpecificOutput"] is not None:
        hso = raw["hookSpecificOutput"]
        if not isinstance(hso, Mapping):
            raise SideSessionError(
                ErrorCode.SCHEMA_ERROR,
                "'hookSpecificOutput' must be an object",
                {"event": event},
            )
        hook_event_name = hso.get("hookEventName")
        if hook_event_name != event:
            raise SideSessionError(
                ErrorCode.SCHEMA_ERROR,
                f"hookSpecificOutput.hookEventName ({hook_event_name!r}) does not match event ({event!r})",
                {"event": event, "hookEventName": hook_event_name},
            )
        unknown_hso = sorted(set(hso.keys()) - {"hookEventName"})
        if unknown_hso:
            raise SideSessionError(
                ErrorCode.UNKNOWN_FIELD,
                f"Unknown key(s) in hookSpecificOutput for {event}: {', '.join(unknown_hso)}",
                {"event": event, "unknown_keys": unknown_hso},
            )
        validated["hookSpecificOutput"] = {"hookEventName": event}

    return HookOutputDict(validated)
