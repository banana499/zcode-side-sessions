#!/usr/bin/env python3
"""Synchronous hook entrypoint for side-sessions (SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, Stop)."""

from __future__ import annotations

import time

started_mono = time.monotonic()

from datetime import datetime, timedelta, timezone  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
from pathlib import Path  # noqa: E402
import sqlite3  # noqa: E402
import sys  # noqa: E402
from typing import Any, Mapping  # noqa: E402
import uuid  # noqa: E402

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from agent_ctl import probe_and_kick_nonblocking as _maybe_kick_agent  # type: ignore  # noqa: E402
from contracts import (  # type: ignore  # noqa: E402
    MCP_PLUGIN_TOOL_PREFIX,
    MCP_TOOL_PREFIX,
    READ_ONLY_BUILTIN_TOOLS,
    READ_ONLY_DENYLIST,
    VALID_HOOK_EVENTS,
    ErrorCode,
    HookContext,
    SideSessionError,
    validate_hook_output,
)
from driver import ZCodeDriver  # type: ignore  # noqa: E402
from engine import Engine, _err  # type: ignore  # noqa: E402
from state import open_store, resolve_state_root  # type: ignore  # noqa: E402
from worker_kick import WorkerKicker  # type: ignore  # noqa: E402


_ENV_SESSION_ID_KEYS: tuple[str, ...] = (
    "CLAUDE_SESSION_ID",
    "ZCODE_SESSION_ID",
    "CLAUDE_CODE_SESSION_ID",
)


def _write_stream(stream: Any, text: str) -> None:
    if stream is None:
        return
    try:
        stream.write(text)
    except TypeError:
        stream.write(text.encode("utf-8"))
    if hasattr(stream, "flush"):
        try:
            stream.flush()
        except Exception:
            pass


def parse_hook_input(
    raw_bytes: bytes | bytearray | str | Mapping[str, Any],
    environ: Mapping[str, str] | None = None,
) -> HookContext:
    """Parse and validate hook stdin JSON and environment into a canonical HookContext."""
    env_map: Mapping[str, str] = os.environ if environ is None else environ

    if isinstance(raw_bytes, Mapping):
        data: dict[str, Any] = dict(raw_bytes)
    else:
        if isinstance(raw_bytes, (bytes, bytearray)):
            try:
                raw_text = bytes(raw_bytes).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    "Hook stdin is not valid UTF-8",
                ) from exc
        elif isinstance(raw_bytes, str):
            raw_text = raw_bytes
        else:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"Unsupported hook raw input type: {type(raw_bytes).__name__}",
            )

        stripped = raw_text.strip()
        if not stripped:
            data = {}
        else:
            try:
                parsed = json.loads(stripped)
            except Exception as exc:
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    f"Hook stdin is not valid JSON: {exc}",
                ) from exc
            if not isinstance(parsed, Mapping):
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    "Hook stdin JSON root must be an object",
                )
            data = dict(parsed)

    # Validate session_id / sessionId inside JSON
    if "session_id" in data and not isinstance(data.get("session_id"), (str, type(None))):
        raise _err(
            "HOOK_IDENTITY_MISMATCH",
            f"Hook identity field session_id must be a string (got {type(data.get('session_id')).__name__})",
            {"field": "session_id"},
            aliases=(ErrorCode.CALLER_CONTEXT_CONFLICT, ErrorCode.INVALID_REQUEST),
        )
    if "sessionId" in data and not isinstance(data.get("sessionId"), (str, type(None))):
        raise _err(
            "HOOK_IDENTITY_MISMATCH",
            f"Hook identity field sessionId must be a string (got {type(data.get('sessionId')).__name__})",
            {"field": "sessionId"},
            aliases=(ErrorCode.CALLER_CONTEXT_CONFLICT, ErrorCode.INVALID_REQUEST),
        )
    raw_sid_snake = data.get("session_id")
    raw_sid_camel = data.get("sessionId")
    sid_snake = str(raw_sid_snake).strip() if isinstance(raw_sid_snake, str) and raw_sid_snake.strip() else None
    sid_camel = str(raw_sid_camel).strip() if isinstance(raw_sid_camel, str) and raw_sid_camel.strip() else None

    if sid_snake is not None and sid_camel is not None and sid_snake != sid_camel:
        raise _err(
            "HOOK_IDENTITY_MISMATCH",
            f"Conflicting session_id ({sid_snake!r}) and sessionId ({sid_camel!r}) in hook stdin JSON",
            {"session_id": sid_snake, "sessionId": sid_camel},
            aliases=(ErrorCode.CALLER_CONTEXT_CONFLICT, ErrorCode.INVALID_REQUEST),
        )
    stdin_sid = sid_snake or sid_camel

    # Validate environment session ID variables
    raw_env_sids: dict[str, str] = {}
    for env_key in _ENV_SESSION_ID_KEYS:
        val = env_map.get(env_key)
        if isinstance(val, str) and val.strip():
            raw_env_sids[env_key] = val.strip()

    # Filter out ambient ZCode subagent harness session IDs if overridden or when stdin uses a non-subagent ID
    non_subagent_env_sids = {
        k: v for k, v in raw_env_sids.items() if not v.startswith("sess_subagent_")
    }
    if non_subagent_env_sids:
        env_sids = non_subagent_env_sids
    elif stdin_sid is not None and not stdin_sid.startswith("sess_subagent_"):
        env_sids = {}
    else:
        env_sids = raw_env_sids

    distinct_env_sids = set(env_sids.values())
    if len(distinct_env_sids) > 1:
        raise _err(
            "HOOK_IDENTITY_MISMATCH",
            "Conflicting session IDs in environment variables",
            {"env_session_ids": env_sids},
            aliases=(ErrorCode.CALLER_CONTEXT_CONFLICT, ErrorCode.INVALID_REQUEST),
        )
    env_sid = next(iter(distinct_env_sids), None)

    if stdin_sid is not None and env_sid is not None and stdin_sid != env_sid:
        raise _err(
            "HOOK_IDENTITY_MISMATCH",
            f"Hook stdin session_id ({stdin_sid!r}) does not match environment session ID ({env_sid!r})",
            {"stdin_session_id": stdin_sid, "env_session_id": env_sid, "env_vars": env_sids},
            aliases=(ErrorCode.CALLER_CONTEXT_CONFLICT, ErrorCode.INVALID_REQUEST),
        )

    if not stdin_sid:
        raise _err(
            ErrorCode.CALLER_UNBOUND,
            "Hook stdin JSON is missing a non-empty string session_id",
            aliases=("HOOK_IDENTITY_MISMATCH", ErrorCode.INVALID_REQUEST),
        )
    runtime_sid = stdin_sid

    raw_event = (
        data.get("hook_event_name")
        or data.get("hookEventName")
        or data.get("event")
    )
    if not isinstance(raw_event, str) or not raw_event.strip():
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            "hook_event_name is required and must be a non-empty string",
            {"event": raw_event},
        )
    event = raw_event.strip()
    if event not in VALID_HOOK_EVENTS:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"Unsupported hook event: {event!r}",
            {"event": event},
        )

    raw_cwd = (
        data.get("cwd")
        or data.get("workspace_path")
        or env_map.get("CLAUDE_PROJECT_DIR")
        or env_map.get("PWD")
        or os.getcwd()
    )
    cwd = str(raw_cwd).strip() if raw_cwd is not None else ""

    for turn_field in ("turn_id", "turnId", "runtime_turn_id"):
        if turn_field in data and data[turn_field] is not None and not isinstance(data[turn_field], str):
            raise _err(
                "HOOK_IDENTITY_MISMATCH",
                f"Hook identity field {turn_field} must be a string (got {type(data[turn_field]).__name__})",
                {"field": turn_field},
                aliases=(ErrorCode.CALLER_CONTEXT_CONFLICT, ErrorCode.INVALID_REQUEST),
            )
    raw_turn_id = (
        data.get("turn_id")
        or data.get("turnId")
        or data.get("runtime_turn_id")
        or env_map.get("CLAUDE_TURN_ID")
        or env_map.get("ZCODE_TURN_ID")
    )
    runtime_turn_id = str(raw_turn_id).strip() if isinstance(raw_turn_id, str) and raw_turn_id.strip() else None

    stop_hook_active: bool | None = None
    raw_stop = None
    if "stop_hook_active" in data:
        raw_stop = data["stop_hook_active"]
    elif "stopHookActive" in data:
        raw_stop = data["stopHookActive"]
    if raw_stop is not None:
        if type(raw_stop) is not bool:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                "stop_hook_active must be a JSON boolean",
                {"value": raw_stop, "actual_type": type(raw_stop).__name__},
            )
        stop_hook_active = raw_stop
    if event == "Stop" and stop_hook_active is not False:
        # True or missing/unknown: do not hand the context to the continuation path.
        pass

    invocation_id = str(data.get("invocation_id") or data.get("invocationId") or uuid.uuid4())
    deadline_at = str(
        data.get("deadline_at")
        or (datetime.now(timezone.utc) + timedelta(seconds=3)).isoformat().replace("+00:00", "Z")
    )

    return HookContext(
        event=event,
        invocation_id=invocation_id,
        runtime_sid=runtime_sid,
        cwd=cwd,
        raw_input=data,
        deadline_at=deadline_at,
        runtime_turn_id=runtime_turn_id,
        stop_hook_active=stop_hook_active,
    )


def _read_stdin_bytes(stdin: Any) -> bytes:
    if stdin is None:
        stdin = sys.stdin
    if isinstance(stdin, (bytes, bytearray)):
        return bytes(stdin)
    if isinstance(stdin, str):
        return stdin.encode("utf-8")
    if hasattr(stdin, "buffer"):
        try:
            data = stdin.buffer.read()
            if isinstance(data, (bytes, bytearray)):
                return bytes(data)
        except Exception:
            pass
    raw = stdin.read()
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    return str(raw or "").encode("utf-8")


_PRETOOL_READ_ONLY_CONTROL_ALLOWLIST: frozenset[str] = frozenset({
    "list_sessions",
    "get_session",
    "list_tasks",
    "get_task",
    "get_current_task",
    "list_events",
    "get_event",
    "list_waits",
    "get_control",
    "get_operation",
    "get_dispatch_group",
    "read_brief",
    "read_context",
    "read_report",
    "read_artifact",
    "diff_worktree",
})


def _is_read_only_tool(tool_name: str) -> bool:
    """Return True only if tool_name is in READ_ONLY_BUILTIN_TOOLS or pure read-only control allowlist and not denied."""
    t = str(tool_name or "").strip()
    if not t or t in READ_ONLY_DENYLIST:
        return False
    if t in READ_ONLY_BUILTIN_TOOLS:
        return True
    short = t
    for prefix in (MCP_TOOL_PREFIX, MCP_PLUGIN_TOOL_PREFIX):
        if t.startswith(prefix):
            short = t[len(prefix) :]
            break
    return short in _PRETOOL_READ_ONLY_CONTROL_ALLOWLIST and short not in READ_ONLY_DENYLIST


def main(
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
    environ: Mapping[str, str] | None = None,
    *,
    deadline_monotonic: float | None = None,
) -> int:
    """Execute synchronous side-sessions hook and write validated single-line JSON to stdout if non-empty."""
    out_stream = sys.stdout if stdout is None else stdout
    err_stream = sys.stderr if stderr is None else stderr
    env_map: Mapping[str, str] = os.environ if environ is None else environ
    base_mono = started_mono if stdin is None else time.monotonic()
    hook_deadline_mono = deadline_monotonic if deadline_monotonic is not None else (base_mono + 2.65)

    store = None
    try:
        raw_bytes = _read_stdin_bytes(stdin)
        ctx = parse_hook_input(raw_bytes, env_map)
        state_root = resolve_state_root(env=env_map)

        try:
            db_file = state_root / "state.sqlite3"
            if ctx.event == "SessionStart":
                store = open_store(
                    state_root,
                    writable=True,
                    initialize=True,
                    deadline_monotonic=hook_deadline_mono,
                )
                _maybe_kick_agent(state_root, deadline_monotonic=hook_deadline_mono)
            else:
                if not state_root.is_symlink() and not db_file.is_symlink() and not db_file.exists():
                    return 0
                try:
                    store = open_store(
                        state_root,
                        writable=True,
                        initialize=False,
                        deadline_monotonic=hook_deadline_mono,
                    )
                except SideSessionError as open_exc:
                    if open_exc.code == ErrorCode.RETRY_LATER and open_exc.details.get("db_exists") is False:
                        return 0
                    if (
                        open_exc.code == ErrorCode.VERSION_MISMATCH
                        and open_exc.details.get("db_engine_schema_version") == "1.1"
                    ):
                        if (hook_deadline_mono - time.monotonic()) >= 1.0:
                            store = open_store(
                                state_root,
                                writable=True,
                                initialize=True,
                                deadline_monotonic=hook_deadline_mono,
                            )
                        else:
                            raise open_exc
                    else:
                        raise

            eng = Engine(
                store,
                runtime_execution="deferred",
                driver=ZCodeDriver(),
                supervisor_port=WorkerKicker(state_root, include_node_id=False),
            )
            hook_output = eng.handle_hook(ctx, defer_emit_confirm=True)
            if hook_output:
                validated = validate_hook_output(ctx.event, hook_output)
                if validated:
                    json_line = json.dumps(dict(validated), ensure_ascii=False, separators=(",", ":")) + "\n"
                    _write_stream(out_stream, json_line)
                    if getattr(eng, "_pending_emit_deliveries", None) and (hook_deadline_mono - time.monotonic()) >= 0.04:
                        try:
                            eng.confirm_emitted()
                        except Exception:
                            pass
            return 0
        except (SideSessionError, sqlite3.OperationalError) as db_exc:
            is_guard_err = isinstance(db_exc, sqlite3.OperationalError) or (
                isinstance(db_exc, SideSessionError)
                and db_exc.code in (ErrorCode.LOCK_BUSY, ErrorCode.RETRY_LATER, ErrorCode.VERSION_MISMATCH)
            )
            if not is_guard_err:
                raise
            if ctx.event == "PreToolUse":
                raw_in = ctx.raw_input if isinstance(ctx.raw_input, Mapping) else {}
                tool_name = str(
                    raw_in.get("tool_name")
                    or raw_in.get("toolName")
                    or raw_in.get("tool")
                    or ""
                ).strip()
                if not _is_read_only_tool(tool_name):
                    code_str = str(db_exc.code) if isinstance(db_exc, SideSessionError) else ErrorCode.LOCK_BUSY.value
                    payload = validate_hook_output(
                        "PreToolUse",
                        {
                            "continue": False,
                            "additionalContext": (
                                f"[{code_str}] side-sessions store busy or unmigrated during PreToolUse write guard; "
                                "retry after active transaction completes."
                            ),
                        },
                    )
                    json_line = json.dumps(dict(payload), ensure_ascii=False, separators=(",", ":")) + "\n"
                    _write_stream(out_stream, json_line)
                return 0
            return 0
    except SideSessionError as exc:
        err_payload = {
            "ok": False,
            "error": {
                "code": str(exc.code),
                "message": exc.message,
                "details": exc.details,
            },
        }
        _write_stream(err_stream, json.dumps(err_payload, ensure_ascii=False) + "\n")
        return 1
    except Exception as exc:
        err_payload = {
            "ok": False,
            "error": {
                "code": "HOOK_INTERNAL_ERROR",
                "message": str(exc),
            },
        }
        _write_stream(err_stream, json.dumps(err_payload, ensure_ascii=False) + "\n")
        return 1
    finally:
        if store is not None:
            try:
                store.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
