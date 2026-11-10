"""Authoritative SQLite store, file locks, safe path resolution, and atomic projection exports."""

from __future__ import annotations

from contextlib import contextmanager
import errno
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from typing import Any, Iterator, Mapping
import uuid

try:
    from .contracts import (
        DRIVER_API_VERSION,
        ENGINE_SCHEMA_VERSION,
        EXPORT_SCHEMA_VERSION,
        ErrorCode,
        ExportRef,
        SideSessionError,
        canonical_json,
        canonical_json_bytes,
        normalize_text,
        sha256_hex,
        utc_now_iso,
        validate_uuid,
    )
except ImportError:  # pragma: no cover
    from contracts import (  # type: ignore
        DRIVER_API_VERSION,
        ENGINE_SCHEMA_VERSION,
        EXPORT_SCHEMA_VERSION,
        ErrorCode,
        ExportRef,
        SideSessionError,
        canonical_json,
        canonical_json_bytes,
        normalize_text,
        sha256_hex,
        utc_now_iso,
        validate_uuid,
    )

# Worker order is session → repo_merge → maintenance(shared) → DB. Holding maintenance forbids acquiring session/repo_merge.
LOCK_ORDER: tuple[str, ...] = ("session", "repo_merge", "maintenance")
_LOCK_RANKS: dict[str, int] = {
    "supervisor": 0,
    "session": 1,
    "repo_merge": 2,
    "maintenance": 3,
}

_THREAD_LOCAL = threading.local()

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


def _get_held_locks() -> list[tuple[int, str, str]]:
    held = getattr(_THREAD_LOCAL, "held_locks", None)
    if held is None:
        held = []
        _THREAD_LOCAL.held_locks = held
    return held


def _get_in_db_txn() -> bool:
    return bool(getattr(_THREAD_LOCAL, "in_db_txn", False))


def _set_in_db_txn(val: bool) -> None:
    _THREAD_LOCAL.in_db_txn = val


def _expand_with_env_home(raw_path: str, env_map: Mapping[str, str]) -> Path:
    if raw_path.startswith("~"):
        home = env_map.get("HOME")
        if home:
            suffix = raw_path[1:].lstrip("/")
            return (Path(home) / suffix) if suffix else Path(home)
    return Path(os.path.expanduser(raw_path))


def resolve_state_root(
    env: Mapping[str, str] | None = None,
    plugin_data: Path | str | None = None,
) -> Path:
    """Resolve authoritative state root directory.

    Priority:
    1. ZCODE_SIDE_SESSIONS_HOME from `env` (or os.environ if env is None)
    2. `plugin_data/config.json` or `plugin_data/side-sessions-config.json` (`state_root` or `state_home`)
    3. Default `~/.zcode/side-sessions`
    """
    env_map: Mapping[str, str] = os.environ if env is None else env

    env_home = env_map.get("ZCODE_SIDE_SESSIONS_HOME")
    if isinstance(env_home, str) and env_home.strip():
        return _expand_with_env_home(env_home.strip(), env_map).absolute()

    data_dir: Path | None = None
    if plugin_data is not None:
        data_dir = _expand_with_env_home(str(plugin_data).strip(), env_map)
    else:
        for env_key in ("CLAUDE_PLUGIN_DATA", "ZCODE_PLUGIN_DATA"):
            val = env_map.get(env_key)
            if isinstance(val, str) and val.strip():
                data_dir = _expand_with_env_home(val.strip(), env_map)
                break

    if data_dir is not None:
        candidate_files: list[Path] = []
        if data_dir.suffix == ".json" and data_dir.is_file():
            candidate_files.append(data_dir)
        else:
            candidate_files.append(data_dir / "config.json")
            candidate_files.append(data_dir / "side-sessions-config.json")

        for cfg_path in candidate_files:
            if cfg_path.is_symlink():
                raise SideSessionError(
                    ErrorCode.SYMLINK_FORBIDDEN,
                    f"Plugin config file cannot be a symlink: {cfg_path}",
                    {"path": str(cfg_path)},
                )
            if cfg_path.is_file():
                try:
                    cfg_data = json.loads(cfg_path.read_text(encoding="utf-8"))
                except Exception as exc:
                    raise SideSessionError(
                        ErrorCode.INVALID_REQUEST,
                        f"Failed to parse plugin config JSON: {cfg_path}",
                        {"path": str(cfg_path), "error": str(exc)},
                    ) from exc
                if isinstance(cfg_data, Mapping):
                    for key in ("state_root", "state_home"):
                        raw_val = cfg_data.get(key)
                        if isinstance(raw_val, str) and raw_val.strip():
                            return _expand_with_env_home(raw_val.strip(), env_map).absolute()

    return _expand_with_env_home("~/.zcode/side-sessions", env_map).absolute()


def resolve_worktrees_home(env: Mapping[str, str] | None = None) -> Path:
    """Resolve the independent worktrees home (outside the state root).

    Priority:
    1. ZCODE_SIDE_SESSIONS_WORKTREES_HOME
    2. Default `~/.zcode/side-session-worktrees`
    """
    env_map: Mapping[str, str] = os.environ if env is None else env
    env_home = env_map.get("ZCODE_SIDE_SESSIONS_WORKTREES_HOME")
    if isinstance(env_home, str) and env_home.strip():
        return _expand_with_env_home(env_home.strip(), env_map).absolute()
    return _expand_with_env_home("~/.zcode/side-session-worktrees", env_map).absolute()


def _verify_dir_stat(st: os.stat_result, label: str) -> None:
    if stat.S_ISLNK(st.st_mode):
        raise SideSessionError(
            ErrorCode.SYMLINK_FORBIDDEN,
            f"Symlink forbidden for directory: {label}",
            {"path": label},
        )
    if not stat.S_ISDIR(st.st_mode):
        raise SideSessionError(
            ErrorCode.UNSAFE_PATH,
            f"Expected directory, got non-directory at: {label}",
            {"path": label},
        )
    if st.st_uid != os.getuid():
        raise SideSessionError(
            ErrorCode.UNSAFE_PATH,
            f"Directory owner UID ({st.st_uid}) does not match current UID ({os.getuid()}): {label}",
            {"path": label, "owner_uid": st.st_uid, "expected_uid": os.getuid()},
        )


def _verify_reg_or_dir_stat(st: os.stat_result, label: str, *, require_regular: bool = False) -> None:
    if stat.S_ISLNK(st.st_mode):
        raise SideSessionError(
            ErrorCode.SYMLINK_FORBIDDEN,
            f"Symlink forbidden at: {label}",
            {"path": label},
        )
    if require_regular:
        if not stat.S_ISREG(st.st_mode):
            raise SideSessionError(
                ErrorCode.UNSAFE_PATH,
                f"Expected regular file at: {label}",
                {"path": label},
            )
    else:
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
            raise SideSessionError(
                ErrorCode.UNSAFE_PATH,
                f"Unsupported special file type at: {label}",
                {"path": label},
            )
    if st.st_uid != os.getuid():
        raise SideSessionError(
            ErrorCode.UNSAFE_PATH,
            f"File owner UID ({st.st_uid}) does not match current UID ({os.getuid()}): {label}",
            {"path": label, "owner_uid": st.st_uid, "expected_uid": os.getuid()},
        )


def ensure_safe_dir(path: Path | str, *, mode: int = 0o700) -> Path:
    """Ensure directory exists via mkdirat + openat(O_NOFOLLOW); parent symlinks are rejected."""
    p = Path(path).absolute()
    missing: list[str] = []
    existing = p
    existing_lstat: os.stat_result | None = None
    while True:
        try:
            existing_lstat = os.lstat(existing)
            break
        except FileNotFoundError:
            if existing == existing.parent:
                raise SideSessionError(
                    ErrorCode.NOT_FOUND,
                    f"No existing ancestor for directory: {p}",
                    {"path": str(p)},
                )
            missing.append(existing.name)
            existing = existing.parent
    assert existing_lstat is not None
    if stat.S_ISLNK(existing_lstat.st_mode):
        raise SideSessionError(
            ErrorCode.SYMLINK_FORBIDDEN,
            f"Existing ancestor is a symlink: {existing}",
            {"path": str(existing)},
        )
    if not stat.S_ISDIR(existing_lstat.st_mode):
        raise SideSessionError(
            ErrorCode.UNSAFE_PATH,
            f"Existing ancestor is not a directory: {existing}",
            {"path": str(existing)},
        )
    dir_fd = os.open(str(existing), os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
    current = existing
    try:
        if not missing:
            _verify_dir_stat(os.fstat(dir_fd), str(current))
            try:
                os.fchmod(dir_fd, mode)
            except OSError:
                pass
            return current
        for part in reversed(missing):
            current = current / part
            try:
                next_fd = os.open(part, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=dir_fd)
            except FileNotFoundError:
                os.mkdir(part, mode, dir_fd=dir_fd)
                next_fd = os.open(part, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=dir_fd)
            except OSError as exc:
                if getattr(exc, "errno", None) in (errno.ELOOP, getattr(errno, "EMLINK", errno.ELOOP)):
                    raise SideSessionError(
                        ErrorCode.SYMLINK_FORBIDDEN,
                        f"Symlink component forbidden while creating directory: {current}",
                        {"path": str(current), "component": part},
                    ) from exc
                try:
                    st = os.lstat(part, dir_fd=dir_fd)
                except OSError:
                    raise
                if stat.S_ISLNK(st.st_mode):
                    raise SideSessionError(
                        ErrorCode.SYMLINK_FORBIDDEN,
                        f"Symlink component forbidden while creating directory: {current}",
                        {"path": str(current), "component": part},
                    ) from exc
                raise
            os.close(dir_fd)
            dir_fd = next_fd
            _verify_dir_stat(os.fstat(dir_fd), str(current))
        try:
            os.fchmod(dir_fd, mode)
        except OSError:
            pass
        return current
    finally:
        os.close(dir_fd)


def _validate_relative_parts(relative_path: Path | str) -> list[str]:
    if not isinstance(relative_path, (str, Path)):
        raise SideSessionError(
            ErrorCode.UNSAFE_PATH,
            "relative_path must be a string or Path",
        )
    raw = str(relative_path)
    if not raw or "\x00" in raw:
        raise SideSessionError(
            ErrorCode.UNSAFE_PATH,
            "relative_path cannot be empty or contain NUL bytes",
            {"relative_path": raw},
        )
    if "\\" in raw or raw.startswith("/"):
        raise SideSessionError(
            ErrorCode.PATH_ESCAPE,
            f"Absolute or backslash path forbidden: {raw}",
            {"relative_path": raw},
        )
    parts = raw.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise SideSessionError(
                ErrorCode.PATH_ESCAPE,
                f"Invalid path traversal segment {part!r} in {raw!r}",
                {"relative_path": raw, "segment": part},
            )
    return parts


def safe_resolve_under(
    base_dir: Path | str,
    relative_path: Path | str,
    *,
    mkdirs: bool = False,
) -> Path:
    """Safely resolve `relative_path` under `base_dir` step-by-step using O_NOFOLLOW.

    Rejects `..`, `.`, absolute paths, symlinks at any level, and UID mismatches.
    """
    base = Path(base_dir).absolute()
    try:
        base_lstat = os.lstat(base)
    except FileNotFoundError as exc:
        raise SideSessionError(
            ErrorCode.NOT_FOUND,
            f"Base directory does not exist: {base}",
            {"base_dir": str(base)},
        ) from exc
    _verify_dir_stat(base_lstat, str(base))

    parts = _validate_relative_parts(relative_path)
    canonical_base = Path(os.path.realpath(base))

    dir_fd = os.open(str(base), os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
    try:
        f_st = os.fstat(dir_fd)
        _verify_dir_stat(f_st, str(base))
        current_path = canonical_base

        for idx, part in enumerate(parts):
            is_last = idx == len(parts) - 1
            current_path = current_path / part

            try:
                comp_st = os.lstat(part, dir_fd=dir_fd)
            except FileNotFoundError:
                if is_last:
                    # Parent directory fd is verified; last component may be created by the caller.
                    break
                if mkdirs:
                    os.mkdir(part, 0o700, dir_fd=dir_fd)
                    next_fd = os.open(part, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=dir_fd)
                    os.close(dir_fd)
                    dir_fd = next_fd
                    _verify_dir_stat(os.fstat(dir_fd), str(current_path))
                    continue
                raise SideSessionError(
                    ErrorCode.NOT_FOUND,
                    f"Path component does not exist: {current_path}",
                    {"path": str(current_path), "component": part, "base_dir": str(canonical_base)},
                )

            if stat.S_ISLNK(comp_st.st_mode):
                raise SideSessionError(
                    ErrorCode.SYMLINK_FORBIDDEN,
                    f"Symlink component forbidden: {current_path}",
                    {"path": str(current_path), "component": part},
                )

            if not is_last:
                _verify_dir_stat(comp_st, str(current_path))
                next_fd = os.open(part, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=dir_fd)
                os.close(dir_fd)
                dir_fd = next_fd
                _verify_dir_stat(os.fstat(dir_fd), str(current_path))
            else:
                _verify_reg_or_dir_stat(comp_st, str(current_path))
    finally:
        os.close(dir_fd)

    # Final containment check
    try:
        rel_check = current_path.relative_to(canonical_base)
    except ValueError as exc:
        raise SideSessionError(
            ErrorCode.PATH_ESCAPE,
            f"Resolved path escapes base directory: {current_path}",
            {"base_dir": str(canonical_base), "resolved": str(current_path)},
        ) from exc
    if ".." in rel_check.parts:
        raise SideSessionError(
            ErrorCode.PATH_ESCAPE,
            f"Resolved path contains parent traversal: {current_path}",
            {"base_dir": str(canonical_base), "resolved": str(current_path)},
        )
    return current_path


def _infer_lock_kind_and_key(lock_path: Path, explicit_kind: str | None = None) -> tuple[str, str]:
    name = lock_path.name
    if explicit_kind is not None:
        kind = explicit_kind
    elif name == "maintenance.lock":
        kind = "maintenance"
    elif name == "supervisor.lock":
        kind = "supervisor"
    elif name.startswith("repo-merge-") and name.endswith(".lock"):
        kind = "repo_merge"
    elif name.startswith("session-") and name.endswith(".lock"):
        kind = "session"
    else:
        kind = "session"
    return kind, name


class FileLock:
    """Fixed side-channel file lock based on `fcntl.flock` with stable inode verification.

    Enforces lock order `session -> repo_merge -> maintenance(shared) for DB` and never replaces or unlinks
    the lock file itself. Holding maintenance forbids acquiring a session or repo_merge lock.
    """

    LOCK_ORDER = LOCK_ORDER

    def __init__(
        self,
        lock_path: Path | str,
        *,
        kind: str | None = None,
        shared: bool = False,
        timeout_ms: int | None = 3000,
        blocking: bool = True,
        check_order: bool = True,
        _for_db_txn: bool = False,
        deadline_monotonic: float | None = None,
    ) -> None:
        self.path = Path(lock_path).absolute()
        self.kind, self.lock_key = _infer_lock_kind_and_key(self.path, kind)
        if self.kind not in _LOCK_RANKS:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"Unknown lock kind: {self.kind}",
                {"kind": self.kind},
            )
        self.rank = _LOCK_RANKS[self.kind]
        self.shared = bool(shared)
        self.timeout_ms = 0 if not blocking else (3000 if timeout_ms is None else max(0, int(timeout_ms)))
        self.blocking = bool(blocking) and (self.timeout_ms > 0 or deadline_monotonic is not None)
        self.check_order = bool(check_order)
        self._for_db_txn = bool(_for_db_txn)
        self._deadline_monotonic = deadline_monotonic
        self._fd: int | None = None
        self._dev: int | None = None
        self._ino: int | None = None
        self._held_entry: tuple[int, str, str] | None = None

    @property
    def is_locked(self) -> bool:
        return self._fd is not None

    def _check_lock_order_before_acquire(self) -> None:
        if not self.check_order:
            return
        if self.kind in ("session", "repo_merge") and _get_in_db_txn():
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"Lock order violation: cannot acquire {self.kind} lock while inside an active DB transaction",
                {"requested_lock": self.lock_key, "lock_order": list(LOCK_ORDER)},
            )
        held = _get_held_locks()
        for held_rank, held_kind, held_key in held:
            if held_key == self.lock_key:
                raise SideSessionError(
                    ErrorCode.LOCK_BUSY,
                    f"Lock {self.lock_key} is already held on this thread",
                    {"lock": self.lock_key},
                )
            if held_kind == "maintenance" and self.kind in ("session", "repo_merge"):
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    f"Lock order violation: cannot acquire {self.kind} lock while holding maintenance lock",
                    {"held_lock": held_key, "requested_lock": self.lock_key, "lock_order": list(LOCK_ORDER)},
                )
            if held_kind in ("session", "repo_merge") and self.kind == "maintenance" and not self.shared:
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    f"Lock order violation: cannot acquire exclusive maintenance lock while holding {held_kind} lock",
                    {"held_lock": held_key, "requested_lock": self.lock_key},
                )
            if held_rank > self.rank:
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    f"Lock order violation: cannot acquire {self.kind} lock ({self.lock_key}) while holding {held_kind} lock ({held_key}); required order is session -> repo_merge -> maintenance",
                    {
                        "held_kind": held_kind,
                        "held_lock": held_key,
                        "requested_kind": self.kind,
                        "requested_lock": self.lock_key,
                        "lock_order": list(LOCK_ORDER),
                    },
                )
            if held_rank == self.rank and self.kind in ("session", "repo_merge") and held_key > self.lock_key:
                raise SideSessionError(
                    ErrorCode.INVALID_REQUEST,
                    f"Lock order violation between {self.kind} locks: {held_key} held before {self.lock_key}",
                    {"held_lock": held_key, "requested_lock": self.lock_key},
                )

    def acquire(
        self,
        *,
        blocking: bool | None = None,
        timeout_ms: int | None = None,
        shared: bool | None = None,
        deadline_monotonic: float | None = None,
    ) -> FileLock:
        if self._fd is not None:
            return self

        if shared is not None:
            self.shared = bool(shared)
        use_blocking = self.blocking if blocking is None else bool(blocking)
        use_timeout_ms = self.timeout_ms if timeout_ms is None else max(0, int(timeout_ms))
        if not use_blocking:
            use_timeout_ms = 0

        self._check_lock_order_before_acquire()

        parent_dir = ensure_safe_dir(self.path.parent, mode=0o700)
        lock_file_path = parent_dir / self.path.name

        if lock_file_path.is_symlink():
            raise SideSessionError(
                ErrorCode.SYMLINK_FORBIDDEN,
                f"Lock file cannot be a symlink: {lock_file_path}",
                {"path": str(lock_file_path)},
            )

        fd = os.open(
            str(lock_file_path),
            os.O_CREAT | os.O_RDWR | _O_NOFOLLOW,
            0o600,
        )
        try:
            st = os.fstat(fd)
            _verify_reg_or_dir_stat(st, str(lock_file_path), require_regular=True)

            op = fcntl.LOCK_SH if self.shared else fcntl.LOCK_EX
            deadline = time.monotonic() + (use_timeout_ms / 1000.0)
            eff_dl_mono = deadline_monotonic if deadline_monotonic is not None else self._deadline_monotonic
            if eff_dl_mono is not None:
                deadline = min(deadline, eff_dl_mono) if use_blocking else eff_dl_mono

            while True:
                try:
                    fcntl.flock(fd, op | fcntl.LOCK_NB)
                    break
                except (BlockingIOError, OSError) as exc:
                    rem = deadline - time.monotonic()
                    if not use_blocking or rem <= 0:
                        raise SideSessionError(
                            ErrorCode.LOCK_BUSY,
                            f"Timed out acquiring lock {lock_file_path.name}",
                            {
                                "lock": lock_file_path.name,
                                "kind": self.kind,
                                "shared": self.shared,
                                "timeout_ms": use_timeout_ms,
                            },
                            retryable=True,
                        ) from exc
                    time.sleep(min(0.005, max(0.0, rem)))

            # Verify the lock file on disk was not replaced or unlinked while acquiring
            try:
                disk_st = os.lstat(lock_file_path)
            except FileNotFoundError as exc:
                fcntl.flock(fd, fcntl.LOCK_UN)
                raise SideSessionError(
                    ErrorCode.LOCK_REPLACED,
                    f"Lock file was unlinked during acquisition: {lock_file_path}",
                    {"path": str(lock_file_path)},
                ) from exc

            if disk_st.st_ino != st.st_ino or disk_st.st_dev != st.st_dev:
                fcntl.flock(fd, fcntl.LOCK_UN)
                raise SideSessionError(
                    ErrorCode.LOCK_REPLACED,
                    f"Lock file inode was replaced: {lock_file_path}",
                    {
                        "path": str(lock_file_path),
                        "expected_ino": st.st_ino,
                        "actual_ino": disk_st.st_ino,
                    },
                )

            self.path = lock_file_path
            self._fd = fd
            self._dev = st.st_dev
            self._ino = st.st_ino
            entry = (self.rank, self.kind, self.lock_key)
            self._held_entry = entry
            _get_held_locks().append(entry)
            return self
        except Exception:
            os.close(fd)
            raise

    def verify_inode(self) -> None:
        """Verify that the held lock file still has the identical inode on disk."""
        if self._fd is None:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"Lock {self.lock_key} is not currently held",
            )
        try:
            disk_st = os.lstat(self.path)
        except FileNotFoundError as exc:
            raise SideSessionError(
                ErrorCode.LOCK_REPLACED,
                f"Held lock file was unlinked: {self.path}",
                {"path": str(self.path)},
            ) from exc
        if disk_st.st_ino != self._ino or disk_st.st_dev != self._dev:
            raise SideSessionError(
                ErrorCode.LOCK_REPLACED,
                f"Held lock file was replaced on disk: {self.path}",
                {
                    "path": str(self.path),
                    "expected_ino": self._ino,
                    "actual_ino": disk_st.st_ino,
                },
            )

    def release(self) -> None:
        if self._fd is None:
            return
        fd = self._fd
        entry = self._held_entry
        held = _get_held_locks()
        if entry is None or not held or held[-1] != entry:
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"Lock release order violation: {self.lock_key} is not the most recently acquired lock (LIFO required)",
                {
                    "requested_release": self.lock_key,
                    "held_locks": [k for _, _, k in held],
                },
            )
        held.pop()
        self._fd = None
        self._held_entry = None
        try:
            self.verify_inode_before_close(fd)
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def verify_inode_before_close(self, fd: int) -> None:
        try:
            disk_st = os.lstat(self.path)
        except FileNotFoundError as exc:
            raise SideSessionError(
                ErrorCode.LOCK_REPLACED,
                f"Lock file was unlinked while held: {self.path}",
                {"path": str(self.path)},
            ) from exc
        if disk_st.st_ino != self._ino or disk_st.st_dev != self._dev:
            raise SideSessionError(
                ErrorCode.LOCK_REPLACED,
                f"Lock file inode changed while held: {self.path}",
                {
                    "path": str(self.path),
                    "expected_ino": self._ino,
                    "actual_ino": disk_st.st_ino,
                },
            )

    def __enter__(self) -> FileLock:
        return self.acquire()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()


def _build_sync_triggers_sql(
    table_a: str,
    table_b: str,
    pk_cols: list[str],
    all_cols: list[str],
) -> str:
    cols_csv = ", ".join(all_cols)
    new_cols_csv = ", ".join(f"NEW.{c}" for c in all_cols)
    pk_match_new = " AND ".join(f"{c} = NEW.{c}" for c in pk_cols)
    pk_match_old = " AND ".join(f"{c} = OLD.{c}" for c in pk_cols)
    set_clause = ", ".join(f"{c} = NEW.{c}" for c in all_cols)
    diff_clause = " OR ".join(f"{c} IS NOT NEW.{c}" for c in all_cols)

    return f"""
    CREATE TRIGGER IF NOT EXISTS trg_sync_{table_a}_to_{table_b}_ins
    AFTER INSERT ON {table_a}
    BEGIN
        INSERT INTO {table_b} ({cols_csv})
        SELECT {new_cols_csv}
        WHERE NOT EXISTS (SELECT 1 FROM {table_b} WHERE {pk_match_new});
    END;

    CREATE TRIGGER IF NOT EXISTS trg_sync_{table_b}_to_{table_a}_ins
    AFTER INSERT ON {table_b}
    BEGIN
        INSERT INTO {table_a} ({cols_csv})
        SELECT {new_cols_csv}
        WHERE NOT EXISTS (SELECT 1 FROM {table_a} WHERE {pk_match_new});
    END;

    CREATE TRIGGER IF NOT EXISTS trg_sync_{table_a}_to_{table_b}_upd
    AFTER UPDATE ON {table_a}
    BEGIN
        UPDATE {table_b}
        SET {set_clause}
        WHERE {pk_match_old} AND ({diff_clause});
    END;

    CREATE TRIGGER IF NOT EXISTS trg_sync_{table_b}_to_{table_a}_upd
    AFTER UPDATE ON {table_b}
    BEGIN
        UPDATE {table_a}
        SET {set_clause}
        WHERE {pk_match_old} AND ({diff_clause});
    END;

    CREATE TRIGGER IF NOT EXISTS trg_sync_{table_a}_to_{table_b}_del
    AFTER DELETE ON {table_a}
    BEGIN
        DELETE FROM {table_b} WHERE {pk_match_old};
    END;

    CREATE TRIGGER IF NOT EXISTS trg_sync_{table_b}_to_{table_a}_del
    AFTER DELETE ON {table_b}
    BEGIN
        DELETE FROM {table_a} WHERE {pk_match_old};
    END;
    """


_SCHEMA_DDL = (
    """
    CREATE TABLE IF NOT EXISTS schema_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1) DEFAULT 1,
        store_instance_id TEXT NOT NULL,
        engine_schema_version TEXT NOT NULL DEFAULT '1.2',
        driver_api_version TEXT NOT NULL DEFAULT '1.1',
        export_version TEXT NOT NULL DEFAULT '1.1',
        revision INTEGER NOT NULL DEFAULT 0,
        maintenance_state TEXT NOT NULL DEFAULT 'normal',
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS store_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1) DEFAULT 1,
        store_instance_id TEXT NOT NULL,
        engine_schema_version TEXT NOT NULL DEFAULT '1.2',
        driver_api_version TEXT NOT NULL DEFAULT '1.1',
        export_version TEXT NOT NULL DEFAULT '1.1',
        revision INTEGER NOT NULL DEFAULT 0,
        maintenance_state TEXT NOT NULL DEFAULT 'normal',
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS nodes (
        node_id TEXT PRIMARY KEY,
        runtime_session_id TEXT UNIQUE,
        parent_node_id TEXT REFERENCES nodes(node_id),
        root_node_id TEXT NOT NULL,
        name TEXT NOT NULL,
        title TEXT NOT NULL DEFAULT '',
        node_status TEXT NOT NULL DEFAULT 'active' CHECK (node_status IN ('active', 'paused', 'done', 'archived')),
        pause_requested INTEGER NOT NULL DEFAULT 0,
        task_kind TEXT NOT NULL DEFAULT 'read_only' CHECK (task_kind IN ('read_only', 'write_code')),
        context_requested TEXT NOT NULL DEFAULT 'fresh' CHECK (context_requested IN ('fresh', 'fork')),
        context_applied TEXT NOT NULL DEFAULT 'fresh' CHECK (context_applied IN ('fresh', 'native_fork', 'summary_copy', 'brief_only')),
        workspace_mode TEXT NOT NULL DEFAULT 'inherit' CHECK (workspace_mode IN ('inherit', 'branch')),
        canonical_workspace TEXT,
        repo_root TEXT,
        base_commit TEXT,
        host_link_verified INTEGER NOT NULL DEFAULT 0,
        recovery_status TEXT NOT NULL DEFAULT 'topology_restored' CHECK (recovery_status IN ('topology_restored', 'runtime_resumable', 'needs_rehydration', 'orphaned')),
        last_turn_report TEXT NOT NULL DEFAULT '',
        last_turn_seq INTEGER NOT NULL DEFAULT 0,
        primary_task_id TEXT,
        shared_context_revision INTEGER NOT NULL DEFAULT 0,
        shared_context_content TEXT NOT NULL DEFAULT '',
        brief_id TEXT,
        brief_revision INTEGER NOT NULL DEFAULT 0,
        brief_hash TEXT,
        brief_content TEXT NOT NULL DEFAULT '',
        driver_kind TEXT DEFAULT 'zcode',
        driver_api_version TEXT DEFAULT '1.1',
        host_version TEXT DEFAULT '0.17.1',
        protocol_revision TEXT DEFAULT '1.1',
        runtime_store_ref TEXT,
        capability_fingerprint TEXT,
        revision INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT ''
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_parent_name
    ON nodes(parent_node_id, name) WHERE parent_node_id IS NOT NULL;

    CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_root_name
    ON nodes(name) WHERE parent_node_id IS NULL;

    CREATE TABLE IF NOT EXISTS bindings (
        runtime_sid TEXT PRIMARY KEY,
        node_id TEXT NOT NULL REFERENCES nodes(node_id),
        schema_version TEXT NOT NULL DEFAULT '1.1',
        last_turn_id TEXT,
        cwd TEXT NOT NULL DEFAULT '',
        last_seen_at TEXT NOT NULL DEFAULT '',
        db_check_state TEXT NOT NULL DEFAULT 'pending' CHECK (db_check_state IN ('pending', 'verified', 'mismatch', 'missing', 'deleted', 'archived'))
    );

    CREATE TABLE IF NOT EXISTS proposals (
        proposal_id TEXT PRIMARY KEY,
        parent_node_id TEXT NOT NULL REFERENCES nodes(node_id),
        kind TEXT NOT NULL CHECK (kind IN ('offer', 'full', 'user_asked', 'own_initiative')),
        state TEXT NOT NULL CHECK (state IN ('waiting_user', 'awaiting_brief', 'approved', 'claiming', 'started', 'dismissed', 'expired', 'cleared', 'failed', 'reconciliation')),
        canonical_task TEXT NOT NULL DEFAULT '{}',
        task_hash TEXT NOT NULL DEFAULT '',
        approval_source TEXT,
        approval_id TEXT,
        approved_task_hash TEXT,
        expires_at TEXT NOT NULL,
        child_node_id TEXT,
        request_id TEXT NOT NULL,
        operation_id TEXT,
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS requests (
        actor_node_id TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        request_id TEXT NOT NULL,
        normalized_hash TEXT NOT NULL,
        result TEXT NOT NULL DEFAULT '{}',
        operation_id TEXT,
        created_at TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (actor_node_id, tool_name, request_id)
    );

    CREATE TABLE IF NOT EXISTS parent_slots (
        parent_node_id TEXT NOT NULL REFERENCES nodes(node_id),
        slot_no INTEGER NOT NULL CHECK (slot_no BETWEEN 1 AND 4),
        node_id TEXT NOT NULL,
        operation_id TEXT,
        run_id TEXT,
        state TEXT NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved', 'starting', 'running', 'waiting_input', 'stopping', 'reconciliation', 'released')),
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (parent_node_id, slot_no)
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_parent_slots_active_node
    ON parent_slots(node_id) WHERE state != 'released';

    CREATE TABLE IF NOT EXISTS slots (
        parent_node_id TEXT NOT NULL REFERENCES nodes(node_id),
        slot_no INTEGER NOT NULL CHECK (slot_no BETWEEN 1 AND 4),
        node_id TEXT NOT NULL,
        operation_id TEXT,
        run_id TEXT,
        state TEXT NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved', 'starting', 'running', 'waiting_input', 'stopping', 'reconciliation', 'released')),
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (parent_node_id, slot_no)
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_slots_active_node
    ON slots(node_id) WHERE state != 'released';

    CREATE TABLE IF NOT EXISTS dispatch_groups (
        dispatch_group_id TEXT PRIMARY KEY,
        parent_node_id TEXT NOT NULL REFERENCES nodes(node_id),
        batch_id TEXT,
        assembly_state TEXT NOT NULL DEFAULT 'open' CHECK (assembly_state IN ('open', 'sealed', 'closed_incomplete')),
        completion_state TEXT NOT NULL DEFAULT 'pending' CHECK (completion_state IN ('pending', 'completed')),
        integrity_state TEXT NOT NULL DEFAULT 'ok' CHECK (integrity_state IN ('ok', 'reconciliation')),
        expected_member_count INTEGER NOT NULL CHECK (expected_member_count BETWEEN 1 AND 4),
        member_count INTEGER NOT NULL DEFAULT 0 CHECK (member_count BETWEEN 0 AND 4),
        revision INTEGER NOT NULL DEFAULT 1,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT '',
        seal_deadline TEXT,
        sealed_at TEXT,
        incomplete_acknowledged INTEGER NOT NULL DEFAULT 0,
        manifest_ref TEXT
    );

    CREATE TABLE IF NOT EXISTS dispatch_group_members (
        member_id TEXT PRIMARY KEY,
        dispatch_group_id TEXT NOT NULL REFERENCES dispatch_groups(dispatch_group_id),
        node_id TEXT NOT NULL,
        message_id TEXT NOT NULL UNIQUE,
        operation_id TEXT,
        run_id TEXT UNIQUE,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 1),
        state TEXT NOT NULL DEFAULT 'admitted' CHECK (state IN ('admitted', 'queued', 'starting', 'running', 'waiting_input', 'terminal', 'reconciliation')),
        outcome TEXT,
        exit_confirmed TEXT,
        report_id TEXT,
        terminal_reason TEXT,
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT '',
        UNIQUE (dispatch_group_id, ordinal)
    );

    CREATE TABLE IF NOT EXISTS dispatch_members (
        member_id TEXT PRIMARY KEY,
        dispatch_group_id TEXT NOT NULL REFERENCES dispatch_groups(dispatch_group_id),
        node_id TEXT NOT NULL,
        message_id TEXT NOT NULL UNIQUE,
        operation_id TEXT,
        run_id TEXT UNIQUE,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 1),
        state TEXT NOT NULL DEFAULT 'admitted' CHECK (state IN ('admitted', 'queued', 'starting', 'running', 'waiting_input', 'terminal', 'reconciliation')),
        outcome TEXT,
        exit_confirmed TEXT,
        report_id TEXT,
        terminal_reason TEXT,
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT '',
        UNIQUE (dispatch_group_id, ordinal)
    );

    CREATE TABLE IF NOT EXISTS operations (
        operation_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL,
        node_id TEXT,
        actor_node_id TEXT NOT NULL,
        task_id TEXT,
        kind TEXT NOT NULL DEFAULT 'start_session',
        requested_group_id TEXT,
        member_id TEXT,
        source_cutoff TEXT,
        context_snapshot_id TEXT,
        context_acceptance_id TEXT,
        stage TEXT NOT NULL CHECK (stage IN ('preparing_context', 'awaiting_context_acceptance', 'ready_for_admission', 'reserved', 'worktree_created', 'session_created', 'brief_accepted', 'running', 'finished', 'failed', 'reconciliation')),
        attempt INTEGER NOT NULL DEFAULT 1,
        external_ids TEXT NOT NULL DEFAULT '{}',
        expected_paths TEXT NOT NULL DEFAULT '{}',
        result_state TEXT,
        error TEXT,
        revision INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS context_snapshots (
        snapshot_id TEXT PRIMARY KEY,
        operation_id TEXT NOT NULL,
        source_node_id TEXT NOT NULL,
        source_runtime_sid TEXT NOT NULL,
        source_turn_id TEXT,
        source_revision INTEGER,
        task_revision INTEGER,
        anchor_json TEXT NOT NULL DEFAULT '{}',
        history_quality TEXT NOT NULL CHECK (history_quality IN ('stable_projection', 'brief_only')),
        projection_ref TEXT,
        projection_sha256 TEXT,
        brief_hash TEXT NOT NULL,
        snapshot_hash TEXT NOT NULL UNIQUE,
        excluded_ranges TEXT NOT NULL DEFAULT '[]',
        reason TEXT,
        created_at TEXT NOT NULL DEFAULT '',
        expires_at TEXT,
        state TEXT NOT NULL DEFAULT 'candidate' CHECK (state IN ('candidate', 'authorized', 'stale', 'rejected', 'expired'))
    );

    CREATE TABLE IF NOT EXISTS context_acceptances (
        acceptance_id TEXT PRIMARY KEY,
        operation_id TEXT NOT NULL,
        snapshot_hash TEXT NOT NULL,
        history_quality TEXT NOT NULL CHECK (history_quality IN ('stable_projection', 'brief_only')),
        brief_hash TEXT NOT NULL,
        task_hash TEXT,
        task_revision INTEGER,
        approved_by TEXT NOT NULL,
        input_id TEXT NOT NULL,
        approval_evidence_ref TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'used', 'stale', 'expired', 'rejected')),
        created_at TEXT NOT NULL DEFAULT '',
        UNIQUE (operation_id, snapshot_hash, history_quality)
    );

    CREATE TABLE IF NOT EXISTS worktrees (
        worktree_id TEXT PRIMARY KEY,
        node_id TEXT NOT NULL,
        operation_id TEXT NOT NULL,
        canonical_worktree_path TEXT NOT NULL UNIQUE,
        worktrees_home TEXT NOT NULL,
        workspace_mode TEXT NOT NULL DEFAULT 'branch',
        repo_key TEXT,
        repo_root TEXT,
        base_commit TEXT,
        branch TEXT UNIQUE,
        source_patch_hash TEXT,
        ownership_marker TEXT,
        state TEXT NOT NULL DEFAULT 'created' CHECK (state IN ('created', 'verified', 'in_use', 'merged', 'cleaned', 'retained_dirty', 'reconciliation')),
        last_known_tip TEXT,
        merged_into_ref TEXT,
        merged_commit TEXT,
        merged_tree TEXT,
        merge_mode TEXT,
        pre_parent_head TEXT,
        cleaned_at TEXT,
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS inbox_messages (
        message_id TEXT NOT NULL,
        target_node_id TEXT NOT NULL,
        source_node_id TEXT NOT NULL,
        seq INTEGER NOT NULL CHECK (seq >= 1),
        delivery_kind TEXT NOT NULL DEFAULT 'managed_dispatch' CHECK (delivery_kind IN ('managed_dispatch', 'owner_input')),
        dispatch_group_id TEXT,
        member_id TEXT UNIQUE,
        task_id TEXT,
        payload_hash TEXT NOT NULL,
        payload TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'claimed', 'running', 'completed', 'failed', 'cancelled', 'reconciliation')),
        run_id TEXT,
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (target_node_id, message_id),
        UNIQUE (target_node_id, seq)
    );

    CREATE TABLE IF NOT EXISTS messages (
        message_id TEXT NOT NULL,
        target_node_id TEXT NOT NULL,
        source_node_id TEXT NOT NULL,
        seq INTEGER NOT NULL CHECK (seq >= 1),
        delivery_kind TEXT NOT NULL DEFAULT 'managed_dispatch' CHECK (delivery_kind IN ('managed_dispatch', 'owner_input')),
        dispatch_group_id TEXT,
        member_id TEXT UNIQUE,
        task_id TEXT,
        payload_hash TEXT NOT NULL,
        payload TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'claimed', 'running', 'completed', 'failed', 'cancelled', 'reconciliation')),
        run_id TEXT,
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (target_node_id, message_id),
        UNIQUE (target_node_id, seq)
    );

    CREATE TABLE IF NOT EXISTS owners (
        node_id TEXT PRIMARY KEY,
        worker_id TEXT NOT NULL,
        owner_token TEXT NOT NULL,
        owner_epoch INTEGER NOT NULL DEFAULT 1,
        fencing_token TEXT NOT NULL,
        pid INTEGER,
        process_started_at TEXT,
        process_group INTEGER,
        model_pid INTEGER,
        model_started_at TEXT,
        runtime_instance_id TEXT,
        current_run_id TEXT,
        heartbeat TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT 'active'
    );

    CREATE TABLE IF NOT EXISTS turns (
        run_id TEXT PRIMARY KEY,
        node_id TEXT NOT NULL,
        turn_seq INTEGER NOT NULL CHECK (turn_seq >= 1),
        worker_turn_id TEXT NOT NULL UNIQUE,
        runtime_turn_id TEXT,
        input_id TEXT,
        message_id TEXT NOT NULL,
        dispatch_group_id TEXT,
        member_id TEXT UNIQUE,
        task_id TEXT,
        task_revision INTEGER,
        owner_epoch INTEGER NOT NULL DEFAULT 1,
        fencing_token TEXT NOT NULL DEFAULT '',
        execution_state TEXT NOT NULL DEFAULT 'queued' CHECK (execution_state IN ('queued', 'starting', 'running', 'waiting_input', 'stopping', 'exited', 'failed', 'cancelled', 'reconciliation')),
        report_state TEXT NOT NULL DEFAULT 'none' CHECK (report_state IN ('none', 'checkpointed', 'final')),
        outcome TEXT,
        exit_code INTEGER,
        cancel_requested_at TEXT,
        cancel_reason TEXT,
        started_at TEXT,
        ended_at TEXT,
        UNIQUE (node_id, turn_seq)
    );

    CREATE TABLE IF NOT EXISTS reports (
        report_id TEXT PRIMARY KEY,
        node_id TEXT NOT NULL,
        turn_seq INTEGER NOT NULL,
        run_id TEXT NOT NULL,
        phase TEXT NOT NULL CHECK (phase IN ('checkpoint', 'final')),
        report_revision INTEGER,
        canonical_json TEXT NOT NULL,
        semantic_sha256 TEXT NOT NULL,
        full_report_ref TEXT NOT NULL,
        artifact_ref TEXT,
        artifact_sha256 TEXT,
        outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failed', 'cancelled', 'blocked')),
        origin TEXT NOT NULL DEFAULT 'child' CHECK (origin IN ('child', 'runner')),
        created_at TEXT NOT NULL DEFAULT ''
    );

    CREATE UNIQUE INDEX IF NOT EXISTS one_final_per_turn
    ON reports(node_id, turn_seq) WHERE phase = 'final';

    CREATE UNIQUE INDEX IF NOT EXISTS one_checkpoint_revision
    ON reports(node_id, turn_seq, report_revision) WHERE phase = 'checkpoint';

    CREATE TABLE IF NOT EXISTS artifacts (
        artifact_id TEXT PRIMARY KEY,
        owner_node_id TEXT NOT NULL,
        run_id TEXT,
        kind TEXT NOT NULL DEFAULT 'blob',
        storage_kind TEXT NOT NULL CHECK (storage_kind IN ('inline', 'blob')),
        inline_bytes BLOB,
        relative_blob_path TEXT,
        sha256 TEXT NOT NULL,
        byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
        media_type TEXT NOT NULL DEFAULT 'application/octet-stream',
        state TEXT NOT NULL DEFAULT 'staged' CHECK (state IN ('staged', 'published')),
        source_manifest TEXT,
        created_at TEXT NOT NULL DEFAULT '',
        CHECK (
            (storage_kind = 'inline' AND inline_bytes IS NOT NULL AND relative_blob_path IS NULL)
            OR (storage_kind = 'blob' AND inline_bytes IS NULL AND relative_blob_path IS NOT NULL)
        )
    );

    CREATE TABLE IF NOT EXISTS outbox_events (
        event_id TEXT PRIMARY KEY,
        event_seq INTEGER NOT NULL UNIQUE,
        producer_key TEXT NOT NULL UNIQUE,
        parent_node_id TEXT NOT NULL,
        parent_session_id TEXT,
        child_node_id TEXT,
        child_session_id TEXT,
        child_turn_id TEXT,
        turn_seq INTEGER,
        run_id TEXT,
        dispatch_group_id TEXT,
        member_id TEXT,
        kind TEXT NOT NULL,
        payload TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'presented', 'acked')),
        presented_in_turn TEXT,
        lease_owner TEXT,
        lease_until TEXT,
        attempt_count INTEGER NOT NULL DEFAULT 0,
        acked_at TEXT,
        created_at TEXT NOT NULL DEFAULT ''
    );

    CREATE UNIQUE INDEX IF NOT EXISTS one_event_kind_per_turn_events
    ON outbox_events(child_node_id, turn_seq, kind);

    CREATE TABLE IF NOT EXISTS outbox (
        event_id TEXT PRIMARY KEY,
        event_seq INTEGER NOT NULL UNIQUE,
        producer_key TEXT NOT NULL UNIQUE,
        parent_node_id TEXT NOT NULL,
        parent_session_id TEXT,
        child_node_id TEXT,
        child_session_id TEXT,
        child_turn_id TEXT,
        turn_seq INTEGER,
        run_id TEXT,
        dispatch_group_id TEXT,
        member_id TEXT,
        kind TEXT NOT NULL,
        payload TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'presented', 'acked')),
        presented_in_turn TEXT,
        lease_owner TEXT,
        lease_until TEXT,
        attempt_count INTEGER NOT NULL DEFAULT 0,
        acked_at TEXT,
        created_at TEXT NOT NULL DEFAULT ''
    );

    CREATE UNIQUE INDEX IF NOT EXISTS one_event_kind_per_turn
    ON outbox(child_node_id, turn_seq, kind);

    CREATE TABLE IF NOT EXISTS event_acks (
        event_id TEXT NOT NULL,
        consumer_parent_node_id TEXT NOT NULL,
        receipt_kind TEXT NOT NULL DEFAULT 'explicit_ack',
        receipt_ref TEXT NOT NULL DEFAULT '',
        acked_at TEXT NOT NULL,
        PRIMARY KEY (event_id, consumer_parent_node_id, receipt_kind, receipt_ref)
    );

    CREATE TABLE IF NOT EXISTS wake_budget (
        parent_node_id TEXT PRIMARY KEY,
        user_epoch INTEGER NOT NULL DEFAULT 0,
        last_verified_human_input_id TEXT,
        wake_count INTEGER NOT NULL DEFAULT 0 CHECK (wake_count BETWEEN 0 AND 10),
        wake_inflight TEXT,
        parent_stop_state TEXT NOT NULL DEFAULT 'idle',
        pending_human INTEGER NOT NULL DEFAULT 0,
        pending_permission INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS wake_state (
        parent_node_id TEXT PRIMARY KEY,
        user_epoch INTEGER NOT NULL DEFAULT 0,
        last_verified_human_input_id TEXT,
        wake_count INTEGER NOT NULL DEFAULT 0 CHECK (wake_count BETWEEN 0 AND 10),
        wake_inflight TEXT,
        parent_stop_state TEXT NOT NULL DEFAULT 'idle',
        pending_human INTEGER NOT NULL DEFAULT 0,
        pending_permission INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS group_wakes (
        parent_node_id TEXT NOT NULL,
        user_epoch INTEGER NOT NULL,
        dispatch_group_id TEXT NOT NULL,
        reservation_id TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'reserved',
        host_input_id TEXT,
        created_at TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (parent_node_id, user_epoch, dispatch_group_id)
    );

    CREATE TABLE IF NOT EXISTS tasks (
        task_id TEXT PRIMARY KEY,
        origin_node_id TEXT NOT NULL,
        owner_node_id TEXT NOT NULL,
        title TEXT NOT NULL,
        remaining_plan TEXT NOT NULL,
        task_kind TEXT NOT NULL CHECK (task_kind IN ('read_only', 'write_code')),
        scope_json TEXT NOT NULL DEFAULT '{}',
        state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'transfer_preparing', 'transferring', 'paused', 'done')),
        task_revision INTEGER NOT NULL DEFAULT 1 CHECK (task_revision >= 1),
        last_stable_anchor TEXT,
        current_transfer_id TEXT,
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS task_turn_bindings (
        binding_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(task_id),
        node_id TEXT NOT NULL,
        runtime_sid TEXT NOT NULL,
        runtime_turn_id TEXT NOT NULL,
        task_revision INTEGER NOT NULL,
        state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'frozen', 'released')),
        created_at TEXT NOT NULL DEFAULT ''
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_binding_per_turn
    ON task_turn_bindings(runtime_sid, runtime_turn_id) WHERE state = 'active';

    CREATE TABLE IF NOT EXISTS task_actions (
        action_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(task_id),
        task_revision INTEGER NOT NULL,
        binding_id TEXT NOT NULL REFERENCES task_turn_bindings(binding_id),
        runtime_sid TEXT NOT NULL DEFAULT '',
        runtime_turn_id TEXT NOT NULL,
        tool_use_id TEXT NOT NULL,
        scope_digest TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'admitted' CHECK (state IN ('admitted', 'running', 'completed', 'failed', 'unknown')),
        result_ref TEXT,
        started_at TEXT NOT NULL DEFAULT '',
        ended_at TEXT,
        UNIQUE (tool_use_id, runtime_sid)
    );

    CREATE TABLE IF NOT EXISTS task_guards (
        guard_id TEXT PRIMARY KEY,
        transfer_id TEXT NOT NULL UNIQUE,
        task_id TEXT NOT NULL REFERENCES tasks(task_id),
        task_revision INTEGER NOT NULL,
        source_owner_id TEXT NOT NULL,
        scope_digest TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('requested', 'prepared', 'committed', 'resume_requested', 'resumed', 'unknown')),
        inflight_action_ids TEXT NOT NULL DEFAULT '[]',
        stable_anchor TEXT,
        receipt_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS transfers (
        transfer_id TEXT PRIMARY KEY,
        source_node_id TEXT NOT NULL,
        child_node_id TEXT,
        task_id TEXT NOT NULL REFERENCES tasks(task_id),
        source_task_revision INTEGER NOT NULL,
        source_scope_json TEXT NOT NULL DEFAULT '{}',
        target_scope_json TEXT NOT NULL DEFAULT '{}',
        guard_id TEXT,
        context_snapshot_id TEXT,
        state TEXT NOT NULL DEFAULT 'preparing' CHECK (state IN ('preparing', 'transferring', 'brief_accepted', 'committed', 'failed', 'reconciliation')),
        brief_id TEXT,
        brief_hash TEXT,
        accepted_receipt TEXT,
        operation_id TEXT,
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS wait_requests (
        wait_id TEXT PRIMARY KEY,
        node_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        runtime_turn_id TEXT,
        runtime_instance_id TEXT NOT NULL,
        owner_epoch INTEGER NOT NULL,
        host_request_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('input', 'elicitation', 'permission')),
        nonce TEXT NOT NULL,
        question TEXT NOT NULL DEFAULT '',
        options TEXT NOT NULL DEFAULT '[]',
        required_authority TEXT NOT NULL DEFAULT 'human' CHECK (required_authority IN ('human', 'parent_agent_allowed')),
        deadline_at TEXT,
        state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'responding', 'resolved', 'expired', 'cancelled', 'unknown')),
        response_hash TEXT,
        receipt_ref TEXT,
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT '',
        UNIQUE (host_request_id, runtime_instance_id)
    );

    CREATE INDEX IF NOT EXISTS idx_wait_requests_node_state
    ON wait_requests(node_id, state);

    CREATE TABLE IF NOT EXISTS control_commands (
        control_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        node_id TEXT NOT NULL,
        run_id TEXT,
        owner_epoch INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('respond_wait', 'cancel_run')),
        wait_id TEXT,
        payload_hash TEXT NOT NULL,
        payload TEXT NOT NULL,
        authority_ref TEXT,
        state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'claimed', 'applied', 'rejected', 'unknown')),
        receipt_ref TEXT,
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS note_entries (
        entry_id TEXT PRIMARY KEY,
        owner_node_id TEXT NOT NULL,
        author_node_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        content TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        artifact_ref TEXT,
        created_at TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS input_provenance (
        owner_id TEXT NOT NULL,
        input_id TEXT NOT NULL,
        runtime_turn_id TEXT,
        origin TEXT NOT NULL,
        command_id TEXT,
        evidence_ref TEXT,
        verified INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT '',
        runtime_session_id TEXT,
        action_binding_json TEXT,
        PRIMARY KEY (owner_id, input_id)
    );

    CREATE TABLE IF NOT EXISTS approval_consumptions (
        consumption_id TEXT PRIMARY KEY,
        owner_id TEXT NOT NULL,
        input_id TEXT NOT NULL,
        runtime_session_id TEXT,
        purpose TEXT NOT NULL CHECK (purpose IN ('proposal','context_quality','wait_response','worktree_merge')),
        target_id TEXT NOT NULL,
        target_hash TEXT NOT NULL,
        action_hash TEXT NOT NULL,
        request_id TEXT NOT NULL,
        consumed_at TEXT NOT NULL,
        UNIQUE (owner_id, input_id)
    );

    CREATE TABLE IF NOT EXISTS proposal_claim_jobs (
        proposal_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL CHECK (state IN ('queued','running','completed','failed')),
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS worktree_jobs (
        job_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        node_id TEXT NOT NULL,
        worktree_id TEXT NOT NULL,
        repo_key TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('merge','cleanup')),
        mode TEXT CHECK (mode IN ('ff-only','merge','squash')),
        cleanup_after INTEGER NOT NULL DEFAULT 0,
        preview_hash TEXT NOT NULL,
        approval_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('queued','running','prepared','completed','failed','reconciliation')),
        candidate_commit TEXT,
        candidate_tree TEXT,
        lease_until TEXT,
        result_json TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS desktop_index_probe (
        node_id TEXT PRIMARY KEY,
        state TEXT NOT NULL CHECK (state IN ('pending', 'indexed', 'timeout')),
        checked_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS inbox_deliveries (
        message_id TEXT NOT NULL,
        target_node_id TEXT NOT NULL,
        channel TEXT NOT NULL CHECK (channel IN ('mailbox', 'child_hook')),
        state TEXT NOT NULL CHECK (state IN ('written', 'read', 'presented', 'acked', 'fallback')),
        envelope_name TEXT,
        presented_in_turn TEXT,
        emitted_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (target_node_id, message_id, channel)
    );

    CREATE TABLE IF NOT EXISTS interactive_leases (
        node_id TEXT PRIMARY KEY,
        lease_until TEXT NOT NULL,
        source_turn_id TEXT
    );
    """
    + _build_sync_triggers_sql(
        "schema_meta",
        "store_meta",
        ["id"],
        [
            "id",
            "store_instance_id",
            "engine_schema_version",
            "driver_api_version",
            "export_version",
            "revision",
            "maintenance_state",
            "created_at",
            "updated_at",
        ],
    )
    + _build_sync_triggers_sql(
        "parent_slots",
        "slots",
        ["parent_node_id", "slot_no"],
        [
            "parent_node_id",
            "slot_no",
            "node_id",
            "operation_id",
            "run_id",
            "state",
            "created_at",
            "updated_at",
        ],
    )
    + _build_sync_triggers_sql(
        "dispatch_group_members",
        "dispatch_members",
        ["member_id"],
        [
            "member_id",
            "dispatch_group_id",
            "node_id",
            "message_id",
            "operation_id",
            "run_id",
            "ordinal",
            "state",
            "outcome",
            "exit_confirmed",
            "report_id",
            "terminal_reason",
            "created_at",
            "updated_at",
        ],
    )
    + _build_sync_triggers_sql(
        "inbox_messages",
        "messages",
        ["target_node_id", "message_id"],
        [
            "message_id",
            "target_node_id",
            "source_node_id",
            "seq",
            "delivery_kind",
            "dispatch_group_id",
            "member_id",
            "task_id",
            "payload_hash",
            "payload",
            "state",
            "run_id",
            "created_at",
            "updated_at",
        ],
    )
    + _build_sync_triggers_sql(
        "outbox_events",
        "outbox",
        ["event_id"],
        [
            "event_id",
            "event_seq",
            "producer_key",
            "parent_node_id",
            "parent_session_id",
            "child_node_id",
            "child_session_id",
            "child_turn_id",
            "turn_seq",
            "run_id",
            "dispatch_group_id",
            "member_id",
            "kind",
            "payload",
            "state",
            "presented_in_turn",
            "lease_owner",
            "lease_until",
            "attempt_count",
            "acked_at",
            "created_at",
        ],
    )
    + _build_sync_triggers_sql(
        "wake_budget",
        "wake_state",
        ["parent_node_id"],
        [
            "parent_node_id",
            "user_epoch",
            "last_verified_human_input_id",
            "wake_count",
            "wake_inflight",
            "parent_stop_state",
            "pending_human",
            "pending_permission",
            "updated_at",
        ],
    )
)


class TransactionContext:
    """Wrapper around sqlite3.Connection inside a Store.transaction() block."""

    def __init__(self, store: Store, conn: sqlite3.Connection, revision: int) -> None:
        self.store = store
        self.conn = conn
        self.revision = revision

    @property
    def store_instance_id(self) -> str:
        return self.store.store_instance_id

    def execute(self, sql: str, parameters: Any = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, parameters)

    def executemany(self, sql: str, seq_of_parameters: Any) -> sqlite3.Cursor:
        return self.conn.executemany(sql, seq_of_parameters)

    def executescript(self, sql_script: str) -> sqlite3.Cursor:
        return self.conn.executescript(sql_script)

    def cursor(self) -> sqlite3.Cursor:
        return self.conn.cursor()


def _atomic_write_under_base(
    base_dir: Path,
    relative_path: Path | str,
    data: bytes | str,
    *,
    revision: int = 0,
) -> ExportRef:
    parts = _validate_relative_parts(relative_path)
    if parts[0] == "locks" or (len(parts) >= 1 and parts[-1].endswith(".lock") and "locks" in parts):
        raise SideSessionError(
            ErrorCode.LOCK_REPLACED,
            f"Lock files must never be replaced or exported: {relative_path}",
            {"relative_path": str(relative_path)},
        )

    raw_bytes = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    target_path = safe_resolve_under(base_dir, relative_path, mkdirs=True)
    parent_dir = target_path.parent
    filename = target_path.name

    parent_fd = os.open(str(parent_dir), os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
    try:
        _verify_dir_stat(os.fstat(parent_fd), str(parent_dir))

        # Check if existing target is a symlink before replacing
        try:
            existing_st = os.lstat(filename, dir_fd=parent_fd)
            if stat.S_ISLNK(existing_st.st_mode):
                raise SideSessionError(
                    ErrorCode.SYMLINK_FORBIDDEN,
                    f"Cannot overwrite symlink at export target: {target_path}",
                    {"path": str(target_path)},
                )
            if stat.S_ISDIR(existing_st.st_mode):
                raise SideSessionError(
                    ErrorCode.UNSAFE_PATH,
                    f"Cannot overwrite directory with file export: {target_path}",
                    {"path": str(target_path)},
                )
        except FileNotFoundError:
            pass

        tmp_name = f".tmp-{filename}-{uuid.uuid4().hex}"
        tmp_fd = os.open(
            tmp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            with os.fdopen(tmp_fd, "wb", closefd=False) as f:
                f.write(raw_bytes)
                f.flush()
                os.fsync(tmp_fd)
        finally:
            os.close(tmp_fd)

        try:
            os.replace(tmp_name, filename, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        except Exception:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass
            raise
    finally:
        os.close(parent_fd)

    rel_norm = "/".join(parts)
    return ExportRef(
        relative_path=rel_norm,
        absolute_path=str(target_path),
        sha256=sha256_hex(raw_bytes),
        byte_length=len(raw_bytes),
        revision=revision,
    )


def atomic_export(
    relative_path_or_base: Path | str,
    data_or_rel: bytes | str,
    maybe_data: bytes | str | None = None,
    *,
    root: Path | str | None = None,
    revision: int = 0,
) -> ExportRef:
    """Atomically write bytes to a relative path under state root (or explicit base directory).

    Supports both:
    - `atomic_export(relative_path, data_bytes, root=...)`
    - `atomic_export(base_dir, relative_path, data_bytes)`
    """
    if maybe_data is not None:
        base_dir = ensure_safe_dir(relative_path_or_base)
        rel_path = data_or_rel
        payload = maybe_data
    else:
        base_dir = ensure_safe_dir(root if root is not None else resolve_state_root())
        rel_path = relative_path_or_base
        payload = data_or_rel
    return _atomic_write_under_base(base_dir, rel_path, payload, revision=revision)


class Store:
    """Authoritative SQLite store and projection manager for side-sessions."""

    SUBDIRS = (
        "locks",
        "artifacts",
        "artifacts/briefs",
        "artifacts/reports",
        "artifacts/history",
        "artifacts/patches",
        "notes",
        "side-session-notes",
        "exports",
        "exports/bindings",
        "exports/events",
        "logs",
        "backups",
    )

    def __init__(
        self,
        root: Path | str,
        *,
        writable: bool = True,
        initialize: bool = True,
        deadline_monotonic: float | None = None,
    ) -> None:
        raw_root = Path(root).expanduser().absolute()
        if raw_root.is_symlink():
            raise SideSessionError(
                ErrorCode.SYMLINK_FORBIDDEN,
                f"State root cannot be a symlink: {raw_root}",
                {"state_root": str(raw_root)},
            )
        self.writable = bool(writable)
        self.initialize = bool(initialize)
        self._default_deadline_monotonic = deadline_monotonic

        if self.writable and self.initialize:
            self.root = ensure_safe_dir(raw_root, mode=0o700)
            for sub in self.SUBDIRS:
                safe_resolve_under(self.root, sub, mkdirs=True)
                ensure_safe_dir(self.root / sub, mode=0o700)
        else:
            if not raw_root.exists():
                if not self.initialize:
                    raise SideSessionError(
                        ErrorCode.RETRY_LATER,
                        f"store not initialized: {raw_root}",
                        {"state_root": str(raw_root), "db_exists": False},
                        retryable=True,
                    )
                raise SideSessionError(
                    ErrorCode.NOT_FOUND,
                    f"State root does not exist: {raw_root}",
                    {"state_root": str(raw_root)},
                )
            st = os.lstat(raw_root)
            _verify_dir_stat(st, str(raw_root))
            self.root = Path(os.path.realpath(raw_root))

        self.db_path = self.root / "state.sqlite3"
        if self.db_path.is_symlink():
            raise SideSessionError(
                ErrorCode.SYMLINK_FORBIDDEN,
                f"SQLite state file cannot be a symlink: {self.db_path}",
                {"db_path": str(self.db_path)},
            )

        if not self.initialize:
            if not self.db_path.exists():
                raise SideSessionError(
                    ErrorCode.RETRY_LATER,
                    f"store not initialized: {self.db_path}",
                    {"db_path": str(self.db_path), "db_exists": False},
                    retryable=True,
                )
            if deadline_monotonic is not None:
                rem_s = deadline_monotonic - time.monotonic()
                if rem_s <= 0:
                    raise SideSessionError(
                        ErrorCode.LOCK_BUSY,
                        "Deadline exceeded before opening store",
                        {"db_path": str(self.db_path)},
                        retryable=True,
                    )
                conn_timeout = min(1.0, max(0.01, rem_s))
                busy_ms = int(min(1000, max(10, rem_s * 1000)))
            else:
                conn_timeout = 1.0
                busy_ms = 1000

            if not self.writable:
                uri = f"file:{self.db_path}?mode=ro"
                self.conn = sqlite3.connect(
                    uri,
                    uri=True,
                    timeout=conn_timeout,
                    isolation_level=None,
                    check_same_thread=False,
                )
            else:
                self.conn = sqlite3.connect(
                    str(self.db_path),
                    timeout=conn_timeout,
                    isolation_level=None,
                    check_same_thread=False,
                )
            self.conn.row_factory = sqlite3.Row
            try:
                self.conn.execute("PRAGMA foreign_keys=ON;")
                self.conn.execute(f"PRAGMA busy_timeout={busy_ms};")
                self.conn.execute(f"PRAGMA query_only={'0' if self.writable else '1'};")
                self._verify_existing_meta()
            except Exception:
                self.conn.close()
                raise
            return

        if not self.writable:
            if not self.db_path.exists():
                raise SideSessionError(
                    ErrorCode.NOT_FOUND,
                    f"SQLite database does not exist: {self.db_path}",
                    {"db_path": str(self.db_path)},
                )
            uri = f"file:{self.db_path}?mode=ro"
            self.conn = sqlite3.connect(uri, uri=True, timeout=5.0, isolation_level=None, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys=ON;")
            self.conn.execute("PRAGMA busy_timeout=5000;")
            self.conn.execute("PRAGMA query_only=ON;")
            self._verify_existing_meta()
        else:
            conn_timeout = 5.0
            if deadline_monotonic is not None:
                rem_s = deadline_monotonic - time.monotonic()
                if rem_s <= 0:
                    raise SideSessionError(
                        ErrorCode.LOCK_BUSY,
                        "Deadline exceeded before opening store",
                        {"db_path": str(self.db_path)},
                        retryable=True,
                    )
                conn_timeout = min(5.0, max(0.01, rem_s))
            self.conn = sqlite3.connect(
                str(self.db_path),
                timeout=conn_timeout,
                isolation_level=None,
                check_same_thread=False,
            )
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass
            self.conn.row_factory = sqlite3.Row
            try:
                self._initialize_database()
            except Exception:
                self.conn.close()
                raise

    def _migrate_schema_if_needed(self) -> None:
        """Idempotently add Phase 2 columns and tables without rebuilding existing tables."""
        def _cols(tbl: str) -> set[str]:
            return {str(r["name"]) for r in self.conn.execute(f"PRAGMA table_info({tbl})").fetchall()}

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            ip_cols = _cols("input_provenance")
            if ip_cols:
                if "runtime_session_id" not in ip_cols:
                    self.conn.execute("ALTER TABLE input_provenance ADD COLUMN runtime_session_id TEXT")
                if "action_binding_json" not in ip_cols:
                    self.conn.execute("ALTER TABLE input_provenance ADD COLUMN action_binding_json TEXT")

            id_cols = _cols("inbox_deliveries")
            if id_cols and "emitted_at" not in id_cols:
                self.conn.execute("ALTER TABLE inbox_deliveries ADD COLUMN emitted_at TEXT")
                self.conn.execute(
                    "UPDATE inbox_deliveries SET emitted_at = COALESCE(updated_at, created_at) WHERE emitted_at IS NULL"
                )

            wt_cols = _cols("worktrees")
            if wt_cols:
                for col_name in (
                    "last_known_tip",
                    "merged_into_ref",
                    "merged_commit",
                    "merged_tree",
                    "merge_mode",
                    "pre_parent_head",
                    "cleaned_at",
                ):
                    if col_name not in wt_cols:
                        self.conn.execute(f"ALTER TABLE worktrees ADD COLUMN {col_name} TEXT")

            row = self.conn.execute("SELECT * FROM schema_meta WHERE id = 1").fetchone()
            if row is not None and str(row["engine_schema_version"]) == "1.1":
                now = utc_now_iso()
                self.conn.execute(
                    "UPDATE schema_meta SET engine_schema_version = ?, updated_at = ? WHERE id = 1",
                    (ENGINE_SCHEMA_VERSION, now),
                )
            self.conn.execute("PRAGMA user_version = 2;")
            self.conn.execute("COMMIT")
        except Exception:
            try:
                if self.conn.in_transaction:
                    self.conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    def _initialize_database(self) -> None:
        has_lower_locks = any(k in ("session", "repo_merge") for _, k, _ in _get_held_locks())
        init_timeout_ms = 5000
        if self._default_deadline_monotonic is not None:
            rem_s = self._default_deadline_monotonic - time.monotonic()
            if rem_s <= 0:
                raise SideSessionError(
                    ErrorCode.LOCK_BUSY,
                    "Deadline exceeded before initializing database",
                    retryable=True,
                )
            init_timeout_ms = max(1, min(5000, int(rem_s * 1000)))
        with self.maintenance_lock(
            shared=has_lower_locks,
            timeout_ms=init_timeout_ms,
            _for_db_txn=True,
            deadline_monotonic=self._default_deadline_monotonic,
        ):
            busy_ms = init_timeout_ms
            if self._default_deadline_monotonic is not None:
                rem_s = self._default_deadline_monotonic - time.monotonic()
                if rem_s <= 0:
                    raise SideSessionError(
                        ErrorCode.LOCK_BUSY,
                        "Deadline exceeded while acquiring maintenance lock for initialization",
                        retryable=True,
                    )
                busy_ms = max(1, min(5000, int(rem_s * 1000)))
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=FULL;")
            self.conn.execute("PRAGMA foreign_keys=ON;")
            self.conn.execute(f"PRAGMA busy_timeout={busy_ms};")
            try:
                has_schema_meta = (
                    self.conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta'"
                    ).fetchone()
                    is not None
                )
                if has_schema_meta:
                    pre_meta = self.conn.execute(
                        "SELECT engine_schema_version, driver_api_version FROM schema_meta WHERE id = 1"
                    ).fetchone()
                    if pre_meta is not None:
                        db_engine_ver = pre_meta["engine_schema_version"]
                        db_driver_ver = pre_meta["driver_api_version"]
                        if (
                            db_engine_ver not in ("1.1", ENGINE_SCHEMA_VERSION)
                            or db_driver_ver != DRIVER_API_VERSION
                        ):
                            raise SideSessionError(
                                ErrorCode.VERSION_MISMATCH,
                                f"Store version mismatch: DB has engine={db_engine_ver}/driver={db_driver_ver}, expected engine={ENGINE_SCHEMA_VERSION}/driver={DRIVER_API_VERSION}",
                                {
                                    "db_engine_schema_version": db_engine_ver,
                                    "db_driver_api_version": db_driver_ver,
                                    "expected_engine_schema_version": ENGINE_SCHEMA_VERSION,
                                    "expected_driver_api_version": DRIVER_API_VERSION,
                                },
                            )
            except sqlite3.OperationalError as exc:
                msg = str(exc).lower()
                if "locked" in msg or "busy" in msg:
                    raise SideSessionError(
                        ErrorCode.LOCK_BUSY,
                        "SQLite database is busy while checking schema_meta before initialization",
                        retryable=True,
                    ) from exc
                raise
            self.conn.executescript(_SCHEMA_DDL)
            self.conn.execute("PRAGMA foreign_keys=ON;")
            self._migrate_schema_if_needed()

            row = self.conn.execute("SELECT * FROM schema_meta WHERE id = 1").fetchone()
            if row is None:
                now = utc_now_iso()
                instance_id = str(uuid.uuid4())
                self.conn.execute("BEGIN IMMEDIATE")
                try:
                    self.conn.execute(
                        """
                        INSERT OR IGNORE INTO schema_meta (
                            id, store_instance_id, engine_schema_version, driver_api_version,
                            export_version, revision, maintenance_state, created_at, updated_at
                        ) VALUES (1, ?, ?, ?, ?, 0, 'normal', ?, ?)
                        """,
                        (
                            instance_id,
                            ENGINE_SCHEMA_VERSION,
                            DRIVER_API_VERSION,
                            EXPORT_SCHEMA_VERSION,
                            now,
                            now,
                        ),
                    )
                    self.conn.execute("COMMIT")
                except Exception:
                    self.conn.execute("ROLLBACK")
                    raise
            self._verify_existing_meta()

    def _verify_existing_meta(self) -> None:
        try:
            row = self.conn.execute(
                "SELECT store_instance_id, engine_schema_version, driver_api_version FROM schema_meta WHERE id = 1"
            ).fetchone()
        except sqlite3.OperationalError as exc:
            msg = str(exc).lower()
            if "locked" in msg or "busy" in msg:
                raise SideSessionError(
                    ErrorCode.LOCK_BUSY,
                    "SQLite database is busy while reading schema_meta",
                    retryable=True,
                ) from exc
            if "no such table" in msg:
                raise SideSessionError(
                    ErrorCode.VERSION_MISMATCH,
                    "schema_meta table does not exist in store",
                    {
                        "db_engine_schema_version": None,
                        "expected_engine_schema_version": ENGINE_SCHEMA_VERSION,
                    },
                ) from exc
            raise
        if row is None:
            if not self.initialize:
                raise SideSessionError(
                    ErrorCode.VERSION_MISMATCH,
                    "schema_meta singleton row is missing",
                    {
                        "db_engine_schema_version": None,
                        "expected_engine_schema_version": ENGINE_SCHEMA_VERSION,
                    },
                )
            raise SideSessionError(
                ErrorCode.SCHEMA_ERROR,
                "schema_meta singleton row is missing",
            )
        db_engine_ver = row["engine_schema_version"]
        db_driver_ver = row["driver_api_version"]
        if db_engine_ver != ENGINE_SCHEMA_VERSION or db_driver_ver != DRIVER_API_VERSION:
            raise SideSessionError(
                ErrorCode.VERSION_MISMATCH,
                f"Store version mismatch: DB has engine={db_engine_ver}/driver={db_driver_ver}, expected engine={ENGINE_SCHEMA_VERSION}/driver={DRIVER_API_VERSION}",
                {
                    "db_engine_schema_version": db_engine_ver,
                    "db_driver_api_version": db_driver_ver,
                    "expected_engine_schema_version": ENGINE_SCHEMA_VERSION,
                    "expected_driver_api_version": DRIVER_API_VERSION,
                },
            )
        self._store_instance_id: str = row["store_instance_id"]

    @property
    def store_instance_id(self) -> str:
        row = self.conn.execute("SELECT store_instance_id FROM schema_meta WHERE id = 1").fetchone()
        return str(row["store_instance_id"]) if row else self._store_instance_id

    @property
    def revision(self) -> int:
        return self.get_revision()

    def get_revision(self) -> int:
        row = self.conn.execute("SELECT revision FROM schema_meta WHERE id = 1").fetchone()
        return int(row["revision"]) if row else 0

    def check_state_root_match(
        self,
        expected_root: Path | str,
        expected_store_instance_id: str | None = None,
    ) -> None:
        """Verify canonical state_root and store_instance_id match across entrypoints."""
        exp_real = Path(os.path.realpath(Path(expected_root).expanduser()))
        if exp_real != self.root:
            raise SideSessionError(
                ErrorCode.STATE_ROOT_MISMATCH,
                f"State root mismatch: {self.root} != {exp_real}",
                {"actual_root": str(self.root), "expected_root": str(exp_real)},
            )
        if expected_store_instance_id is not None and expected_store_instance_id != self.store_instance_id:
            raise SideSessionError(
                ErrorCode.STATE_ROOT_MISMATCH,
                "Store instance ID mismatch across entrypoints",
                {
                    "actual_store_instance_id": self.store_instance_id,
                    "expected_store_instance_id": expected_store_instance_id,
                },
            )

    def maintenance_lock(
        self,
        *,
        shared: bool = False,
        timeout_ms: int = 3000,
        blocking: bool = True,
        check_order: bool = True,
        _for_db_txn: bool = False,
        deadline_monotonic: float | None = None,
    ) -> FileLock:
        return FileLock(
            self.root / "locks" / "maintenance.lock",
            kind="maintenance",
            shared=shared,
            timeout_ms=timeout_ms,
            blocking=blocking,
            check_order=check_order,
            _for_db_txn=_for_db_txn,
            deadline_monotonic=deadline_monotonic if deadline_monotonic is not None else self._default_deadline_monotonic,
        )

    def session_lock(
        self,
        node_id: str,
        *,
        timeout_ms: int = 0,
        blocking: bool = False,
        check_order: bool = True,
        deadline_monotonic: float | None = None,
    ) -> FileLock:
        parts = _validate_relative_parts(node_id)
        if len(parts) != 1:
            raise SideSessionError(
                ErrorCode.UNSAFE_PATH,
                f"Invalid node_id for session lock: {node_id}",
                {"node_id": node_id},
            )
        return FileLock(
            self.root / "locks" / f"session-{parts[0]}.lock",
            kind="session",
            shared=False,
            timeout_ms=timeout_ms,
            blocking=blocking,
            check_order=check_order,
            deadline_monotonic=deadline_monotonic if deadline_monotonic is not None else self._default_deadline_monotonic,
        )

    def repo_merge_lock(
        self,
        repo_key: str,
        *,
        timeout_ms: int = 5000,
        blocking: bool = True,
        check_order: bool = True,
        deadline_monotonic: float | None = None,
    ) -> FileLock:
        parts = _validate_relative_parts(repo_key)
        if len(parts) != 1:
            raise SideSessionError(
                ErrorCode.UNSAFE_PATH,
                f"Invalid repo_key for repo_merge lock: {repo_key}",
                {"repo_key": repo_key},
            )
        return FileLock(
            self.root / "locks" / f"repo-merge-{parts[0]}.lock",
            kind="repo_merge",
            shared=False,
            timeout_ms=timeout_ms,
            blocking=blocking,
            check_order=check_order,
            deadline_monotonic=deadline_monotonic if deadline_monotonic is not None else self._default_deadline_monotonic,
        )

    def supervisor_lock(
        self,
        *,
        timeout_ms: int = 0,
        blocking: bool = False,
    ) -> FileLock:
        return FileLock(
            self.root / "locks" / "supervisor.lock",
            kind="supervisor",
            shared=False,
            timeout_ms=timeout_ms,
            blocking=blocking,
            check_order=False,
        )

    @contextmanager
    def transaction(
        self,
        mode: str = "IMMEDIATE",
        deadline_ms: int = 3000,
        *,
        deadline_monotonic: float | None = None,
    ) -> Iterator[TransactionContext]:
        """Execute an atomic SQLite transaction and increment `schema_meta.revision`."""
        norm_mode = mode.strip().upper()
        if norm_mode not in ("IMMEDIATE", "EXCLUSIVE", "DEFERRED", "READONLY"):
            raise SideSessionError(
                ErrorCode.INVALID_REQUEST,
                f"Unsupported transaction mode: {mode}",
                {"mode": mode},
            )

        is_write = norm_mode in ("IMMEDIATE", "EXCLUSIVE")
        if is_write and not self.writable:
            raise SideSessionError(
                ErrorCode.READ_ONLY_STORE,
                "Cannot open write transaction on a read-only Store",
            )

        budget_ms = max(1, int(deadline_ms))
        now_mono = time.monotonic()
        candidates = [now_mono + (budget_ms / 1000.0)]
        if self._default_deadline_monotonic is not None:
            candidates.append(self._default_deadline_monotonic)
        if deadline_monotonic is not None:
            candidates.append(deadline_monotonic)
        eff_deadline = min(candidates)

        rem_start = eff_deadline - time.monotonic()
        if rem_start <= 0:
            raise SideSessionError(
                ErrorCode.LOCK_BUSY,
                "transaction deadline exceeded before start",
                {"deadline_ms": deadline_ms},
                retryable=True,
            )

        orig_busy_ms = int(self.conn.execute("PRAGMA busy_timeout;").fetchone()[0])
        maint_cm = None
        try:
            init_rem_ms = max(1, int(rem_start * 1000))
            self.conn.execute(f"PRAGMA busy_timeout={init_rem_ms};")
            self._verify_existing_meta()

            rem_before_maint = eff_deadline - time.monotonic()
            if rem_before_maint <= 0:
                raise SideSessionError(
                    ErrorCode.LOCK_BUSY,
                    "transaction deadline exceeded before maintenance lock",
                    {"deadline_ms": deadline_ms},
                    retryable=True,
                )

            held_keys = {k for _, _, k in _get_held_locks()}
            need_maint = "maintenance.lock" not in held_keys

            maint_cm = (
                self.maintenance_lock(
                    shared=True,
                    timeout_ms=max(1, int(rem_before_maint * 1000)),
                    blocking=True,
                    _for_db_txn=True,
                    deadline_monotonic=eff_deadline,
                )
                if need_maint
                else None
            )

            if maint_cm is not None:
                maint_cm.acquire(deadline_monotonic=eff_deadline)

            rem_s = eff_deadline - time.monotonic()
            if rem_s <= 0:
                raise SideSessionError(
                    ErrorCode.LOCK_BUSY,
                    "transaction deadline exceeded after maintenance lock",
                    {"deadline_ms": deadline_ms},
                    retryable=True,
                )
            rem_ms = max(1, int(rem_s * 1000))
            self.conn.execute(f"PRAGMA busy_timeout={rem_ms};")

            begin_sql = "BEGIN DEFERRED" if norm_mode == "READONLY" else f"BEGIN {norm_mode}"
            try:
                self.conn.execute(begin_sql)
            except sqlite3.OperationalError as exc:
                msg = str(exc).lower()
                if "locked" in msg or "busy" in msg:
                    raise SideSessionError(
                        ErrorCode.RETRY_LATER,
                        "SQLite database is busy; retry later",
                        {"deadline_ms": deadline_ms},
                        retryable=True,
                    ) from exc
                raise

            if eff_deadline - time.monotonic() <= 0:
                try:
                    if self.conn.in_transaction:
                        self.conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise SideSessionError(
                    ErrorCode.LOCK_BUSY,
                    "transaction deadline exceeded after BEGIN",
                    {"deadline_ms": deadline_ms},
                    retryable=True,
                )

            prev_in_txn = _get_in_db_txn()
            _set_in_db_txn(True)
            try:
                if is_write:
                    now = utc_now_iso()
                    self.conn.execute(
                        "UPDATE schema_meta SET revision = revision + 1, updated_at = ? WHERE id = 1",
                        (now,),
                    )
                new_rev = self.get_revision()
                txn_ctx = TransactionContext(self, self.conn, new_rev)
                yield txn_ctx
                self.conn.execute("COMMIT")
            except Exception as exc:
                try:
                    if self.conn.in_transaction:
                        self.conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                if isinstance(exc, sqlite3.OperationalError):
                    msg = str(exc).lower()
                    if "locked" in msg or "busy" in msg:
                        raise SideSessionError(
                            ErrorCode.RETRY_LATER,
                            "SQLite transaction timed out waiting on lock",
                            {"deadline_ms": deadline_ms},
                            retryable=True,
                        ) from exc
                raise
            finally:
                _set_in_db_txn(prev_in_txn)
        finally:
            try:
                self.conn.execute(f"PRAGMA busy_timeout={orig_busy_ms};")
            except Exception:
                pass
            if maint_cm is not None:
                maint_cm.release()

    def safe_resolve(self, relative_path: Path | str, *, mkdirs: bool = False) -> Path:
        """Resolve a relative path safely under `self.root`."""
        return safe_resolve_under(self.root, relative_path, mkdirs=mkdirs)

    def atomic_export(
        self,
        relative_path: Path | str,
        data_bytes: bytes | str,
        *,
        revision: int | None = None,
    ) -> ExportRef:
        """Atomically write an export or projection file under `self.root`."""
        if not self.writable:
            raise SideSessionError(
                ErrorCode.READ_ONLY_STORE,
                "Cannot export files from a read-only Store",
            )
        rev = self.get_revision() if revision is None else int(revision)
        return _atomic_write_under_base(self.root, relative_path, data_bytes, revision=rev)

    def read_safe_bytes(self, relative_path: Path | str) -> bytes:
        """Safely read a regular file under `self.root` with O_NOFOLLOW."""
        target = safe_resolve_under(self.root, relative_path, mkdirs=False)
        fd = os.open(str(target), os.O_RDONLY | _O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            _verify_reg_or_dir_stat(st, str(target), require_regular=True)
            with os.fdopen(fd, "rb", closefd=False) as f:
                return f.read()
        finally:
            os.close(fd)

    def write_artifact_blob(
        self,
        relative_blob_path: Path | str,
        data: bytes | str,
        *,
        revision: int | None = None,
    ) -> ExportRef:
        """Atomically write an immutable artifact blob under `artifacts/` or `notes/`."""
        parts = _validate_relative_parts(relative_blob_path)
        if parts[0] not in ("artifacts", "notes"):
            rel_path: Path | str = Path("artifacts") / "/".join(parts)
        else:
            rel_path = "/".join(parts)
        return self.atomic_export(rel_path, data, revision=revision)

    # ------------------------------------------------------------------
    # Projection & Note Export Helpers (Section 4.1 & 11)
    # ------------------------------------------------------------------

    def export_child_brief(
        self,
        parent_node_id: str,
        child_node_id: str,
        content: str | bytes,
        *,
        revision: int | None = None,
    ) -> ExportRef:
        parent_uuid = validate_uuid(parent_node_id, "parent_node_id")
        child_uuid = validate_uuid(child_node_id, "child_node_id")
        rel = f"side-session-notes/{parent_uuid}/{child_uuid}-brief.md"
        text = normalize_text(content, strip=False) if isinstance(content, str) else content
        return self.atomic_export(rel, text, revision=revision)

    def export_child_report(
        self,
        parent_node_id: str,
        child_node_id: str,
        content: str | bytes,
        *,
        revision: int | None = None,
    ) -> ExportRef:
        parent_uuid = validate_uuid(parent_node_id, "parent_node_id")
        child_uuid = validate_uuid(child_node_id, "child_node_id")
        rel = f"side-session-notes/{parent_uuid}/{child_uuid}-report.md"
        text = normalize_text(content, strip=False) if isinstance(content, str) else content
        return self.atomic_export(rel, text, revision=revision)

    def export_shared_context(
        self,
        parent_node_id: str,
        content: str | bytes,
        *,
        revision: int | None = None,
    ) -> ExportRef:
        parent_uuid = validate_uuid(parent_node_id, "parent_node_id")
        rel = f"side-session-notes/{parent_uuid}/shared-context.md"
        text = normalize_text(content, strip=False) if isinstance(content, str) else content
        return self.atomic_export(rel, text, revision=revision)

    def export_aliases(
        self,
        parent_node_id: str,
        aliases: Mapping[str, Any],
        *,
        revision: int | None = None,
    ) -> ExportRef:
        parent_uuid = validate_uuid(parent_node_id, "parent_node_id")
        rev = self.get_revision() if revision is None else int(revision)
        payload = {
            "engine_schema_version": ENGINE_SCHEMA_VERSION,
            "export_version": EXPORT_SCHEMA_VERSION,
            "store_instance_id": self.store_instance_id,
            "parent_node_id": parent_uuid,
            "revision": rev,
            "aliases": dict(aliases),
        }
        rel = f"side-session-notes/{parent_uuid}/aliases.json"
        return self.atomic_export(rel, canonical_json_bytes(payload), revision=rev)

    def export_parent_notes(self, parent_node_id: str) -> dict[str, ExportRef]:
        """Rebuild all side-session-notes/<parent_node_id>/ projections from SQLite."""
        parent_uuid = validate_uuid(parent_node_id, "parent_node_id")
        rev = self.get_revision()
        refs: dict[str, ExportRef] = {}

        parent_row = self.conn.execute(
            "SELECT * FROM nodes WHERE node_id = ?",
            (parent_uuid,),
        ).fetchone()
        shared_content = parent_row["shared_context_content"] if parent_row else ""
        shared_rev = parent_row["shared_context_revision"] if parent_row else 0
        shared_md = f"<!-- revision: {shared_rev} | store_revision: {rev} -->\n{shared_content}\n"
        refs["shared-context.md"] = self.export_shared_context(parent_uuid, shared_md, revision=rev)

        children = self.conn.execute(
            "SELECT * FROM nodes WHERE parent_node_id = ? ORDER BY created_at ASC, node_id ASC",
            (parent_uuid,),
        ).fetchall()

        aliases_map: dict[str, dict[str, Any]] = {}
        for child in children:
            cid = child["node_id"]
            cname = child["name"]
            aliases_map[cname] = {
                "node_id": cid,
                "title": child["title"],
                "brief_file": f"{cid}-brief.md",
                "report_file": f"{cid}-report.md",
            }
            if child["brief_content"]:
                refs[f"{cid}-brief.md"] = self.export_child_brief(
                    parent_uuid,
                    cid,
                    child["brief_content"],
                    revision=rev,
                )
            latest_report = self.conn.execute(
                """
                SELECT * FROM reports
                WHERE node_id = ?
                ORDER BY turn_seq DESC, CASE WHEN phase = 'final' THEN 0 ELSE 1 END ASC
                LIMIT 1
                """,
                (cid,),
            ).fetchone()
            if latest_report is not None:
                try:
                    rep_obj = json.loads(latest_report["canonical_json"])
                    rep_md = rep_obj.get("full_report") or child["last_turn_report"]
                except Exception:
                    rep_md = child["last_turn_report"]
                refs[f"{cid}-report.md"] = self.export_child_report(
                    parent_uuid,
                    cid,
                    rep_md,
                    revision=rev,
                )

        refs["aliases.json"] = self.export_aliases(parent_uuid, aliases_map, revision=rev)
        return refs

    def export_registry(self) -> ExportRef:
        """Export authoritative topology and state snapshot to `exports/registry.json`."""
        rev = self.get_revision()
        tables = (
            "nodes",
            "proposals",
            "dispatch_groups",
            "dispatch_group_members",
            "parent_slots",
            "operations",
            "context_snapshots",
            "context_acceptances",
            "inbox_messages",
            "turns",
            "reports",
            "artifacts",
            "outbox_events",
            "event_acks",
            "wake_budget",
            "group_wakes",
            "tasks",
            "task_turn_bindings",
            "task_actions",
            "task_guards",
            "transfers",
            "wait_requests",
            "control_commands",
            "note_entries",
        )
        snapshot: dict[str, Any] = {
            "engine_schema_version": ENGINE_SCHEMA_VERSION,
            "driver_api_version": DRIVER_API_VERSION,
            "export_version": EXPORT_SCHEMA_VERSION,
            "store_instance_id": self.store_instance_id,
            "revision": rev,
            "exported_at": utc_now_iso(),
        }
        for tbl in tables:
            rows = [dict(r) for r in self.conn.execute(f"SELECT * FROM {tbl}").fetchall()]
            if tbl == "turns":
                for r in rows:
                    r.pop("fencing_token", None)
            elif tbl == "artifacts":
                for r in rows:
                    if r.get("inline_bytes") is not None:
                        r["inline_bytes"] = None
            snapshot[tbl] = rows

        # Owners are exported without secret owner_token or fencing_token (Section 11)
        owner_rows = [dict(r) for r in self.conn.execute("SELECT * FROM owners").fetchall()]
        for r in owner_rows:
            r.pop("owner_token", None)
            r.pop("fencing_token", None)
        snapshot["owners"] = owner_rows

        return self.atomic_export("exports/registry.json", canonical_json_bytes(snapshot), revision=rev)

    def export_worktrees(self) -> ExportRef:
        """Export worktree records to `exports/worktrees.json`."""
        rev = self.get_revision()
        rows = [dict(r) for r in self.conn.execute("SELECT * FROM worktrees ORDER BY created_at ASC, worktree_id ASC").fetchall()]
        payload = {
            "engine_schema_version": ENGINE_SCHEMA_VERSION,
            "export_version": EXPORT_SCHEMA_VERSION,
            "store_instance_id": self.store_instance_id,
            "revision": rev,
            "worktrees": rows,
        }
        return self.atomic_export("exports/worktrees.json", canonical_json_bytes(payload), revision=rev)

    def export_binding(self, runtime_sid: str) -> ExportRef:
        """Export a runtime binding to `exports/bindings/<runtime_sid_sha256>.json`."""
        rev = self.get_revision()
        sid_hash = sha256_hex(runtime_sid)
        row = self.conn.execute("SELECT * FROM bindings WHERE runtime_sid = ?", (runtime_sid,)).fetchone()
        payload = {
            "engine_schema_version": ENGINE_SCHEMA_VERSION,
            "export_version": EXPORT_SCHEMA_VERSION,
            "store_instance_id": self.store_instance_id,
            "revision": rev,
            "runtime_sid_sha256": sid_hash,
            "binding": dict(row) if row is not None else None,
        }
        return self.atomic_export(
            f"exports/bindings/{sid_hash}.json",
            canonical_json_bytes(payload),
            revision=rev,
        )

    def export_events(self, parent_node_id: str) -> ExportRef:
        """Export outbox events for a parent node to `exports/events/<parent_node_id>.json`."""
        parent_uuid = validate_uuid(parent_node_id, "parent_node_id")
        rev = self.get_revision()
        rows = [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM outbox_events WHERE parent_node_id = ? ORDER BY event_seq ASC",
                (parent_uuid,),
            ).fetchall()
        ]
        payload = {
            "engine_schema_version": ENGINE_SCHEMA_VERSION,
            "export_version": EXPORT_SCHEMA_VERSION,
            "store_instance_id": self.store_instance_id,
            "revision": rev,
            "parent_node_id": parent_uuid,
            "events": rows,
        }
        return self.atomic_export(
            f"exports/events/{parent_uuid}.json",
            canonical_json_bytes(payload),
            revision=rev,
        )

    def rebuild_projections(self) -> dict[str, Any]:
        """Rebuild all JSON/Markdown projections from authoritative SQLite tables."""
        results: dict[str, Any] = {
            "registry": self.export_registry(),
            "worktrees": self.export_worktrees(),
            "bindings": {},
            "events": {},
            "notes": {},
        }
        for b_row in self.conn.execute("SELECT runtime_sid FROM bindings").fetchall():
            sid = b_row["runtime_sid"]
            results["bindings"][sid] = self.export_binding(sid)

        parent_ids = {
            r["parent_node_id"]
            for r in self.conn.execute(
                "SELECT DISTINCT parent_node_id FROM nodes WHERE parent_node_id IS NOT NULL"
            ).fetchall()
        }
        parent_ids.update(
            r["parent_node_id"]
            for r in self.conn.execute("SELECT DISTINCT parent_node_id FROM outbox_events").fetchall()
        )
        for pid in sorted(parent_ids):
            try:
                validate_uuid(pid, "parent_node_id")
            except SideSessionError:
                continue
            results["events"][pid] = self.export_events(pid)
            if self.conn.execute("SELECT 1 FROM nodes WHERE node_id = ?", (pid,)).fetchone():
                results["notes"][pid] = self.export_parent_notes(pid)

        return results

    export_all = rebuild_projections

    def backup_to(self, backup_dir: Path | str) -> Path:
        """Create a consistent SQLite backup using sqlite3 backup API under exclusive maintenance lock."""
        dest_dir = ensure_safe_dir(backup_dir, mode=0o700)
        dest_db = dest_dir / "state.sqlite3"
        with self.maintenance_lock(shared=False, timeout_ms=5000):
            bck_conn = sqlite3.connect(str(dest_db))
            try:
                self.conn.backup(bck_conn)
            finally:
                bck_conn.close()
        return dest_db

    def close(self) -> None:
        if getattr(self, "conn", None) is not None:
            self.conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


def open_store(
    root: Path | str | None = None,
    writable: bool = True,
    *,
    initialize: bool = True,
    deadline_monotonic: float | None = None,
) -> Store:
    """Open or initialize the authoritative Store at `root`."""
    resolved_root = resolve_state_root() if root is None else Path(root)
    return Store(
        resolved_root,
        writable=writable,
        initialize=initialize,
        deadline_monotonic=deadline_monotonic,
    )


__all__ = [
    "FileLock",
    "LOCK_ORDER",
    "Store",
    "TransactionContext",
    "atomic_export",
    "ensure_safe_dir",
    "open_store",
    "resolve_state_root",
    "safe_resolve_under",
]
