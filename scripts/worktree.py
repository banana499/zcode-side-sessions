"""Git source inspection, external worktree preparation (R06), verification, and owned cleanup."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping
import uuid

try:
    from .contracts import (
        CleanupResult,
        ErrorCode,
        RepoSnapshot,
        SideSessionError,
        WorkspaceCheck,
        WorkspaceSpec,
        WorktreeRecord,
        canonical_json_bytes,
        canonical_json_sha256,
        sha256_hex,
    )
    from .state import ensure_safe_dir, resolve_worktrees_home, safe_resolve_under
except ImportError:  # pragma: no cover
    from contracts import (  # type: ignore
        CleanupResult,
        ErrorCode,
        RepoSnapshot,
        SideSessionError,
        WorkspaceCheck,
        WorkspaceSpec,
        WorktreeRecord,
        canonical_json_bytes,
        canonical_json_sha256,
        sha256_hex,
    )
    from state import ensure_safe_dir, resolve_worktrees_home, safe_resolve_under  # type: ignore

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

_GIT_STRIP_ENV_KEYS = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
)
_GIT_ISOLATED_PREFIX_ARGS = [
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "commit.gpgSign=false",
    "-c",
    "tag.gpgSign=false",
]


def _build_isolated_git_env(base_env: Mapping[str, str] | None = None) -> dict[str, str]:
    src = os.environ if base_env is None else base_env
    env: dict[str, str] = {}
    for k in (
        "HOME",
        "XDG_CONFIG_HOME",
        "PATH",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "SSH_AUTH_SOCK",
        "SYSTEMROOT",
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
    ):
        val = src.get(k)
        if isinstance(val, str) and val:
            env[k] = val
    for k, v in src.items():
        if k in _GIT_STRIP_ENV_KEYS or k.startswith("GIT_CONFIG_"):
            continue
        if k.startswith(("ZCODE_", "LC_", "LANG")):
            env[k] = v
    env.setdefault("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_MERGE_AUTOEDIT"] = "no"
    env["LC_ALL"] = "C"
    return env


def git_identity_args(cwd: Path | str) -> list[str]:
    """Return `-c user.name=... -c user.email=...` fallback args only when Git lacks configured identity."""
    args: list[str] = []
    has_env_name = bool(os.environ.get("GIT_AUTHOR_NAME") and os.environ.get("GIT_COMMITTER_NAME"))
    has_env_email = bool(os.environ.get("GIT_AUTHOR_EMAIL") and os.environ.get("GIT_COMMITTER_EMAIL"))
    if not has_env_name:
        n_proc = _run_git(cwd, ["config", "--get", "user.name"], isolated=True)
        if n_proc.returncode != 0 or not n_proc.stdout.strip():
            args.extend(["-c", "user.name=side-sessions"])
    if not has_env_email:
        e_proc = _run_git(cwd, ["config", "--get", "user.email"], isolated=True)
        if e_proc.returncode != 0 or not e_proc.stdout.strip():
            args.extend(["-c", "user.email=side-sessions@localhost"])
    return args


git_identity_fallback_args = git_identity_args


def _extract_git_subcommand(args: list[str]) -> str:
    idx = 0
    while idx < len(args):
        tok = args[idx]
        if tok in ("-c", "-C", "--git-dir", "--work-tree", "--namespace"):
            idx += 2
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        return tok
    return ""


def _run_git(
    cwd: Path | str,
    args: list[str],
    *,
    timeout_sec: float = 15.0,
    isolated: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    prefix = list(_GIT_ISOLATED_PREFIX_ARGS) if isolated else []
    subcmd = _extract_git_subcommand(args)
    if subcmd in ("commit-tree", "merge", "commit") and not any(
        tok.startswith("user.email=") for tok in args
    ):
        prefix.extend(git_identity_args(cwd))
    cmd = ["git", *prefix, "-C", str(cwd), *args]
    env = _build_isolated_git_env() if isolated else None
    try:
        return subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_sec,
            check=False,
            env=env,
        )
    except FileNotFoundError as exc:
        raise SideSessionError(
            ErrorCode.CAPABILITY_UNAVAILABLE,
            "git executable is not available on PATH",
            {"cmd": cmd},
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise SideSessionError(
            ErrorCode.RETRY_LATER,
            f"git command timed out after {timeout_sec}s: {' '.join(args)}",
            {"cmd": cmd},
            retryable=True,
        ) from exc


def _run_isolated_git(
    cwd: Path | str,
    args: list[str],
    *,
    timeout: float = 15.0,
    timeout_sec: float | None = None,
    max_stdout_bytes: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    eff_timeout = timeout_sec if timeout_sec is not None else timeout
    proc = _run_git(cwd, args, timeout_sec=eff_timeout, isolated=True)
    if max_stdout_bytes is not None and len(proc.stdout) > max_stdout_bytes:
        return subprocess.CompletedProcess(
            proc.args,
            proc.returncode,
            proc.stdout[:max_stdout_bytes],
            proc.stderr,
        )
    return proc


def check_no_custom_git_drivers(repo_root: Path | str) -> None:
    """Reject repositories configured with custom external merge or filter drivers."""
    proc = _run_git(
        repo_root,
        ["config", "--get-regexp", r"^(filter|merge)\..*\.(clean|smudge|process|driver)$"],
        isolated=True,
    )
    if proc.returncode == 0:
        out = proc.stdout.decode("utf-8", errors="replace").strip()
        if out:
            raise SideSessionError(
                ErrorCode.CAPABILITY_UNAVAILABLE,
                "repository uses custom git merge/filter drivers",
                {"drivers": out},
            )


def _resolve_with_existing_ancestor(path: Path | str) -> Path:
    """Resolve symlinks on the deepest existing ancestor and re-attach remaining segments."""
    p = Path(path).expanduser().absolute()
    missing_parts: list[str] = []
    cur = p
    while not cur.exists() and cur != cur.parent:
        missing_parts.append(cur.name)
        cur = cur.parent
    resolved = Path(os.path.realpath(cur))
    for part in reversed(missing_parts):
        resolved = resolved / part
    return resolved


def _is_subpath_or_equal(candidate: Path, root: Path) -> bool:
    cand_real = _resolve_with_existing_ancestor(candidate)
    root_real = _resolve_with_existing_ancestor(root)
    if cand_real == root_real:
        return True
    try:
        cand_real.relative_to(root_real)
        return True
    except ValueError:
        return False


def inspect_source(cwd: Path | str, *, require_git: bool = True) -> RepoSnapshot:
    """Inspect `cwd` using git argv and return a RepoSnapshot.

    Raises `SideSessionError(ErrorCode.NOT_GIT_REPO, ...)` if `cwd` is not a valid git
    repository with a verified HEAD commit (when `require_git=True`).
    """
    src_path = Path(cwd).expanduser().absolute()
    if not src_path.exists():
        if require_git:
            raise SideSessionError(
                ErrorCode.NOT_GIT_REPO,
                f"Source directory does not exist: {src_path}",
                {"source_cwd": str(src_path)},
            )
        raise SideSessionError(
            ErrorCode.NOT_FOUND,
            f"Source directory does not exist: {src_path}",
            {"source_cwd": str(src_path)},
        )
    if src_path.is_symlink():
        raise SideSessionError(
            ErrorCode.SYMLINK_FORBIDDEN,
            f"Source cwd cannot be a symlink: {src_path}",
            {"source_cwd": str(src_path)},
        )
    if not src_path.is_dir():
        raise SideSessionError(
            ErrorCode.NOT_GIT_REPO if require_git else ErrorCode.UNSAFE_PATH,
            f"Source cwd is not a directory: {src_path}",
            {"source_cwd": str(src_path)},
        )

    canonical_cwd = os.path.realpath(src_path)

    top_proc = _run_git(canonical_cwd, ["rev-parse", "--show-toplevel"], isolated=True)
    if top_proc.returncode != 0:
        if require_git:
            raise SideSessionError(
                ErrorCode.NOT_GIT_REPO,
                f"Directory is not a git repository: {canonical_cwd}",
                {
                    "source_cwd": canonical_cwd,
                    "stderr": top_proc.stderr.decode("utf-8", errors="replace").strip(),
                },
            )
        return RepoSnapshot(
            source_cwd=canonical_cwd,
            is_git_repo=False,
        )

    raw_top = top_proc.stdout.decode("utf-8", errors="replace").strip()
    if not raw_top:
        if require_git:
            raise SideSessionError(
                ErrorCode.NOT_GIT_REPO,
                f"Empty git toplevel for: {canonical_cwd}",
                {"source_cwd": canonical_cwd},
            )
        return RepoSnapshot(source_cwd=canonical_cwd, is_git_repo=False)

    canonical_repo_root = os.path.realpath(raw_top)

    head_proc = _run_git(canonical_repo_root, ["rev-parse", "--verify", "HEAD"], isolated=True)
    if head_proc.returncode != 0:
        if require_git:
            raise SideSessionError(
                ErrorCode.NOT_GIT_REPO,
                f"Git repository has no valid HEAD commit: {canonical_repo_root}",
                {
                    "source_cwd": canonical_cwd,
                    "repo_root": canonical_repo_root,
                    "reason": ErrorCode.GIT_HEAD_UNAVAILABLE.value,
                    "stderr": head_proc.stderr.decode("utf-8", errors="replace").strip(),
                },
            )
        return RepoSnapshot(
            source_cwd=canonical_cwd,
            is_git_repo=False,
            repo_root=canonical_repo_root,
        )

    head_commit = head_proc.stdout.decode("utf-8", errors="replace").strip()

    common_proc = _run_git(canonical_repo_root, ["rev-parse", "--git-common-dir"], isolated=True)
    if common_proc.returncode == 0:
        raw_common = common_proc.stdout.decode("utf-8", errors="replace").strip()
        common_path = Path(raw_common)
        if not common_path.is_absolute():
            common_path = Path(canonical_repo_root) / common_path
        canonical_common_dir = os.path.realpath(common_path)
    else:
        canonical_common_dir = os.path.realpath(Path(canonical_repo_root) / ".git")

    repo_key = sha256_hex(canonical_common_dir)

    status_proc = _run_git(
        canonical_repo_root,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        isolated=True,
    )
    if status_proc.returncode != 0:
        raise SideSessionError(
            ErrorCode.NOT_GIT_REPO,
            f"git status failed in {canonical_repo_root}",
            {
                "repo_root": canonical_repo_root,
                "stderr": status_proc.stderr.decode("utf-8", errors="replace").strip(),
            },
        )

    porcelain_output = status_proc.stdout.decode("utf-8", errors="replace")
    dirty_entries = [line for line in porcelain_output.splitlines() if line.strip()]
    is_dirty = len(dirty_entries) > 0

    return RepoSnapshot(
        source_cwd=canonical_cwd,
        is_git_repo=True,
        repo_root=canonical_repo_root,
        git_common_dir=canonical_common_dir,
        repo_key=repo_key,
        head_commit=head_commit,
        is_dirty=is_dirty,
        dirty_entries=dirty_entries,
        porcelain_output=porcelain_output,
    )


def _list_registered_worktree_roots(repo_root: str) -> list[Path]:
    roots: list[Path] = [Path(repo_root)]
    proc = _run_git(repo_root, ["worktree", "list", "--porcelain"], isolated=True)
    if proc.returncode == 0:
        text = proc.stdout.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if line.startswith("worktree "):
                wt_str = line[len("worktree ") :].strip()
                if wt_str:
                    roots.append(_resolve_with_existing_ancestor(wt_str))
    return roots


def _parse_porcelain_z(repo_root: str) -> list[tuple[str, str]]:
    """Parse `git status --porcelain=v1 -z --untracked-files=all` into (status_xy, rel_path) pairs."""
    proc = _run_git(repo_root, ["status", "--porcelain=v1", "-z", "--untracked-files=all"], isolated=True)
    if proc.returncode != 0:
        raise SideSessionError(
            ErrorCode.NOT_GIT_REPO,
            "Failed to read git status -z",
            {"repo_root": repo_root},
        )
    raw = proc.stdout
    tokens = raw.split(b"\x00")
    entries: list[tuple[str, str]] = []
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        idx += 1
        if not tok or len(tok) < 4:
            continue
        xy = tok[:2].decode("utf-8", errors="replace")
        path_str = tok[3:].decode("utf-8", errors="replace")
        entries.append((xy, path_str))
        # In porcelain v1 -z, R or C is followed by the original path token
        if "R" in xy or "C" in xy:
            if idx < len(tokens):
                orig_path = tokens[idx].decode("utf-8", errors="replace")
                idx += 1
                if orig_path:
                    entries.append((xy, orig_path))
    return entries


def _path_parts(rel_path: str) -> list[str]:
    return [p for p in rel_path.strip("/").split("/") if p]


def _is_path_approved(rel_path: str, manifest: list[str] | None) -> bool:
    if not manifest:
        return False
    rel_parts = _path_parts(rel_path)
    if not rel_parts:
        return False
    for allowed in manifest:
        allowed_parts = _path_parts(str(allowed))
        if not allowed_parts:
            continue
        if rel_parts == allowed_parts:
            return True
        if len(rel_parts) > len(allowed_parts) and rel_parts[: len(allowed_parts)] == allowed_parts:
            return True
    return False


def _open_regular_under(repo_root: str | Path, rel_path: str) -> tuple[bytes, os.stat_result]:
    """Read a regular file under repo_root via safe_resolve_under + O_NOFOLLOW."""
    resolved = safe_resolve_under(repo_root, rel_path, mkdirs=False)
    parent = resolved.parent
    parent_fd = os.open(str(parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _O_NOFOLLOW)
    try:
        fd = os.open(resolved.name, os.O_RDONLY | _O_NOFOLLOW, dir_fd=parent_fd)
        try:
            st = os.fstat(fd)
            if stat.S_ISLNK(st.st_mode):
                raise SideSessionError(
                    ErrorCode.SYMLINK_FORBIDDEN,
                    f"Cannot snapshot symlink in dirty source repository: {rel_path}",
                    {"path": rel_path},
                )
            if not stat.S_ISREG(st.st_mode):
                raise SideSessionError(
                    ErrorCode.UNSAFE_PATH,
                    f"Dirty path is not a regular file: {rel_path}",
                    {"path": rel_path},
                )
            with os.fdopen(fd, "rb", closefd=False) as f:
                data = f.read()
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    return data, st


def _identity_map_for_entries(
    repo_root: str,
    entries: list[tuple[str, str]],
    approved_manifest: list[str],
) -> tuple[list[str], list[str], dict[str, str | None]]:
    tracked_paths: list[str] = []
    untracked_paths: list[str] = []
    pre_file_hashes: dict[str, str | None] = {}
    for xy, rel_path in entries:
        if not rel_path or rel_path.startswith("/") or "\\" in rel_path or ".." in rel_path.split("/"):
            raise SideSessionError(
                ErrorCode.PATH_ESCAPE,
                f"Unsafe dirty path in source repository: {rel_path}",
                {"path": rel_path},
            )
        if not _is_path_approved(rel_path, approved_manifest):
            raise SideSessionError(
                ErrorCode.DIRTY_SOURCE,
                f"Dirty file '{rel_path}' is outside approved_path_manifest",
                {"path": rel_path, "approved_path_manifest": approved_manifest},
            )
        try:
            data, _st = _open_regular_under(repo_root, rel_path)
            pre_file_hashes[rel_path] = sha256_hex(data)
        except FileNotFoundError:
            pre_file_hashes[rel_path] = None
        except SideSessionError as exc:
            if exc.code == ErrorCode.NOT_FOUND:
                pre_file_hashes[rel_path] = None
            else:
                raise
        if xy == "??":
            if rel_path not in untracked_paths:
                untracked_paths.append(rel_path)
        elif rel_path not in tracked_paths:
            tracked_paths.append(rel_path)
    return tracked_paths, untracked_paths, pre_file_hashes


def _capture_patch_snapshot(
    repo_root: str,
    approved_manifest: list[str] | None,
) -> tuple[bytes, list[dict[str, Any]], str, list[tuple[str, str]], dict[str, str | None]]:
    """Capture a verified binary patch for tracked changes and file manifest for untracked files."""
    if not approved_manifest:
        raise SideSessionError(
            ErrorCode.DIRTY_SOURCE,
            "patch_snapshot requires a non-empty approved_path_manifest",
            {"approved_path_manifest": approved_manifest},
        )
    entries = _parse_porcelain_z(repo_root)
    if not entries:
        return b"", [], sha256_hex(b""), entries, {}

    tracked_paths, untracked_paths, pre_file_hashes = _identity_map_for_entries(
        repo_root, entries, approved_manifest
    )

    patch_bytes = b""
    if tracked_paths:
        diff_proc = _run_git(repo_root, ["diff", "--binary", "HEAD", "--", *tracked_paths], isolated=True)
        if diff_proc.returncode != 0:
            raise SideSessionError(
                ErrorCode.DIRTY_SOURCE,
                "git diff --binary HEAD failed while snapshotting dirty source",
                {"stderr": diff_proc.stderr.decode("utf-8", errors="replace").strip()},
            )
        patch_bytes = diff_proc.stdout

    untracked_items: list[dict[str, Any]] = []
    for rel_path in sorted(untracked_paths):
        content_bytes, st = _open_regular_under(repo_root, rel_path)
        untracked_items.append(
            {
                "path": rel_path,
                "mode": stat.S_IMODE(st.st_mode) or 0o600,
                "sha256": sha256_hex(content_bytes),
                "bytes": content_bytes,
            }
        )

    post_entries = _parse_porcelain_z(repo_root)
    if post_entries != entries:
        raise SideSessionError(
            ErrorCode.SOURCE_CHANGED,
            "Source repository status changed concurrently during patch_snapshot export",
            {"repo_root": repo_root},
        )
    for rel_path, expected_hash in pre_file_hashes.items():
        try:
            data, _st = _open_regular_under(repo_root, rel_path)
            cur_hash: str | None = sha256_hex(data)
        except FileNotFoundError:
            cur_hash = None
        except SideSessionError as exc:
            if exc.code == ErrorCode.NOT_FOUND:
                cur_hash = None
            else:
                raise
        if cur_hash != expected_hash:
            raise SideSessionError(
                ErrorCode.SOURCE_CHANGED,
                f"Source file '{rel_path}' changed concurrently during patch_snapshot export",
                {"path": rel_path},
            )

    manifest_summary = {
        "patch_sha256": sha256_hex(patch_bytes),
        "untracked": [
            {"path": item["path"], "mode": item["mode"], "sha256": item["sha256"]}
            for item in untracked_items
        ],
    }
    source_patch_hash = canonical_json_sha256(manifest_summary)
    return patch_bytes, untracked_items, source_patch_hash, entries, pre_file_hashes


def _assert_source_unchanged(
    repo_root: str,
    entries: list[tuple[str, str]],
    pre_file_hashes: dict[str, str | None],
) -> None:
    post_entries = _parse_porcelain_z(repo_root)
    if post_entries != entries:
        raise SideSessionError(
            ErrorCode.SOURCE_CHANGED,
            "Source repository status changed concurrently during worktree export",
            {"repo_root": repo_root},
        )
    for rel_path, expected_hash in pre_file_hashes.items():
        try:
            data, _st = _open_regular_under(repo_root, rel_path)
            cur_hash: str | None = sha256_hex(data)
        except FileNotFoundError:
            cur_hash = None
        except SideSessionError as exc:
            if exc.code == ErrorCode.NOT_FOUND:
                cur_hash = None
            else:
                raise
        if cur_hash != expected_hash:
            raise SideSessionError(
                ErrorCode.SOURCE_CHANGED,
                f"Source file '{rel_path}' changed concurrently during worktree export",
                {"path": rel_path},
            )


def _owner_sidecar_path(worktree_path: Path) -> Path:
    return worktree_path.parent / f".owner-{worktree_path.name}.json"


def _write_ownership_sidecar(
    worktree_path: Path,
    payload: dict[str, Any],
) -> None:
    sidecar = _owner_sidecar_path(worktree_path)
    raw = canonical_json_bytes(payload)
    fd = os.open(
        str(sidecar),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(fd, "wb", closefd=False) as f:
            f.write(raw)
            f.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def _read_ownership_sidecar(worktree_path: Path) -> dict[str, Any] | None:
    sidecar = _owner_sidecar_path(worktree_path)
    if not sidecar.exists() or sidecar.is_symlink():
        return None
    try:
        return json.loads(sidecar.read_text(encoding="utf-8"))
    except Exception:
        return None


def _sanitize_slug(raw: str, field_name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9-]", "-", raw.strip()).strip("-").lower()
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    if not cleaned:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"Cannot derive safe slug from {field_name}: {raw!r}",
            {"field": field_name, "value": raw},
        )
    return cleaned[:48]


def _node_uuid_hex(node_id: str) -> str:
    try:
        return uuid.UUID(str(node_id)).hex
    except (ValueError, AttributeError, TypeError) as exc:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"node_id must be a UUID so the engine can allocate side/<node_uuid_hex>: {node_id!r}",
            {"node_id": node_id},
        ) from exc


def _engine_branch_name(node_id: str) -> str:
    return f"side/{_node_uuid_hex(node_id)}"


def _derive_op_short(operation_id: str) -> str:
    if not isinstance(operation_id, str) or not operation_id.strip():
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            "operation_id must be a non-empty string",
            {"field": "operation_id"},
        )
    alnum = re.sub(r"[^a-zA-Z0-9]", "", operation_id.strip()).lower()
    if len(alnum) >= 8:
        return alnum[:8]
    return (alnum + sha256_hex(operation_id))[:8]


def prepare(
    spec: WorkspaceSpec,
    operation_id: str,
    worktrees_home: Path | str | None = None,
) -> WorktreeRecord:
    """Prepare a workspace according to `spec` and `operation_id` (Section 7.2 & R06).

    - `workspace_mode == "inherit"`: verifies `source_cwd` exists and records its canonical `realpath`
      without creating a git worktree.
    - `workspace_mode == "branch"`: inspects git source, enforces `dirty_policy`, verifies that
      `worktrees_home` is outside all source checkouts, and creates an external worktree at
      `<worktrees_home>/<repo_key>/<node_uuid_hex>` on engine-allocated branch `side/<node_uuid_hex>`.
    """
    if not isinstance(spec, WorkspaceSpec):
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            "spec must be a WorkspaceSpec instance",
        )
    if spec.workspace_mode not in ("inherit", "branch"):
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"Unsupported workspace_mode: {spec.workspace_mode!r}",
            {"workspace_mode": spec.workspace_mode},
        )
    if spec.dirty_policy not in ("reject", "patch_snapshot"):
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            f"Unsupported dirty_policy: {spec.dirty_policy!r}",
            {"dirty_policy": spec.dirty_policy},
        )

    worktree_id = str(uuid.uuid4())

    if spec.branch is not None or spec.target_path is not None:
        raise SideSessionError(
            ErrorCode.INVALID_REQUEST,
            "prepare() rejects caller-supplied branch and target_path; the engine allocates side/<node_uuid_hex>",
            {"branch": spec.branch, "target_path": spec.target_path},
        )

    if worktrees_home is None:
        raw_wt_home = resolve_worktrees_home()
    else:
        raw_wt_home = Path(worktrees_home).expanduser().absolute()

    if spec.workspace_mode == "inherit":
        snap = inspect_source(spec.source_cwd, require_git=False)
        canonical_wt_home = str(_resolve_with_existing_ancestor(raw_wt_home))
        return WorktreeRecord(
            worktree_id=worktree_id,
            node_id=spec.node_id,
            operation_id=operation_id,
            canonical_worktree_path=snap.source_cwd,
            worktrees_home=canonical_wt_home,
            workspace_mode="inherit",
            repo_key=snap.repo_key,
            repo_root=snap.repo_root,
            base_commit=snap.head_commit,
            branch=None,
            source_patch_hash=None,
            ownership_marker=None,
            state="verified",
        )

    # workspace_mode == "branch"
    snap = inspect_source(spec.source_cwd, require_git=True)
    assert snap.repo_root is not None
    assert snap.repo_key is not None
    assert snap.head_commit is not None

    if spec.repo_root is not None:
        expected_repo_root = os.path.realpath(Path(spec.repo_root).expanduser())
        if expected_repo_root != snap.repo_root:
            raise SideSessionError(
                ErrorCode.WORKSPACE_MISMATCH,
                f"Source repo_root ({snap.repo_root}) does not match expected repo_root ({expected_repo_root})",
                {"actual_repo_root": snap.repo_root, "expected_repo_root": expected_repo_root},
            )

    base_commit = spec.base_commit or snap.head_commit
    if spec.base_commit is not None:
        commit_proc = _run_git(snap.repo_root, ["rev-parse", "--verify", f"{spec.base_commit}^{{commit}}"], isolated=True)
        if commit_proc.returncode != 0:
            raise SideSessionError(
                ErrorCode.NOT_GIT_REPO,
                f"Specified base_commit does not exist in repository: {spec.base_commit}",
                {"base_commit": spec.base_commit, "repo_root": snap.repo_root},
            )
        base_commit = commit_proc.stdout.decode("utf-8", errors="replace").strip()

    # R06: Verify worktrees_home is strictly outside source repo_root, source_cwd, .git, and any registered checkout
    forbidden_roots: list[Path] = _list_registered_worktree_roots(snap.repo_root)
    forbidden_roots.append(Path(snap.source_cwd))
    if snap.git_common_dir:
        forbidden_roots.append(Path(snap.git_common_dir))

    resolved_wt_home = _resolve_with_existing_ancestor(raw_wt_home)
    for f_root in forbidden_roots:
        if _is_subpath_or_equal(resolved_wt_home, f_root):
            raise SideSessionError(
                ErrorCode.WORKTREE_HOME_INSIDE_SOURCE,
                f"worktrees_home ({resolved_wt_home}) cannot be inside source repository or checkout ({f_root})",
                {
                    "worktrees_home": str(resolved_wt_home),
                    "forbidden_root": str(f_root),
                },
            )

    safe_wt_home = ensure_safe_dir(raw_wt_home, mode=0o700)
    repo_wt_dir = safe_resolve_under(safe_wt_home, snap.repo_key, mkdirs=True)
    ensure_safe_dir(repo_wt_dir, mode=0o700)

    wt_dir_name = _node_uuid_hex(spec.node_id)
    target_wt_path = safe_resolve_under(repo_wt_dir, wt_dir_name, mkdirs=False)
    branch_name = _engine_branch_name(spec.node_id)

    ref_check = _run_git(snap.repo_root, ["check-ref-format", "--branch", branch_name], isolated=True)
    if ref_check.returncode != 0:
        raise SideSessionError(
            ErrorCode.INVALID_NAME,
            f"Invalid git branch name: {branch_name}",
            {"branch": branch_name},
        )

    patch_bytes = b""
    untracked_items: list[dict[str, Any]] = []
    source_patch_hash: str | None = None
    snapshot_entries: list[tuple[str, str]] = []
    snapshot_hashes: dict[str, str | None] = {}

    if snap.is_dirty:
        if spec.dirty_policy == "reject":
            raise SideSessionError(
                ErrorCode.DIRTY_SOURCE,
                "Source repository has uncommitted or untracked changes and dirty_policy='reject'",
                {
                    "repo_root": snap.repo_root,
                    "dirty_entries": snap.dirty_entries,
                },
            )
        if spec.dirty_policy == "patch_snapshot" and not spec.approved_path_manifest:
            raise SideSessionError(
                ErrorCode.DIRTY_SOURCE,
                "patch_snapshot requires a non-empty approved_path_manifest",
                {"approved_path_manifest": spec.approved_path_manifest},
            )
        patch_bytes, untracked_items, source_patch_hash, snapshot_entries, snapshot_hashes = _capture_patch_snapshot(
            snap.repo_root,
            spec.approved_path_manifest,
        )

    if target_wt_path.exists():
        raise SideSessionError(
            ErrorCode.WORKSPACE_MISMATCH,
            f"Target worktree path already exists: {target_wt_path}",
            {"target_worktree_path": str(target_wt_path)},
        )

    def _rollback_new_worktree() -> None:
        _run_git(snap.repo_root, ["worktree", "remove", "--force", str(target_wt_path)], isolated=True)
        _run_git(snap.repo_root, ["branch", "-d", branch_name], isolated=True)

    add_proc = _run_git(
        snap.repo_root,
        ["worktree", "add", "-b", branch_name, str(target_wt_path), base_commit],
        isolated=True,
    )
    if add_proc.returncode != 0:
        raise SideSessionError(
            ErrorCode.WORKSPACE_MISMATCH,
            f"git worktree add failed for branch {branch_name}",
            {
                "repo_root": snap.repo_root,
                "target_worktree_path": str(target_wt_path),
                "branch": branch_name,
                "stderr": add_proc.stderr.decode("utf-8", errors="replace").strip(),
            },
        )

    canonical_wt_path = os.path.realpath(target_wt_path)

    if snap.is_dirty and spec.dirty_policy == "patch_snapshot":
        try:
            _assert_source_unchanged(snap.repo_root, snapshot_entries, snapshot_hashes)
        except SideSessionError:
            _rollback_new_worktree()
            raise
        tmp_patch_file = repo_wt_dir / f".tmp-patch-{wt_dir_name}.diff"
        try:
            if patch_bytes:
                fd = os.open(
                    str(tmp_patch_file),
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_NOFOLLOW,
                    0o600,
                )
                try:
                    with os.fdopen(fd, "wb", closefd=False) as f:
                        f.write(patch_bytes)
                        f.flush()
                        os.fsync(fd)
                finally:
                    os.close(fd)

                chk_proc = _run_git(
                    canonical_wt_path,
                    ["apply", "--check", "--binary", str(tmp_patch_file)],
                    isolated=True,
                )
                if chk_proc.returncode != 0:
                    _rollback_new_worktree()
                    raise SideSessionError(
                        ErrorCode.DIRTY_SOURCE,
                        "git apply --check failed for dirty source patch snapshot",
                        {
                            "worktree_path": canonical_wt_path,
                            "stderr": chk_proc.stderr.decode("utf-8", errors="replace").strip(),
                        },
                    )

                apply_proc = _run_git(
                    canonical_wt_path,
                    ["apply", "--binary", str(tmp_patch_file)],
                    isolated=True,
                )
                if apply_proc.returncode != 0:
                    _rollback_new_worktree()
                    raise SideSessionError(
                        ErrorCode.DIRTY_SOURCE,
                        "git apply failed for dirty source patch snapshot",
                        {
                            "worktree_path": canonical_wt_path,
                            "stderr": apply_proc.stderr.decode("utf-8", errors="replace").strip(),
                        },
                    )

            for item in untracked_items:
                dest_file = safe_resolve_under(Path(canonical_wt_path), item["path"], mkdirs=True)
                parent_fd = os.open(str(dest_file.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _O_NOFOLLOW)
                try:
                    fd = os.open(
                        dest_file.name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW,
                        int(item["mode"]),
                        dir_fd=parent_fd,
                    )
                    try:
                        with os.fdopen(fd, "wb", closefd=False) as f:
                            f.write(item["bytes"])
                            f.flush()
                            os.fsync(fd)
                    finally:
                        os.close(fd)
                finally:
                    os.close(parent_fd)
                written_sha = sha256_hex(dest_file.read_bytes())
                if written_sha != item["sha256"]:
                    _rollback_new_worktree()
                    raise SideSessionError(
                        ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                        f"Untracked file hash mismatch after copy: {item['path']}",
                        {"path": item["path"]},
                    )
            try:
                _assert_source_unchanged(snap.repo_root, snapshot_entries, snapshot_hashes)
            except SideSessionError:
                _rollback_new_worktree()
                raise
        finally:
            try:
                if tmp_patch_file.exists():
                    tmp_patch_file.unlink()
            except OSError:
                pass

    ownership_payload = {
        "worktree_id": worktree_id,
        "node_id": spec.node_id,
        "operation_id": operation_id,
        "canonical_worktree_path": canonical_wt_path,
        "repo_root": snap.repo_root,
        "base_commit": base_commit,
        "branch": branch_name,
    }
    ownership_marker = canonical_json_sha256(ownership_payload)
    ownership_payload["ownership_marker"] = ownership_marker
    _write_ownership_sidecar(Path(canonical_wt_path), ownership_payload)

    return WorktreeRecord(
        worktree_id=worktree_id,
        node_id=spec.node_id,
        operation_id=operation_id,
        canonical_worktree_path=canonical_wt_path,
        worktrees_home=str(safe_wt_home),
        workspace_mode="branch",
        repo_key=snap.repo_key,
        repo_root=snap.repo_root,
        base_commit=base_commit,
        branch=branch_name,
        source_patch_hash=source_patch_hash,
        ownership_marker=ownership_marker,
        state="created",
    )


def verify(record: WorktreeRecord) -> WorkspaceCheck:
    """Verify worktree record against actual filesystem and git state.

    Checks `realpath`, `git rev-parse --show-toplevel`, `HEAD`, branch name, and ownership marker.
    """
    wt_path = Path(record.canonical_worktree_path)
    if not wt_path.exists():
        return WorkspaceCheck(
            ok=False,
            canonical_path=record.canonical_worktree_path,
            workspace_mode=record.workspace_mode,
            branch=record.branch,
            head_commit=None,
            is_clean=False,
            ownership_verified=False,
            reason="workspace path does not exist",
        )
    if wt_path.is_symlink():
        return WorkspaceCheck(
            ok=False,
            canonical_path=record.canonical_worktree_path,
            workspace_mode=record.workspace_mode,
            branch=record.branch,
            head_commit=None,
            is_clean=False,
            ownership_verified=False,
            reason="workspace path is a symlink",
        )

    actual_realpath = os.path.realpath(wt_path)
    if actual_realpath != record.canonical_worktree_path:
        return WorkspaceCheck(
            ok=False,
            canonical_path=actual_realpath,
            workspace_mode=record.workspace_mode,
            branch=record.branch,
            head_commit=None,
            is_clean=False,
            ownership_verified=False,
            reason=f"realpath mismatch: expected {record.canonical_worktree_path}, got {actual_realpath}",
        )

    if record.workspace_mode == "inherit":
        return WorkspaceCheck(
            ok=True,
            canonical_path=actual_realpath,
            workspace_mode="inherit",
            branch=None,
            head_commit=record.base_commit,
            is_clean=True,
            ownership_verified=True,
            reason=None,
        )

    # workspace_mode == "branch"
    top_proc = _run_git(actual_realpath, ["rev-parse", "--show-toplevel"], isolated=True)
    if top_proc.returncode != 0:
        return WorkspaceCheck(
            ok=False,
            canonical_path=actual_realpath,
            workspace_mode=record.workspace_mode,
            branch=record.branch,
            head_commit=None,
            is_clean=False,
            ownership_verified=False,
            reason="git rev-parse --show-toplevel failed",
        )
    top_realpath = os.path.realpath(top_proc.stdout.decode("utf-8", errors="replace").strip())
    if top_realpath != record.canonical_worktree_path:
        return WorkspaceCheck(
            ok=False,
            canonical_path=actual_realpath,
            workspace_mode=record.workspace_mode,
            branch=record.branch,
            head_commit=None,
            is_clean=False,
            ownership_verified=False,
            reason=f"git toplevel ({top_realpath}) does not match canonical_worktree_path ({record.canonical_worktree_path})",
        )

    head_proc = _run_git(actual_realpath, ["rev-parse", "--verify", "HEAD"], isolated=True)
    if head_proc.returncode != 0:
        return WorkspaceCheck(
            ok=False,
            canonical_path=actual_realpath,
            workspace_mode=record.workspace_mode,
            branch=record.branch,
            head_commit=None,
            is_clean=False,
            ownership_verified=False,
            reason="git rev-parse --verify HEAD failed",
        )
    actual_head = head_proc.stdout.decode("utf-8", errors="replace").strip()

    branch_proc = _run_git(actual_realpath, ["symbolic-ref", "--short", "HEAD"], isolated=True)
    if branch_proc.returncode == 0:
        actual_branch: str | None = branch_proc.stdout.decode("utf-8", errors="replace").strip()
    else:
        rev_branch_proc = _run_git(actual_realpath, ["rev-parse", "--abbrev-ref", "HEAD"], isolated=True)
        actual_branch = (
            rev_branch_proc.stdout.decode("utf-8", errors="replace").strip()
            if rev_branch_proc.returncode == 0
            else None
        )

    status_proc = _run_git(actual_realpath, ["status", "--porcelain=v1", "--untracked-files=all"], isolated=True)
    is_clean = status_proc.returncode == 0 and not status_proc.stdout.decode("utf-8", errors="replace").strip()

    sidecar = _read_ownership_sidecar(Path(actual_realpath))
    ownership_verified = True
    if record.ownership_marker is not None:
        if (
            sidecar is None
            or sidecar.get("operation_id") != record.operation_id
            or sidecar.get("node_id") != record.node_id
            or sidecar.get("ownership_marker") != record.ownership_marker
        ):
            ownership_verified = False

    reasons: list[str] = []
    if record.base_commit is not None and actual_head != record.base_commit:
        reasons.append(f"HEAD ({actual_head}) != base_commit ({record.base_commit})")
    if record.branch is not None and actual_branch != record.branch:
        reasons.append(f"branch ({actual_branch}) != expected ({record.branch})")
    if not ownership_verified:
        reasons.append("ownership marker verification failed")

    ok = len(reasons) == 0
    return WorkspaceCheck(
        ok=ok,
        canonical_path=actual_realpath,
        workspace_mode=record.workspace_mode,
        branch=actual_branch,
        head_commit=actual_head,
        is_clean=is_clean,
        ownership_verified=ownership_verified,
        reason="; ".join(reasons) if reasons else None,
    )


def verify_owned_post_run(
    record: WorktreeRecord,
    *,
    expected_tip: str | None = None,
) -> dict[str, Any]:
    """Verify an owned branch worktree after child run execution (where HEAD may have advanced from base_commit)."""
    if record.workspace_mode != "branch":
        return {
            "ok": False,
            "reason": "workspace_mode is not 'branch'",
            "actual_head": None,
            "actual_tree": None,
            "clean": False,
            "has_ignored": False,
            "dirty_entries": [],
            "commits_ahead": 0,
        }

    home = Path(record.worktrees_home).expanduser().absolute()
    try:
        rel = Path(record.canonical_worktree_path).absolute().relative_to(home)
        resolved_wt = safe_resolve_under(home, rel.as_posix(), mkdirs=False)
    except Exception as exc:
        return {
            "ok": False,
            "reason": f"worktree path is not safely under worktrees_home: {exc}",
            "actual_head": None,
            "actual_tree": None,
            "clean": False,
            "has_ignored": False,
            "dirty_entries": [],
            "commits_ahead": 0,
        }

    wt_path = Path(resolved_wt)
    if not wt_path.exists() or wt_path.is_symlink():
        return {
            "ok": False,
            "reason": "worktree path is missing or a symlink",
            "actual_head": None,
            "actual_tree": None,
            "clean": False,
            "has_ignored": False,
            "dirty_entries": [],
            "commits_ahead": 0,
        }
    actual_realpath = os.path.realpath(wt_path)
    if actual_realpath != record.canonical_worktree_path:
        return {
            "ok": False,
            "reason": f"realpath mismatch: {actual_realpath} != {record.canonical_worktree_path}",
            "actual_head": None,
            "actual_tree": None,
            "clean": False,
            "has_ignored": False,
            "dirty_entries": [],
            "commits_ahead": 0,
        }

    sidecar = _read_ownership_sidecar(wt_path)
    expected_sidecar_payload = {
        "worktree_id": record.worktree_id,
        "node_id": record.node_id,
        "operation_id": record.operation_id,
        "canonical_worktree_path": record.canonical_worktree_path,
        "repo_root": record.repo_root,
        "base_commit": record.base_commit,
        "branch": record.branch,
    }
    expected_marker = canonical_json_sha256(expected_sidecar_payload)
    if (
        sidecar is None
        or not record.ownership_marker
        or record.ownership_marker != expected_marker
        or sidecar.get("ownership_marker") != record.ownership_marker
        or any(sidecar.get(k) != v for k, v in expected_sidecar_payload.items())
    ):
        return {
            "ok": False,
            "reason": "ownership sidecar verification failed across 8 ownership keys",
            "actual_head": None,
            "actual_tree": None,
            "clean": False,
            "has_ignored": False,
            "dirty_entries": [],
            "commits_ahead": 0,
        }

    if not record.repo_root or not Path(record.repo_root).is_dir():
        return {
            "ok": False,
            "reason": "parent repo_root does not exist",
            "actual_head": None,
            "actual_tree": None,
            "clean": False,
            "has_ignored": False,
            "dirty_entries": [],
            "commits_ahead": 0,
        }

    p_common = _run_git(record.repo_root, ["rev-parse", "--path-format=absolute", "--git-common-dir"], isolated=True)
    c_common = _run_git(wt_path, ["rev-parse", "--path-format=absolute", "--git-common-dir"], isolated=True)
    if p_common.returncode != 0 or c_common.returncode != 0:
        return {
            "ok": False,
            "reason": "failed to resolve git-common-dir for parent or worktree",
            "actual_head": None,
            "actual_tree": None,
            "clean": False,
            "has_ignored": False,
            "dirty_entries": [],
            "commits_ahead": 0,
        }
    p_common_real = os.path.realpath(p_common.stdout.decode("utf-8", errors="replace").strip())
    c_common_real = os.path.realpath(c_common.stdout.decode("utf-8", errors="replace").strip())
    if p_common_real != c_common_real:
        return {
            "ok": False,
            "reason": f"git-common-dir mismatch: {p_common_real} != {c_common_real}",
            "actual_head": None,
            "actual_tree": None,
            "clean": False,
            "has_ignored": False,
            "dirty_entries": [],
            "commits_ahead": 0,
        }

    sym_proc = _run_git(wt_path, ["symbolic-ref", "-q", "HEAD"], isolated=True)
    sym_ref = sym_proc.stdout.decode("utf-8", errors="replace").strip() if sym_proc.returncode == 0 else ""
    if sym_proc.returncode != 0 or sym_ref != f"refs/heads/{record.branch}":
        return {
            "ok": False,
            "reason": f"detached HEAD or branch mismatch: expected refs/heads/{record.branch}, got {sym_ref!r}",
            "actual_head": None,
            "actual_tree": None,
            "clean": False,
            "has_ignored": False,
            "dirty_entries": [],
            "commits_ahead": 0,
        }

    head_proc = _run_git(wt_path, ["rev-parse", "--verify", "HEAD^{commit}"], isolated=True)
    tree_proc = _run_git(wt_path, ["rev-parse", "--verify", "HEAD^{tree}"], isolated=True)
    if head_proc.returncode != 0 or tree_proc.returncode != 0:
        return {
            "ok": False,
            "reason": "failed to resolve HEAD commit or tree",
            "actual_head": None,
            "actual_tree": None,
            "clean": False,
            "has_ignored": False,
            "dirty_entries": [],
            "commits_ahead": 0,
        }
    actual_head = head_proc.stdout.decode("utf-8", errors="replace").strip()
    actual_tree = tree_proc.stdout.decode("utf-8", errors="replace").strip()

    if record.base_commit:
        anc_proc = _run_git(
            wt_path,
            ["merge-base", "--is-ancestor", record.base_commit, actual_head],
            isolated=True,
        )
        if anc_proc.returncode != 0:
            return {
                "ok": False,
                "reason": f"base_commit ({record.base_commit}) is not an ancestor of HEAD ({actual_head})",
                "actual_head": actual_head,
                "actual_tree": actual_tree,
                "clean": False,
                "has_ignored": False,
                "dirty_entries": [],
                "commits_ahead": 0,
            }

    if expected_tip is not None and actual_head != expected_tip:
        return {
            "ok": False,
            "reason": f"HEAD ({actual_head}) != expected_tip ({expected_tip})",
            "actual_head": actual_head,
            "actual_tree": actual_tree,
            "clean": False,
            "has_ignored": False,
            "dirty_entries": [],
            "commits_ahead": 0,
        }

    st_proc = _run_git(wt_path, ["status", "--porcelain=v1", "-z", "-uall"], isolated=True)
    ig_proc = _run_git(wt_path, ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"], isolated=True)
    dirty_entries = [e for e in st_proc.stdout.decode("utf-8", errors="replace").split("\x00") if e]
    ignored_entries = [e for e in ig_proc.stdout.decode("utf-8", errors="replace").split("\x00") if e]
    is_clean = st_proc.returncode == 0 and len(dirty_entries) == 0

    commits_ahead = 0
    if record.base_commit:
        cnt_proc = _run_git(wt_path, ["rev-list", "--count", f"{record.base_commit}..{actual_head}"], isolated=True)
        if cnt_proc.returncode == 0:
            try:
                commits_ahead = int(cnt_proc.stdout.decode("utf-8", errors="replace").strip())
            except ValueError:
                commits_ahead = 0

    has_submodule = False
    has_escaping_symlink = False
    if record.base_commit:
        diff_raw = _run_git(
            wt_path,
            ["diff-tree", "-r", "--no-commit-id", "-z", record.base_commit, actual_head],
            isolated=True,
        )
        tokens = [t for t in diff_raw.stdout.decode("utf-8", errors="replace").split("\x00") if t]
        idx = 0
        while idx < len(tokens):
            tok = tokens[idx]
            if tok.startswith(":"):
                parts = tok.split()
                dst_mode = parts[1] if len(parts) > 1 else ""
                status_ch = parts[4][0] if len(parts) > 4 and parts[4] else ""
                path_arg = tokens[idx + 2] if status_ch in ("R", "C") and (idx + 2) < len(tokens) else (tokens[idx + 1] if (idx + 1) < len(tokens) else "")
                step = 3 if status_ch in ("R", "C") else 2
                if dst_mode == "160000":
                    has_submodule = True
                elif dst_mode == "120000" and path_arg:
                    cand = wt_path / path_arg
                    if cand.is_symlink():
                        target_raw = os.readlink(cand)
                        if os.path.isabs(target_raw) or not _is_subpath_or_equal(cand.parent / target_raw, wt_path):
                            has_escaping_symlink = True
                idx += step
            else:
                idx += 1

    return {
        "ok": True,
        "actual_head": actual_head,
        "actual_tree": actual_tree,
        "clean": is_clean,
        "has_ignored": bool(ignored_entries),
        "ignored_entries": ignored_entries,
        "dirty_entries": dirty_entries,
        "commits_ahead": commits_ahead,
        "has_submodule": has_submodule,
        "has_escaping_symlink": has_escaping_symlink,
        "reason": None,
    }


def cleanup_owned(
    record: WorktreeRecord,
    *,
    expected_operation_id: str,
    idle_evidence: Mapping[str, Any] | None = None,
    expected_head: str | None = None,
    delete_branch: bool = True,
) -> CleanupResult:
    """Safely remove an owned, clean, idle worktree created by this operation.

    Requires a matching on-disk ownership marker, a canonical path strictly inside
    `record.worktrees_home`, and caller-supplied idle evidence. Branch deletion uses
    `git branch -d` and only for the engine-allocated `side/<node_uuid_hex>` name
    when HEAD still equals `base_commit`.
    """
    if record.operation_id != expected_operation_id:
        return CleanupResult(
            cleaned=False,
            state="ownership_mismatch",
            canonical_path=record.canonical_worktree_path,
            branch_removed=False,
            reason=f"record.operation_id ({record.operation_id}) != expected_operation_id ({expected_operation_id})",
        )

    if record.workspace_mode != "branch":
        return CleanupResult(
            cleaned=False,
            state="not_applicable",
            canonical_path=record.canonical_worktree_path,
            branch_removed=False,
            reason="inherit workspace is not owned by operation",
        )

    if record.ownership_marker is None:
        return CleanupResult(
            cleaned=False,
            state="ownership_mismatch",
            canonical_path=record.canonical_worktree_path,
            branch_removed=False,
            reason="ownership_marker is missing; refusing to delete an unmarked worktree",
        )

    if idle_evidence is None or not bool(idle_evidence.get("idle")):
        state = "reconciliation" if idle_evidence is None else "retained"
        return CleanupResult(
            cleaned=False,
            state=state,
            canonical_path=record.canonical_worktree_path,
            branch_removed=False,
            reason="cleanup_owned requires verified idle evidence (no bound runtime / live process)",
        )

    home = Path(record.worktrees_home).expanduser().absolute()
    try:
        rel = Path(record.canonical_worktree_path).absolute().relative_to(home)
    except ValueError:
        return CleanupResult(
            cleaned=False,
            state="PATH_ESCAPE",
            canonical_path=record.canonical_worktree_path,
            branch_removed=False,
            reason=f"canonical_worktree_path is outside worktrees_home ({home})",
        )
    try:
        resolved_wt = safe_resolve_under(home, rel.as_posix(), mkdirs=False)
    except SideSessionError as exc:
        return CleanupResult(
            cleaned=False,
            state="PATH_ESCAPE" if exc.code == ErrorCode.PATH_ESCAPE else "ownership_mismatch",
            canonical_path=record.canonical_worktree_path,
            branch_removed=False,
            reason=exc.message,
        )
    wt_path = Path(resolved_wt)

    sidecar = _read_ownership_sidecar(wt_path)
    if (
        sidecar is None
        or sidecar.get("operation_id") != expected_operation_id
        or sidecar.get("ownership_marker") != record.ownership_marker
        or sidecar.get("node_id") != record.node_id
    ):
        return CleanupResult(
            cleaned=False,
            state="ownership_mismatch",
            canonical_path=record.canonical_worktree_path,
            branch_removed=False,
            reason="on-disk ownership marker is missing or does not match expected_operation_id",
        )

    if not wt_path.exists():
        sidecar_file = _owner_sidecar_path(wt_path)
        if sidecar_file.exists():
            try:
                sidecar_file.unlink()
            except OSError:
                pass
        return CleanupResult(
            cleaned=True,
            state="cleaned",
            canonical_path=record.canonical_worktree_path,
            branch_removed=False,
            reason="worktree path already absent",
        )

    status_proc = _run_git(wt_path, ["status", "--porcelain=v1", "--untracked-files=all"], isolated=True)
    if status_proc.returncode != 0:
        return CleanupResult(
            cleaned=False,
            state="reconciliation",
            canonical_path=record.canonical_worktree_path,
            branch_removed=False,
            reason="git status failed inside worktree",
        )

    porcelain = status_proc.stdout.decode("utf-8", errors="replace").strip()
    if porcelain:
        return CleanupResult(
            cleaned=False,
            state="retained_dirty",
            canonical_path=record.canonical_worktree_path,
            branch_removed=False,
            reason="worktree has uncommitted or untracked changes",
        )

    ig_proc = _run_git(wt_path, ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"], isolated=True)
    if ig_proc.returncode == 0 and ig_proc.stdout.strip(b"\x00"):
        return CleanupResult(
            cleaned=False,
            state="retained_dirty",
            canonical_path=record.canonical_worktree_path,
            branch_removed=False,
            reason="worktree has ignored untracked files",
        )

    head_proc = _run_git(wt_path, ["rev-parse", "--verify", "HEAD"], isolated=True)
    if head_proc.returncode != 0:
        return CleanupResult(
            cleaned=False,
            state="reconciliation",
            canonical_path=record.canonical_worktree_path,
            branch_removed=False,
            reason="failed to verify worktree HEAD before cleanup",
        )
    cur_head = head_proc.stdout.decode("utf-8", errors="replace").strip()
    target_expected_head = expected_head if expected_head is not None else record.base_commit
    if target_expected_head is not None and cur_head != target_expected_head:
        return CleanupResult(
            cleaned=False,
            state="retained_dirty",
            canonical_path=record.canonical_worktree_path,
            branch_removed=False,
            reason=f"worktree HEAD ({cur_head}) has diverged from expected ({target_expected_head})",
        )

    repo_root = record.repo_root or str(wt_path)
    rm_proc = _run_git(repo_root, ["worktree", "remove", str(wt_path)], isolated=True)
    if rm_proc.returncode != 0:
        return CleanupResult(
            cleaned=False,
            state="reconciliation",
            canonical_path=record.canonical_worktree_path,
            branch_removed=False,
            reason=f"git worktree remove failed: {rm_proc.stderr.decode('utf-8', errors='replace').strip()}",
        )

    branch_removed = False
    expected_branch = _engine_branch_name(record.node_id)
    if (
        delete_branch
        and record.branch == expected_branch
        and record.repo_root
        and target_expected_head is not None
        and cur_head == target_expected_head
    ):
        br_proc = _run_git(record.repo_root, ["branch", "-d", record.branch], isolated=True)
        branch_removed = br_proc.returncode == 0

    sidecar_file = _owner_sidecar_path(wt_path)
    if sidecar_file.exists():
        try:
            sidecar_file.unlink()
        except OSError:
            pass

    return CleanupResult(
        cleaned=True,
        state="cleaned",
        canonical_path=record.canonical_worktree_path,
        branch_removed=branch_removed,
        reason=None,
    )


prepare_worktree = prepare


__all__ = [
    "_run_isolated_git",
    "check_no_custom_git_drivers",
    "cleanup_owned",
    "git_identity_args",
    "git_identity_fallback_args",
    "inspect_source",
    "prepare",
    "prepare_worktree",
    "verify",
    "verify_owned_post_run",
]
