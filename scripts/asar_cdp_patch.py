from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import plistlib
import re
import stat
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from state import resolve_state_root  # noqa: E402

APP = Path("/Applications/ZCode.app")
ASAR = APP / "Contents/Resources/app.asar"
FRAMEWORK = APP / "Contents/Frameworks/Electron Framework.framework/Electron Framework"
PAT = re.compile(
    rb'!(\w+)\.isPackaged&&process\.env\.ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT!=="1"&&'
    rb'\1\.commandLine\.appendSwitch\("remote-debugging-port","9229"\)'
)
PAT_PATCHED = re.compile(
    rb'(\w+)\.commandLine\.appendSwitch\("remote-debugging-port","0"\)/\*ss-cdp\*/ *'
)
WIRE_IDX_NODE_CLI_INSPECT = 3  # 第 4 位：node_cli_inspect
WIRE_IDX_ASAR_INTEGRITY = 4  # 第 5 位：embedded_asar_integrity_validation
DEFAULT_FUSE_WIRE_OFFSET = 157950204


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_header(f: Any) -> tuple[dict[str, Any], int]:
    a, header_size, _payload, json_len = struct.unpack("<4I", f.read(16))
    hdr = json.loads(f.read(json_len))
    return hdr, 8 + header_size


def read_fuse_wire(entry: dict[str, Any] | None = None, framework_path: Path | None = None) -> tuple[str | None, str | None]:
    fw = framework_path or FRAMEWORK
    if not fw.is_file():
        return None, "FRAMEWORK_NOT_FOUND"
    off = int((entry or {}).get("fuseWireOffset", DEFAULT_FUSE_WIRE_OFFSET))
    sentinel = str((entry or {}).get("fuseSentinel") or "")
    try:
        with fw.open("rb") as f:
            f.seek(off)
            probe = f.read(2)
            if len(probe) != 2:
                return None, "FUSE_WIRE_UNREADABLE"
            # Support both sentinel-start offset (157950204, wire at +32) and direct wire offset (157950236)
            wire_off = off if (probe[0] == 1 and 1 <= probe[1] <= 64) else (off + 32)
            if sentinel:
                s = sentinel.encode("ascii")
                s_off = wire_off - len(s)
                if s_off < 0:
                    return None, "FUSE_SENTINEL_MISMATCH"
                f.seek(s_off)
                if f.read(len(s)) != s:
                    return None, "FUSE_SENTINEL_MISMATCH"
            f.seek(wire_off)
            raw_head = f.read(2)
            if len(raw_head) != 2:
                return None, "FUSE_WIRE_UNREADABLE"
            ver, n = raw_head[0], raw_head[1]
            wire_bytes = f.read(n)
            try:
                wire = wire_bytes.decode("ascii")
            except UnicodeDecodeError:
                return None, "FUSE_WIRE_UNREADABLE"
    except OSError:
        return None, "FUSE_WIRE_UNREADABLE"
    if ver != 1 or len(wire) != n or (set(wire) - set("01r")):
        return None, "FUSE_WIRE_UNREADABLE"
    return wire, None


def check_fuse(entry: dict[str, Any] | None = None, framework_path: Path | None = None) -> str | None:
    wire, err = read_fuse_wire(entry, framework_path=framework_path)
    if err:
        return err
    assert wire is not None
    if len(wire) <= WIRE_IDX_ASAR_INTEGRITY:
        return "FUSE_WIRE_UNREADABLE"
    return None if wire[WIRE_IDX_ASAR_INTEGRITY] == "0" else "INTEGRITY_FUSE_ON"


def _locate_in_stream(f: Any) -> dict[str, Any]:
    hdr, base = read_header(f)
    fe = hdr["files"]["out"]["files"]["main"]["files"]["index.js"]
    f.seek(base + int(fe["offset"]))
    body = f.read(int(fe["size"]))
    ms = list(PAT.finditer(body))
    if len(ms) != 1:
        patched_ms = list(PAT_PATCHED.finditer(body))
        res: dict[str, Any] = {
            "ok": False,
            "code": "PATTERN_COUNT",
            "count": len(ms),
            "alreadyPatched": len(patched_ms) == 1,
        }
        if len(patched_ms) == 1:
            pm = patched_ms[0]
            res["patchedAbs"] = base + int(fe["offset"]) + pm.start()
            res["patchedLen"] = pm.end() - pm.start()
            res["patchedBytes"] = pm.group(0).decode("latin-1")
        return res
    m = ms[0]
    repl = m.group(1) + b'.commandLine.appendSwitch("remote-debugging-port","0")/*ss-cdp*/'
    if len(repl) > len(m.group(0)):
        return {"ok": False, "code": "REPLACEMENT_TOO_LONG"}
    padded = repl + b" " * (len(m.group(0)) - len(repl))
    expected_hash = fe.get("integrity", {}).get("hash")
    file_sha_ok = (expected_hash is None) or (hashlib.sha256(body).hexdigest() == expected_hash)
    return {
        "ok": True,
        "abs": base + int(fe["offset"]) + m.start(),
        "orig": m.group(0),
        "new": padded,
        "fileShaOk": file_sha_ok,
    }


def locate(asar_path: Path | None = None) -> dict[str, Any]:
    target_asar = asar_path or ASAR
    if not target_asar.is_file():
        return {"ok": False, "code": "ASAR_NOT_FOUND", "path": str(target_asar)}
    with target_asar.open("rb") as f:
        return _locate_in_stream(f)


def codesign_ok(app_path: Path | None = None) -> bool:
    target_app = app_path or APP
    return (
        subprocess.run(
            ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(target_app)],
            capture_output=True,
        ).returncode
        == 0
    )


def read_coderesources_hash2(app_path: Path | None = None) -> str | None:
    target_app = app_path or APP
    cr = target_app / "Contents" / "_CodeSignature" / "CodeResources"
    if not cr.is_file():
        return None
    try:
        pl = plistlib.loads(cr.read_bytes())
        h2 = pl.get("files2", {}).get("Resources/app.asar", {}).get("hash2")
        if isinstance(h2, (bytes, bytearray)):
            return bytes(h2).hex()
    except Exception:
        pass
    return None


def write_patch(abs_off: int, data: bytes, asar_path: Path | None = None) -> str | None:
    target_asar = asar_path or ASAR
    tmp = target_asar.with_name(".app.asar.ss-tmp")
    try:
        subprocess.run(["/bin/cp", "-c", str(target_asar), str(tmp)], check=True)
        fd = os.open(tmp, os.O_WRONLY)
        try:
            os.pwrite(fd, data, abs_off)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, target_asar)
        return None
    except PermissionError:
        tmp.unlink(missing_ok=True)
        return "APP_MANAGEMENT_DENIED"
    except subprocess.CalledProcessError:
        tmp.unlink(missing_ok=True)
        return "CLONE_FAILED"


def _load_builds_map() -> dict[str, Any]:
    compat_file = HERE.parent / "ui" / "compatibility.json"
    if compat_file.is_file():
        try:
            builds = json.loads(compat_file.read_text(encoding="utf-8")).get("builds", {})
            if isinstance(builds, dict):
                return builds
        except Exception:
            pass
    return {}


def _stat_ident(st: os.stat_result) -> tuple[int, int, int, int]:
    return (
        st.st_dev,
        st.st_ino,
        st.st_size,
        getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)),
    )


def migrate_legacy_manifest_if_verified(
    asar_path: Path,
    manifest_path: Path,
    builds_map: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Idempotently self-heal a legacy manifest missing patchedSha if reversing the slice yields origSha."""
    if not isinstance(builds_map, Mapping):
        return None
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        m_fd = os.open(str(manifest_path), os.O_RDONLY | o_nofollow)
    except OSError:
        return None
    try:
        m_st = os.fstat(m_fd)
        if (
            not stat.S_ISREG(m_st.st_mode)
            or m_st.st_uid != os.getuid()
            or (m_st.st_mode & 0o022) != 0
        ):
            return None
        m_bytes = b""
        m_off = 0
        while True:
            part = os.pread(m_fd, 65536, m_off)
            if not part:
                break
            m_bytes += part
            m_off += len(part)
        manifest = json.loads(m_bytes.decode("utf-8"))
    except Exception:
        return None
    finally:
        os.close(m_fd)

    if not isinstance(manifest, dict):
        return None
    orig_sha = manifest.get("origSha")
    if (
        not isinstance(orig_sha, str)
        or not re.fullmatch(r"[0-9a-fA-F]{64}", orig_sha)
        or orig_sha not in builds_map
    ):
        return None
    abs_off = manifest.get("abs")
    if not isinstance(abs_off, int) or isinstance(abs_off, bool) or abs_off < 0:
        return None
    orig_str = manifest.get("orig")
    if not isinstance(orig_str, str) or not orig_str:
        return None
    try:
        orig_bytes = orig_str.encode("latin-1")
    except UnicodeEncodeError:
        return None

    existing_patched_sha = manifest.get("patchedSha")
    if existing_patched_sha is not None and not isinstance(existing_patched_sha, str):
        return None

    try:
        fd = os.open(str(asar_path), os.O_RDONLY | o_nofollow)
    except OSError:
        return None
    try:
        st1 = os.fstat(fd)
        if not stat.S_ISREG(st1.st_mode):
            return None
        buf = bytearray()
        off = 0
        while True:
            chunk = os.pread(fd, 1 << 20, off)
            if not chunk:
                break
            buf.extend(chunk)
            off += len(chunk)
        st2 = os.fstat(fd)
        try:
            lst = os.lstat(asar_path)
        except OSError:
            return None
        if (
            stat.S_ISLNK(lst.st_mode)
            or (lst.st_dev, lst.st_ino) != (st1.st_dev, st1.st_ino)
            or _stat_ident(st1) != _stat_ident(st2)
        ):
            return None
    finally:
        os.close(fd)

    if abs_off + len(orig_bytes) > len(buf):
        return None
    try:
        loc = _locate_in_stream(io.BytesIO(buf))
    except Exception:
        return None
    if not (loc.get("alreadyPatched") is True and loc.get("patchedAbs") == abs_off):
        return None

    cur_sha = hashlib.sha256(buf).hexdigest()
    if isinstance(existing_patched_sha, str) and existing_patched_sha.strip() and existing_patched_sha != cur_sha:
        return None

    patched_bytes = bytes(buf[abs_off : abs_off + len(orig_bytes)])
    buf[abs_off : abs_off + len(orig_bytes)] = orig_bytes
    restored_sha = hashlib.sha256(buf).hexdigest()
    if restored_sha != orig_sha.lower():
        return None

    updated = dict(manifest)
    updated["patchedSha"] = cur_sha
    updated["patchLen"] = len(orig_bytes)
    updated["patched"] = patched_bytes.decode("latin-1")
    updated["patchedSliceSha"] = hashlib.sha256(patched_bytes).hexdigest()
    if not updated.get("origSliceSha"):
        updated["origSliceSha"] = hashlib.sha256(orig_bytes).hexdigest()

    if updated != manifest:
        parent = manifest_path.parent
        try:
            p_st = os.lstat(parent)
            can_write = (
                stat.S_ISDIR(p_st.st_mode)
                and p_st.st_uid == os.getuid()
                and os.access(parent, os.W_OK)
            )
        except OSError:
            can_write = False
        if can_write:
            tmp_p = parent / f".{manifest_path.name}.{os.getpid()}.tmp"
            try:
                t_fd = os.open(
                    str(tmp_p),
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC | o_nofollow,
                    0o600,
                )
                try:
                    payload = json.dumps(updated, indent=2).encode("utf-8")
                    os.write(t_fd, payload)
                    os.fchmod(t_fd, 0o600)
                    os.fsync(t_fd)
                finally:
                    os.close(t_fd)
                os.replace(tmp_p, manifest_path)
            except OSError:
                try:
                    tmp_p.unlink(missing_ok=True)
                except OSError:
                    pass

    return updated


def apply(
    entry: dict[str, Any],
    manifest_path: Path,
    *,
    app_path: Path | None = None,
    builds: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    target_app = app_path or APP
    target_asar = target_app / "Contents/Resources/app.asar" if app_path else ASAR
    target_fw = (
        target_app / "Contents/Frameworks/Electron Framework.framework/Electron Framework"
        if app_path
        else FRAMEWORK
    )
    if e := check_fuse(entry, framework_path=target_fw):
        return {"ok": False, "code": e}

    builds_map = builds if builds is not None else _load_builds_map()
    if manifest_path.is_file():
        try:
            existing_m = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            existing_m = None
        if isinstance(existing_m, dict):
            p_sha = existing_m.get("patchedSha")
            if not isinstance(p_sha, str) or not p_sha.strip():
                migrate_legacy_manifest_if_verified(target_asar, manifest_path, builds_map)

    loc = locate(asar_path=target_asar)
    if not loc["ok"]:
        if loc.get("alreadyPatched") and manifest_path.is_file():
            try:
                m_cur = json.loads(manifest_path.read_text(encoding="utf-8"))
            except Exception:
                m_cur = None
            cur_sha = sha256_file(target_asar)
            if not isinstance((m_cur or {}).get("patchedSha"), str) or not str((m_cur or {}).get("patchedSha") or "").strip():
                m_cur = migrate_legacy_manifest_if_verified(target_asar, manifest_path, builds_map)
            if (
                isinstance(m_cur, dict)
                and m_cur.get("patchedSha") == cur_sha
                and m_cur.get("abs") == loc.get("patchedAbs")
            ):
                return {
                    "ok": True,
                    "alreadyApplied": True,
                    "abs": int(m_cur["abs"]),
                    "origSha": m_cur.get("origSha"),
                    "patchedSha": cur_sha,
                    "codesignNowFails": not codesign_ok(target_app),
                }
        return loc
    if not loc["fileShaOk"]:
        return {"ok": False, "code": "INDEXJS_ALREADY_MODIFIED"}
    orig_sha = sha256_file(target_asar)
    hash2 = read_coderesources_hash2(target_app)
    had_manifest = manifest_path.is_file()
    prev_manifest = manifest_path.read_text(encoding="utf-8") if had_manifest else None
    manifest: dict[str, Any] = {
        "origSha": orig_sha,
        "patchedSha": None,
        "codeResourcesHash2": hash2,
        "abs": loc["abs"],
        "patchLen": len(loc["orig"]),
        "orig": loc["orig"].decode("latin-1"),
        "patched": loc["new"].decode("latin-1"),
        "origSliceSha": hashlib.sha256(loc["orig"]).hexdigest(),
        "patchedSliceSha": hashlib.sha256(loc["new"]).hexdigest(),
        "note": "ElectronAsarIntegrity 无法复现，仅在 fuse=0 时允许；头部 integrity 与 Info.plist 均不更新",
    }
    manifest_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    try:
        os.chmod(manifest_path, 0o600)
    except OSError:
        pass
    if e := write_patch(int(loc["abs"]), loc["new"], asar_path=target_asar):
        if prev_manifest is not None:
            manifest_path.write_text(prev_manifest, encoding="utf-8")
        else:
            manifest_path.unlink(missing_ok=True)
        return {"ok": False, "code": e}
    patched_sha = sha256_file(target_asar)
    manifest["patchedSha"] = patched_sha
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    try:
        os.chmod(manifest_path, 0o600)
    except OSError:
        pass
    return {
        "ok": True,
        "abs": loc["abs"],
        "origSha": orig_sha,
        "patchedSha": patched_sha,
        "codesignNowFails": not codesign_ok(target_app),
    }


def restore(
    manifest_path: Path,
    hash2: str | None = None,
    *,
    app_path: Path | None = None,
    builds: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    target_app = app_path or APP
    target_asar = target_app / "Contents/Resources/app.asar" if app_path else ASAR
    if not manifest_path.is_file():
        return {"ok": False, "code": "MANIFEST_NOT_FOUND", "manifest": str(manifest_path)}
    if not target_asar.is_file():
        return {"ok": False, "code": "ASAR_NOT_FOUND", "path": str(target_asar)}
    m = json.loads(manifest_path.read_text(encoding="utf-8"))
    orig_sha = m.get("origSha")
    patched_sha = m.get("patchedSha")
    cur_sha = sha256_file(target_asar)
    expected_hash2 = hash2 or read_coderesources_hash2(target_app) or m.get("codeResourcesHash2") or orig_sha

    if cur_sha == orig_sha:
        cs_ok = codesign_ok(target_app)
        ok = (cur_sha == orig_sha == expected_hash2) and cs_ok
        if ok:
            manifest_path.unlink(missing_ok=True)
        return {
            "ok": ok,
            "alreadyRestored": True,
            "sha": cur_sha,
            "origSha": orig_sha,
            "patchedSha": patched_sha,
            "hash2": expected_hash2,
            "codesignOk": cs_ok,
        }

    if not isinstance(patched_sha, str) or not patched_sha.strip():
        builds_map = builds if builds is not None else _load_builds_map()
        migrated = migrate_legacy_manifest_if_verified(target_asar, manifest_path, builds_map)
        if migrated is not None:
            m = migrated
            patched_sha = m.get("patchedSha")

    if not patched_sha or cur_sha != patched_sha:
        return {
            "ok": False,
            "code": "ASAR_VERSION_CONFLICT",
            "sha": cur_sha,
            "origSha": orig_sha,
            "patchedSha": patched_sha,
        }

    orig_bytes = m["orig"].encode("latin-1")
    abs_off = int(m["abs"])
    if "patched" in m:
        expected_patched_bytes = m["patched"].encode("latin-1")
        with target_asar.open("rb") as f:
            f.seek(abs_off)
            actual_slice = f.read(len(orig_bytes))
        if actual_slice != expected_patched_bytes:
            return {
                "ok": False,
                "code": "ASAR_SLICE_MISMATCH",
                "sha": cur_sha,
                "origSha": orig_sha,
                "patchedSha": patched_sha,
            }

    if e := write_patch(abs_off, orig_bytes, asar_path=target_asar):
        return {"ok": False, "code": e}
    sha = sha256_file(target_asar)
    cs_ok = codesign_ok(target_app)
    ok = (sha == orig_sha == expected_hash2) and cs_ok
    if ok:
        manifest_path.unlink(missing_ok=True)
    return {
        "ok": ok,
        "sha": sha,
        "origSha": orig_sha,
        "patchedSha": patched_sha,
        "hash2": expected_hash2,
        "codesignOk": cs_ok,
    }


def resolve_build_entry(
    asar_path: Path | None,
    manifest_path: Path | None,
    builds: dict[str, Any] | Any,
    cache: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, str, str | None]:
    """Atomically verify ASAR SHA-256 and optional patch manifest on the same file descriptor."""
    target_asar = asar_path or ASAR
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(target_asar), os.O_RDONLY | o_nofollow)
    except OSError:
        return None, "", "ASAR_NOT_FOUND"

    try:
        st1 = os.fstat(fd)
        if not stat.S_ISREG(st1.st_mode):
            return None, "", "ASAR_NOT_REGULAR"

        stat_key = (
            st1.st_dev,
            st1.st_ino,
            st1.st_size,
            getattr(st1, "st_mtime_ns", int(st1.st_mtime * 1e9)),
            getattr(st1, "st_ctime_ns", int(st1.st_ctime * 1e9)),
        )
        if (
            isinstance(cache, dict)
            and cache.get("stat_key") == stat_key
            and isinstance(cache.get("sha"), str)
            and cache["sha"]
        ):
            cur_sha = str(cache["sha"])
        else:
            h = hashlib.sha256()
            off = 0
            while True:
                chunk = os.pread(fd, 1 << 20, off)
                if not chunk:
                    break
                h.update(chunk)
                off += len(chunk)
            st2 = os.fstat(fd)
            try:
                lst = os.lstat(target_asar)
            except OSError:
                return None, "", "ASAR_REPLACED"
            if (
                stat.S_ISLNK(lst.st_mode)
                or (lst.st_dev, lst.st_ino) != (st1.st_dev, st1.st_ino)
                or (
                    st2.st_dev,
                    st2.st_ino,
                    st2.st_size,
                    getattr(st2, "st_mtime_ns", int(st2.st_mtime * 1e9)),
                )
                != (stat_key[0], stat_key[1], stat_key[2], stat_key[3])
            ):
                return None, "", "ASAR_REPLACED"
            cur_sha = h.hexdigest()
            if isinstance(cache, dict):
                cache["stat_key"] = stat_key
                cache["sha"] = cur_sha

        builds_map = builds if isinstance(builds, Mapping) else {}
        if cur_sha in builds_map:
            return dict(builds_map[cur_sha]), cur_sha, None

        if manifest_path is None:
            return None, cur_sha, "UNSUPPORTED_BUILD"

        try:
            m_fd = os.open(str(manifest_path), os.O_RDONLY | o_nofollow)
        except OSError:
            return None, cur_sha, "UNSUPPORTED_BUILD"

        try:
            m_st = os.fstat(m_fd)
            if (
                not stat.S_ISREG(m_st.st_mode)
                or m_st.st_uid != os.getuid()
                or (m_st.st_mode & 0o022) != 0
            ):
                return None, cur_sha, "MANIFEST_UNTRUSTED"
            m_bytes = b""
            m_off = 0
            while True:
                part = os.pread(m_fd, 65536, m_off)
                if not part:
                    break
                m_bytes += part
                m_off += len(part)
            manifest = json.loads(m_bytes.decode("utf-8"))
        except Exception:
            return None, cur_sha, "MANIFEST_INVALID"
        finally:
            os.close(m_fd)

        if not isinstance(manifest, dict):
            return None, cur_sha, "MANIFEST_INVALID"

        patched_sha = manifest.get("patchedSha")
        if (
            not isinstance(patched_sha, str)
            or not patched_sha.strip()
            or not all(k in manifest for k in ("abs", "patched", "patchLen"))
        ):
            migrated = migrate_legacy_manifest_if_verified(target_asar, manifest_path, builds_map)
            if migrated is not None:
                manifest = migrated
                patched_sha = manifest.get("patchedSha")

        orig_sha = manifest.get("origSha")
        if not isinstance(patched_sha, str) or not patched_sha.strip():
            return None, cur_sha, "PATCH_MANIFEST_INCOMPLETE"
        if patched_sha != cur_sha:
            return None, cur_sha, "PATCHED_SHA_MISMATCH"
        if not isinstance(orig_sha, str) or orig_sha not in builds_map:
            return None, cur_sha, "ORIG_SHA_UNSUPPORTED"
        if not all(k in manifest for k in ("patchedSha", "abs", "patched", "patchLen")):
            return None, cur_sha, "PATCH_MANIFEST_INCOMPLETE"

        raw_abs = manifest.get("abs")
        raw_patched = manifest.get("patched")
        raw_patch_len = manifest.get("patchLen")
        if (
            not isinstance(raw_abs, int)
            or isinstance(raw_abs, bool)
            or not isinstance(raw_patched, str)
            or not isinstance(raw_patch_len, int)
            or isinstance(raw_patch_len, bool)
        ):
            return None, cur_sha, "PATCH_MANIFEST_INCOMPLETE"

        base_ident = (stat_key[0], stat_key[1], stat_key[2], stat_key[3])
        try:
            abs_off = int(raw_abs)
            expected_patched = raw_patched.encode("latin-1")
            patch_len = int(raw_patch_len)
            if patch_len <= 0 or patch_len != len(expected_patched) or abs_off < 0:
                return None, cur_sha, "ASAR_SLICE_MISMATCH"
            st_pre = os.fstat(fd)
            actual_slice = os.pread(fd, patch_len, abs_off)
            st_post = os.fstat(fd)
        except Exception:
            return None, cur_sha, "ASAR_SLICE_MISMATCH"

        if _stat_ident(st_pre) != base_ident or _stat_ident(st_post) != base_ident:
            return None, cur_sha, "ASAR_REPLACED"
        if actual_slice != expected_patched:
            return None, cur_sha, "ASAR_SLICE_MISMATCH"
        expected_slice_sha = manifest.get("patchedSliceSha")
        if expected_slice_sha and hashlib.sha256(actual_slice).hexdigest() != expected_slice_sha:
            return None, cur_sha, "ASAR_SLICE_MISMATCH"

        return dict(builds_map[orig_sha]), cur_sha, None
    finally:
        os.close(fd)


def status(manifest_path: Path | None = None, *, app_path: Path | None = None) -> dict[str, Any]:
    target_app = app_path or APP
    target_asar = target_app / "Contents/Resources/app.asar" if app_path else ASAR
    target_fw = (
        target_app / "Contents/Frameworks/Electron Framework.framework/Electron Framework"
        if app_path
        else FRAMEWORK
    )
    if not target_asar.is_file():
        return {"ok": False, "state": "absent", "code": "ASAR_NOT_FOUND"}
    loc = locate(asar_path=target_asar)
    fuse_err = check_fuse({"fuseWireOffset": DEFAULT_FUSE_WIRE_OFFSET}, framework_path=target_fw)
    cs_ok = codesign_ok(target_app)
    applied = bool(not loc.get("ok") and loc.get("alreadyPatched"))
    return {
        "ok": True,
        "state": "applied" if applied else "absent",
        "asarSha": sha256_file(target_asar),
        "fuseCheck": "ok" if fuse_err is None else fuse_err,
        "codesign": "valid" if cs_ok else ("invalid(patched)" if applied else "invalid"),
        "manifestExists": bool(manifest_path and manifest_path.is_file()),
        "locate": {
            "ok": bool(loc.get("ok")),
            "code": loc.get("code"),
            "abs": loc.get("abs"),
            "alreadyPatched": applied,
        },
    }


def _default_manifest_path(state_home: str | None) -> Path:
    root = Path(state_home).expanduser().resolve() if state_home else resolve_state_root()
    return root / "sidebar-ui" / "backups" / "asar_patch.json"


def _load_default_entry() -> dict[str, Any]:
    compat_file = HERE.parent / "ui" / "compatibility.json"
    if compat_file.is_file():
        try:
            builds = json.loads(compat_file.read_text(encoding="utf-8")).get("builds", {})
            if builds:
                return next(iter(builds.values()))
        except Exception:
            pass
    return {"fuseWireOffset": DEFAULT_FUSE_WIRE_OFFSET, "fuseSentinel": ""}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Opt-in equal-length ZCode ASAR CDP port patch utility")
    sub = parser.add_subparsers(dest="cmd")

    for name in ("status", "locate", "apply", "restore"):
        p = sub.add_parser(name)
        p.add_argument("--state-home", default=None, help="State root directory")
        p.add_argument("--manifest", default=None, help="Override backup manifest path")
        p.add_argument("--app", default=None, help="Override ZCode.app path (for isolated testing)")

    args = parser.parse_args(argv)
    cmd = args.cmd or "status"
    app_p = Path(args.app).expanduser().resolve() if getattr(args, "app", None) else None
    manifest_p = (
        Path(args.manifest).expanduser().resolve()
        if getattr(args, "manifest", None)
        else _default_manifest_path(getattr(args, "state_home", None))
    )

    if cmd == "status":
        res = status(manifest_p, app_path=app_p)
    elif cmd == "locate":
        loc = locate((app_p / "Contents/Resources/app.asar") if app_p else None)
        if "orig" in loc:
            loc = {**loc, "orig": loc["orig"].decode("latin-1"), "new": loc["new"].decode("latin-1")}
        res = loc
    elif cmd == "apply":
        target_asar = (app_p / "Contents/Resources/app.asar") if app_p else ASAR
        builds_map = _load_builds_map()
        b_entry, cur_sha, b_err = resolve_build_entry(target_asar, manifest_p, builds_map)
        if b_entry is None:
            res = {
                "ok": False,
                "code": "UNSUPPORTED_ASAR_VERSION",
                "asarSha": cur_sha,
                "buildCheckError": b_err,
            }
        else:
            res = apply(b_entry, manifest_p, app_path=app_p, builds=builds_map)
    elif cmd == "restore":
        res = restore(manifest_p, app_path=app_p)
    else:
        res = {"ok": False, "code": "UNKNOWN_COMMAND"}

    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())
