"""Lightweight detached worker kicker shared by mcp_server and side_sessions_hook."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Mapping

try:
    from .driver import sanitize_subprocess_env
except ImportError:  # pragma: no cover
    from driver import sanitize_subprocess_env  # type: ignore


class WorkerKicker:
    def __init__(self, state_root: Path, *, include_node_id: bool = True):
        self.state_root = Path(state_root)
        self.include_node_id = bool(include_node_id)

    def wake(self, payload: Mapping[str, Any] | None = None) -> None:
        node_id = str((payload or {}).get("node_id") or "") if self.include_node_id else ""
        root = self.state_root
        (root / "logs").mkdir(mode=0o700, parents=True, exist_ok=True)
        env = sanitize_subprocess_env()
        zbin = env.get("ZCODE_SIDE_SESSIONS_ZCODE_BIN") or shutil.which("zcode") or "zcode"
        node = shutil.which("node")
        if node:
            existing_path = env.get("PATH", "")
            node_dir = str(Path(node).parent)
            env["PATH"] = f"{node_dir}{os.pathsep}{existing_path}" if existing_path else node_dir
        env.update(
            {
                "ZCODE_SIDE_SESSIONS_HOME": str(root),
                "ZCODE_SIDE_SESSIONS_ZCODE_BIN": zbin,
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        argv = [
            sys.executable,
            "-B",
            str(Path(__file__).with_name("worker_runner.py")),
            "serve",
            "--state-home",
            str(root),
            "--drain",
        ]
        if node_id:
            argv += ["--node-id", node_id]
        with open(root / "logs" / "worker-kick.log", "ab", buffering=0) as log:
            subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                close_fds=True,
                start_new_session=True,
                cwd=str(root),
                env=env,
            )


__all__ = ["WorkerKicker"]
