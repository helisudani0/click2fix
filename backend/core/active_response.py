from __future__ import annotations

import os
import shlex
import subprocess
from collections.abc import Sequence


def _normalize_command(cmd: str | Sequence[str]) -> list[str]:
    if isinstance(cmd, str):
        posix = os.name != "nt"
        parts = shlex.split(cmd, posix=posix)
        if not parts:
            raise ValueError("Command cannot be empty")
        return parts
    parts = [str(part) for part in (cmd or []) if str(part).strip()]
    if not parts:
        raise ValueError("Command cannot be empty")
    return parts


def run_command(cmd: str | Sequence[str], timeout: int = 600):
    try:
        argv = _normalize_command(cmd)
        proc = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=max(1, int(timeout)),
        )
        return {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "returncode": proc.returncode,
        }
    except Exception as e:
        return {"error": str(e)}
