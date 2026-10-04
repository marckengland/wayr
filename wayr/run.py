"""Thin wrapper around subprocess so the rest of the code stays testable."""
from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List


class CommandUnavailable(RuntimeError):
    pass


@dataclass
class Result:
    returncode: int
    stdout: str
    stderr: str


def is_macos() -> bool:
    return sys.platform == "darwin"


def run(args: List[str], timeout: int = 120) -> Result:
    if shutil.which(args[0]) is None:
        raise CommandUnavailable(
            f"`{args[0]}` was not found. This command needs macOS."
        )
    try:
        p = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise CommandUnavailable(f"`{' '.join(args)}` timed out after {timeout}s") from e
    return Result(p.returncode, p.stdout, p.stderr)
