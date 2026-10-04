"""Terminal output helpers: colors, headings, findings."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import List, Optional

_CODES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
}

_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def set_color(enabled: bool) -> None:
    global _color
    _color = enabled


def style(text: str, *names: str) -> str:
    if not _color or not names:
        return text
    seq = ";".join(_CODES[n] for n in names)
    return f"\033[{seq}m{text}\033[0m"


def heading(text: str) -> None:
    print()
    print(style(text, "bold"))
    print(style("─" * len(text), "dim"))


def note(text: str) -> None:
    print(style(text, "dim"))


def fmt_duration(secs: float) -> str:
    secs = int(round(secs))
    if secs < 60:
        return f"{secs}s"
    mins, s = divmod(secs, 60)
    if mins < 60:
        return f"{mins}m{s:02d}s" if mins < 10 and s else f"{mins}m"
    hours, m = divmod(mins, 60)
    if hours < 24:
        return f"{hours}h{m:02d}m"
    days, h = divmod(hours, 24)
    return f"{days}d{h:02d}h"


def table(rows: List[List[str]], indent: str = "  ") -> None:
    """Print rows as left-aligned columns (ANSI-aware widths)."""
    if not rows:
        return
    import re

    ansi = re.compile(r"\033\[[0-9;]*m")

    def width(cell: str) -> int:
        return len(ansi.sub("", cell))

    ncols = max(len(r) for r in rows)
    widths = [0] * ncols
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], width(cell))
    for r in rows:
        parts = []
        for i, cell in enumerate(r):
            pad = "" if i == len(r) - 1 else " " * (widths[i] - width(cell))
            parts.append(cell + pad)
        print(indent + "  ".join(parts).rstrip())


SEVERITIES = ["high", "medium", "low", "info", "ok"]
_SEV_STYLE = {
    "high": ("red", "bold"),
    "medium": ("yellow",),
    "low": ("cyan",),
    "info": ("dim",),
    "ok": ("green",),
}


@dataclass
class Finding:
    severity: str  # one of SEVERITIES
    title: str
    detail: str = ""
    fix: Optional[str] = None  # a command or a short instruction

    @property
    def rank(self) -> int:
        return SEVERITIES.index(self.severity)


def badge(severity: str) -> str:
    return style(f"{severity.upper():<6}", *_SEV_STYLE[severity])


def print_finding(f: Finding) -> None:
    print(f"  {badge(f.severity)} {f.title}")
    if f.detail:
        for line in f.detail.splitlines():
            print(f"         {style(line, 'dim')}")
    if f.fix:
        for line in f.fix.splitlines():
            print(f"         {style('fix:', 'green')} {line}")
