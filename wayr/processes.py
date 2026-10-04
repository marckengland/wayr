"""Find unusual or heavy background processes (`ps`, optionally `codesign`)."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .knowledge import lookup_process
from .ui import SEVERITIES

PS_ARGS = ["ps", "-axo", "pid=,ppid=,user=,%cpu=,%mem=,etime=,time=,comm="]

APPLE_PREFIXES = (
    "/System/",
    "/usr/libexec/",
    "/usr/sbin/",
    "/usr/bin/",
    "/usr/lib/",
    "/bin/",
    "/sbin/",
    "/Library/Apple/",
)
SUSPICIOUS_DIRS = (
    "/tmp/",
    "/private/tmp/",
    "/var/tmp/",
    "/private/var/tmp/",
    "/var/folders/",
    "/private/var/folders/",
    "/Users/Shared/",
)


@dataclass
class Proc:
    pid: int
    ppid: int
    user: str
    cpu: float
    mem: float
    elapsed: int  # seconds since start
    cpu_time: int  # seconds of CPU used
    path: str
    reasons: List[str] = field(default_factory=list)
    severity: str = "info"
    headline: str = ""  # the most severe reason
    signer: Optional[str] = None

    @property
    def name(self) -> str:
        return os.path.basename(self.path.rstrip("/")) or self.path

    @property
    def avg_cpu(self) -> float:
        return 100.0 * self.cpu_time / self.elapsed if self.elapsed > 0 else 0.0

    @property
    def is_system(self) -> bool:
        return self.path.startswith(APPLE_PREFIXES)

    @property
    def is_app(self) -> bool:
        """Part of an app the user installed (the app itself or its helpers)."""
        return self.path.startswith(("/Applications/", "/System/Applications/")) or bool(
            re.match(r"/Users/[^/]+/Applications/", self.path))


def parse_clock(s: str) -> int:
    """Parse ps time formats: [[dd-]hh:]mm:ss[.cc]  ->  seconds."""
    s = s.strip()
    days = 0
    if "-" in s:
        d, s = s.split("-", 1)
        days = int(d) if d.isdigit() else 0
    secs = 0.0
    for part in s.split(":"):
        try:
            secs = secs * 60 + float(part)
        except ValueError:
            return 0
    return int(days * 86400 + secs)


def parse_ps(text: str) -> List[Proc]:
    procs = []
    for line in text.splitlines():
        parts = line.split(None, 7)
        if len(parts) < 8 or not parts[0].isdigit():
            continue
        try:
            procs.append(Proc(
                pid=int(parts[0]), ppid=int(parts[1]), user=parts[2],
                cpu=float(parts[3]), mem=float(parts[4]),
                elapsed=parse_clock(parts[5]), cpu_time=parse_clock(parts[6]),
                path=parts[7].strip(),
            ))
        except ValueError:
            continue
    return procs


def _bump(p: Proc, severity: str, reason: str) -> None:
    p.reasons.append(reason)
    if not p.headline or SEVERITIES.index(severity) < SEVERITIES.index(p.severity):
        p.headline = reason
    if SEVERITIES.index(severity) < SEVERITIES.index(p.severity):
        p.severity = severity


def _fmt_secs(secs: int) -> str:
    from .ui import fmt_duration

    return fmt_duration(secs)


def assess(p: Proc) -> Proc:
    known = lookup_process(p.name)
    path = p.path

    if known and known.keeps_awake:
        _bump(p, "high", "keep-awake tool: " + known.what)

    if path.startswith(SUSPICIOUS_DIRS):
        _bump(p, "high", "runs from a temporary/shared folder (unusual for legit software)")
    comps = [c for c in path.split("/") if c]
    if any(c.startswith(".") and len(c) > 1 for c in comps[:-1]) or (comps and comps[-1].startswith(".")):
        _bump(p, "medium", "runs from a hidden folder (normal for dev tools like ~/.nvm, "
                           "but also a classic hiding spot)")
    if "/Downloads/" in path:
        _bump(p, "medium", "runs from the Downloads folder")
    if "/AppTranslocation/" in path:
        _bump(p, "low", "app runs from a quarantined (translocated) location: move it to /Applications")

    if p.cpu >= 25:
        _bump(p, "medium", f"using {p.cpu:.0f}% CPU right now")
    if p.elapsed >= 600 and p.avg_cpu >= 10:
        _bump(p, "medium", f"averaged {p.avg_cpu:.0f}% CPU over {_fmt_secs(p.elapsed)}")
    elif p.cpu_time >= 1800 and p.avg_cpu >= 2:
        _bump(p, "low", f"has used {_fmt_secs(p.cpu_time)} of CPU time")

    if p.path.startswith("/") and not p.is_system and not p.is_app:
        _bump(p, "low", "third-party background process")

    if p.signer == "unsigned":
        _bump(p, "high", "binary is not code-signed")

    if known and not known.keeps_awake and p.reasons:
        p.reasons.append(f"{known.what} {known.tip}".rstrip())
    return p


_AUTHORITY_RE = re.compile(r"^Authority=(.+)$", re.M)
_TEAM_RE = re.compile(r"^TeamIdentifier=(.+)$", re.M)


def signer_of(path: str, cache: Dict[str, str]) -> str:
    if path in cache:
        return cache[path]
    from .run import run

    res = run(["codesign", "-dv", "--verbose=2", path], timeout=15)
    text = res.stderr + res.stdout
    if "not signed at all" in text:
        signer = "unsigned"
    else:
        m = _AUTHORITY_RE.search(text)
        signer = m.group(1).strip() if m else "unknown"
        if signer == "Software Signing":
            signer = "Apple"
        t = _TEAM_RE.search(text)
        if t and t.group(1).strip() not in ("not set", "") and signer != "Apple":
            signer += f" [{t.group(1).strip()}]"
    cache[path] = signer
    return signer


def collect(check_signatures: bool = False) -> List[Proc]:
    from .run import run

    procs = parse_ps(run(PS_ARGS).stdout)
    me = os.getpid()
    procs = [p for p in procs if p.pid != me and p.ppid != me]
    if check_signatures:
        cache: Dict[str, str] = {}
        for p in procs:
            if p.path.startswith("/") and not p.is_system and os.path.exists(p.path):
                p.signer = signer_of(p.path, cache)
    return [assess(p) for p in procs]


def flagged(procs: List[Proc], include_info: bool = False) -> List[Proc]:
    out = [p for p in procs if p.reasons and (include_info or p.severity != "low"
                                               or p.cpu_time >= 600 or p.cpu >= 5)]
    out.sort(key=lambda p: (SEVERITIES.index(p.severity), -p.cpu, -p.cpu_time))
    return out
