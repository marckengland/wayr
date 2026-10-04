"""Inspect launchd jobs: the things that run "in intervals" in the background."""
from __future__ import annotations

import glob
import os
import plistlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .processes import SUSPICIOUS_DIRS
from .ui import SEVERITIES, fmt_duration

SCOPES = [
    ("~/Library/LaunchAgents", "user agent"),
    ("/Library/LaunchAgents", "agent (all users)"),
    ("/Library/LaunchDaemons", "daemon (root)"),
]

_WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


@dataclass
class Job:
    label: str
    plist: str
    scope: str
    program: Optional[str] = None
    run_at_load: bool = False
    keep_alive: Any = False
    start_interval: Optional[int] = None
    calendar: Any = None
    watch_paths: List[str] = field(default_factory=list)
    disabled: bool = False
    error: Optional[str] = None
    loaded: bool = False
    pid: Optional[int] = None
    reasons: List[str] = field(default_factory=list)
    severity: str = "info"
    headline: str = ""  # the most severe reason

    @property
    def is_apple(self) -> bool:
        return self.label.startswith("com.apple.")

    @property
    def program_exists(self) -> bool:
        return bool(self.program) and os.path.exists(self.program)

    @property
    def is_daemon(self) -> bool:
        return "LaunchDaemons" in self.plist


def _describe_calendar(cal: Any) -> str:
    entries = cal if isinstance(cal, list) else [cal]
    out = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        hour, minute = e.get("Hour"), e.get("Minute")
        wd, day = e.get("Weekday"), e.get("Day")
        if hour is None and minute is not None and wd is None and day is None:
            out.append(f"hourly at :{minute:02d}")
            continue
        when = f"{hour if hour is not None else '*'}:{minute if minute is not None else 0:02d}"
        if wd is not None and 0 <= int(wd) <= 7:
            out.append(f"{_WEEKDAYS[int(wd)]} at {when}")
        elif day is not None:
            out.append(f"day {day} of the month at {when}")
        elif hour is not None:
            out.append(f"daily at {when}")
        else:
            out.append(str(e))
    return ", ".join(out) or "on a calendar schedule"


def schedule(job: Job) -> str:
    parts = []
    if job.start_interval:
        parts.append(f"every {fmt_duration(job.start_interval)}")
    if job.calendar:
        parts.append(_describe_calendar(job.calendar))
    if job.keep_alive:
        parts.append("kept alive (restarted if it exits)")
    if job.watch_paths:
        parts.append("when files change")
    if job.run_at_load:
        parts.append("at login/boot")
    return "; ".join(parts) or "on demand"


def load_plist(path: str, scope: str) -> Job:
    label = os.path.splitext(os.path.basename(path))[0]
    try:
        with open(path, "rb") as fh:
            d: Dict[str, Any] = plistlib.load(fh)
    except Exception as e:  # unreadable or malformed plist
        return Job(label=label, plist=path, scope=scope, error=str(e))
    args = d.get("ProgramArguments") or []
    program = d.get("Program") or (args[0] if args else None)
    interval = d.get("StartInterval")
    return Job(
        label=d.get("Label", label),
        plist=path,
        scope=scope,
        program=program,
        run_at_load=bool(d.get("RunAtLoad")),
        keep_alive=d.get("KeepAlive", False),
        start_interval=int(interval) if isinstance(interval, (int, float)) else None,
        calendar=d.get("StartCalendarInterval"),
        watch_paths=list(d.get("WatchPaths") or []) + list(d.get("QueueDirectories") or []),
        disabled=bool(d.get("Disabled")),
    )


def parse_launchctl_list(text: str) -> Dict[str, Optional[int]]:
    """`launchctl list` -> {label: pid or None}."""
    out: Dict[str, Optional[int]] = {}
    for line in text.splitlines()[1:]:
        parts = line.split(None, 2)
        if len(parts) == 3:
            out[parts[2]] = int(parts[0]) if parts[0].isdigit() else None
    return out


def _bump(job: Job, severity: str, reason: str) -> None:
    job.reasons.append(reason)
    if not job.headline or SEVERITIES.index(severity) < SEVERITIES.index(job.severity):
        job.headline = reason
    if SEVERITIES.index(severity) < SEVERITIES.index(job.severity):
        job.severity = severity


def assess(job: Job) -> Job:
    if job.error:
        _bump(job, "low", f"could not read plist: {job.error}")
        return job
    if job.disabled:
        return job
    if job.start_interval:
        if job.start_interval <= 900:
            _bump(job, "medium", f"runs every {fmt_duration(job.start_interval)}")
        elif job.start_interval <= 3600:
            _bump(job, "low", f"runs every {fmt_duration(job.start_interval)}")
    if job.calendar:
        _bump(job, "low", "runs on a schedule: " + _describe_calendar(job.calendar))
    if job.keep_alive:
        _bump(job, "low", "always running (KeepAlive)")
    if job.program and job.program.startswith("/") and not job.program_exists:
        _bump(job, "low", f"program is missing ({job.program}). Leftover from an uninstalled app?")
    if job.program and job.program.startswith(SUSPICIOUS_DIRS):
        _bump(job, "high", f"program lives in a temporary/shared folder: {job.program}")
    if job.program and "/." in job.program:
        _bump(job, "medium", f"program lives in a hidden folder: {job.program}")
    return job


def disable_command(job: Job) -> str:
    if job.is_daemon:
        return (f"sudo launchctl bootout system/{job.label}; "
                f"sudo launchctl disable system/{job.label}")
    return (f"launchctl bootout gui/$(id -u)/{job.label}; "
            f"launchctl disable gui/$(id -u)/{job.label}")


def collect(dirs: Optional[List[Tuple[str, str]]] = None, loaded: Optional[Dict[str, Optional[int]]] = None) -> List[Job]:
    jobs = []
    for d, scope in dirs or SCOPES:
        for path in sorted(glob.glob(os.path.join(os.path.expanduser(d), "*.plist"))):
            jobs.append(load_plist(path, scope))
    if loaded is None:
        loaded = {}
        try:
            from .run import run

            loaded = parse_launchctl_list(run(["launchctl", "list"]).stdout)
        except Exception:
            pass
    for j in jobs:
        if j.label in loaded:
            j.loaded = True
            j.pid = loaded[j.label]
    return [assess(j) for j in jobs]
