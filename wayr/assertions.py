"""Who is preventing sleep right now (`pmset -g assertions`)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from .knowledge import lookup_process
from .ui import Finding, fmt_duration

_OWNER_RE = re.compile(
    r"pid\s+(\d+)\(([^)]*)\):\s+\[[^\]]*\]\s+(\d+:\d+:\d+)\s+(\w+)\s+named:\s+\"(.*?)\"\s*$"
)
_KERNEL_RE = re.compile(r"owner=(.+?)\s*$")

# Assertion types that matter for sleep, and what they do.
IMPORTANT = {
    "PreventSystemSleep": "keeps the whole system awake, even with the display off",
    "PreventUserIdleSystemSleep": "prevents idle sleep (closing the lid on battery still sleeps)",
    "NoIdleSleepAssertion": "prevents idle sleep",
    "NetworkClientActive": "keeps the network up during sleep",
    "BackgroundTask": "background work holding the system awake",
    "ApplePushServiceTask": "push-notification work",
    "InternalPreventSleep": "internal system work preventing sleep",
}



@dataclass
class Assertion:
    pid: int
    process: str
    age: str
    type: str
    name: str
    on_behalf_of: Optional[int] = None  # "Created for PID: N"


@dataclass
class AssertionState:
    totals: Dict[str, int]
    owners: List[Assertion]
    kernel: List[str]
    idle_preventers: List[str]


def parse(text: str) -> AssertionState:
    totals: Dict[str, int] = {}
    owners: List[Assertion] = []
    kernel: List[str] = []
    idle: List[str] = []
    section = ""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Assertion status system-wide"):
            section = "totals"
            continue
        if s.startswith("Listed by owning process"):
            section = "owners"
            continue
        if s.startswith("Kernel Assertions"):
            section = "kernel"
            continue
        if s.startswith("Idle sleep preventers"):
            idle = [p for p in s.split(":", 1)[1].split() if p]
            section = ""
            continue
        if section == "totals":
            parts = s.split()
            if len(parts) == 2 and parts[1].isdigit():
                totals[parts[0]] = int(parts[1])
        elif section == "owners":
            m = _OWNER_RE.search(s)
            c = re.match(r"Created for PID:\s*(\d+)", s)
            if c and owners:
                owners[-1].on_behalf_of = int(c.group(1))
            elif m:
                owners.append(Assertion(int(m.group(1)), m.group(2), m.group(3),
                                        m.group(4), m.group(5)))
        elif section == "kernel":
            m = _KERNEL_RE.search(s)
            if m and m.group(1) not in kernel:
                kernel.append(m.group(1))
    return AssertionState(totals, owners, kernel, idle)


def collect() -> AssertionState:
    from .run import run

    return parse(run(["pmset", "-g", "assertions"]).stdout)


# runningboardd names its assertions after the app they're for:
#   "app<application.com.apple.Safari.190775.191441(501)>..."
_RB_APP_RE = re.compile(r"application\.([A-Za-z0-9._-]+?)\.\d+\.\d+\(")
_IDLE_ONLY = {"PreventUserIdleSystemSleep", "NoIdleSleepAssertion"}
_BACKGROUND = {"BackgroundTask", "ApplePushServiceTask", "NetworkClientActive"}


def _secs(age: str) -> int:
    h, m, s = (int(x) for x in age.split(":"))
    return h * 3600 + m * 60 + s


def responsible_app(a: Assertion, pid_names: Dict[int, str]) -> str:
    """Best guess at the app behind an assertion (system services act for apps)."""
    m = _RB_APP_RE.search(a.name)
    if m:
        return m.group(1).split(".")[-1]
    if a.on_behalf_of:
        name = pid_names.get(a.on_behalf_of)
        if not name:
            return f"pid {a.on_behalf_of}"
        if name.startswith("com.apple.WebKit"):
            return "WebKit (web page media)"
        return name
    return a.process


def _why(a: Assertion) -> str:
    low = a.name.lower()
    if "playback" in low or "media" in low:
        return "playing media"
    if a.process == "coreaudiod":
        return "audio device in use"
    if a.type in _BACKGROUND:
        return "background work"
    return f'"{a.name[:60]}"'


def findings(state: AssertionState, pid_names: Optional[Dict[int, str]] = None) -> List[Finding]:
    pid_names = pid_names or {}
    groups: Dict[str, List[Assertion]] = {}
    for a in state.owners:
        # powerd always holds "prevent sleep while display is on"; that's not news.
        if a.type not in IMPORTANT or a.process == "powerd":
            continue
        groups.setdefault(responsible_app(a, pid_names), []).append(a)

    out: List[Finding] = []
    for app, items in groups.items():
        types = {a.type for a in items}
        known = lookup_process(app)
        if "PreventSystemSleep" in types or (known and known.keeps_awake):
            sev, what = "high", "is keeping the Mac awake"
        elif types & _IDLE_ONLY:
            sev, what = "low", "is preventing idle sleep"
        else:
            sev, what = "low", "is doing background work"
        whys = sorted({_why(a) for a in items})
        via = sorted({a.process for a in items if a.process != app})
        longest = max(_secs(a.age) for a in items)
        detail = f"why: {', '.join(whys)}; held up to {fmt_duration(longest)}"
        if via:
            detail += f"\nvia: {', '.join(via)}"
        if sev == "high":
            detail += "\nThis can stop sleep even with the lid closed."
        if known and known.tip:
            detail += f"\n{known.tip}"
        if app.startswith("pid "):
            fix: Optional[str] = f"Find the app: ps -o command= -p {app[4:]}"
        elif sev == "high":
            fix = f"Quit {app} before closing the lid."
        else:
            fix = None
        out.append(Finding(sev, f"{app} {what}", detail, fix))

    if state.kernel:
        out.append(Finding(
            "info", "USB devices connected: " + ", ".join(state.kernel),
            "Normal while plugged in. A wireless mouse/keyboard dongle left plugged in can\n"
            "wake the Mac if the mouse moves or a key is pressed in the bag.",
        ))
    if not out:
        out.append(Finding("ok", "Nothing is preventing sleep right now"))
    elif all(f.severity != "high" for f in out):
        out.append(Finding(
            "ok", "Nothing here stops the Mac sleeping when you close the lid",
            "Idle-sleep blockers only matter while the lid is open.",
        ))
    out.sort(key=lambda f: f.rank)
    return out
