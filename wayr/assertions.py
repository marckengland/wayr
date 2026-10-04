"""Who is preventing sleep right now (`pmset -g assertions`)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from .knowledge import lookup_process
from .ui import Finding

_OWNER_RE = re.compile(
    r"pid\s+(\d+)\(([^)]*)\):\s+\[[^\]]*\]\s+(\d+:\d+:\d+)\s+(\w+)\s+named:\s+\"(.*?)\"\s*$"
)
_KERNEL_RE = re.compile(r"description=(\S+).*?owner=(\S+)")

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


_SYSTEM_SERVICES = {"coreaudiod", "cloudd", "bird", "backupd", "mds", "mds_stores", "sharingd",
                    "bluetoothd", "apsd", "nsurlsessiond", "WindowServer", "useractivityd"}


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
            if m:
                kernel.append(f"{m.group(2)} ({m.group(1)})")
    return AssertionState(totals, owners, kernel, idle)


def collect() -> AssertionState:
    from .run import run

    return parse(run(["pmset", "-g", "assertions"]).stdout)


def findings(state: AssertionState, prevented_by: List[str]) -> List[Finding]:
    out: List[Finding] = []
    for a in state.owners:
        # powerd always holds "prevent sleep while display is on"; that's not news.
        if a.type not in IMPORTANT or a.process == "powerd":
            continue
        known = lookup_process(a.process)
        sev = "high" if a.type == "PreventSystemSleep" or (known and known.keeps_awake) else "medium"
        if a.type in ("BackgroundTask", "ApplePushServiceTask", "NetworkClientActive"):
            sev = "low"
        detail = f"{a.type}: {IMPORTANT[a.type]}\n\"{a.name}\" (held for {a.age})"
        if known:
            detail += f"\n{known.what} {known.tip}".rstrip()
        if a.on_behalf_of:
            fix = (f"It's acting for pid {a.on_behalf_of}. Find that app with: "
                   f"ps -o command= -p {a.on_behalf_of}")
        elif a.process in _SYSTEM_SERVICES:
            fix = "A system service. Look for the app using it (audio, calls, sync) and quit that app."
        else:
            fix = f"Quit {a.process}, or see what started it: ps -o ppid=,command= -p {a.pid}"
        out.append(Finding(sev, f"{a.process} (pid {a.pid}) is holding a sleep assertion", detail, fix))
    for k in state.kernel:
        out.append(Finding("low", f"Kernel assertion from a device: {k}",
                           "A connected device (often USB) is preventing sleep.",
                           "Unplug accessories before sleeping."))
    if prevented_by:
        out.append(Finding("info", "Idle sleep is currently prevented by: " + ", ".join(prevented_by),
                           "From `pmset -g`. Usually the same processes as above."))
    if not out:
        out.append(Finding("ok", "Nothing is preventing sleep right now"))
    return out
