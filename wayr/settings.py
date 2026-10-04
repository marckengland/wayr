"""Audit power-management settings (`pmset -g custom`, `pmset -g`, `pmset -g sched`)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from .ui import Finding

_ROW_RE = re.compile(r"^\s*(.+?)\s+(\S+)(?:\s+\((.*)\))?\s*$")

Section = Dict[str, str]


@dataclass
class PowerSettings:
    battery: Section
    ac: Section
    system: Section
    in_use: Section
    sleep_prevented_by: List[str]
    scheduled: List[str]

    @property
    def is_laptop(self) -> bool:
        return bool(self.battery)


def parse_sections(text: str) -> Dict[str, Section]:
    """Parse pmset output made of 'Header:' lines followed by indented rows."""
    sections: Dict[str, Section] = {}
    extras: Dict[str, str] = {}
    current: Optional[str] = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace() and line.rstrip().endswith(":"):
            current = line.strip().rstrip(":")
            sections.setdefault(current, {})
            continue
        if current is None:
            continue
        m = _ROW_RE.match(line)
        if m:
            sections[current][m.group(1).strip()] = m.group(2)
            if m.group(3):
                extras[f"{current}/{m.group(1).strip()}"] = m.group(3)
    sections["_extras"] = extras
    return sections


def parse_prevented_by(pmset_g: str) -> List[str]:
    for line in pmset_g.splitlines():
        m = re.search(r"sleep prevented by ([^)]*)\)", line)
        if m and line.strip().startswith("sleep "):
            names = [p.strip() for p in m.group(1).split(",") if p.strip()]
            return list(dict.fromkeys(names))  # dedupe, keep order
    return []


def parse_sched(text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.endswith(":"):
            continue
        if re.search(r"\b(wake|poweron|wakeorpoweron|wakepoweron)\b", s, re.I):
            out.append(s)
    return out


def load(custom: str, pmset_g: str, sched: str) -> PowerSettings:
    c = parse_sections(custom)
    g = parse_sections(pmset_g)
    return PowerSettings(
        battery=c.get("Battery Power", {}),
        ac=c.get("AC Power", {}),
        system=g.get("System-wide power settings", {}),
        in_use=g.get("Currently in use", {}),
        sleep_prevented_by=parse_prevented_by(pmset_g),
        scheduled=parse_sched(sched),
    )


def collect() -> PowerSettings:
    from .run import run

    return load(
        run(["pmset", "-g", "custom"]).stdout,
        run(["pmset", "-g"]).stdout,
        run(["pmset", "-g", "sched"]).stdout,
    )


def audit(s: PowerSettings, apple_silicon: bool) -> List[Finding]:
    f: List[Finding] = []
    b, a = s.battery, s.ac
    both = {k: (b.get(k), a.get(k)) for k in set(b) | set(a)}

    def on(section: Section, key: str) -> bool:
        return section.get(key) == "1"

    def any_on(key: str) -> bool:
        return "1" in both.get(key, (None, None))

    if s.system.get("SleepDisabled") == "1" or s.in_use.get("SleepDisabled") == "1":
        f.append(Finding(
            "high", "Sleep is disabled system-wide (SleepDisabled = 1)",
            "Your Mac will NOT sleep when you close the lid. Keep-awake apps "
            "(Amphetamine, etc.) and `pmset disablesleep 1` set this.",
            "sudo pmset -a disablesleep 0",
        ))

    if b.get("sleep") == "0":
        f.append(Finding(
            "high", "Never idle-sleeps on battery (sleep = 0)", "",
            "sudo pmset -b sleep 10",
        ))

    if on(b, "womp"):
        f.append(Finding(
            "medium", "Wake for network access is ON while on battery (womp)",
            "Network traffic can wake the Mac while it's in your bag.",
            "sudo pmset -a womp 0",
        ))
    elif on(a, "womp"):
        f.append(Finding(
            "low", "Wake for network access is ON while plugged in (womp)",
            "Fine for a desk setup. Turn it off if you don't need remote access while asleep.",
            "sudo pmset -a womp 0",
        ))

    if on(b, "powernap"):
        f.append(Finding(
            "low", "Power Nap is ON while on battery",
            "Lets the Mac dark-wake briefly for Mail, iCloud, Find My, etc. Usually harmless.\n"
            "Only worth turning off if `wayr sleep` shows many Power Nap/maintenance wakes.",
            "sudo pmset -b powernap 0",
        ))
    elif on(a, "powernap"):
        f.append(Finding(
            "info", "Power Nap is ON while plugged in",
            "Usually fine. Turn it off if the Mac gets warm while charging and asleep.",
            "sudo pmset -c powernap 0",
        ))

    if on(b, "tcpkeepalive"):
        f.append(Finding(
            "low", "TCP keep-alive is ON while on battery",
            "Causes periodic maintenance wakes to keep network connections alive.\n"
            "Trade-off: turning it off makes 'Find My Mac' less reliable while asleep.",
            "sudo pmset -b tcpkeepalive 0",
        ))

    if any_on("ttyskeepawake"):
        f.append(Finding(
            "low", "An open remote session (SSH/screen sharing) keeps the Mac awake (ttyskeepawake)",
            "", "sudo pmset -a ttyskeepawake 0",
        ))

    if any_on("proximitywake"):
        f.append(Finding(
            "low", "Proximity wake is ON",
            "Your iPhone or Apple Watch nearby can wake the Mac.",
            "sudo pmset -a proximitywake 0",
        ))

    if any_on("acwake"):
        f.append(Finding(
            "low", "Wakes when the power source changes (acwake)", "",
            "sudo pmset -a acwake 0",
        ))

    if b.get("standby") == "0":
        f.append(Finding(
            "medium", "Standby is OFF on battery",
            "Without standby the Mac never drops into its deepest, lowest-power sleep.",
            "sudo pmset -b standby 1",
        ))

    hib = b.get("hibernatemode")
    if hib == "0":
        f.append(Finding(
            "medium", "hibernatemode is 0 on battery",
            "Memory is never saved to disk, so the Mac can't fall back to zero-power hibernation.",
            "sudo pmset -b hibernatemode 3",
        ))
    elif hib == "3" and not apple_silicon:
        f.append(Finding(
            "info", "Optional 'bag mode': hibernate instead of sleep on battery",
            "hibernatemode 25 writes memory to disk and powers off almost completely.\n"
            "Wakes take a few seconds longer, but the battery barely drains. Intel Macs only.",
            "sudo pmset -b hibernatemode 25",
        ))

    if s.is_laptop and b.get("lowpowermode") == "0":
        f.append(Finding(
            "info", "Low Power Mode is off on battery",
            "Low Power Mode also makes background work less aggressive.",
            "sudo pmset -b lowpowermode 1",
        ))

    # macOS schedules its own timers (by 'com.apple.…'). They come back if cancelled.
    system = [x for x in s.scheduled if "by 'com.apple." in x]
    other = [x for x in s.scheduled if x not in system]
    if other:
        f.append(Finding(
            "medium", f"{len(other)} scheduled wake(s) set by an app or by you (pmset -g sched)",
            "\n".join(other),
            "sudo pmset schedule cancelall   # one-off events\n"
            "sudo pmset repeat cancel        # repeating events",
        ))
    if system:
        f.append(Finding(
            "info", f"{len(system)} wake timer(s) scheduled by macOS itself",
            "\n".join(re.sub(r"^\[\d+\]\s+", "", x) for x in system)
            + "\nNormal. Power Nap and TCP keep-alive decide how much happens in these wakes.",
        ))

    if not f:
        f.append(Finding("ok", "Power settings look good for sleeping on battery"))
    return f
