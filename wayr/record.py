"""Periodic snapshots, run by a LaunchAgent, to catch the Mac awake with the lid closed.

macOS's own logs say when the Mac woke. They don't say what was burning CPU
while it was awake. A LaunchAgent only runs while the Mac is actually awake, so
any snapshot taken with the lid closed is proof the Mac was awake in the bag,
and it records the top processes at that moment.
"""
from __future__ import annotations

import json
import os
import plistlib
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

LOG_DIR = os.path.expanduser("~/Library/Logs/why-are-you-running")
SNAPSHOTS = os.path.join(LOG_DIR, "snapshots.jsonl")
AGENT_LABEL = "local.why-are-you-running.recorder"
AGENT_PLIST = os.path.expanduser(f"~/Library/LaunchAgents/{AGENT_LABEL}.plist")
MAX_BYTES = 5 * 1024 * 1024
DEFAULT_INTERVAL = 300

_BATT_RE = re.compile(r"(\d{1,3})%;\s*([^;]+);")


def parse_batt(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    m = re.search(r"'(AC Power|Battery Power|UPS Power)'", text)
    if m:
        out["source"] = "battery" if m.group(1) == "Battery Power" else "ac"
    m = _BATT_RE.search(text)
    if m:
        out["percent"] = int(m.group(1))
        out["state"] = m.group(2).strip()
    return out


def parse_clamshell(text: str) -> Optional[bool]:
    m = re.search(r'"AppleClamshellState"\s*=\s*(Yes|No)', text)
    return None if not m else m.group(1) == "Yes"


def take_snapshot() -> Dict[str, Any]:
    from . import assertions, processes
    from .run import run

    snap: Dict[str, Any] = {"ts": datetime.now().astimezone().isoformat(timespec="seconds")}
    snap["lid_closed"] = parse_clamshell(
        run(["ioreg", "-r", "-k", "AppleClamshellState", "-d", "4"]).stdout)
    snap["battery"] = parse_batt(run(["pmset", "-g", "batt"]).stdout)

    procs = processes.parse_ps(run(processes.PS_ARGS).stdout)
    me = os.getpid()
    procs = [p for p in procs if p.pid != me and p.ppid != me]
    procs.sort(key=lambda p: -p.cpu)
    snap["top"] = [
        {"pid": p.pid, "name": p.name, "cpu": p.cpu, "path": p.path}
        for p in procs[:8] if p.cpu >= 1.0
    ]
    state = assertions.parse(run(["pmset", "-g", "assertions"]).stdout)
    snap["assertions"] = [
        {"process": a.process, "type": a.type, "name": a.name}
        for a in state.owners
        if a.type in assertions.IMPORTANT and a.process != "powerd"
    ]
    return snap


def _rotate(path: str) -> None:
    try:
        if os.path.getsize(path) <= MAX_BYTES:
            return
    except OSError:
        return
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines[len(lines) // 2:])


def record(path: str = SNAPSHOTS) -> Dict[str, Any]:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    snap = take_snapshot()
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(snap) + "\n")
    _rotate(path)
    return snap


def load_snapshots(path: str = SNAPSHOTS, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
    out = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    snap = json.loads(line)
                    snap["_ts"] = datetime.fromisoformat(snap["ts"])
                except (ValueError, KeyError):
                    continue
                if since is None or snap["_ts"] >= since:
                    out.append(snap)
    except FileNotFoundError:
        pass
    return out


@dataclass
class LidClosedRun:
    """Consecutive lid-closed snapshots: the Mac stayed awake in the bag."""
    snaps: List[Dict[str, Any]]

    @property
    def start(self) -> datetime:
        return self.snaps[0]["_ts"]

    @property
    def end(self) -> datetime:
        return self.snaps[-1]["_ts"]

    @property
    def duration(self) -> float:
        return (self.end - self.start).total_seconds()

    @property
    def battery_drop(self) -> Optional[int]:
        a = self.snaps[0].get("battery", {}).get("percent")
        b = self.snaps[-1].get("battery", {}).get("percent")
        return None if a is None or b is None else a - b

    def top_processes(self, n: int = 5) -> List[tuple]:
        """(name, snapshots seen in, average CPU when seen)."""
        seen: Dict[str, List[float]] = {}
        for s in self.snaps:
            for p in s.get("top", []):
                seen.setdefault(p["name"], []).append(p["cpu"])
        ranked = sorted(seen.items(), key=lambda kv: (-len(kv[1]), -sum(kv[1])))
        return [(name, len(v), sum(v) / len(v)) for name, v in ranked[:n]]

    def holders(self) -> List[str]:
        names: Dict[str, None] = {}
        for s in self.snaps:
            for a in s.get("assertions", []):
                names.setdefault(f"{a['process']} ({a['type']})")
        return list(names)


def lid_closed_runs(snaps: List[Dict[str, Any]], interval: int = DEFAULT_INTERVAL) -> List[LidClosedRun]:
    gap = timedelta(seconds=interval * 1.6)
    runs: List[LidClosedRun] = []
    cur: List[Dict[str, Any]] = []
    for s in snaps:
        if s.get("lid_closed"):
            if cur and s["_ts"] - cur[-1]["_ts"] > gap:
                runs.append(LidClosedRun(cur))
                cur = []
            cur.append(s)
        elif cur:
            runs.append(LidClosedRun(cur))
            cur = []
    if cur:
        runs.append(LidClosedRun(cur))
    return runs


def agent_plist(interval: int = DEFAULT_INTERVAL) -> Dict[str, Any]:
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return {
        "Label": AGENT_LABEL,
        "ProgramArguments": [sys.executable, "-m", "wayr", "record", "--quiet"],
        "EnvironmentVariables": {"PYTHONPATH": pkg_parent},
        "StartInterval": interval,
        "RunAtLoad": True,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "Nice": 10,
        "StandardErrorPath": os.path.join(LOG_DIR, "recorder.err.log"),
    }


def install_agent(interval: int = DEFAULT_INTERVAL) -> str:
    from .run import run

    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(AGENT_PLIST), exist_ok=True)
    domain = f"gui/{os.getuid()}"
    run(["launchctl", "bootout", f"{domain}/{AGENT_LABEL}"])  # ignore "not loaded"
    with open(AGENT_PLIST, "wb") as fh:
        plistlib.dump(agent_plist(interval), fh)
    res = run(["launchctl", "bootstrap", domain, AGENT_PLIST])
    if res.returncode != 0:
        raise RuntimeError(f"launchctl bootstrap failed: {res.stderr.strip() or res.stdout.strip()}")
    return AGENT_PLIST


def uninstall_agent() -> bool:
    from .run import run

    run(["launchctl", "bootout", f"gui/{os.getuid()}/{AGENT_LABEL}"])
    if os.path.exists(AGENT_PLIST):
        os.remove(AGENT_PLIST)
        return True
    return False


def agent_installed() -> bool:
    return os.path.exists(AGENT_PLIST)
