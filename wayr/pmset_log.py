"""Parse `pmset -g log` and reconstruct what happened while the Mac was "asleep".

A sleep session runs from the moment the Mac enters sleep until the next full
wake (lid open, key press, boot). Inside a session the Mac may *dark wake*
several times: the screen stays off, but the CPU is running. Those dark wakes
are what drain the battery and heat the laptop.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .knowledge import WakeCause, classify_wake

TS_FMT = "%Y-%m-%d %H:%M:%S %z"
_LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})\s+(.*)$")
_CHARGE_RE = re.compile(r"Charge:\s*(\d{1,3})")
_POWER_RE = re.compile(r"Using\s+(AC|Batt(?:ery)?)\b", re.I)
_DUE_TO_RE = re.compile(r"due to\s+(.*?)(?:\s+Using\s+(?:AC|Batt(?:ery)?)\b.*)?$", re.I)
_SLEEP_REASON_RE = re.compile(r"due to '([^']+)'")
_ASSERTION_RE = re.compile(r"PID\s+(-?\d+)\(([^)]*)\)\s+(\w+)\s+(\w+)(?:\s+\"([^\"]*)\")?")
_BRACKET_RE = re.compile(r"\[([^\[\]]*)\]")
_KV_RE = re.compile(r"(\w+)=(\"[^\"]*\"|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}|\S+)")
_TRAILING_SECS_RE = re.compile(r"\s+(\d+)\s+secs?\s*$")

# Assertion actions that mean "this process started doing something".
_STARTED_ACTIONS = {"Created", "TurnedOn"}
# Processes that show up on every wake and tell you nothing.
_NOISE_PROCESSES = {"powerd", "kernel_task"}

# How close a scheduled wake must be to a "wakeAt" request to be attributed.
_REQUEST_TOLERANCE = timedelta(minutes=3)
# Assertions logged this close to a sleep/wake transition belong to that transition:
# pmset often writes a process's assertion a moment before the DarkWake line itself.
_TRANSITION_WINDOW = timedelta(seconds=15)


@dataclass
class Entry:
    ts: datetime
    domain: str
    message: str

    @property
    def charge(self) -> Optional[int]:
        m = _CHARGE_RE.search(self.message)
        return int(m.group(1)) if m else None

    @property
    def on_battery(self) -> Optional[bool]:
        m = _POWER_RE.search(self.message)
        if not m:
            return None
        return m.group(1).lower() != "ac"

    @property
    def kind(self) -> str:
        d = self.domain.lower()
        msg = self.message.lower()
        if d == "sleep":
            return "sleep"
        if d == "darkwake":
            return "darkwake"
        if d == "wake":
            if msg.startswith("darkwake from"):
                return "darkwake"
            return "wake"
        if d == "start":
            return "boot"
        if d.startswith("shutdown"):
            return "shutdown"
        if d == "assertions":
            return "assertion"
        if d == "wake requests":
            return "wake_requests"
        if d == "failure" or "sleep failure" in msg or "wake failure" in msg:
            return "failure"
        return "other"

    @property
    def logged_secs(self) -> Optional[int]:
        """pmset's own 'Duration' column: how long the Mac stayed in this state."""
        m = _TRAILING_SECS_RE.search(self.message)
        return int(m.group(1)) if m else None

    @property
    def wake_reason(self) -> Optional[str]:
        m = _DUE_TO_RE.search(_TRAILING_SECS_RE.sub("", self.message))
        if not m:
            return None
        reason = m.group(1).strip().rstrip("/").strip()
        return reason or None

    @property
    def sleep_reason(self) -> str:
        m = _SLEEP_REASON_RE.search(self.message)
        return m.group(1) if m else "Sleep"


def parse_lines(lines: Iterable[str]) -> Iterator[Entry]:
    for raw in lines:
        m = _LINE_RE.match(raw.rstrip("\r\n"))
        if not m:
            continue
        try:
            ts = datetime.strptime(m.group(1), TS_FMT)
        except ValueError:
            continue
        rest = m.group(2)
        if "\t" in rest:
            domain, _, message = rest.partition("\t")
        else:
            parts = re.split(r"\s{2,}", rest, maxsplit=1)
            domain, message = parts[0], (parts[1] if len(parts) > 1 else "")
        yield Entry(ts, domain.strip(), message.strip())


@dataclass
class WakeRequest:
    process: str
    request: str
    wake_at: Optional[datetime]  # naive, local time (same clock as the log)
    chosen: bool


def parse_wake_requests(message: str) -> List[WakeRequest]:
    out = []
    for chunk in _BRACKET_RE.findall(message):
        chunk = chunk.strip()
        chosen = chunk.startswith("*")
        kv = {k: v.strip('"') for k, v in _KV_RE.findall(chunk.lstrip("*"))}
        if "process" not in kv:
            continue
        wake_at = None
        if "wakeAt" in kv:
            try:
                wake_at = datetime.strptime(kv["wakeAt"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
        out.append(WakeRequest(kv["process"], kv.get("request", "?"), wake_at, chosen))
    return out


@dataclass
class DarkWake:
    start: datetime
    reason: Optional[str]
    end: Optional[datetime] = None
    requested_by: Optional[str] = None
    request_type: Optional[str] = None
    processes: Counter = field(default_factory=Counter)  # name -> assertions started
    promoted: bool = False  # turned into a full wake (user opened the lid)
    logged_secs: Optional[int] = None

    @property
    def cause(self) -> WakeCause:
        return classify_wake(self.reason)

    @property
    def duration(self) -> float:
        if not self.end:
            return float(self.logged_secs or 0)
        secs = (self.end - self.start).total_seconds()
        # If the "back to sleep" line is missing, trust pmset's own duration.
        if self.logged_secs is not None and secs > self.logged_secs + 60:
            return float(self.logged_secs)
        return secs


STORM_WAKES_PER_HOUR = 60


@dataclass
class SleepSession:
    start: datetime
    sleep_reason: str
    charge_start: Optional[int] = None
    end: Optional[datetime] = None
    wake_reason: Optional[str] = None
    charge_end: Optional[int] = None
    dark_wakes: List[DarkWake] = field(default_factory=list)
    partial: bool = False  # the log began in the middle of this session
    saw_ac: bool = False
    saw_battery: bool = False
    # Assertions logged while we believed the Mac was fully asleep.
    asleep_activity: Counter = field(default_factory=Counter)

    def observe(self, e: Entry) -> None:
        b = e.on_battery
        if b is True:
            self.saw_battery = True
        elif b is False:
            self.saw_ac = True
        if e.charge is not None:
            if self.charge_start is None:
                self.charge_start = e.charge
            self.charge_end = e.charge

    @property
    def duration(self) -> float:
        return (self.end - self.start).total_seconds() if self.end else 0.0

    @property
    def darkwake_secs(self) -> float:
        return sum(d.duration for d in self.dark_wakes)

    @property
    def longest_darkwake(self) -> float:
        return max((d.duration for d in self.dark_wakes), default=0.0)

    @property
    def on_battery_only(self) -> bool:
        return self.saw_battery and not self.saw_ac

    @property
    def battery_drop(self) -> Optional[int]:
        if not self.on_battery_only or self.charge_start is None or self.charge_end is None:
            return None
        return self.charge_start - self.charge_end

    @property
    def drain_per_hour(self) -> Optional[float]:
        drop = self.battery_drop
        if drop is None or self.duration < 1800:
            return None
        return drop / (self.duration / 3600)

    @property
    def wake_cause(self) -> WakeCause:
        return classify_wake(self.wake_reason)

    @property
    def wakes_per_hour(self) -> Optional[float]:
        if self.duration < 1800:
            return None
        return len(self.dark_wakes) / (self.duration / 3600)

    @property
    def is_storm(self) -> bool:
        """Waking more than once a minute. A healthy Mac wakes a few times an hour."""
        rate = self.wakes_per_hour
        return rate is not None and rate >= STORM_WAKES_PER_HOUR and len(self.dark_wakes) >= 100


@dataclass
class Analysis:
    sessions: List[SleepSession]
    failures: List[Entry]

    @property
    def dark_wakes(self) -> List[DarkWake]:
        return [d for s in self.sessions for d in s.dark_wakes]

    def reasons(self) -> List[Tuple[WakeCause, int, float]]:
        """(cause, count, total seconds) for dark wakes, most frequent first."""
        counts: Dict[str, int] = Counter()
        secs: Dict[str, float] = Counter()
        causes: Dict[str, WakeCause] = {}
        for d in self.dark_wakes:
            c = d.cause
            causes[c.key] = c
            counts[c.key] += 1
            secs[c.key] += d.duration
        return [(causes[k], n, secs[k]) for k, n in Counter(counts).most_common()]

    def raw_reasons(self) -> List[Tuple[str, int]]:
        return Counter(d.reason or "(none)" for d in self.dark_wakes).most_common()

    def requesters(self) -> List[Tuple[str, int]]:
        return Counter(
            d.requested_by for d in self.dark_wakes if d.requested_by
        ).most_common()

    def processes(self) -> List[Tuple[str, int, float]]:
        """(process, dark wakes it was active in, total seconds of those wakes)."""
        n: Dict[str, int] = Counter()
        secs: Dict[str, float] = Counter()
        for d in self.dark_wakes:
            for p in d.processes:
                n[p] += 1
                secs[p] += d.duration
        return [(p, c, secs[p]) for p, c in Counter(n).most_common()]

    def storms(self) -> List[List[SleepSession]]:
        """Back-to-back storm sessions merged into periods (a brief wake doesn't end a storm)."""
        periods: List[List[SleepSession]] = []
        for s in self.sessions:
            if not s.is_storm:
                continue
            last = periods[-1][-1] if periods else None
            if last is not None and last.end is not None and s.start - last.end <= timedelta(minutes=30):
                periods[-1].append(s)
            else:
                periods.append([s])
        return periods

    def asleep_activity(self) -> List[Tuple[str, int]]:
        total: Counter = Counter()
        for s in self.sessions:
            total.update(s.asleep_activity)
        return total.most_common()


def _attach_request(dw: DarkWake, requests: List[WakeRequest]) -> None:
    if not requests or dw.cause.category not in ("scheduled", "unknown", "hardware"):
        return
    local = dw.start.replace(tzinfo=None)
    best: Optional[WakeRequest] = None
    best_gap: Optional[timedelta] = None
    for r in requests:
        if r.wake_at is None:
            continue
        gap = abs(r.wake_at - local)
        if gap > _REQUEST_TOLERANCE:
            continue
        # Prefer the request powerd marked as the one it scheduled (*).
        if best is None or (r.chosen and not best.chosen) or (
            r.chosen == best.chosen and best_gap is not None and gap < best_gap
        ):
            best, best_gap = r, gap
    if best:
        dw.requested_by = best.process
        dw.request_type = best.request


def analyze(entries: Iterable[Entry], since: Optional[datetime] = None) -> Analysis:
    sessions: List[SleepSession] = []
    failures: List[Entry] = []
    cur: Optional[SleepSession] = None
    dw: Optional[DarkWake] = None
    prev_dw: Optional[DarkWake] = None  # the dark wake that just ended
    last_sleep: Optional[datetime] = None
    state = "awake"
    requests: List[WakeRequest] = []
    # Assertions seen while asleep, held until we know whether a wake follows right after.
    # Each carries the dark wake that ended just before it (if it was logged right after it).
    pending: List[Tuple[datetime, str, Optional[DarkWake], timedelta]] = []

    def settle(next_ts: Optional[datetime], into: Optional[DarkWake]) -> None:
        """Assign each pending assertion to the nearer of the wake right after it and the
        wake that ended right before it. Anything near neither really happened while asleep."""
        for ts, name, tail_of, since_sleep in pending:
            near_next = next_ts is not None and next_ts - ts <= _TRANSITION_WINDOW
            options = []
            if near_next and into is not None:
                options.append((next_ts - ts, into))
            if tail_of is not None:
                options.append((since_sleep, tail_of))
            if options:
                min(options, key=lambda o: o[0])[1].processes[name] += 1
            elif not near_next and cur is not None:
                cur.asleep_activity[name] += 1
            # else: right before a full wake. That's the user waking it, not "asleep".
        pending.clear()

    for e in sorted(entries, key=lambda x: x.ts):
        k = e.kind
        if k == "sleep":
            if dw is not None and dw.end is None:
                dw.end = e.ts
            settle(None, None)
            prev_dw, dw, last_sleep = dw, None, e.ts
            if cur is None:
                cur = SleepSession(start=e.ts, sleep_reason=e.sleep_reason)
            state = "sleep"
        elif k == "darkwake":
            if cur is None:
                cur = SleepSession(start=e.ts, sleep_reason="(log starts mid-sleep)", partial=True)
            if dw is not None and dw.end is None:
                dw.end = e.ts
            dw = DarkWake(start=e.ts, reason=e.wake_reason, logged_secs=e.logged_secs)
            settle(e.ts, dw)
            _attach_request(dw, requests)
            cur.dark_wakes.append(dw)
            state = "darkwake"
        elif k in ("wake", "boot", "shutdown"):
            if cur is not None:
                settle(e.ts, None)  # right before a full wake: part of waking up, not "asleep"
                if dw is not None and dw.end is None:
                    dw.end = e.ts
                    dw.promoted = k == "wake"
                cur.observe(e)
                cur.end = e.ts
                if k == "wake":
                    cur.wake_reason = e.wake_reason
                else:
                    cur.wake_reason = "Boot" if k == "boot" else "Shutdown"
                sessions.append(cur)
            pending.clear()
            cur, dw, prev_dw, state, requests = None, None, None, "awake", []
            continue
        elif k == "assertion":
            m = _ASSERTION_RE.search(e.message)
            if m and m.group(3) in _STARTED_ACTIONS:
                name = m.group(2) or f"pid {m.group(1)}"
                if name not in _NOISE_PROCESSES:
                    if state == "darkwake" and dw is not None:
                        dw.processes[name] += 1
                    elif state == "sleep" and cur is not None:
                        since_sleep = e.ts - last_sleep if last_sleep is not None else _TRANSITION_WINDOW * 2
                        just_slept = since_sleep <= _TRANSITION_WINDOW
                        pending.append((e.ts, name, prev_dw if just_slept else None, since_sleep))
        elif k == "wake_requests":
            requests = parse_wake_requests(e.message)
        elif k == "failure":
            failures.append(e)

        if cur is not None:
            cur.observe(e)

    if cur is not None:  # still asleep at the end of the log (or log truncated)
        settle(None, None)
        sessions.append(cur)

    if since is not None:
        sessions = [s for s in sessions if (s.end or s.start) >= since]
        failures = [f for f in failures if f.ts >= since]
    return Analysis(sessions, failures)
