"""wayr: why are you running? Find out what keeps your Mac awake (and hot) while it 'sleeps'."""
from __future__ import annotations

import argparse
import os
import platform
import sys
from datetime import datetime, timedelta
from typing import List, Optional

from . import __version__
from . import assertions, launchd, pmset_log, processes, record, settings
from .knowledge import lookup_process
from .run import CommandUnavailable, is_macos, run
from .ui import (Finding, fmt_duration, heading, note, print_finding, set_color,
                 style, table)

# ---------------------------------------------------------------------------
# sleep


def _fmt_ts(ts: Optional[datetime]) -> str:
    return ts.strftime("%b %d %H:%M") if ts else "…"


def _load_log(path: Optional[str]) -> List[pmset_log.Entry]:
    if path:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return list(pmset_log.parse_lines(fh))
    return list(pmset_log.parse_lines(run(["pmset", "-g", "log"], timeout=300).stdout.splitlines()))


def _process_note(name: str) -> str:
    k = lookup_process(name)
    return k.what if k else ""


def sleep_findings(a: pmset_log.Analysis) -> List[Finding]:
    out: List[Finding] = []
    worst = max((s for s in a.sessions if s.drain_per_hour is not None),
                key=lambda s: s.drain_per_hour, default=None)
    if worst is not None and worst.drain_per_hour >= 1.5:
        sev = "high" if worst.drain_per_hour >= 3 else "medium"
        out.append(Finding(
            sev,
            f"Battery dropped {worst.battery_drop}% over {fmt_duration(worst.duration)} asleep "
            f"({worst.drain_per_hour:.1f}%/hour) starting {_fmt_ts(worst.start)}",
            "A sleeping Mac should lose roughly 1%/hour or less. More than that means "
            "it was awake a lot.",
        ))
    total_sleep = sum(s.duration for s in a.sessions)
    total_dw = sum(s.darkwake_secs for s in a.sessions)
    if total_sleep > 3600 and total_dw / total_sleep >= 0.10:
        out.append(Finding(
            "medium",
            f"Awake {fmt_duration(total_dw)} ({100 * total_dw / total_sleep:.0f}%) of the time it was 'asleep'",
            f"{len(a.dark_wakes)} dark wakes. See the breakdown by reason and process below.",
        ))
    long_ones = [d for d in a.dark_wakes if d.duration >= 600]
    if long_ones:
        procs = sorted({p for d in long_ones for p in d.processes})
        out.append(Finding(
            "medium",
            f"{len(long_ones)} dark wake(s) lasted 10+ minutes (longest {fmt_duration(max(d.duration for d in long_ones))})",
            ("Active during them: " + ", ".join(procs[:8])) if procs else
            "Long dark wakes are what make a Mac warm in a bag.",
        ))
    for cause, n, secs in a.reasons()[:3]:
        if cause.category == "user" or n < 3:
            continue
        out.append(Finding("medium" if n >= 10 else "low",
                           f"{n}× woken by: {cause.label} ({fmt_duration(secs)} awake)",
                           cause.advice))
    if a.failures:
        out.append(Finding("medium", f"{len(a.failures)} sleep/wake failure(s) logged",
                           a.failures[-1].message[:160]))
    return out


def render_sleep(a: pmset_log.Analysis, label: str, verbose: bool, compact: bool = False) -> List[Finding]:
    heading(f"Sleep history ({label})")
    if not a.sessions:
        note("  No sleep sessions found in this period.")
        return []

    total_sleep = sum(s.duration for s in a.sessions)
    total_dw = sum(s.darkwake_secs for s in a.sessions)
    pct = (100 * total_dw / total_sleep) if total_sleep else 0
    print(f"  {len(a.sessions)} sleep sessions · {fmt_duration(total_sleep)} asleep · "
          f"{len(a.dark_wakes)} dark wakes · awake {fmt_duration(total_dw)} of that ({pct:.1f}%)")
    print()

    rows = [[style(h, "dim") for h in ("slept", "woke", "length", "battery", "dark wakes", "woke up because")]]
    sessions = a.sessions[-8:] if compact else a.sessions
    for s in sessions:
        if s.battery_drop is not None:
            batt = f"{s.charge_start}→{s.charge_end}%"
            if s.drain_per_hour is not None:
                rate = f"{s.drain_per_hour:.1f}%/h"
                if s.drain_per_hour >= 3:
                    rate = style(rate, "red", "bold")
                elif s.drain_per_hour >= 1.5:
                    rate = style(rate, "yellow")
                batt += f" {rate}"
        elif s.saw_ac:
            batt = style("on AC", "dim")
        else:
            batt = "?"
        dw = f"{len(s.dark_wakes)}"
        if s.dark_wakes:
            dw += f" · {fmt_duration(s.darkwake_secs)}"
            if s.longest_darkwake >= 600:
                dw += style(f" (max {fmt_duration(s.longest_darkwake)})", "yellow")
        woke = s.wake_cause.label if s.wake_reason else ("still asleep" if s.end is None else "?")
        if s.wake_reason and s.wake_cause.key == "unknown":
            woke = s.wake_reason
        rows.append([
            _fmt_ts(s.start) + ("*" if s.partial else ""),
            _fmt_ts(s.end),
            fmt_duration(s.duration) if s.end else "…",
            batt, dw, woke,
        ])
    table(rows)
    if compact and len(a.sessions) > len(sessions):
        note(f"  (showing the last {len(sessions)}; run `wayr sleep` for all)")

    reasons = a.reasons()
    if reasons:
        heading("Why it woke up while asleep (dark wakes)")
        rows = [[style(h, "dim") for h in ("count", "awake", "reason")]]
        for cause, n, secs in reasons:
            rows.append([str(n), fmt_duration(secs), cause.label])
        table(rows)
        if verbose:
            print()
            note("  Raw reasons from pmset:")
            for r, n in a.raw_reasons()[:15]:
                note(f"    {n:>4}  {r}")

    req = a.requesters()
    if req:
        heading("Who scheduled those wakes")
        rows = [[style(h, "dim") for h in ("wakes", "process", "")]]
        for name, n in req[:10]:
            rows.append([str(n), name, style(_process_note(name), "dim")])
        table(rows)

    procs = a.processes()
    if procs:
        heading("What ran during dark wakes")
        rows = [[style(h, "dim") for h in ("wakes", "awake", "process", "")]]
        for name, n, secs in procs[: 8 if compact else 20]:
            rows.append([str(n), fmt_duration(secs), name, style(_process_note(name), "dim")])
        table(rows)
        note("  (processes that took a power assertion during a dark wake; 'awake' is the total "
             "length of those wakes)")

    asleep = a.asleep_activity()
    if asleep:
        heading("Activity logged while the Mac was supposedly fully asleep")
        for name, n in asleep[:10]:
            print(f"  {n:>4}  {name}  {style(_process_note(name), 'dim')}")

    if verbose and a.dark_wakes:
        heading("Every dark wake")
        rows = [[style(h, "dim") for h in ("time", "length", "reason", "requested by", "active")]]
        for d in a.dark_wakes:
            rows.append([
                _fmt_ts(d.start), fmt_duration(d.duration), d.reason or "?",
                d.requested_by or "", ", ".join(p for p, _ in d.processes.most_common(4)),
            ])
        table(rows)

    if a.failures:
        heading("Sleep/wake failures")
        for e in a.failures[-5:]:
            print(f"  {_fmt_ts(e.ts)}  {e.message[:140]}")

    findings = sleep_findings(a)
    if findings and not compact:
        heading("Takeaways")
        for f in findings:
            print_finding(f)
    return findings


def cmd_sleep(args: argparse.Namespace) -> List[Finding]:
    entries = _load_log(args.file)
    days = args.days if args.days is not None else (None if args.file else 3)
    since = datetime.now().astimezone() - timedelta(days=days) if days else None
    a = pmset_log.analyze(entries, since=since)
    label = f"last {days} day{'s' if days != 1 else ''}" if days else "whole log"
    return render_sleep(a, label, args.verbose)


# ---------------------------------------------------------------------------
# settings / blockers


def cmd_settings(args: argparse.Namespace) -> List[Finding]:
    s = settings.collect()
    found = settings.audit(s, apple_silicon=platform.machine() == "arm64")
    heading("Power settings")
    for f in sorted(found, key=lambda f: f.rank):
        print_finding(f)
    return found


def cmd_blockers(args: argparse.Namespace) -> List[Finding]:
    state = assertions.collect()
    prevented = settings.parse_prevented_by(run(["pmset", "-g"]).stdout)
    found = assertions.findings(state, prevented)
    heading("Preventing sleep right now")
    for f in sorted(found, key=lambda f: f.rank):
        print_finding(f)
    return found


# ---------------------------------------------------------------------------
# processes / jobs


def cmd_procs(args: argparse.Namespace, limit: Optional[int] = None) -> List[Finding]:
    procs = processes.collect(check_signatures=args.signatures)
    shown = processes.flagged(procs, include_info=args.all)
    limit = limit or args.limit
    heading("Unusual or heavy processes")
    if not shown:
        print_finding(Finding("ok", "Nothing unusual is running right now"))
        return []
    rows = [[style(h, "dim") for h in ("", "pid", "process", "cpu now", "cpu total", "why")]]
    for p in shown[:limit]:
        name = p.name
        if p.signer:
            name += style(f" [{p.signer}]", "dim")
        rows.append([
            style(p.severity.upper(), *{"high": ("red", "bold"), "medium": ("yellow",),
                                         "low": ("cyan",)}.get(p.severity, ("dim",))),
            str(p.pid), name, f"{p.cpu:.0f}%", fmt_duration(p.cpu_time), p.headline,
        ])
        for r in (r for r in p.reasons if r != p.headline):
            rows.append(["", "", "", "", "", style(r, "dim")])
        if args.verbose:
            rows.append(["", "", style(p.path, "dim"), "", "", ""])
    table(rows)
    if len(shown) > limit:
        note(f"  …and {len(shown) - limit} more (use --limit)")
    if not args.signatures:
        note("  Tip: add --signatures to check code signatures (slower).")
    def fix_for(p: processes.Proc) -> Optional[str]:
        if p.is_system:
            known = lookup_process(p.name)
            return known.tip if known and known.tip else None
        return f"Quit it, or see what started it: ps -o ppid=,command= -p {p.pid}"

    return [Finding(p.severity, f"{p.name} (pid {p.pid}): {p.headline}", fix=fix_for(p))
            for p in shown if p.severity in ("high", "medium")]


def cmd_jobs(args: argparse.Namespace, compact: bool = False) -> List[Finding]:
    jobs = launchd.collect()
    shown = [j for j in jobs if args.all or (not j.is_apple and not j.disabled)]
    shown.sort(key=lambda j: (launchd.SEVERITIES.index(j.severity), j.label))
    if compact:
        shown = [j for j in shown if j.severity in ("high", "medium")]
    heading("Background jobs (launchd)" + ("" if args.all else ": non-Apple"))
    if not shown:
        print_finding(Finding("ok", "No third-party launchd jobs found" if not compact
                              else "No launchd jobs that run frequently"))
        return []
    for j in shown:
        state = "running" if j.pid else ("loaded" if j.loaded else "not loaded")
        if j.disabled:
            state = "disabled"
        sev = j.severity if j.reasons else "info"
        print(f"  {style(sev.upper(), *{'high': ('red', 'bold'), 'medium': ('yellow',), 'low': ('cyan',)}.get(sev, ('dim',))):<6} "
              f"{style(j.label, 'bold')}  {style(f'({j.scope}, {state})', 'dim')}")
        print(f"         runs: {launchd.schedule(j)}")
        if j.program:
            print(f"         {style(j.program, 'dim')}")
        for r in j.reasons:
            print(f"         {style('•', 'dim')} {r}")
        if sev in ("high", "medium") or args.verbose:
            print(f"         {style('stop:', 'green')} {launchd.disable_command(j)}")
    note("\n  Usually easiest: System Settings → General → Login Items & Extensions → "
         "'Allow in the Background',\n  or uninstall the app that installed the job.")
    return [Finding(j.severity, f"launchd job {j.label}: {j.headline}", launchd.schedule(j),
                    launchd.disable_command(j))
            for j in shown if j.severity in ("high", "medium")]


# ---------------------------------------------------------------------------
# recorder


def cmd_record(args: argparse.Namespace) -> None:
    snap = record.record()
    if not args.quiet:
        print(f"Recorded snapshot to {record.SNAPSHOTS}")
        print(f"  lid closed: {snap.get('lid_closed')}  battery: {snap.get('battery')}")
        for p in snap.get("top", [])[:5]:
            print(f"  {p['cpu']:>5.1f}%  {p['name']}")


def cmd_agent(args: argparse.Namespace) -> None:
    if args.action == "install":
        here = os.path.abspath(__file__)
        protected = [d for d in ("Desktop", "Documents", "Downloads")
                     if here.startswith(os.path.expanduser(f"~/{d}/"))]
        if protected:
            print(style(f"Warning: wayr lives in ~/{protected[0]}. macOS privacy protection can "
                        "stop background agents from reading files there. If the recorder "
                        "produces no snapshots, move the repo elsewhere or `pipx install` it.",
                        "yellow"))
        path = record.install_agent(args.interval)
        print(f"Installed {path}")
        print(f"Snapshots every {fmt_duration(args.interval)} → {record.SNAPSHOTS}")
        print("Close the lid as usual. Later, run `wayr snapshots` to see if it was ever awake "
              "with the lid closed.")
    elif args.action == "uninstall":
        removed = record.uninstall_agent()
        print("Recorder removed." if removed else "Recorder was not installed.")
    else:
        print("installed" if record.agent_installed() else "not installed")
        snaps = record.load_snapshots()
        if snaps:
            print(f"{len(snaps)} snapshots, latest {snaps[-1]['ts']}")


def cmd_snapshots(args: argparse.Namespace, compact: bool = False) -> List[Finding]:
    since = datetime.now().astimezone() - timedelta(days=args.days or 7)
    snaps = record.load_snapshots(since=since)
    heading("Recorder: awake with the lid closed")
    if not snaps:
        note("  No snapshots yet. Install the recorder: wayr agent install")
        return []
    runs = record.lid_closed_runs(snaps, interval=args.interval)
    closed = sum(len(r.snaps) for r in runs)
    print(f"  {len(snaps)} snapshots in the last {args.days or 7} days, {closed} with the lid closed.")
    if not runs:
        print_finding(Finding("ok", "Never caught awake with the lid closed"))
        return []
    found: List[Finding] = []
    for r in runs[-(5 if compact else 50):]:
        length = f"~{fmt_duration(r.duration + args.interval)}" if len(r.snaps) > 1 else "brief"
        drop = f", battery -{r.battery_drop}%" if r.battery_drop else ""
        print(f"\n  {style(_fmt_ts(r.start), 'bold')} → {_fmt_ts(r.end)}  awake {length}{drop}")
        for name, n, avg in r.top_processes():
            print(f"     {avg:>5.1f}% avg  {name}  {style(f'(in {n}/{len(r.snaps)} snapshots)', 'dim')}")
        holders = r.holders()
        if holders:
            print(f"     holding sleep assertions: {', '.join(holders[:6])}")
        if len(r.snaps) >= 3:
            top = r.top_processes(1)
            found.append(Finding(
                "high",
                f"Awake with the lid closed for ~{fmt_duration(r.duration + args.interval)} on {_fmt_ts(r.start)}",
                f"Top process: {top[0][0]}" if top else "",
            ))
    note("\n  A single lid-closed snapshot is usually a short dark wake. Several in a row "
         "mean the Mac stayed awake in the bag.")
    return found


# ---------------------------------------------------------------------------
# tips / report

TIPS = [
    ("System Settings → Battery → Options", "Set 'Wake for network access' to Never (or Only on "
     "Power Adapter) and turn off Power Nap. These are the GUI versions of womp/powernap."),
    ("System Settings → Bluetooth", "If you see 'Allow Bluetooth devices to wake this computer', "
     "turn it off. A mouse or headphones in the same bag can wake the Mac."),
    ("System Settings → General → Login Items & Extensions", "Under 'Allow in the Background', "
     "turn off anything you don't recognize or need."),
    ("Before closing the lid", "Quit Docker, VMs, Zoom/Teams calls and anything playing audio. "
     "Unplug USB hubs and docks. A Mac on power with an external display stays awake "
     "(clamshell mode)."),
    ("Long trips", "If it'll be in a bag all day, shutting down is the only 100% guarantee. "
     "On Intel Macs, `sudo pmset -b hibernatemode 25` gets close."),
    ("Keep an eye on it", "Install the recorder (`wayr agent install`). It proves whether the Mac "
     "is awake in the bag and shows what was running."),
    ("Find My trade-off", "Turning off tcpkeepalive / Power Nap can make Find My Mac and "
     "notifications less timely while asleep. That's usually worth it on battery."),
]


def cmd_tips(args: argparse.Namespace) -> None:
    heading("Things to check by hand")
    for title, text in TIPS:
        print(f"  {style('•', 'cyan')} {style(title, 'bold')}")
        print(f"    {text}")


def cmd_report(args: argparse.Namespace) -> None:
    print(style("why are you running?", "bold") + style(f"  v{__version__}", "dim"))
    findings: List[Finding] = []

    def section(fn, *a, **kw):
        try:
            res = fn(*a, **kw)
            if res:
                findings.extend(res)
        except CommandUnavailable as e:
            note(f"  skipped: {e}")

    section(cmd_settings, args)
    section(cmd_blockers, args)

    def sleep_section():
        entries = _load_log(None)
        since = datetime.now().astimezone() - timedelta(days=args.days or 3)
        a = pmset_log.analyze(entries, since=since)
        return render_sleep(a, f"last {args.days or 3} days", verbose=False, compact=True)

    section(sleep_section)
    if record.load_snapshots():
        section(cmd_snapshots, args, compact=True)
    section(cmd_jobs, args, compact=True)
    section(cmd_procs, args, limit=10)

    actionable = [f for f in findings if f.severity in ("high", "medium")]
    heading("What to do next")
    if not actionable:
        print_finding(Finding("ok", "Nothing urgent found"))
    seen = set()
    for f in sorted(actionable, key=lambda f: f.rank):
        key = (f.title, f.fix)
        if key in seen:
            continue
        seen.add(key)
        # Details were shown above; here just the headline and the fix.
        print_finding(Finding(f.severity, f.title, fix=f.fix))
    if not record.agent_installed():
        print()
        note("  Not sure it's fixed? Run `wayr agent install`. It records snapshots every 5 minutes, "
             "and `wayr snapshots` later shows whether the Mac was awake with the lid closed.")
    note("  More manual checks: wayr tips")


# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wayr",
        description="Why are you running? Find what keeps your Mac awake (and warm) while it sleeps.",
    )
    p.add_argument("--version", action="version", version=f"wayr {__version__}")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    # Let --no-color work after the subcommand too (SUPPRESS keeps the top-level value).
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS,
                        help="disable colored output")
    sub = p.add_subparsers(dest="command")
    _add = sub.add_parser
    sub.add_parser = lambda *a, **kw: _add(*a, parents=[shared], **kw)  # type: ignore[assignment]

    def common(sp, days_help="how many days back to look"):
        sp.add_argument("--days", type=int, help=days_help)
        sp.add_argument("-v", "--verbose", action="store_true")
        sp.add_argument("--all", action="store_true", help="show everything, not just what's flagged")
        sp.add_argument("--signatures", action="store_true", help="check code signatures (slower)")
        sp.add_argument("--limit", type=int, default=25)
        sp.add_argument("--interval", type=int, default=record.DEFAULT_INTERVAL,
                        help=argparse.SUPPRESS)

    common(sub.add_parser("report", help="full check-up (default)"))

    sp = sub.add_parser("sleep", help="analyze sleep, dark wakes and battery drain from `pmset -g log`")
    common(sp, "days back to look (default 3; whole file with --file)")
    sp.add_argument("--file", help="analyze a saved `pmset -g log` output instead")

    common(sub.add_parser("settings", help="audit pmset power settings"))
    common(sub.add_parser("blockers", help="what is preventing sleep right now"))
    common(sub.add_parser("procs", help="unusual or heavy processes running now"))
    common(sub.add_parser("jobs", help="launchd agents/daemons and how often they run"))
    common(sub.add_parser("snapshots", help="show times the recorder caught the Mac awake with the lid closed"))
    sub.add_parser("tips", help="manual checks this tool can't do for you")

    sp = sub.add_parser("record", help="take one snapshot (used by the recorder agent)")
    sp.add_argument("--quiet", action="store_true")

    sp = sub.add_parser("agent", help="install/uninstall the background recorder")
    sp.add_argument("action", choices=["install", "uninstall", "status"])
    sp.add_argument("--interval", type=int, default=record.DEFAULT_INTERVAL,
                    help="seconds between snapshots (default 300)")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.no_color:
        set_color(False)
    command = args.command or "report"
    if command == "report" and args.command is None:
        args = parser.parse_args(["report"] + (["--no-color"] if args.no_color else []))

    if not is_macos() and not (command == "sleep" and getattr(args, "file", None)) and command != "tips":
        print("wayr needs macOS (it reads pmset, launchd and ps). On other systems you can "
              "still analyze a saved log: wayr sleep --file pmset.log", file=sys.stderr)
        return 2

    handlers = {
        "report": cmd_report,
        "sleep": cmd_sleep,
        "settings": cmd_settings,
        "blockers": cmd_blockers,
        "procs": cmd_procs,
        "jobs": cmd_jobs,
        "snapshots": cmd_snapshots,
        "tips": cmd_tips,
        "record": cmd_record,
        "agent": cmd_agent,
    }
    try:
        handlers[command](args)
    except CommandUnavailable as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0
    return 0
