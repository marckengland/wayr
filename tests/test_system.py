import os
import plistlib
import tempfile
import unittest
from datetime import datetime, timedelta

from wayr import assertions, launchd, processes, record, settings

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture(name):
    with open(os.path.join(FIX, name)) as fh:
        return fh.read()


class SettingsTest(unittest.TestCase):
    def setUp(self):
        self.s = settings.load(fixture("pmset_custom.txt"), fixture("pmset_g.txt"),
                               fixture("pmset_sched.txt"))

    def test_parse(self):
        self.assertEqual(self.s.battery["womp"], "1")
        self.assertEqual(self.s.battery["Sleep On Power Button"], "1")
        self.assertEqual(self.s.ac["displaysleep"], "10")
        self.assertEqual(self.s.system["SleepDisabled"], "1")
        self.assertEqual(self.s.sleep_prevented_by, ["coreaudiod", "sharingd"])
        self.assertEqual(len(self.s.scheduled), 2)

    def test_audit(self):
        found = settings.audit(self.s, apple_silicon=True)
        titles = " | ".join(f.title for f in found)
        self.assertIn("SleepDisabled", titles)
        self.assertIn("womp", titles)
        self.assertIn("Power Nap", titles)
        self.assertIn("TCP keep-alive", titles)
        self.assertIn("ttyskeepawake", titles)
        self.assertIn("2 scheduled wake(s)", titles)
        self.assertNotIn("bag mode", titles)  # Intel-only suggestion
        self.assertEqual(found[0].severity, "high")

    def test_intel_gets_hibernate_tip(self):
        found = settings.audit(self.s, apple_silicon=False)
        self.assertTrue(any("bag mode" in f.title for f in found))

    def test_clean_settings(self):
        s = settings.load("Battery Power:\n womp 0\n powernap 0\n tcpkeepalive 0\n lowpowermode 1\n",
                          "System-wide power settings:\n SleepDisabled 0\n", "")
        found = settings.audit(s, apple_silicon=True)
        self.assertEqual([f.severity for f in found], ["ok"])


class AssertionsTest(unittest.TestCase):
    def test_parse_and_findings(self):
        st = assertions.parse(fixture("pmset_assertions.txt"))
        self.assertEqual(st.totals["PreventSystemSleep"], 1)
        self.assertEqual([a.process for a in st.owners],
                         ["powerd", "coreaudiod", "Amphetamine", "cloudd", "WindowServer"])
        self.assertEqual(st.kernel, ["AppleUSBXHCIPort (com.apple.usb.externaldevice.14100000)"])
        self.assertEqual(st.idle_preventers, ["IODisplayWrangler"])
        self.assertEqual(st.owners[1].on_behalf_of, 512)
        found = assertions.findings(st, ["coreaudiod"])
        audio = next(f for f in found if f.title.startswith("coreaudiod"))
        self.assertIn("ps -o command= -p 512", audio.fix)
        by_title = {f.title.split(" ")[0]: f.severity for f in found}
        self.assertEqual(by_title["Amphetamine"], "high")
        self.assertEqual(by_title["coreaudiod"], "medium")
        self.assertEqual(by_title["cloudd"], "low")
        self.assertNotIn("powerd", by_title)
        self.assertNotIn("WindowServer", by_title)


class ProcessesTest(unittest.TestCase):
    def setUp(self):
        self.procs = {p.pid: processes.assess(p) for p in processes.parse_ps(fixture("ps.txt"))}

    def test_parse_clock(self):
        self.assertEqual(processes.parse_clock("10-02:11:33"), 10 * 86400 + 2 * 3600 + 11 * 60 + 33)
        self.assertEqual(processes.parse_clock("45:12.34"), 45 * 60 + 12)
        self.assertEqual(processes.parse_clock("30:12:00.00"), 30 * 3600 + 12 * 60)
        self.assertEqual(processes.parse_clock("00:05"), 5)

    def test_paths_with_spaces(self):
        self.assertEqual(self.procs[900].path, "/Users/marc/Library/Application Support/.hidden/agentd")
        self.assertEqual(self.procs[902].name, "GoogleUpdater")

    def test_flags(self):
        p = self.procs
        self.assertEqual(p[812].severity, "high")  # Amphetamine
        self.assertEqual(p[901].severity, "high")  # /private/tmp
        self.assertEqual(p[900].severity, "medium")  # hidden dir
        self.assertEqual(p[777].severity, "medium")  # docker CPU
        self.assertTrue(any("Docker" in r for r in p[777].reasons))
        self.assertEqual(p[501].severity, "medium")  # mds_stores busy
        self.assertEqual(p[1].reasons, [])  # launchd: system, light
        self.assertEqual(p[903].reasons, [])  # Safari app, idle

    def test_flagged_order(self):
        names = [p.name for p in processes.flagged(list(self.procs.values()))]
        self.assertEqual(names[:2], ["Amphetamine", "updater"])
        self.assertNotIn("GoogleUpdater", names)  # quiet third-party; shown with --all
        all_names = [p.name for p in processes.flagged(list(self.procs.values()), include_info=True)]
        self.assertIn("GoogleUpdater", all_names)


class LaunchdTest(unittest.TestCase):
    def test_collect(self):
        with tempfile.TemporaryDirectory() as d:
            def write(name, data):
                with open(os.path.join(d, name), "wb") as fh:
                    plistlib.dump(data, fh)

            write("com.google.keystone.agent.plist", {
                "Label": "com.google.keystone.agent",
                "ProgramArguments": ["/nonexistent/GoogleUpdater", "--wake"],
                "StartInterval": 3600, "RunAtLoad": True,
            })
            write("com.evil.plist", {
                "Label": "com.evil", "Program": "/private/tmp/x",
                "StartInterval": 300, "KeepAlive": True,
            })
            write("com.daily.plist", {
                "Label": "com.daily", "Program": "/bin/ls",
                "StartCalendarInterval": {"Hour": 3, "Minute": 15},
            })
            write("com.off.plist", {"Label": "com.off", "Program": "/bin/ls",
                                    "StartInterval": 60, "Disabled": True})
            with open(os.path.join(d, "broken.plist"), "w") as fh:
                fh.write("not a plist")

            jobs = {j.label: j for j in launchd.collect([(d, "user agent")],
                                                       loaded={"com.evil": 4242})}
        evil = jobs["com.evil"]
        self.assertEqual(evil.severity, "high")
        self.assertEqual(evil.pid, 4242)
        self.assertIn("temporary", evil.headline)  # most severe reason, not the first
        self.assertIn("every 5m", launchd.schedule(evil))
        g = jobs["com.google.keystone.agent"]
        self.assertEqual(g.severity, "low")
        self.assertTrue(any("missing" in r for r in g.reasons))
        self.assertEqual(launchd.schedule(jobs["com.daily"]), "daily at 3:15")
        self.assertEqual(jobs["com.off"].reasons, [])
        self.assertIsNotNone(jobs["broken"].error)
        self.assertIn("gui/$(id -u)/com.evil", launchd.disable_command(evil))

    def test_parse_launchctl_list(self):
        text = "PID\tStatus\tLabel\n123\t0\tcom.a\n-\t0\tcom.b\n"
        self.assertEqual(launchd.parse_launchctl_list(text), {"com.a": 123, "com.b": None})


class RecordTest(unittest.TestCase):
    def test_parsers(self):
        self.assertTrue(record.parse_clamshell(fixture("ioreg_clamshell.txt")))
        self.assertIsNone(record.parse_clamshell(""))
        self.assertEqual(record.parse_batt(fixture("pmset_batt.txt")),
                         {"source": "battery", "percent": 83, "state": "discharging"})

    def test_lid_closed_runs(self):
        t0 = datetime.fromisoformat("2026-10-01T10:00:00+02:00")

        def snap(minutes, closed, pct, top=()):
            return {"_ts": t0 + timedelta(minutes=minutes), "lid_closed": closed,
                    "battery": {"percent": pct},
                    "top": [{"name": n, "cpu": c} for n, c in top]}

        snaps = [
            snap(0, False, 90),
            snap(5, True, 89, [("Docker", 90.0)]),
            snap(10, True, 88, [("Docker", 80.0), ("mds", 10.0)]),
            snap(15, True, 87, [("Docker", 70.0)]),
            snap(120, True, 80),  # gap: a separate brief run
            snap(125, False, 80),
        ]
        runs = record.lid_closed_runs(snaps, interval=300)
        self.assertEqual([len(r.snaps) for r in runs], [3, 1])
        self.assertEqual(runs[0].battery_drop, 2)
        self.assertEqual(runs[0].duration, 600)
        self.assertEqual(runs[0].top_processes()[0], ("Docker", 3, 80.0))

    def test_load_snapshots(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.jsonl")
            with open(path, "w") as fh:
                fh.write('{"ts": "2026-10-01T10:00:00+02:00", "lid_closed": true}\n')
                fh.write("garbage\n")
                fh.write('{"ts": "2026-10-03T10:00:00+02:00", "lid_closed": false}\n')
            self.assertEqual(len(record.load_snapshots(path)), 2)
            since = datetime.fromisoformat("2026-10-02T00:00:00+02:00")
            self.assertEqual(len(record.load_snapshots(path, since)), 1)

    def test_agent_plist(self):
        p = record.agent_plist(120)
        self.assertEqual(p["StartInterval"], 120)
        self.assertEqual(p["ProgramArguments"][1:], ["-m", "wayr", "record", "--quiet"])
        plistlib.dumps(p)  # serializable


if __name__ == "__main__":
    unittest.main()
