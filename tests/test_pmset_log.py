import os
import unittest
from datetime import datetime

from wayr import pmset_log
from wayr.knowledge import classify_wake

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def load():
    with open(os.path.join(FIX, "pmset_log.txt")) as fh:
        return list(pmset_log.parse_lines(fh))


class ParseTest(unittest.TestCase):
    def test_parses_entries_and_skips_headers(self):
        entries = load()
        self.assertEqual(entries[0].domain, "DarkWake")
        self.assertTrue(all(e.ts.tzinfo for e in entries))
        self.assertEqual(len(entries), 27)

    def test_fields(self):
        e = next(e for e in load() if e.domain == "Wake" and "LidOpen" in e.message)
        self.assertEqual(e.kind, "wake")
        self.assertEqual(e.wake_reason, "EC.LidOpen/Lid Open")
        self.assertEqual(e.charge, 80)
        self.assertTrue(e.on_battery)

    def test_sleep_reason(self):
        e = next(e for e in load() if e.kind == "sleep")
        self.assertEqual(e.sleep_reason, "Clamshell Sleep")

    def test_darkwake_reason_strips_power_and_duration(self):
        e = next(e for e in load() if e.kind == "darkwake" and "wifibt" in e.message)
        self.assertEqual(e.wake_reason, "SMC.OutboxNotEmpty smc.70070000 wifibt")

    def test_promoted_darkwake_is_full_wake(self):
        e = next(e for e in load() if "DarkWake to FullWake" in e.message)
        self.assertEqual(e.kind, "wake")

    def test_space_separated_fallback(self):
        line = "2026-10-01 10:00:00 +0200 DarkWake               DarkWake from Deep Idle [CDNP] : due to RTC/Maintenance Using BATT (Charge:50%)"
        (e,) = pmset_log.parse_lines([line])
        self.assertEqual(e.domain, "DarkWake")
        self.assertEqual(e.wake_reason, "RTC/Maintenance")

    def test_wake_requests(self):
        msg = ('[*process=mDNSResponder request=Maintenance deltaSecs=3600 wakeAt=2026-10-01 10:00:02 info="x y"] '
               '[process=dasd request=SleepService deltaSecs=7200 wakeAt=2026-10-01 11:00:01]')
        reqs = pmset_log.parse_wake_requests(msg)
        self.assertEqual([r.process for r in reqs], ["mDNSResponder", "dasd"])
        self.assertTrue(reqs[0].chosen)
        self.assertEqual(reqs[0].wake_at, datetime(2026, 10, 1, 10, 0, 2))


class AnalyzeTest(unittest.TestCase):
    def setUp(self):
        self.a = pmset_log.analyze(load())

    def test_sessions(self):
        s = self.a.sessions
        self.assertEqual(len(s), 3)
        self.assertTrue(s[0].partial)
        self.assertEqual(s[0].wake_cause.key, "user")
        self.assertEqual(s[1].sleep_reason, "Clamshell Sleep")
        self.assertEqual(s[1].wake_cause.key, "lid")
        self.assertEqual(len(s[1].dark_wakes), 4)
        self.assertEqual(s[2].wake_cause.key, "power_button")

    def test_battery_drain(self):
        s = self.a.sessions[1]
        self.assertEqual(s.charge_start, 95)
        self.assertEqual(s.charge_end, 80)
        self.assertEqual(s.battery_drop, 15)
        self.assertAlmostEqual(s.drain_per_hour, 15 / 8, places=2)
        self.assertIsNone(self.a.sessions[2].battery_drop)  # on AC

    def test_darkwake_durations(self):
        dws = self.a.sessions[1].dark_wakes
        self.assertEqual([int(d.duration) for d in dws], [45, 1200, 60, 30])
        self.assertEqual(self.a.sessions[1].longest_darkwake, 1200)

    def test_missing_sleep_line_uses_logged_duration(self):
        dw = self.a.sessions[0].dark_wakes[0]
        self.assertTrue(dw.promoted)
        self.assertEqual(dw.duration, 30)

    def test_requests_attributed(self):
        dws = self.a.sessions[1].dark_wakes
        self.assertEqual(dws[0].requested_by, "mDNSResponder")
        self.assertEqual(dws[1].requested_by, "dasd")
        self.assertIsNone(dws[2].requested_by)  # network wake, not scheduled
        self.assertEqual(dict(self.a.requesters()), {"mDNSResponder": 1, "dasd": 1})

    def test_processes_during_darkwake(self):
        procs = {p: n for p, n, _ in self.a.processes()}
        self.assertEqual(procs, {"backupd": 1, "cloudd": 1, "mds_stores": 1, "com.docker.backend": 1})
        self.assertNotIn("powerd", procs)

    def test_activity_while_asleep(self):
        self.assertEqual(self.a.asleep_activity(), [("com.docker.backend", 1)])

    def test_reasons(self):
        keys = {c.key: n for c, n, _ in self.a.reasons()}
        self.assertEqual(keys, {"maintenance": 2, "sleep_service": 1, "wifi_bt": 2, "usb": 1})

    def test_failures(self):
        self.assertEqual(len(self.a.failures), 1)

    def test_since_filter(self):
        since = datetime.fromisoformat("2026-10-01T20:00:00+02:00")
        a = pmset_log.analyze(load(), since=since)
        self.assertEqual(len(a.sessions), 1)
        self.assertEqual(a.failures, [])


class ClassifyTest(unittest.TestCase):
    def test_classification(self):
        cases = {
            "EC.LidOpen/Lid Open": "lid",
            "NUB.SPMI0Sw3IRQ nub-spmi0.0x02 rtc/Maintenance": "maintenance",
            "RTC/Maintenance": "maintenance",
            "EC.RTC (Maintenance)/Maintenance": "maintenance",
            "rtc/SleepService": "sleep_service",
            "NUB.SPMISw3IRQ nub-spmi-a0.0x02 rtc/HalfHourAlarm": "rtc",
            "SMC.OutboxNotEmpty smc.70070000 wifibt": "wifi_bt",
            "ARPT": "wifi_bt",
            "XHC1": "usb",
            "EC.ACAttach": "power_adapter",
            "UserActivity Assertion": "user",
            "EC.PowerButton/User": "power_button",
            "GIGE": "ethernet",
            "SMC.OutboxNotEmpty": "smc",
            "Unknown": "unknown",
            None: "unknown",
        }
        for reason, key in cases.items():
            self.assertEqual(classify_wake(reason).key, key, reason)


if __name__ == "__main__":
    unittest.main()
