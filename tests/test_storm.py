import unittest
from datetime import datetime, timedelta

from wayr import cli, pmset_log

T0 = datetime.fromisoformat("2026-10-02T17:00:00+08:00")


def line(t, domain, msg):
    return f"{t.strftime('%Y-%m-%d %H:%M:%S %z')} {domain:<20}\t{msg}"


def assertion(t, pid, name):
    return line(t, "Assertions", f'PID {pid}({name}) Created PreventUserIdleSystemSleep "x" 00:00:00  id:0x1')


def night(start, wakes, every, wake_secs, reason, charge=(80, 80)):
    """A sleep session: `wakes` dark wakes, one every `every` seconds."""
    out = [line(start, "Sleep", f"Entering Sleep state due to 'Clamshell Sleep': Using Batt (Charge:{charge[0]}%)")]
    t = start
    for _ in range(wakes):
        t += timedelta(seconds=every)
        out.append(assertion(t - timedelta(seconds=2), 333, "mDNSResponder"))  # logged just before the wake
        out.append(line(t, "DarkWake", f"DarkWake from Deep Idle [CDNP] : due to {reason} Using BATT (Charge:{charge[0]}%) {wake_secs} secs"))
        out.append(line(t + timedelta(seconds=wake_secs), "Sleep", "Entering Sleep state due to 'Maintenance Sleep': Using Batt"))
        out.append(assertion(t + timedelta(seconds=wake_secs + 1), 400, "cloudd"))  # right after going back to sleep
    end = t + timedelta(seconds=every)
    out.append(line(end, "Wake", f"Wake from Deep Idle [CDNVA] : due to UserActivity Assertion Using BATT (Charge:{charge[1]}%)"))
    return out, end


def build():
    lines = []
    storm1, end1 = night(T0, 400, 15, 6, "SMC.OutboxNotEmpty smc.70070000 wifibt/", (77, 60))
    storm2, end2 = night(end1 + timedelta(seconds=10), 400, 15, 6, "SMC.OutboxNotEmpty smc.70070000 wifibt/", (60, 45))
    normal, _ = night(end2 + timedelta(hours=2), 10, 600, 20, "NUB.SPMI0Sw3IRQ nub-spmi0.0x02 rtc/Maintenance")
    lines = storm1 + storm2 + normal
    # Genuine activity in the middle of a long sleep stays "asleep activity".
    lines.append(assertion(end2 + timedelta(hours=2, minutes=5), 777, "com.docker.backend"))
    return list(pmset_log.parse_lines(lines))


class StormTest(unittest.TestCase):
    def setUp(self):
        self.a = pmset_log.analyze(build())

    def test_storm_detected_and_merged(self):
        self.assertEqual([len(s.dark_wakes) for s in self.a.sessions], [400, 400, 10])
        self.assertEqual([s.is_storm for s in self.a.sessions], [True, True, False])
        periods = self.a.storms()
        self.assertEqual(len(periods), 1)
        self.assertEqual(len(periods[0]), 2)

    def test_transition_assertions_belong_to_wakes(self):
        procs = {p: n for p, n, _ in self.a.processes()}
        self.assertEqual(procs["mDNSResponder"], 810)
        self.assertEqual(procs["cloudd"], 810)
        self.assertEqual(self.a.asleep_activity(), [("com.docker.backend", 1)])

    def test_takeaways(self):
        found = cli.sleep_findings(self.a, womp_off=True)
        self.assertEqual(found[0].severity, "high")
        self.assertIn("woke 800 times, every ~15s", found[0].title)
        self.assertIn("Wi-Fi / Bluetooth", found[0].detail)
        self.assertEqual(found[1].severity, "ok")
        self.assertIn("sleep looks normal", found[1].title)
        wifi = next(f for f in found if "woken by: Wi-Fi" in f.title)
        self.assertIn("already off", wifi.detail)
        self.assertFalse(any("Maintenance" in f.title for f in found))  # 10 wakes: not significant
        self.assertFalse(any("Battery dropped" in f.title for f in found))  # covered by the storm

    def test_wifi_advice_when_womp_on(self):
        found = cli.sleep_findings(self.a, womp_off=False)
        wifi = next(f for f in found if "woken by: Wi-Fi" in f.title)
        self.assertIn("womp 0", wifi.detail)



class KeepAliveStormTest(unittest.TestCase):
    def test_names_tcp_keepalive_and_fix(self):
        reason = ("smc.sysState.Wake(0x70070000) wifibt SMC.OutboxNotEmpty centauri-alpha "
                  "E_TKO_SEQ_NUM_INVALID ARPT")
        lines, _ = night(T0, 300, 15, 6, reason, (70, 60))
        a = pmset_log.analyze(pmset_log.parse_lines(lines))
        found = cli.sleep_findings(a, womp_off=True)
        self.assertIn("Main cause: Wi-Fi: TCP keep-alive offload", found[0].detail)
        tko = next(f for f in found if "woken by: Wi-Fi: TCP keep-alive" in f.title)
        self.assertIn("sudo pmset -b tcpkeepalive 0", tko.detail)


class HealthyNightTest(unittest.TestCase):
    def test_normal_night_is_ok(self):
        # Like a real healthy night: ~8 Wi-Fi/BT wakes an hour, no battery loss.
        lines, end = night(T0, 80, 450, 6, "SMC.OutboxNotEmpty smc.70070000 wifibt/")
        # Plus a 16-minute Power Nap wake while plugged in, which is normal.
        t = end + timedelta(hours=1)
        lines += [
            line(t, "Sleep", "Entering Sleep state due to 'Idle Sleep': Using AC (Charge:100%)"),
            line(t + timedelta(hours=1), "DarkWake",
                 "DarkWake from Deep Idle [CDNP] : due to rtc/Maintenance Using AC (Charge:100%) 960 secs"),
            line(t + timedelta(hours=1, seconds=960), "Sleep", "Entering Sleep state due to 'Maintenance Sleep': Using AC"),
            line(t + timedelta(hours=3), "Wake", "Wake from Deep Idle [CDNVA] : due to EC.LidOpen/Lid Open Using AC (Charge:100%)"),
        ]
        a = pmset_log.analyze(pmset_log.parse_lines(lines))
        found = cli.sleep_findings(a, womp_off=True)
        self.assertEqual([f.severity for f in found], ["ok"])
        self.assertEqual(found[0].title, "Sleep looks healthy")
        self.assertIn("battery loss up to 0.0%/hour", found[0].detail)


if __name__ == "__main__":
    unittest.main()
