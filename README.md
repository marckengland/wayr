# why are you running?

**`wayr`** finds out what keeps your Mac awake, and warm, while it's supposed to be asleep.

It started with a MacBook that came out of its sleeve hot after a day with the lid closed. macOS
already records most of the evidence. It's just scattered across `pmset`, launchd and `ps`, and
hard to read. `wayr` pulls it together and tells you, in plain words:

- **Was it really asleep?** Every sleep session, how long it lasted, and how much battery it lost
  per hour.
- **Why did it wake up?** Every *dark wake* (CPU on, screen off), grouped by cause: Power Nap,
  network, Bluetooth, USB, timers…
- **Who asked it to wake up?** The process that scheduled each wake (e.g. `mDNSResponder`,
  `dasd`).
- **What ran while it was awake?** Processes that grabbed power assertions during dark wakes.
- **What's preventing sleep right now?** Apps holding sleep assertions (Amphetamine, audio,
  Docker…).
- **Which settings make it worse?** `womp`, Power Nap, TCP keep-alive, `SleepDisabled`, scheduled
  wakes…, each with the command that fixes it.
- **What runs in the background on an interval?** Third-party launchd agents/daemons and how often
  they run, plus orphaned leftovers from uninstalled apps.
- **Which running processes look unusual?** Heavy CPU, keep-awake tools, binaries running from
  `/tmp` or hidden folders, unsigned code.
- **Proof, over time:** an optional recorder that catches the Mac awake *with the lid closed*,
  and what it was running.

## Install

Requires macOS and Python 3.9+. If `python3` isn't there, run `xcode-select --install`.
There are no other dependencies.

```sh
git clone https://github.com/marckengland/why-are-you-running.git ~/src/why-are-you-running
cd ~/src/why-are-you-running
./wayr.sh            # run straight from the checkout
# or install the `wayr` command:
pipx install .       # or: python3 -m pip install --user .
```

> Keep the checkout **outside** `~/Desktop`, `~/Documents` and `~/Downloads` if you plan to
> use the recorder. macOS privacy protection blocks background agents from reading those folders.

## Use

```sh
wayr                     # full check-up (same as `wayr report`)
wayr sleep               # sleep sessions, dark wakes, battery drain (last 3 days)
wayr sleep --days 7 -v   # …a week, listing every single dark wake
wayr blockers            # what is preventing sleep right now
wayr settings            # audit pmset settings, with fix commands
wayr jobs                # third-party launchd jobs and how often they run (--all for everything)
wayr procs               # unusual or heavy processes (--signatures to check code signing)
wayr tips                # things you need to check by hand in System Settings
```

Nothing is changed for you. `wayr` only reads, and it prints the exact command for every fix so
you decide what to run.

### Catch it in the act: the recorder

macOS logs *that* the Mac woke up, but not what was burning CPU while it was awake. The
recorder fills that gap:

```sh
wayr agent install       # snapshot every 5 min via a LaunchAgent (--interval to change)
# …use the Mac normally, close the lid, go out…
wayr snapshots           # when was it awake with the lid closed, and what was running?
wayr agent uninstall
```

A LaunchAgent only runs while the Mac is actually awake. So a snapshot taken with the lid closed
is proof it was awake in the bag, and several in a row mean it *stayed* awake. Snapshots go to
`~/Library/Logs/why-are-you-running/snapshots.jsonl`: lid state, battery, the top CPU
processes and sleep assertions. The file is capped at about 5 MB.

### Analyze someone else's log

```sh
pmset -g log > pmset.log      # on the Mac in question
wayr sleep --file pmset.log   # anywhere, even on Linux
```

## Reading the results

| You see | It means | Usually fix with |
|---|---|---|
| Battery drain > 1.5%/hour while asleep | It was awake a lot | Everything below |
| Dark wakes: *Maintenance* / *Power Nap* | Timers for network upkeep, iCloud, Time Machine | `sudo pmset -b powernap 0`, `sudo pmset -b tcpkeepalive 0` |
| Dark wakes: *Wi-Fi / Bluetooth* / *Network* | Packets or BT devices woke it | `sudo pmset -a womp 0`, turn off Bluetooth wake |
| Dark wakes: *USB / Thunderbolt* | An accessory woke it | Unplug docks/dongles before sleeping |
| Long dark wakes (10+ min) | Real work ran while "asleep" (Spotlight, Docker, backups) | See "What ran during dark wakes" |
| `SleepDisabled = 1` | The Mac will **not** sleep on lid close | `sudo pmset -a disablesleep 0` and check keep-awake apps |
| `PreventSystemSleep` assertion | An app is deliberately keeping it awake | Quit that app |
| Recorder: many lid-closed snapshots in a row | It never went to sleep in the bag | The top process in that run is your suspect |

### About Find My

Turning off TCP keep-alive and Power Nap on battery stops most maintenance wakes. The trade-off is
that Find My Mac, iMessage and notifications refresh less often while the lid is closed. For a
laptop that keeps cooking in a bag, it's usually worth it.

## How it works

| Source | Used for |
|---|---|
| `pmset -g log` | Sleep/wake/dark-wake timeline, wake reasons, `Wake Requests` (who scheduled the wake), assertions created during dark wakes, battery %, sleep failures |
| `pmset -g custom`, `pmset -g`, `pmset -g sched` | Settings audit, `SleepDisabled`, "sleep prevented by", scheduled wakes |
| `pmset -g assertions` | Who is preventing sleep right now (and on whose behalf) |
| `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `launchctl list` | Background jobs, their schedules, whether they're running |
| `ps`, `codesign` | Unusual and heavy processes, signatures |
| `ioreg` (`AppleClamshellState`), `pmset -g batt` | Recorder: lid state and battery |

## Development

```sh
python3 -m unittest discover -s tests -t .
```

Parsers are tested against sample command output in `tests/fixtures/`. CI also runs the real
commands on a GitHub macOS runner. If something on your Mac parses wrong, please open an issue
with the relevant snippet of the command's output.

## Ideas / roadmap

- Menu bar app showing "slept well / restless night" after each lid-close session.
- Notification when a sleep session drains more than X% (run `wayr sleep` from the recorder on wake).
- Read `log show --predicate 'subsystem == "com.apple.powerd"'` for more detail on newer macOS.
- `sudo sfltool dumpbtm` to list Background Task Management items (login items / "Allow in
  the Background") with the app that registered them.
- Thermal history (`pmset -g thermlog`) to show when the Mac was hot.
- One-command "bag mode" profile that applies the battery recommendations and can restore the
  previous settings.
