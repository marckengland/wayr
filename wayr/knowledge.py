"""What we know about wake reasons and common background processes."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Pattern, Tuple


@dataclass(frozen=True)
class WakeCause:
    key: str
    label: str
    category: str  # user | scheduled | network | hardware | unknown
    advice: str


_CAUSES: List[Tuple[WakeCause, List[str]]] = [
    (
        WakeCause("lid", "Lid opened", "user", "That was you."),
        [r"lidopen", r"lid open", r"\blid\b"],
    ),
    (
        WakeCause("power_button", "Power button / Touch ID", "user", "That was you."),
        [r"powerbutton", r"\bpwrb\b", r"power button"],
    ),
    (
        WakeCause("user", "Keyboard / trackpad / user activity", "user",
                  "Something counted as user input. If the Mac was in a bag, a key "
                  "or the trackpad may have been pressed through the sleeve."),
        [r"useractivity", r"hid activity", r"\bhid\b", r"keyboard", r"trackpad"],
    ),
    (
        WakeCause("power_adapter", "Power adapter connected/disconnected", "hardware",
                  "Plugging or unplugging power wakes the Mac (pmset `acwake`)."),
        [r"acattach", r"acdetach", r"ac attach", r"acchange", r"charger"],
    ),
    (
        WakeCause("maintenance", "Maintenance wake (Power Nap / network upkeep)", "scheduled",
                  "macOS wakes on a timer to refresh network registrations, mail, iCloud, "
                  "Find My and Time Machine. Disable Power Nap and TCP keep-alive on battery "
                  "to cut most of these. See 'Requested by' for the process that asked."),
        [r"maintenance"],
    ),
    (
        WakeCause("sleep_service", "Power Nap sleep services", "scheduled",
                  "Power Nap lets apps run while asleep. Turn it off on battery: "
                  "sudo pmset -b powernap 0"),
        [r"sleepservice", r"sleep service"],
    ),
    (
        WakeCause("rtc", "Timer wake (scheduled by software)", "scheduled",
                  "A process scheduled a wake-up. Check `pmset -g sched` and the "
                  "'Requested by' column."),
        [r"\brtc\b", r"alarm"],
    ),
    (
        WakeCause("wifi_bt", "Wi-Fi / Bluetooth", "network",
                  "A network packet or Bluetooth device woke the Mac. Turn off 'Wake for "
                  "network access' (sudo pmset -a womp 0) and Bluetooth wake."),
        [r"wifibt", r"\barpt\b", r"wlan", r"airport", r"wi-?fi"],
    ),
    (
        WakeCause("bluetooth", "Bluetooth device", "network",
                  "A Bluetooth keyboard, mouse or headphones woke the Mac. Turn off "
                  "'Allow Bluetooth devices to wake this computer'."),
        [r"bluetooth", r"\bbt\b"],
    ),
    (
        WakeCause("ethernet", "Network (Ethernet / Wake on LAN)", "network",
                  "Wake on LAN. Disable with: sudo pmset -a womp 0"),
        [r"\bgige\b", r"\ben\d\b", r"ethernet", r"magic ?packet", r"wake ?on ?lan", r"\bnetwork\b"],
    ),
    (
        WakeCause("usb", "USB / Thunderbolt device", "hardware",
                  "A connected accessory (dock, hub, dongle) woke the Mac. Unplug it "
                  "before sleeping."),
        [r"\bxhc", r"usb", r"thunderbolt", r"\brp\d\d\b"],
    ),
    (
        WakeCause("smc", "Power controller (battery / charging / thermal)", "hardware",
                  "A low-level power-controller event. Usually brief and harmless. If "
                  "it's very frequent, suspect an accessory or Bluetooth."),
        [r"smc", r"outboxnotempty", r"spmi", r"\bnub\b", r"\baop\b", r"\bec\."],
    ),
]

UNKNOWN_CAUSE = WakeCause(
    "unknown", "Unknown", "unknown",
    "macOS didn't record a clear reason.",
)

_COMPILED: List[Tuple[WakeCause, List[Pattern[str]]]] = [
    (cause, [re.compile(p) for p in pats]) for cause, pats in _CAUSES
]


def classify_wake(reason: Optional[str]) -> WakeCause:
    if not reason:
        return UNKNOWN_CAUSE
    low = reason.lower()
    for cause, pats in _COMPILED:
        if any(p.search(low) for p in pats):
            return cause
    return UNKNOWN_CAUSE


@dataclass(frozen=True)
class KnownProcess:
    what: str
    tip: str = ""
    keeps_awake: bool = False  # exists mainly to stop the Mac sleeping


_KNOWN: Dict[str, KnownProcess] = {}


def _add(names: List[str], what: str, tip: str = "", keeps_awake: bool = False) -> None:
    for n in names:
        _KNOWN[n.lower()] = KnownProcess(what, tip, keeps_awake)


# --- Apple ---------------------------------------------------------------
_add(["mDNSResponder"], "Bonjour / DNS. Schedules maintenance wakes to keep network "
     "registrations alive while asleep.",
     "Turn off 'Wake for network access' and TCP keep-alive on battery.")
_add(["backupd", "backupd-helper"], "Time Machine.",
     "Backups can run during Power Nap. Disable Power Nap on battery, or back up manually.")
_add(["mds", "mds_stores", "mdworker", "mdworker_shared", "corespotlightd"],
     "Spotlight indexing.",
     "Heavy after updates or big file changes. Exclude large folders in Spotlight > Privacy.")
_add(["photoanalysisd", "mediaanalysisd", "photolibraryd"],
     "Photos library analysis (faces, scenes).",
     "Runs when idle. Usually settles once the library is fully analyzed.")
_add(["cloudd", "bird", "fileproviderd"], "iCloud Drive / CloudKit sync.")
_add(["nsurlsessiond"], "Background downloads for apps and the system.")
_add(["softwareupdated", "softwareupdate_notify_agent"], "macOS software update checks and downloads.")
_add(["apsd"], "Apple Push Notification service connection.")
_add(["dasd"], "Duet Activity Scheduler. Decides when background work runs. It's the "
     "dispatcher, so check which processes run right after it.")
_add(["sharingd"], "AirDrop / Handoff / Continuity.")
_add(["bluetoothd"], "Bluetooth.")
_add(["airportd", "wifid", "wifianalyticsd"], "Wi-Fi.")
_add(["locationd"], "Location services.")
_add(["searchpartyd"], "Find My network.")
_add(["coreaudiod"], "Audio. An app holding the audio device open prevents idle sleep.",
     "Quit apps that play audio, or are in calls, before closing the lid.")
_add(["powerd"], "The power management daemon itself.")
_add(["WindowServer"], "The display server.")
_add(["kernel_task"], "The macOS kernel. High CPU here often means the Mac is hot "
     "and the kernel is throttling.")
_add(["caffeinate"], "Explicitly keeping the Mac awake.",
     "Check what launched it: ps -o ppid= -p <pid>", keeps_awake=True)
_add(["suggestd", "knowledge-agent", "duetexpertd"], "Siri suggestions and on-device learning.")

# --- Keep-awake apps -----------------------------------------------------
_add(["Amphetamine", "Caffeine", "KeepingYouAwake", "Lungo", "Theine", "Owly", "Jolt of Caffeine"],
     "Keep-awake utility. Some modes keep the Mac awake with the lid closed.",
     "Quit it, or turn off its 'closed display' / 'allow system sleep when display closed' options.",
     keeps_awake=True)

# --- Third-party background services ------------------------------------
_add(["GoogleUpdater", "GoogleSoftwareUpdateAgent", "ksfetch", "GoogleSoftwareUpdateDaemon"],
     "Google updater. Runs on an hourly launchd schedule.")
_add(["Microsoft AutoUpdate", "Microsoft Update Assistant", "MAU"], "Microsoft AutoUpdate.")
_add(["OneDrive", "OneDrive File Provider"], "OneDrive sync.")
_add(["Dropbox", "Dropbox Web Helper"], "Dropbox sync.")
_add(["Google Drive"], "Google Drive sync.")
_add(["Adobe Desktop Service", "AdobeIPCBroker", "CCXProcess", "Creative Cloud", "Core Sync",
      "AGSService", "AdobeCRDaemon", "ACCFinderSync"],
     "Adobe Creative Cloud background service.",
     "Quit Creative Cloud, or turn off 'Launch at login' in its preferences.")
_add(["com.docker.backend", "com.docker.vpnkit", "com.docker.hyperkit", "com.docker.virtualization",
      "qemu-system-aarch64", "qemu-system-x86_64", "Docker Desktop"],
     "Docker's VM. Containers keep running and burning CPU until Docker quits.",
     "Quit Docker Desktop before closing the lid.")
_add(["prl_vm_app", "prl_client_app", "VirtualBoxVM", "VirtualBox VM", "UTM"],
     "Virtual machine.", "Suspend or shut down VMs before closing the lid.")
_add(["zoom.us", "CptHost"], "Zoom.", "Quit Zoom after calls. It can hold audio/sleep assertions.")
_add(["Microsoft Teams", "MSTeams", "Microsoft Teams (work or school)"], "Microsoft Teams.")
_add(["logioptionsplus_agent", "LogiMgrDaemon", "Logi Options+"], "Logitech Options+ agent.")
_add(["bztransmit", "bzserv", "bzfilelist", "bzbmenu"], "Backblaze backup.")
_add(["TeamViewer", "TeamViewer_Service", "AnyDesk"], "Remote-access tool. Can enable wake-on-network.")
_add(["node", "python", "python3", "ruby", "java", "deno", "bun"],
     "A script or dev server.", "Check if a dev server or script was left running.")


def lookup_process(name: str) -> Optional[KnownProcess]:
    return _KNOWN.get(name.lower())
