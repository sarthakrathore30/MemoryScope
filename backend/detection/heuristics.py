"""
Suspicious-process heuristics (FR-8, FR-9, TC-DT-04).

Rule-based flags applied on top of the raw process list. Each check function
returns a reason string (or None), and evaluate_process() aggregates every
triggered reason for a process rather than stopping at the first match, so
an investigator sees the full picture when several checks fire at once.

Expected parent/child relationships are drawn from well-documented Windows
process lineage norms (e.g. svchost.exe should be spawned by services.exe).

Known scope limitation: the SRS (FR-8) also calls out "unsigned binaries" as
a suspicious characteristic. True Authenticode signature verification isn't
exposed by any Volatility 3 plugin (it would require dumping each PE from
memory and parsing its certificate table, a much larger undertaking). As a
practical, well-established proxy used by real memory-forensics tooling,
check_masquerading_path() below flags well-known system processes running
from an unexpected directory -- e.g. a process named svchost.exe that isn't
actually under C:/Windows/System32. This catches the common "name a
malicious binary after a trusted system process" trick, though it is not
equivalent to real signature verification (a well-placed but genuinely
unsigned/tampered binary in the correct directory would not be caught).
Anomalous memory regions ARE covered, via check_malfind() below, using
Volatility's malfind plugin (windows.malfind.Malfind / linux.malfind.Malfind).
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from analysis.volatility_wrapper import ProcessInfo

# Known Windows processes and their normal/expected parent process name(s).
# A mismatch here is a classic process-injection / masquerading indicator.
#
# services.exe and lsass.exe list two acceptable parents rather than one:
# wininit.exe (Windows Vista and later) or winlogon.exe (Windows XP and
# earlier, which lacks wininit.exe entirely -- it was introduced in Vista
# specifically to fix a Session 0 isolation issue). Without reliably knowing
# the exact OS version from the process list alone, accepting either avoids
# flagging correct, benign XP lineage as suspicious.
EXPECTED_PARENTS: Dict[str, List[str]] = {
    "svchost.exe": ["services.exe"],
    "lsass.exe": ["wininit.exe", "winlogon.exe"],
    "smss.exe": ["system"],
    "csrss.exe": ["smss.exe"],
    "wininit.exe": ["smss.exe"],
    "winlogon.exe": ["smss.exe"],
    "services.exe": ["wininit.exe", "winlogon.exe"],
}

# Well-known Windows system processes and the directory prefix(es) their
# genuine executable should always run from. A process claiming one of
# these names but running from anywhere else is a classic malware trick
# (e.g. "svchost.exe" launched from a Temp or user-profile directory).
# Paths are compared case-insensitively with forward/back slashes normalized.
EXPECTED_SYSTEM_PATHS: Dict[str, List[str]] = {
    "svchost.exe": [r"c:\windows\system32", r"c:\windows\syswow64"],
    "lsass.exe": [r"c:\windows\system32"],
    "services.exe": [r"c:\windows\system32"],
    "csrss.exe": [r"c:\windows\system32"],
    "winlogon.exe": [r"c:\windows\system32"],
    "wininit.exe": [r"c:\windows\system32"],
    "smss.exe": [r"c:\windows\system32"],
    "explorer.exe": [r"c:\windows"],
}

# The only processes legitimately allowed to have PPID 0 (no real parent).
# Any other process claiming PPID 0 is spoofing its lineage to look like a
# root-level kernel process -- a common evasion trick.
#
# Covers both Windows (System/Idle) and Linux (the init process, PID 1,
# always has PPID 0 -- its name varies by init system: systemd on most
# modern distros, init on older/sysvinit-based ones). Found via live testing
# against a simulated Linux image: systemd was being flagged as a spoofed
# root parent before this fix, the Linux analogue of the Windows XP false
# positives found earlier.
ROOT_PROCESS_NAMES = {"system", "idle", "system idle process", "systemd", "init"}


@dataclass
class SuspicionResult:
    pid: int
    suspicious: bool
    reason: Optional[str] = None  # joined summary of all triggered reasons, if any


def _build_pid_index(processes: List[ProcessInfo]) -> Dict[int, ProcessInfo]:
    return {p.pid: p for p in processes}


def check_unusual_parent(
    proc: ProcessInfo, by_pid: Dict[int, ProcessInfo], hidden_pids: Set[int], malfind_pids: Set[int]
) -> Optional[str]:
    """Flag a well-known process whose parent doesn't match the expected lineage."""
    name = (proc.process_name or "").lower()
    expected = EXPECTED_PARENTS.get(name)
    if not expected:
        return None

    parent = by_pid.get(proc.ppid)
    parent_name = (parent.process_name or "").lower() if parent else None

    if parent_name is None:
        return None  # handled by check_orphaned_process to avoid duplicate reasons

    if parent_name not in expected:
        expected_str = " or ".join(f"'{e}'" for e in expected)
        return (
            f"Unusual parent: '{proc.process_name}' (PID {proc.pid}) is running under "
            f"'{parent.process_name}' (PID {proc.ppid}), expected {expected_str}"
        )
    return None


def _normalize_dir(path: str) -> str:
    """Lowercase, backslash-normalize, and strip the filename from a Windows path."""
    normalized = path.lower().replace("/", "\\")
    return normalized.rsplit("\\", 1)[0] if "\\" in normalized else normalized


def check_masquerading_path(
    proc: ProcessInfo, by_pid: Dict[int, ProcessInfo], hidden_pids: Set[int], malfind_pids: Set[int]
) -> Optional[str]:
    """
    Flag a well-known system process running from an unexpected directory --
    a classic malware trick of naming a malicious binary after a trusted
    system process (e.g. a fake "svchost.exe" launched from a Temp folder).

    This is a practical proxy for the SRS's "unsigned binaries" criterion
    (FR-8); it is not equivalent to real Authenticode signature verification,
    which no Volatility 3 plugin exposes. A process with no resolvable image
    path (e.g. modules extraction failed or didn't include the main image)
    is silently skipped rather than flagged, to avoid false positives from
    missing data.
    """
    name = (proc.process_name or "").lower()
    expected_dirs = EXPECTED_SYSTEM_PATHS.get(name)
    if not expected_dirs or not proc.image_path:
        return None

    actual_dir = _normalize_dir(proc.image_path)
    if actual_dir not in expected_dirs:
        return (
            f"Masquerading process: '{proc.process_name}' (PID {proc.pid}) is running from "
            f"'{proc.image_path}', not the expected system directory -- possible malware "
            f"impersonating a trusted process name"
        )
    return None


# Processes whose normal, well-documented parent reliably exits before a
# memory snapshot is likely to be taken -- so a "missing" parent for these
# is expected Windows behavior, not a red flag. explorer.exe is the classic
# case: winlogon.exe -> userinit.exe -> explorer.exe, and userinit.exe is
# specifically designed to terminate immediately after launching the shell.
# This means virtually every real Windows memory image ever captured shows
# explorer.exe with a PPID that no longer resolves -- flagging it as
# "orphaned"/suspicious on every single image would be constant alarm
# fatigue for a case that is normal on effectively 100% of real systems.
KNOWN_BENIGN_ORPHANS = {"explorer.exe"}


def check_orphaned_process(
    proc: ProcessInfo, by_pid: Dict[int, ProcessInfo], hidden_pids: Set[int], malfind_pids: Set[int]
) -> Optional[str]:
    """Flag any process whose declared parent PID does not exist in the process list at all."""
    if proc.ppid is None or proc.ppid == 0:
        return None  # PID 0 is handled separately by check_ppid_zero_spoof.
    if (proc.process_name or "").lower() in KNOWN_BENIGN_ORPHANS:
        return None
    if proc.ppid not in by_pid:
        return (
            f"Orphaned process: '{proc.process_name}' (PID {proc.pid}) references "
            f"non-existent parent PID {proc.ppid}"
        )
    return None


def check_ppid_zero_spoof(
    proc: ProcessInfo, by_pid: Dict[int, ProcessInfo], hidden_pids: Set[int], malfind_pids: Set[int]
) -> Optional[str]:
    """
    Flag a process claiming PPID 0 when it isn't the System/Idle process.

    Malware commonly zeroes out or spoofs its parent PID to masquerade as a
    root-level kernel process and avoid orphan/lineage checks.
    """
    if proc.ppid != 0:
        return None
    name = (proc.process_name or "").lower()
    if name in ROOT_PROCESS_NAMES:
        return None
    return (
        f"Spoofed root parent: '{proc.process_name}' (PID {proc.pid}) claims PPID 0, "
        f"which is only legitimate for the System/Idle process"
    )


def check_self_parent(
    proc: ProcessInfo, by_pid: Dict[int, ProcessInfo], hidden_pids: Set[int], malfind_pids: Set[int]
) -> Optional[str]:
    """Flag a process that lists itself as its own parent (a known hollowing/rootkit trick)."""
    if proc.ppid is not None and proc.pid is not None and proc.ppid == proc.pid and proc.pid != 0:
        return f"Self-parented process: '{proc.process_name}' (PID {proc.pid}) lists itself as its own parent"
    return None


def check_hidden(
    proc: ProcessInfo, by_pid: Dict[int, ProcessInfo], hidden_pids: Set[int], malfind_pids: Set[int]
) -> Optional[str]:
    """
    Flag a process that was found via psscan but not pslist (hidden/unlinked).

    This links the hidden-process detection result (detection/hidden_process.py)
    into the overall suspicion flag, so a hidden process is never silently
    reported as "not suspicious" just because its lineage looks normal.
    """
    if proc.pid in hidden_pids:
        return (
            f"Hidden/unlinked process: '{proc.process_name}' (PID {proc.pid}) was found via "
            f"pool scan (psscan) but is absent from the standard process list (pslist)"
        )
    return None


def check_malfind(
    proc: ProcessInfo, by_pid: Dict[int, ProcessInfo], hidden_pids: Set[int], malfind_pids: Set[int]
) -> Optional[str]:
    """
    Flag a process with an anomalous memory region detected by Volatility's
    malfind plugin (SRS FR-8) -- typically private, executable memory not
    backed by any file on disk, the classic signature of process hollowing
    or reflective code injection.
    """
    if proc.pid in malfind_pids:
        return (
            f"Anomalous memory region: '{proc.process_name}' (PID {proc.pid}) has a "
            f"private executable memory region not backed by any file on disk, "
            f"consistent with code injection or process hollowing (malfind)"
        )
    return None


ALL_CHECKS = (
    check_hidden,
    check_malfind,
    check_ppid_zero_spoof,
    check_self_parent,
    check_unusual_parent,
    check_masquerading_path,
    check_orphaned_process,
)


def evaluate_process(
    proc: ProcessInfo,
    by_pid: Dict[int, ProcessInfo],
    hidden_pids: Optional[Set[int]] = None,
    malfind_pids: Optional[Set[int]] = None,
) -> SuspicionResult:
    """
    Run every heuristic check against a single process and aggregate all
    triggered reasons (rather than stopping at the first match), so an
    investigator sees the complete set of red flags for that process.
    """
    hidden_pids = hidden_pids or set()
    malfind_pids = malfind_pids or set()
    reasons = [reason for check in ALL_CHECKS if (reason := check(proc, by_pid, hidden_pids, malfind_pids))]

    if not reasons:
        return SuspicionResult(pid=proc.pid, suspicious=False, reason=None)
    return SuspicionResult(pid=proc.pid, suspicious=True, reason="; ".join(reasons))


def evaluate_all(
    processes: List[ProcessInfo],
    hidden_pids: Optional[Set[int]] = None,
    malfind_pids: Optional[Set[int]] = None,
) -> List[SuspicionResult]:
    """Run heuristics across an entire process list (FR-8, FR-9)."""
    by_pid = _build_pid_index(processes)
    hidden_pids = hidden_pids or set()
    malfind_pids = malfind_pids or set()
    return [evaluate_process(p, by_pid, hidden_pids, malfind_pids) for p in processes]
