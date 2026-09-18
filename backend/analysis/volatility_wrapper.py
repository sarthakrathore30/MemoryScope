"""
Analysis Module: wraps Volatility 3 plugins to extract structured forensic
artifacts from a memory image.

Covers FR-4 (process enumeration), FR-5 (DLL/module listing),
FR-6 (process tree), FR-10/FR-11 (network connections).

Implementation note: shells out to the `vol` CLI with JSON output rather than
using the internal Volatility3 framework API directly. This keeps the wrapper
resilient to internal API changes across Volatility3 versions and mirrors how
an analyst would run these plugins manually, which keeps behavior predictable
and testable via subprocess mocking.
"""
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

VOL_TIMEOUT_SECONDS = 900  # generous ceiling for large (multi-GB) images


def _format_hex(value) -> str:
    """
    Volatility's JSON renderer serializes format_hints.Hex fields (memory
    addresses, offsets, base addresses) as plain decimal integers -- Hex is
    just an int subclass with no special case in the JSON renderer's type
    table, so json.dumps() emits it as an ordinary number. Re-format these
    back into the conventional 0x-prefixed hex strings investigators expect
    for addresses, rather than showing raw decimal numbers.
    """
    if value is None or value == "":
        return ""
    if isinstance(value, int):
        return f"0x{value:x}"
    return str(value)  # already a string (e.g. an unexpected/fallback type)


class VolatilityError(Exception):
    """Raised when a Volatility3 plugin invocation fails or returns unparsable output."""


@dataclass
class ProcessInfo:
    pid: int
    ppid: Optional[int]
    process_name: str
    create_time: Optional[str] = None
    offset: Optional[str] = None
    # Populated by the Detection module later; kept here for pipeline convenience.
    seen_in_pslist: bool = False
    seen_in_psscan: bool = False
    # Full path of the process's own executable image, cross-referenced from
    # module listing data (see _attach_image_paths). Used for masquerading
    # detection (FR-8): a well-known system process running from an
    # unexpected directory is a classic indicator of a malicious impersonator.
    image_path: Optional[str] = None


@dataclass
class ModuleInfo:
    pid: int
    dll_name: str
    base_address: Optional[str] = None
    module_size: Optional[int] = None
    path: Optional[str] = None


@dataclass
class NetworkConnectionInfo:
    pid: Optional[int]
    local_ip: Optional[str] = None
    local_port: Optional[int] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: Optional[str] = None
    state: Optional[str] = None


@dataclass
class YaraMatchInfo:
    """A YARA rule match found directly in a process's memory (FR-12, FR-13)."""
    pid: Optional[int]
    process_name: Optional[str]
    rule_name: str
    address: Optional[str] = None


@dataclass
class MalfindHit:
    """
    An anomalous memory region flagged by Volatility's malfind plugin --
    typically a private, executable memory region not backed by any file on
    disk, the classic signature of process hollowing or reflective code
    injection (SRS FR-8's "anomalous memory regions" criterion).
    """
    pid: int
    process_name: Optional[str] = None
    address: Optional[str] = None
    protection: Optional[str] = None


def _run_plugin(image_path: str, plugin: str, extra_args: list = None) -> list:
    """Run a Volatility3 plugin with JSON output and return the parsed rows."""
    vol_bin = shutil.which("vol")
    if not vol_bin:
        raise VolatilityError("Volatility 3 CLI ('vol') not found on PATH.")

    cmd = [vol_bin, "-q", "-r", "json", "-f", image_path, plugin]
    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=VOL_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired as exc:
        raise VolatilityError(f"Plugin '{plugin}' timed out after {VOL_TIMEOUT_SECONDS}s.") from exc

    if result.returncode != 0:
        raise VolatilityError(f"Plugin '{plugin}' failed: {result.stderr.strip()[:1000]}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise VolatilityError(f"Could not parse JSON output for '{plugin}': {exc}") from exc


def _detect_os_family(image_path: str) -> str:
    """
    Return 'windows' or 'linux' based on which plugin family succeeds.

    Note: banners.Banners is registered at the top level (it lives at
    volatility3/framework/plugins/banners.py, not under a linux/
    subdirectory) -- "linux.banners.Banners" does not exist as a plugin
    name and always fails, which silently made every Linux memory image
    fail OS detection entirely (and therefore the whole analysis) until
    this fix, since it was the only fallback after windows.info.Info.
    """
    errors = []
    try:
        _run_plugin(image_path, "windows.info.Info")
        return "windows"
    except VolatilityError as exc:
        errors.append(f"windows.info.Info -> {exc}")
    try:
        _run_plugin(image_path, "banners.Banners")
        return "linux"
    except VolatilityError as exc:
        errors.append(f"banners.Banners -> {exc}")

    raise VolatilityError(
        "Could not determine OS family (Windows/Linux) for this image. "
        "Attempts: " + " | ".join(errors)
    )


def list_processes(image_path: str, os_family: str = None) -> list:
    """
    Enumerate all running processes (FR-4). Uses pslist by default.

    Returns a list of ProcessInfo objects.
    """
    os_family = os_family or _detect_os_family(image_path)
    plugin = "windows.pslist.PsList" if os_family == "windows" else "linux.pslist.PsList"
    rows = _run_plugin(image_path, plugin)

    processes = []
    for row in rows:
        processes.append(ProcessInfo(
            pid=row.get("PID"),
            ppid=row.get("PPID"),
            process_name=row.get("ImageFileName") or row.get("COMM") or row.get("Name", "unknown"),
            create_time=row.get("CreateTime") or row.get("CREATION TIME"),
            offset=_format_hex(row.get("Offset(V)") or row.get("OFFSET (V)")),
            seen_in_pslist=True,
        ))
    return processes


def scan_processes(image_path: str, os_family: str = None) -> list:
    """
    Scan for processes via pool-tag/carving scan (psscan), which finds
    processes regardless of whether they are linked into the active process
    list -- used by the Detection module for hidden-process comparison
    (FR-7, TC-DT-01).
    """
    os_family = os_family or _detect_os_family(image_path)
    plugin = "windows.psscan.PsScan" if os_family == "windows" else "linux.psscan.PsScan"
    rows = _run_plugin(image_path, plugin)

    processes = []
    for row in rows:
        processes.append(ProcessInfo(
            pid=row.get("PID"),
            ppid=row.get("PPID"),
            process_name=row.get("ImageFileName") or row.get("COMM") or row.get("Name", "unknown"),
            create_time=row.get("CreateTime") or row.get("CREATION TIME"),
            offset=_format_hex(row.get("Offset(V)") or row.get("OFFSET (V)") or row.get("OFFSET (P)")),
            seen_in_psscan=True,
        ))
    return processes


def get_process_tree(image_path: str, os_family: str = None) -> list:
    """
    Reconstruct the process tree (FR-6). Returns the same flat ProcessInfo
    list as list_processes(); pid/ppid fields are sufficient for the API/
    frontend layer to build the tree structure, avoiding a second
    duplicate-but-differently-shaped representation.
    """
    os_family = os_family or _detect_os_family(image_path)
    plugin = "windows.pstree.PsTree" if os_family == "windows" else "linux.pstree.PsTree"
    try:
        rows = _run_plugin(image_path, plugin)
    except VolatilityError:
        # Fall back to plain pslist if pstree plugin is unavailable for this profile.
        return list_processes(image_path, os_family)

    processes = []
    for row in rows:
        processes.append(ProcessInfo(
            pid=row.get("PID"),
            ppid=row.get("PPID"),
            process_name=row.get("ImageFileName") or row.get("COMM") or row.get("Name", "unknown"),
            create_time=row.get("CreateTime"),
            seen_in_pslist=True,
        ))
    return processes


def list_dlls(image_path: str, os_family: str = None) -> list:
    """
    List loaded DLLs/modules for each process (FR-5). Windows uses dlllist;
    Linux equivalent is proclist/library maps.
    """
    os_family = os_family or _detect_os_family(image_path)
    plugin = "windows.dlllist.DllList" if os_family == "windows" else "linux.proc.Maps"
    rows = _run_plugin(image_path, plugin)

    modules = []
    if os_family == "windows":
        for row in rows:
            modules.append(ModuleInfo(
                pid=row.get("PID"),
                dll_name=row.get("Name", "unknown"),
                base_address=_format_hex(row.get("Base")),
                module_size=row.get("Size"),
                path=row.get("Path"),
            ))
    else:
        for row in rows:
            file_path = row.get("File Path", "unknown")
            modules.append(ModuleInfo(
                pid=row.get("PID"),
                dll_name=file_path,
                base_address=_format_hex(row.get("Start")),
                module_size=None,
                path=file_path,
            ))
    return modules


def _attach_image_paths(processes: list, modules: list) -> None:
    """
    Cross-reference each process with the full path of its own executable
    image (mutates ProcessInfo.image_path in place), used for masquerading
    detection (FR-8): a well-known system process running from an unexpected
    directory is a classic indicator of a malicious impersonator using a
    legitimate-sounding name.

    The process's own EXE is identified as the module whose file name
    matches the process name (case-insensitive) -- this is how the process's
    own image consistently appears in its own module list (dlllist/proc maps
    always include the main executable alongside its loaded DLLs).
    """
    modules_by_pid: dict = {}
    for m in modules:
        modules_by_pid.setdefault(m.pid, []).append(m)

    for proc in processes:
        candidates = modules_by_pid.get(proc.pid, [])
        proc_name_lower = (proc.process_name or "").lower()
        for m in candidates:
            module_filename = (m.dll_name or "").lower().split("\\")[-1].split("/")[-1]
            if module_filename == proc_name_lower and m.path:
                proc.image_path = m.path
                break


def list_network_connections(image_path: str, os_family: str = None) -> list:
    """
    Extract network connections (FR-10, FR-11). Windows uses netscan;
    Linux uses sockstat.
    """
    os_family = os_family or _detect_os_family(image_path)
    plugin = "windows.netscan.NetScan" if os_family == "windows" else "linux.sockstat.Sockstat"
    rows = _run_plugin(image_path, plugin)

    connections = []
    if os_family == "windows":
        for row in rows:
            connections.append(NetworkConnectionInfo(
                pid=row.get("PID"),
                local_ip=row.get("LocalAddr"),
                local_port=row.get("LocalPort"),
                remote_ip=row.get("ForeignAddr"),
                remote_port=row.get("ForeignPort"),
                protocol=row.get("Proto"),
                state=row.get("State"),
            ))
    else:
        for row in rows:
            connections.append(NetworkConnectionInfo(
                pid=row.get("PID"),
                local_ip=row.get("Source Addr"),
                local_port=row.get("Source Port"),
                remote_ip=row.get("Destination Addr"),
                remote_port=row.get("Destination Port"),
                protocol=row.get("Proto"),
                state=row.get("State"),
            ))
    return connections


def run_yara_scan(image_path: str, rules_path: str, os_family: str = None) -> list:
    """
    Scan live process memory (VAD/VMA regions) for YARA rule matches
    (FR-12, FR-13) using Volatility 3's own scanning plugins.

    This scans directly against memory regions inside the image itself --
    no separate process-memory-dump-then-scan step is needed, and no
    external byte extraction is required, since Volatility already knows
    how to walk each process's virtual address space.

    rules_path must be a single .yar file (Volatility's yara_file option
    does not accept a directory); see
    detection.yara_scanner.build_combined_rules_file() for combining a
    rules directory into one file.

    Column names below are taken directly from each plugin's TreeGrid
    definition (windows.vadyarascan.VadYaraScan includes ImageFileName;
    linux.vmayarascan.VmaYaraScan does not expose a process name column at
    all, only Offset/PID/Rule/Component, so process_name is None on Linux).
    """
    os_family = os_family or _detect_os_family(image_path)
    plugin = "windows.vadyarascan.VadYaraScan" if os_family == "windows" else "linux.vmayarascan.VmaYaraScan"
    rows = _run_plugin(image_path, plugin, extra_args=["--yara-file", rules_path])

    matches = []
    for row in rows:
        matches.append(YaraMatchInfo(
            pid=row.get("PID"),
            process_name=row.get("ImageFileName"),  # not present on Linux; stays None there
            rule_name=row.get("Rule") or "unknown",
            address=_format_hex(row.get("Offset")),
        ))
    return matches


def list_malfind_hits(image_path: str, os_family: str = None) -> list:
    """
    Detect anomalous memory regions indicative of code injection/process
    hollowing (SRS FR-8) via Volatility 3's malfind plugin, which flags
    private, executable memory regions with no backing file on disk.

    Column names differ slightly between OS families: Windows uses
    "Start VPN"; Linux uses "Start" (and "Path" instead of "Process" isn't
    used here since "Process" is present on both).
    """
    os_family = os_family or _detect_os_family(image_path)
    plugin = "windows.malfind.Malfind" if os_family == "windows" else "linux.malfind.Malfind"
    rows = _run_plugin(image_path, plugin)

    hits = []
    for row in rows:
        hits.append(MalfindHit(
            pid=row.get("PID"),
            process_name=row.get("Process"),
            address=_format_hex(row.get("Start VPN") if row.get("Start VPN") is not None else row.get("Start")),
            protection=row.get("Protection"),
        ))
    return hits


def extract_system_metadata(image_path: str, os_family: str = None) -> dict:
    """
    Extract additional forensic system metadata beyond the basic OS profile
    string (SRS "Other Requirements": investigators need system context
    like OS build, architecture, and system timestamps, not just a
    profile label).

    For Windows, this is all data windows.info.Info already returns but
    that acquisition.profile_detector.detect_os_profile discards after
    building its one-line profile string -- captured here as a structured
    dict instead. Note: hostname and timezone are NOT included -- neither
    is part of windows.info.Info's output; obtaining them would need an
    additional registry-reading plugin (e.g. windows.registry.printkey
    against HKLM\\SYSTEM\\...\\ComputerName / TimeZoneInformation), which
    is not currently wired in.

    For Linux, returns the raw kernel banner string, which already embeds
    build date and architecture information in one line.

    Best-effort: returns an empty dict (never raises) if the underlying
    plugin is unavailable, since this is supplementary context, not
    essential to the analysis.
    """
    os_family = os_family or _detect_os_family(image_path)

    if os_family == "windows":
        try:
            rows = _run_plugin(image_path, "windows.info.Info")
        except VolatilityError:
            return {}
        info = {row.get("Variable"): row.get("Value") for row in rows}
        metadata = {}
        for key, label in [
            ("NTBuildLab", "build_lab"),
            ("CSDVersion", "service_pack"),
            ("SystemTime", "system_time"),
            ("NtSystemRoot", "system_root"),
            ("NtProductType", "product_type"),
            ("KeNumberProcessors", "processor_count"),
            ("PE TimeDateStamp", "kernel_timestamp"),
        ]:
            if info.get(key) is not None:
                metadata[label] = info[key]
        return metadata

    try:
        rows = _run_plugin(image_path, "banners.Banners")
    except VolatilityError:
        return {}
    if rows and rows[0].get("Banner"):
        return {"kernel_banner": rows[0]["Banner"]}
    return {}


def run_full_analysis(image_path: str, yara_rules_path: str = None) -> dict:
    """
    Convenience entry point used by the API layer's /analyze endpoint.

    Runs the full extraction pipeline and returns a dict ready to be
    persisted by the Case/Data Management layer.

    Process enumeration (pslist) is the one essential step -- without it
    there's nothing to report, so its failure propagates and fails the case.
    Every other step (psscan, modules, network connections, YARA, malfind)
    is best-effort: some Volatility 3 plugins are known to be unreliable on
    older OS versions (e.g. windows.netscan.NetScan against Windows XP
    builds), and a single plugin crashing should degrade the results, not
    discard an otherwise complete analysis. Non-fatal failures are collected
    into "warnings" so the case can still complete with a clear record of
    what was skipped.

    yara_rules_path: optional path to a single combined .yar file. If
    omitted, YARA scanning is skipped entirely (e.g. no rules configured).
    """
    os_family = _detect_os_family(image_path)
    warnings = []

    processes = list_processes(image_path, os_family)  # essential; let this raise on failure

    try:
        processes_scan = scan_processes(image_path, os_family)
    except VolatilityError as exc:
        warnings.append(f"Hidden-process scan (psscan) unavailable: {exc}")
        processes_scan = processes  # no hidden-process comparison possible, but analysis continues

    try:
        modules = list_dlls(image_path, os_family)
    except VolatilityError as exc:
        warnings.append(f"Module/DLL listing unavailable: {exc}")
        modules = []

    try:
        connections = list_network_connections(image_path, os_family)
    except VolatilityError as exc:
        warnings.append(f"Network connection extraction unavailable: {exc}")
        connections = []

    yara_matches = []
    if yara_rules_path:
        try:
            yara_matches = run_yara_scan(image_path, yara_rules_path, os_family)
        except VolatilityError as exc:
            warnings.append(f"YARA scan unavailable: {exc}")

    try:
        malfind_hits = list_malfind_hits(image_path, os_family)
    except VolatilityError as exc:
        warnings.append(f"Anomalous memory region scan (malfind) unavailable: {exc}")
        malfind_hits = []

    # Cross-reference each process with its own executable's full path
    # (FR-8 masquerading detection -- see detection.heuristics.check_masquerading_path).
    # Best-effort: if modules didn't load, processes simply keep image_path=None
    # and the masquerade check silently has nothing to flag, rather than failing.
    _attach_image_paths(processes, modules)
    _attach_image_paths(processes_scan, modules)

    try:
        system_metadata = extract_system_metadata(image_path, os_family)
    except VolatilityError as exc:
        warnings.append(f"System metadata extraction unavailable: {exc}")
        system_metadata = {}

    return {
        "os_family": os_family,
        "processes": processes,
        "processes_scan": processes_scan,
        "modules": modules,
        "connections": connections,
        "yara_matches": yara_matches,
        "malfind_hits": malfind_hits,
        "system_metadata": system_metadata,
        "warnings": warnings,
    }
