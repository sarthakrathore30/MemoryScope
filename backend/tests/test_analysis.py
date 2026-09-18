"""
Unit tests for the Analysis Module, mapped to TESTING_PLAN.docx:

  TC-AN-01: Process enumeration -> correct PID/PPID
  TC-AN-02: DLL/module listing -> correct DLL names and base addresses
  TC-AN-03: Process tree reconstruction -> correct parent-child relationships
  TC-AN-04: Network connection extraction -> correct IP/port/state values

Volatility3 plugin calls are mocked at the subprocess boundary since running
against a real multi-GB memory image is out of scope for a fast unit test
suite (the real Volatility3 install is exercised separately in integration/
manual testing against sample images per the Test Environment section of the
Testing Plan).
"""
import json
import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis import volatility_wrapper as vw


def _mock_completed_process(stdout_obj, returncode=0):
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = json.dumps(stdout_obj)
    proc.stderr = ""
    return proc


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_tc_an_01_process_enumeration(mock_run, mock_which):
    mock_run.return_value = _mock_completed_process([
        {"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2024-01-01"},
        {"PID": 620, "PPID": 4, "ImageFileName": "smss.exe", "CreateTime": "2024-01-01"},
    ])

    processes = vw.list_processes("fake.raw", os_family="windows")

    assert len(processes) == 2
    assert processes[0].pid == 4 and processes[0].ppid == 0
    assert processes[1].pid == 620 and processes[1].ppid == 4
    assert processes[1].process_name == "smss.exe"


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_tc_an_02_dll_module_listing(mock_run, mock_which):
    mock_run.return_value = _mock_completed_process([
        {"PID": 620, "Name": "ntdll.dll", "Base": 0x7ffabc0000, "Size": 2027520},
    ])

    modules = vw.list_dlls("fake.raw", os_family="windows")

    assert len(modules) == 1
    assert modules[0].dll_name == "ntdll.dll"
    assert modules[0].base_address == "0x7ffabc0000"
    assert modules[0].module_size == 2027520


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_tc_an_03_process_tree_reconstruction(mock_run, mock_which):
    mock_run.return_value = _mock_completed_process([
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 620, "PPID": 4, "ImageFileName": "smss.exe"},
        {"PID": 700, "PPID": 620, "ImageFileName": "csrss.exe"},
    ])

    tree = vw.get_process_tree("fake.raw", os_family="windows")

    by_pid = {p.pid: p for p in tree}
    assert by_pid[700].ppid == 620
    assert by_pid[620].ppid == 4
    assert by_pid[4].ppid == 0


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_tc_an_04_network_connection_extraction(mock_run, mock_which):
    mock_run.return_value = _mock_completed_process([
        {
            "PID": 1234, "LocalAddr": "192.168.1.10", "LocalPort": 445,
            "ForeignAddr": "192.168.1.20", "ForeignPort": 51000,
            "Proto": "TCP", "State": "ESTABLISHED",
        },
    ])

    conns = vw.list_network_connections("fake.raw", os_family="windows")

    assert len(conns) == 1
    c = conns[0]
    assert c.local_ip == "192.168.1.10" and c.local_port == 445
    assert c.remote_ip == "192.168.1.20" and c.remote_port == 51000
    assert c.state == "ESTABLISHED"


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_network_connection_extraction_linux_sockstat_columns(mock_run, mock_which):
    """
    Regression test: linux.sockstat.Sockstat's real column is 'Proto', not
    'Protocol' -- caught by checking against Volatility3's actual installed
    plugin source rather than assuming column names.
    """
    mock_run.return_value = _mock_completed_process([
        {
            "PID": 5678, "Source Addr": "10.0.0.5", "Source Port": "4444",
            "Destination Addr": "203.0.113.9", "Destination Port": "8080",
            "Proto": "TCP", "State": "ESTABLISHED",
        },
    ])

    conns = vw.list_network_connections("fake.raw", os_family="linux")

    assert len(conns) == 1
    assert conns[0].protocol == "TCP"
    assert conns[0].local_ip == "10.0.0.5"
    assert conns[0].remote_ip == "203.0.113.9"


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_scan_processes_linux_uses_real_psscan_plugin(mock_run, mock_which):
    """
    Regression test: scan_processes() previously reused linux.pslist.PsList
    for the Linux 'psscan' step (there is a real linux.psscan.PsScan plugin),
    which made hidden-process detection completely non-functional on Linux
    since comparing pslist against itself always yields zero differences.
    """
    mock_run.return_value = _mock_completed_process([
        {"PID": 1337, "PPID": 1, "COMM": "hidden_proc", "OFFSET (P)": "0xdead"},
    ])

    procs = vw.scan_processes("fake.raw", os_family="linux")

    assert len(procs) == 1
    assert procs[0].pid == 1337
    assert procs[0].process_name == "hidden_proc"
    assert procs[0].seen_in_psscan is True

    called_cmd = mock_run.call_args[0][0]
    assert "linux.psscan.PsScan" in called_cmd
    assert "linux.pslist.PsList" not in called_cmd


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_list_processes_linux_creation_time_column(mock_run, mock_which):
    """
    Regression test: linux.pslist.PsList's real timestamp column is
    'CREATION TIME', not 'CreateTime' (that's the Windows column name).
    """
    mock_run.return_value = _mock_completed_process([
        {"PID": 1, "PPID": 0, "COMM": "init", "CREATION TIME": "2024-01-01T00:00:00"},
    ])

    procs = vw.list_processes("fake.raw", os_family="linux")

    assert procs[0].create_time == "2024-01-01T00:00:00"


@patch("analysis.volatility_wrapper.shutil.which", return_value=None)
def test_missing_vol_binary_raises(mock_which):
    try:
        vw.list_processes("fake.raw", os_family="windows")
        assert False, "expected VolatilityError"
    except vw.VolatilityError as e:
        assert "not found on PATH" in str(e)


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_detect_os_family_linux_uses_correct_banners_plugin_name(mock_run, mock_which):
    """
    Regression test for a real bug: banners.Banners is registered at the
    top level (volatility3/framework/plugins/banners.py, not under linux/)
    -- "linux.banners.Banners" does not exist as a plugin and always fails,
    which silently made _detect_os_family raise for every Linux image.
    """
    call_log = []

    def fake_run(cmd, capture_output, text, timeout):
        call_log.append(cmd)
        plugin = cmd[-1]
        proc = MagicMock()
        if plugin == "windows.info.Info":
            proc.returncode = 1
            proc.stdout = ""
            proc.stderr = "not a windows image"
        elif plugin == "banners.Banners":
            proc.returncode = 0
            proc.stdout = json.dumps([{"Offset": 4096, "Banner": "Linux version 5.4.0"}])
            proc.stderr = ""
        else:
            proc.returncode = 1
            proc.stdout = ""
            proc.stderr = "unexpected plugin"
        return proc

    mock_run.side_effect = fake_run

    family = vw._detect_os_family("fake.raw")

    assert family == "linux"
    called_plugins = [cmd[-1] for cmd in call_log]
    assert "banners.Banners" in called_plugins
    assert "linux.banners.Banners" not in called_plugins


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_plugin_failure_raises_volatility_error(mock_run, mock_which):
    proc = MagicMock()
    proc.returncode = 1
    proc.stdout = ""
    proc.stderr = "Unsatisfied requirement plugins.PsList.primary"
    mock_run.return_value = proc

    try:
        vw.list_processes("fake.raw", os_family="windows")
        assert False, "expected VolatilityError"
    except vw.VolatilityError as e:
        assert "failed" in str(e)


# ---------------------------------------------------------------------------
# run_full_analysis resilience: one crashing plugin (e.g. netscan on an old
# Windows build) should degrade gracefully, not fail the whole analysis.
# ---------------------------------------------------------------------------

def test_run_full_analysis_survives_netscan_crash(monkeypatch):
    """
    Reproduces a real observed failure: windows.netscan.NetScan can crash
    with an unhandled exception in Volatility's own renderer against certain
    older Windows builds (e.g. XP). Network extraction failing should not
    sink process/module extraction or the overall case.
    """
    monkeypatch.setattr(vw, "_detect_os_family", lambda path: "windows")
    monkeypatch.setattr(vw, "list_processes", lambda path, os_family: [
        vw.ProcessInfo(pid=4, ppid=0, process_name="System")
    ])
    monkeypatch.setattr(vw, "scan_processes", lambda path, os_family: [
        vw.ProcessInfo(pid=4, ppid=0, process_name="System")
    ])
    monkeypatch.setattr(vw, "list_dlls", lambda path, os_family: [])
    monkeypatch.setattr(vw, "list_malfind_hits", lambda path, os_family: [])

    def failing_netscan(path, os_family):
        raise vw.VolatilityError("Plugin 'windows.netscan.NetScan' failed: <renderer crash traceback>")
    monkeypatch.setattr(vw, "list_network_connections", failing_netscan)

    result = vw.run_full_analysis("fake.raw")

    assert result["os_family"] == "windows"
    assert len(result["processes"]) == 1
    assert result["connections"] == []
    assert any("Network connection extraction unavailable" in w for w in result["warnings"])


def test_run_full_analysis_essential_process_list_failure_still_raises(monkeypatch):
    """Unlike optional steps, a pslist failure has nothing to degrade to and must still fail."""
    monkeypatch.setattr(vw, "_detect_os_family", lambda path: "windows")

    def failing_pslist(path, os_family):
        raise vw.VolatilityError("Plugin 'windows.pslist.PsList' failed")
    monkeypatch.setattr(vw, "list_processes", failing_pslist)

    try:
        vw.run_full_analysis("fake.raw")
        assert False, "expected VolatilityError to propagate"
    except vw.VolatilityError as e:
        assert "pslist" in str(e)


# ---------------------------------------------------------------------------
# _format_hex: Volatility's JSON renderer serializes format_hints.Hex fields
# (addresses/offsets) as plain decimal integers, not hex strings, since Hex
# is just an int subclass with no special-case JSON encoding. This must be
# reformatted back into conventional 0x-prefixed hex for forensic display.
# ---------------------------------------------------------------------------

def test_format_hex_converts_raw_int_to_hex_string():
    assert vw._format_hex(4096) == "0x1000"
    assert vw._format_hex(0x7ffabc0000) == "0x7ffabc0000"
    assert vw._format_hex(0) == "0x0"


def test_format_hex_handles_none_and_empty():
    assert vw._format_hex(None) == ""
    assert vw._format_hex("") == ""


def test_format_hex_passes_through_unexpected_string_type():
    assert vw._format_hex("already-a-string") == "already-a-string"


# ---------------------------------------------------------------------------
# extract_system_metadata: forensic metadata beyond the one-line OS profile
# string (real gap found via review: this data was already being returned
# by windows.info.Info and simply discarded).
# ---------------------------------------------------------------------------

@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_extract_system_metadata_windows(mock_run, mock_which):
    mock_run.return_value = _mock_completed_process([
        {"Variable": "NTBuildLab", "Value": "19041.1.amd64fre.vb_release.191206-1406"},
        {"Variable": "CSDVersion", "Value": 0},
        {"Variable": "SystemTime", "Value": "2024-01-01 12:00:00"},
        {"Variable": "NtSystemRoot", "Value": r"C:\WINDOWS"},
        {"Variable": "NtProductType", "Value": "NtProductWinNt"},
        {"Variable": "KeNumberProcessors", "Value": 4},
        {"Variable": "PE TimeDateStamp", "Value": "Fri Dec 6 14:06:00 2019"},
    ])

    metadata = vw.extract_system_metadata("fake.raw", os_family="windows")

    assert metadata["build_lab"] == "19041.1.amd64fre.vb_release.191206-1406"
    assert metadata["system_time"] == "2024-01-01 12:00:00"
    assert metadata["system_root"] == r"C:\WINDOWS"
    assert metadata["processor_count"] == 4
    assert metadata["kernel_timestamp"] == "Fri Dec 6 14:06:00 2019"


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_extract_system_metadata_linux_returns_banner(mock_run, mock_which):
    mock_run.return_value = _mock_completed_process([
        {"Offset": 4096, "Banner": "Linux version 5.4.0-42-generic (buildd@lgw01) SMP"},
    ])

    metadata = vw.extract_system_metadata("fake.raw", os_family="linux")

    assert metadata["kernel_banner"] == "Linux version 5.4.0-42-generic (buildd@lgw01) SMP"


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_extract_system_metadata_returns_empty_dict_on_failure(mock_run, mock_which):
    """Best-effort: metadata extraction failing must not raise -- it's
    supplementary context, not essential to the analysis."""
    proc = MagicMock()
    proc.returncode = 1
    proc.stdout = ""
    proc.stderr = "plugin failed"
    mock_run.return_value = proc

    metadata = vw.extract_system_metadata("fake.raw", os_family="windows")

    assert metadata == {}


def test_run_full_analysis_includes_system_metadata(monkeypatch):
    monkeypatch.setattr(vw, "_detect_os_family", lambda path: "windows")
    monkeypatch.setattr(vw, "list_processes", lambda path, os_family: [
        vw.ProcessInfo(pid=4, ppid=0, process_name="System")
    ])
    monkeypatch.setattr(vw, "scan_processes", lambda path, os_family: [
        vw.ProcessInfo(pid=4, ppid=0, process_name="System")
    ])
    monkeypatch.setattr(vw, "list_dlls", lambda path, os_family: [])
    monkeypatch.setattr(vw, "list_network_connections", lambda path, os_family: [])
    monkeypatch.setattr(vw, "list_malfind_hits", lambda path, os_family: [])
    monkeypatch.setattr(vw, "extract_system_metadata", lambda path, os_family: {"system_root": r"C:\WINDOWS"})

    result = vw.run_full_analysis("fake.raw")

    assert result["system_metadata"] == {"system_root": r"C:\WINDOWS"}


# ---------------------------------------------------------------------------
# _attach_image_paths: cross-referencing processes with their own exe path
# (used by detection.heuristics.check_masquerading_path, FR-8)
# ---------------------------------------------------------------------------

def test_attach_image_paths_matches_process_to_its_own_module():
    processes = [
        vw.ProcessInfo(pid=824, ppid=652, process_name="svchost.exe"),
    ]
    modules = [
        vw.ModuleInfo(pid=824, dll_name="svchost.exe", path=r"C:\Windows\System32\svchost.exe"),
        vw.ModuleInfo(pid=824, dll_name="ntdll.dll", path=r"C:\Windows\System32\ntdll.dll"),
        vw.ModuleInfo(pid=824, dll_name="kernel32.dll", path=r"C:\Windows\System32\kernel32.dll"),
    ]

    vw._attach_image_paths(processes, modules)

    assert processes[0].image_path == r"C:\Windows\System32\svchost.exe"


def test_attach_image_paths_case_insensitive_filename_match():
    processes = [vw.ProcessInfo(pid=1, ppid=0, process_name="SVCHOST.EXE")]
    modules = [vw.ModuleInfo(pid=1, dll_name="svchost.exe", path=r"C:\Windows\System32\svchost.exe")]

    vw._attach_image_paths(processes, modules)

    assert processes[0].image_path == r"C:\Windows\System32\svchost.exe"


def test_attach_image_paths_leaves_none_when_no_match_found():
    processes = [vw.ProcessInfo(pid=1, ppid=0, process_name="svchost.exe")]
    modules = [vw.ModuleInfo(pid=1, dll_name="ntdll.dll", path=r"C:\Windows\System32\ntdll.dll")]

    vw._attach_image_paths(processes, modules)

    assert processes[0].image_path is None


def test_attach_image_paths_handles_process_with_no_modules():
    processes = [vw.ProcessInfo(pid=999, ppid=0, process_name="lonely.exe")]

    vw._attach_image_paths(processes, modules=[])

    assert processes[0].image_path is None


# ---------------------------------------------------------------------------
# Real YARA scanning (windows.vadyarascan / linux.vmayarascan) and malfind
# ---------------------------------------------------------------------------

@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_run_yara_scan_windows(mock_run, mock_which):
    mock_run.return_value = _mock_completed_process([
        {"Offset": 0x7ffa0000, "PID": 6688, "CreateTime": "2024-01-01", "PPID": 812,
         "ImageFileName": "update_helper.exe", "SessionId": 0, "Threads": 1,
         "Rule": "Suspicious_Reflective_DLL_Loader", "Component": "vad"},
    ])

    matches = vw.run_yara_scan("fake.raw", "/tmp/combined.yar", os_family="windows")

    assert len(matches) == 1
    assert matches[0].pid == 6688
    assert matches[0].process_name == "update_helper.exe"
    assert matches[0].rule_name == "Suspicious_Reflective_DLL_Loader"
    assert matches[0].address == "0x7ffa0000"

    # Confirm the correct plugin and --yara-file flag were used.
    called_cmd = mock_run.call_args[0][0]
    assert "windows.vadyarascan.VadYaraScan" in called_cmd
    assert "--yara-file" in called_cmd
    assert "/tmp/combined.yar" in called_cmd


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_run_yara_scan_linux_uses_vmayarascan(mock_run, mock_which):
    mock_run.return_value = _mock_completed_process([])

    vw.run_yara_scan("fake.raw", "/tmp/combined.yar", os_family="linux")

    called_cmd = mock_run.call_args[0][0]
    assert "linux.vmayarascan.VmaYaraScan" in called_cmd


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_run_yara_scan_linux_has_no_process_name_column(mock_run, mock_which):
    """linux.vmayarascan.VmaYaraScan's TreeGrid has no ImageFileName column at
    all (only Offset/PID/Rule/Component) -- process_name must stay None
    rather than crashing or fabricating a value."""
    mock_run.return_value = _mock_completed_process([
        {"Offset": 0x1000, "PID": 1234, "Rule": "Some_Rule", "Component": "vma"},
    ])

    matches = vw.run_yara_scan("fake.raw", "/tmp/combined.yar", os_family="linux")

    assert len(matches) == 1
    assert matches[0].pid == 1234
    assert matches[0].process_name is None
    assert matches[0].rule_name == "Some_Rule"


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_run_yara_scan_no_matches_returns_empty_list(mock_run, mock_which):
    mock_run.return_value = _mock_completed_process([])

    matches = vw.run_yara_scan("fake.raw", "/tmp/combined.yar", os_family="windows")

    assert matches == []


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_list_malfind_hits(mock_run, mock_which):
    mock_run.return_value = _mock_completed_process([
        {"PID": 6688, "Process": "update_helper.exe", "Start VPN": 0x2a0000, "Protection": "PAGE_EXECUTE_READWRITE"},
    ])

    hits = vw.list_malfind_hits("fake.raw", os_family="windows")

    assert len(hits) == 1
    assert hits[0].pid == 6688
    assert hits[0].protection == "PAGE_EXECUTE_READWRITE"

    called_cmd = mock_run.call_args[0][0]
    assert "windows.malfind.Malfind" in called_cmd


@patch("analysis.volatility_wrapper.shutil.which", return_value="/usr/bin/vol")
@patch("analysis.volatility_wrapper.subprocess.run")
def test_list_malfind_hits_linux_uses_start_not_start_vpn(mock_run, mock_which):
    """Linux's malfind TreeGrid column is 'Start', not 'Start VPN' like Windows."""
    mock_run.return_value = _mock_completed_process([
        {"PID": 1234, "Process": "evil", "Start": 0x400000, "End": 0x401000,
         "Path": "", "Protection": "rwx"},
    ])

    hits = vw.list_malfind_hits("fake.raw", os_family="linux")

    assert len(hits) == 1
    assert hits[0].pid == 1234
    assert hits[0].address == "0x400000"
    assert hits[0].protection == "rwx"

    called_cmd = mock_run.call_args[0][0]
    assert "linux.malfind.Malfind" in called_cmd


def test_run_full_analysis_includes_yara_and_malfind_when_rules_path_given(monkeypatch):
    monkeypatch.setattr(vw, "_detect_os_family", lambda path: "windows")
    monkeypatch.setattr(vw, "list_processes", lambda path, os_family: [
        vw.ProcessInfo(pid=6688, ppid=812, process_name="update_helper.exe")
    ])
    monkeypatch.setattr(vw, "scan_processes", lambda path, os_family: [
        vw.ProcessInfo(pid=6688, ppid=812, process_name="update_helper.exe")
    ])
    monkeypatch.setattr(vw, "list_dlls", lambda path, os_family: [])
    monkeypatch.setattr(vw, "list_network_connections", lambda path, os_family: [])

    fake_match = vw.YaraMatchInfo(pid=6688, process_name="update_helper.exe", rule_name="Evil_Rule", address="0x1000")
    monkeypatch.setattr(vw, "run_yara_scan", lambda path, rules_path, os_family: [fake_match])

    fake_hit = vw.MalfindHit(pid=6688, process_name="update_helper.exe", address="0x2000", protection="PAGE_EXECUTE_READWRITE")
    monkeypatch.setattr(vw, "list_malfind_hits", lambda path, os_family: [fake_hit])

    result = vw.run_full_analysis("fake.raw", yara_rules_path="/tmp/combined.yar")

    assert result["yara_matches"] == [fake_match]
    assert result["malfind_hits"] == [fake_hit]
    assert result["warnings"] == []


def test_run_full_analysis_skips_yara_when_no_rules_path(monkeypatch):
    """yara_rules_path=None (no rules configured) should skip YARA cleanly, not error."""
    monkeypatch.setattr(vw, "_detect_os_family", lambda path: "windows")
    monkeypatch.setattr(vw, "list_processes", lambda path, os_family: [
        vw.ProcessInfo(pid=4, ppid=0, process_name="System")
    ])
    monkeypatch.setattr(vw, "scan_processes", lambda path, os_family: [
        vw.ProcessInfo(pid=4, ppid=0, process_name="System")
    ])
    monkeypatch.setattr(vw, "list_dlls", lambda path, os_family: [])
    monkeypatch.setattr(vw, "list_network_connections", lambda path, os_family: [])
    monkeypatch.setattr(vw, "list_malfind_hits", lambda path, os_family: [])

    result = vw.run_full_analysis("fake.raw", yara_rules_path=None)

    assert result["yara_matches"] == []
    assert not any("YARA" in w for w in result["warnings"])
