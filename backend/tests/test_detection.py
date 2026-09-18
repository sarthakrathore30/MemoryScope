"""
Unit tests for the Detection Module, mapped to TESTING_PLAN.docx:

  TC-DT-01: Hidden process detection -> is_hidden = true
  TC-DT-02: YARA rule match -> reported with correct rule name and process association
  TC-DT-03: YARA no-match case -> no false-positive matches reported
  TC-DT-04: Suspicious heuristic flag -> correct suspicion_reason
  TC-DT-05: IOC extraction -> IOC records correctly created and linked to case_id
"""
import os
import sys

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from db.database import Base
from db import models  # noqa: F401
from db.models import Case, IOC, ProcessRecord

from analysis.volatility_wrapper import ProcessInfo, NetworkConnectionInfo, YaraMatchInfo, MalfindHit
from detection.hidden_process import find_hidden_processes, is_hidden
from detection.heuristics import evaluate_all
from detection.yara_scanner import load_rules, scan_data, build_combined_rules_file, YaraScanError
from detection.ioc_extractor import extract_from_yara_match_infos, extract_from_malfind_hits
from detection import service as detection_service


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


# ---------------------------------------------------------------------------
# TC-DT-01: Hidden process detection
# ---------------------------------------------------------------------------

def test_tc_dt_01_hidden_process_detected():
    pslist = [
        ProcessInfo(pid=4, ppid=0, process_name="System"),
        ProcessInfo(pid=620, ppid=4, process_name="smss.exe"),
    ]
    # psscan finds an extra process (1337) that pslist did not enumerate.
    psscan = [
        ProcessInfo(pid=4, ppid=0, process_name="System"),
        ProcessInfo(pid=620, ppid=4, process_name="smss.exe"),
        ProcessInfo(pid=1337, ppid=620, process_name="evil.exe"),
    ]

    merged = find_hidden_processes(pslist, psscan)
    hidden = [p for p in merged if is_hidden(p)]

    assert len(hidden) == 1
    assert hidden[0].pid == 1337
    assert hidden[0].process_name == "evil.exe"


def test_no_hidden_processes_when_lists_match():
    pslist = [ProcessInfo(pid=4, ppid=0, process_name="System")]
    psscan = [ProcessInfo(pid=4, ppid=0, process_name="System")]

    merged = find_hidden_processes(pslist, psscan)
    hidden = [p for p in merged if is_hidden(p)]

    assert hidden == []


# ---------------------------------------------------------------------------
# TC-DT-02 / TC-DT-03: YARA scanning
# ---------------------------------------------------------------------------

def test_tc_dt_02_yara_rule_match_reported():
    rules = load_rules()  # loads yara_rules/sample_rules.yar
    data = b"some memory content containing mimikatz artifacts sekurlsa::logonpasswords"

    matches = scan_data(rules, data)

    assert len(matches) >= 1
    rule_names = {m.rule_name for m in matches}
    assert "Suspicious_Mimikatz_Strings" in rule_names


def test_tc_dt_03_yara_no_match_case():
    rules = load_rules()
    benign_data = b"just a normal notepad.exe process with nothing suspicious here at all"

    matches = scan_data(rules, benign_data)

    assert matches == []


# ---------------------------------------------------------------------------
# TC-DT-04: Suspicious heuristic flag
# ---------------------------------------------------------------------------

def test_tc_dt_04_suspicious_heuristic_flag_orphaned_svchost():
    processes = [
        ProcessInfo(pid=4, ppid=0, process_name="System"),
        # svchost.exe running under System instead of services.exe -> unusual parent.
        ProcessInfo(pid=9999, ppid=4, process_name="svchost.exe"),
    ]

    results = evaluate_all(processes)
    flagged = [r for r in results if r.suspicious]

    assert len(flagged) == 1
    assert flagged[0].pid == 9999
    assert "svchost.exe" in flagged[0].reason
    assert "Unusual parent" in flagged[0].reason


def test_normal_process_lineage_not_flagged():
    processes = [
        ProcessInfo(pid=4, ppid=0, process_name="System"),
        ProcessInfo(pid=500, ppid=4, process_name="smss.exe"),
        ProcessInfo(pid=600, ppid=500, process_name="wininit.exe"),
        ProcessInfo(pid=700, ppid=600, process_name="services.exe"),
        ProcessInfo(pid=800, ppid=700, process_name="svchost.exe"),
    ]

    results = evaluate_all(processes)
    flagged = [r for r in results if r.suspicious]

    assert flagged == []


def test_windows_xp_lineage_not_flagged_as_false_positive():
    """
    Windows XP has no wininit.exe (introduced in Vista for Session 0
    isolation) -- winlogon.exe legitimately spawns services.exe and
    lsass.exe directly on XP. This must not be flagged as suspicious.
    Regression test for a real false positive observed against a genuine
    Windows XP SP2 memory image (the classic Cridex sample).
    """
    processes = [
        ProcessInfo(pid=4, ppid=0, process_name="System"),
        ProcessInfo(pid=368, ppid=4, process_name="smss.exe"),
        ProcessInfo(pid=608, ppid=368, process_name="winlogon.exe"),
        ProcessInfo(pid=652, ppid=608, process_name="services.exe"),
        ProcessInfo(pid=664, ppid=608, process_name="lsass.exe"),
        ProcessInfo(pid=824, ppid=652, process_name="svchost.exe"),
    ]

    results = evaluate_all(processes)
    flagged = [r for r in results if r.suspicious]

    assert flagged == []


def test_lsass_under_genuinely_wrong_parent_still_flagged():
    """
    Broadening accepted parents to (wininit.exe OR winlogon.exe) for
    services.exe/lsass.exe must not blind the heuristic to real anomalies --
    a classic lsass.exe process-injection indicator (spawned by something
    that is neither) should still be caught.
    """
    processes = [
        ProcessInfo(pid=4, ppid=0, process_name="System"),
        ProcessInfo(pid=1484, ppid=4, process_name="explorer.exe"),
        ProcessInfo(pid=6000, ppid=1484, process_name="lsass.exe"),  # injected under explorer.exe
    ]

    results = evaluate_all(processes)
    flagged = {r.pid: r for r in results if r.suspicious}

    assert 6000 in flagged
    assert "Unusual parent" in flagged[6000].reason


def test_ppid_zero_spoofing_flagged():
    processes = [
        ProcessInfo(pid=4, ppid=0, process_name="System"),  # legitimate root, not flagged
        ProcessInfo(pid=6666, ppid=0, process_name="malware.exe"),  # spoofed root parent
    ]

    results = evaluate_all(processes)
    by_pid = {r.pid: r for r in results}

    assert by_pid[4].suspicious is False
    assert by_pid[6666].suspicious is True
    assert "Spoofed root parent" in by_pid[6666].reason


def test_linux_init_process_ppid_zero_not_flagged():
    """
    Regression test for a real false positive found via live end-to-end
    testing against a simulated Linux image: PID 1 (systemd or init,
    depending on the distro's init system) legitimately has PPID 0 on
    Linux -- the direct analogue of Windows' System process. This must not
    be flagged as a spoofed root parent.
    """
    processes = [
        ProcessInfo(pid=1, ppid=0, process_name="systemd"),
        ProcessInfo(pid=1, ppid=0, process_name="init"),
    ]

    results = evaluate_all([processes[0]])
    assert results[0].suspicious is False

    results = evaluate_all([processes[1]])
    assert results[0].suspicious is False


def test_self_parented_process_flagged():
    processes = [
        ProcessInfo(pid=7777, ppid=7777, process_name="weird.exe"),
    ]

    results = evaluate_all(processes)

    assert results[0].suspicious is True
    assert "Self-parented process" in results[0].reason


def test_orphaned_process_missing_parent_flagged():
    processes = [
        ProcessInfo(pid=100, ppid=99999, process_name="orphan.exe"),  # 99999 doesn't exist
    ]

    results = evaluate_all(processes)

    assert results[0].suspicious is True
    assert "Orphaned process" in results[0].reason
    assert "non-existent parent PID 99999" in results[0].reason


def test_explorer_exe_missing_userinit_parent_not_flagged():
    """
    Regression test for a real false positive observed against a genuine
    Windows XP memory image: explorer.exe's parent (userinit.exe) legitimately
    exits immediately after spawning the shell, so its PID never resolves in
    a snapshot. This is expected on virtually every real Windows image and
    must not be flagged as an orphaned/suspicious process.
    """
    processes = [
        ProcessInfo(pid=1484, ppid=1464, process_name="explorer.exe"),  # 1464 (userinit.exe) already exited
    ]

    results = evaluate_all(processes)

    assert results[0].suspicious is False


def test_explorer_exe_impersonator_still_caught_by_other_heuristics():
    """
    The explorer.exe orphan exception must not become a blanket free pass --
    other heuristics (self-parenting, PPID-zero spoofing) should still catch
    a genuinely malicious process merely named explorer.exe.
    """
    processes = [
        ProcessInfo(pid=6666, ppid=6666, process_name="explorer.exe"),  # self-parented impersonator
    ]

    results = evaluate_all(processes)

    assert results[0].suspicious is True
    assert "Self-parented process" in results[0].reason


def test_hidden_process_always_flagged_suspicious_even_with_normal_lineage():
    """A process with an innocuous name/parent must still be flagged if hidden."""
    processes = [
        ProcessInfo(pid=4, ppid=0, process_name="System"),
        ProcessInfo(pid=9001, ppid=4, process_name="totally_normal_looking.exe"),
    ]
    hidden_pids = {9001}

    results = evaluate_all(processes, hidden_pids=hidden_pids)
    by_pid = {r.pid: r for r in results}

    assert by_pid[9001].suspicious is True
    assert "Hidden/unlinked process" in by_pid[9001].reason


def test_multiple_triggered_reasons_are_aggregated():
    """A process tripping more than one heuristic should report all reasons, not just the first."""
    processes = [
        ProcessInfo(pid=1, ppid=0, process_name="notepad.exe"),
        # svchost.exe with a wrong parent AND flagged hidden -> two distinct reasons expected.
        ProcessInfo(pid=800, ppid=1, process_name="svchost.exe"),
    ]
    hidden_pids = {800}

    results = evaluate_all(processes, hidden_pids=hidden_pids)
    by_pid = {r.pid: r for r in results}

    assert by_pid[800].suspicious is True
    assert "Hidden/unlinked process" in by_pid[800].reason
    assert "Unusual parent" in by_pid[800].reason
    # Both reasons must be present, joined together, not just the first match.
    assert by_pid[800].reason.count(";") >= 1


# ---------------------------------------------------------------------------
# TC-DT-05: IOC extraction and case linkage
# ---------------------------------------------------------------------------

def test_tc_dt_05_ioc_extraction_and_linkage(db_session):
    case = Case(case_name="Detection Test Case", memory_image_ref="/tmp/fake.raw", status="analyzing")
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)

    pslist = [
        ProcessInfo(pid=4, ppid=0, process_name="System"),
        ProcessInfo(pid=9999, ppid=4, process_name="svchost.exe"),  # will be flagged suspicious
    ]
    psscan = pslist + [ProcessInfo(pid=1337, ppid=9999, process_name="evil.exe")]  # hidden
    connections = [
        NetworkConnectionInfo(pid=1337, local_ip="10.0.0.5", local_port=4444,
                               remote_ip="203.0.113.9", remote_port=8080,
                               protocol="TCP", state="ESTABLISHED"),
    ]

    pipeline_result = detection_service.run_detection_pipeline(pslist, psscan, connections)
    detection_service.persist_detection_results(db_session, case.case_id, pipeline_result)

    stored_iocs = db_session.query(IOC).filter(IOC.case_id == case.case_id).all()
    stored_processes = db_session.query(ProcessRecord).filter(ProcessRecord.case_id == case.case_id).all()

    # All IOCs must be linked to the correct case_id.
    assert len(stored_iocs) > 0
    assert all(ioc.case_id == case.case_id for ioc in stored_iocs)

    ioc_types = {ioc.ioc_type for ioc in stored_iocs}
    assert "hidden_process" in ioc_types
    assert "suspicious_process" in ioc_types
    assert "ip" in ioc_types

    # Hidden and suspicious flags correctly reflected on process records.
    evil = next(p for p in stored_processes if p.pid == 1337)
    svchost = next(p for p in stored_processes if p.pid == 9999)
    assert evil.is_hidden is True
    assert svchost.suspicion_flag is True
    assert svchost.suspicion_reason is not None


# ---------------------------------------------------------------------------
# check_malfind heuristic linkage (FR-8 anomalous memory regions)
# ---------------------------------------------------------------------------

def test_malfind_hit_flags_process_suspicious():
    processes = [
        ProcessInfo(pid=4, ppid=0, process_name="System"),
        ProcessInfo(pid=6688, ppid=4, process_name="update_helper.exe"),
    ]
    malfind_pids = {6688}

    results = evaluate_all(processes, malfind_pids=malfind_pids)
    by_pid = {r.pid: r for r in results}

    assert by_pid[6688].suspicious is True
    assert "Anomalous memory region" in by_pid[6688].reason
    assert by_pid[4].suspicious is False


# ---------------------------------------------------------------------------
# check_masquerading_path (FR-8 proxy for "unsigned binaries")
# ---------------------------------------------------------------------------

def test_masquerading_svchost_flagged():
    """svchost.exe running from a Temp folder instead of System32 is a
    classic malware trick of naming itself after a trusted process."""
    services = ProcessInfo(pid=652, ppid=608, process_name="services.exe")
    proc = ProcessInfo(pid=9999, ppid=652, process_name="svchost.exe")
    proc.image_path = r"C:\Users\victim\AppData\Local\Temp\svchost.exe"

    results = evaluate_all([services, proc])
    by_pid = {r.pid: r for r in results}

    assert by_pid[9999].suspicious is True
    assert "Masquerading process" in by_pid[9999].reason
    assert "not the expected system directory" in by_pid[9999].reason


def test_genuine_svchost_in_system32_not_flagged():
    services = ProcessInfo(pid=652, ppid=608, process_name="services.exe")
    proc = ProcessInfo(pid=824, ppid=652, process_name="svchost.exe")
    proc.image_path = r"C:\Windows\System32\svchost.exe"

    results = evaluate_all([services, proc])
    by_pid = {r.pid: r for r in results}

    assert by_pid[824].suspicious is False


def test_genuine_svchost_in_syswow64_not_flagged():
    """32-bit svchost.exe on a 64-bit system legitimately runs from SysWOW64."""
    services = ProcessInfo(pid=652, ppid=608, process_name="services.exe")
    proc = ProcessInfo(pid=825, ppid=652, process_name="svchost.exe")
    proc.image_path = r"C:\Windows\SysWOW64\svchost.exe"

    results = evaluate_all([services, proc])
    by_pid = {r.pid: r for r in results}

    assert by_pid[825].suspicious is False


def test_masquerading_check_case_insensitive_and_handles_forward_slashes():
    services = ProcessInfo(pid=652, ppid=608, process_name="services.exe")
    proc = ProcessInfo(pid=824, ppid=652, process_name="svchost.exe")
    proc.image_path = "c:/WINDOWS/System32/svchost.exe"  # mixed case, forward slashes

    results = evaluate_all([services, proc])
    by_pid = {r.pid: r for r in results}

    assert by_pid[824].suspicious is False


def test_masquerading_check_skips_when_no_image_path_available():
    """No image path data (e.g. modules extraction failed) must not be
    treated as suspicious -- avoid false positives from missing data."""
    services = ProcessInfo(pid=652, ppid=608, process_name="services.exe")
    proc = ProcessInfo(pid=824, ppid=652, process_name="svchost.exe")
    assert proc.image_path is None

    results = evaluate_all([services, proc])
    by_pid = {r.pid: r for r in results}

    assert by_pid[824].suspicious is False


def test_masquerading_check_ignores_unlisted_process_names():
    """A process name with no entry in EXPECTED_SYSTEM_PATHS is out of
    scope for this check (e.g. arbitrary third-party applications)."""
    init_proc = ProcessInfo(pid=1, ppid=0, process_name="init")
    proc = ProcessInfo(pid=1000, ppid=1, process_name="chrome.exe")
    proc.image_path = r"C:\Users\victim\AppData\Local\Temp\chrome.exe"

    results = evaluate_all([init_proc, proc])
    by_pid = {r.pid: r for r in results}

    assert by_pid[1000].suspicious is False


# ---------------------------------------------------------------------------
# IOC extraction from real YARA matches and malfind hits
# ---------------------------------------------------------------------------

def test_extract_from_yara_match_infos():
    matches = [YaraMatchInfo(pid=6688, process_name="update_helper.exe", rule_name="Evil_Rule", address="0x1000")]

    iocs = extract_from_yara_match_infos(matches)

    assert len(iocs) == 1
    assert iocs[0].ioc_type == "yara_rule"
    assert iocs[0].ioc_value == "Evil_Rule"
    assert iocs[0].related_process_id == 6688
    assert "0x1000" in iocs[0].source


def test_extract_from_malfind_hits():
    hits = [MalfindHit(pid=6688, process_name="update_helper.exe", address="0x2000", protection="PAGE_EXECUTE_READWRITE")]

    iocs = extract_from_malfind_hits(hits)

    assert len(iocs) == 1
    assert iocs[0].ioc_type == "anomalous_memory_region"
    assert iocs[0].related_process_id == 6688
    assert "PAGE_EXECUTE_READWRITE" in iocs[0].source


# ---------------------------------------------------------------------------
# Detection pipeline wiring: real yara_matches / malfind_hits end-to-end
# ---------------------------------------------------------------------------

def test_run_detection_pipeline_with_yara_and_malfind():
    pslist = [
        ProcessInfo(pid=4, ppid=0, process_name="System"),
        ProcessInfo(pid=6688, ppid=4, process_name="update_helper.exe"),
    ]
    yara_matches = [YaraMatchInfo(pid=6688, process_name="update_helper.exe", rule_name="Evil_Rule")]
    malfind_hits = [MalfindHit(pid=6688, process_name="update_helper.exe", protection="PAGE_EXECUTE_READWRITE")]

    result = detection_service.run_detection_pipeline(
        pslist_procs=pslist, psscan_procs=pslist, connections=[],
        yara_matches=yara_matches, malfind_hits=malfind_hits,
    )

    suspicion_by_pid = {r.pid: r for r in result["suspicion_results"]}
    assert suspicion_by_pid[6688].suspicious is True
    assert "Anomalous memory region" in suspicion_by_pid[6688].reason

    ioc_types = {ioc.ioc_type for ioc in result["iocs"]}
    assert "yara_rule" in ioc_types
    assert "anomalous_memory_region" in ioc_types


# ---------------------------------------------------------------------------
# build_combined_rules_file
# ---------------------------------------------------------------------------

def test_build_combined_rules_file_from_real_yara_rules_dir():
    """Uses the actual yara_rules/ directory shipped with the project."""
    path = build_combined_rules_file()

    assert path is not None
    assert os.path.exists(path)
    with open(path) as f:
        content = f.read()
    assert "rule " in content  # combined file contains at least one rule definition
    os.remove(path)


def test_build_combined_rules_file_returns_none_for_missing_dir(tmp_path):
    path = build_combined_rules_file(rules_dir=str(tmp_path / "does_not_exist"))
    assert path is None


def test_build_combined_rules_file_returns_none_for_empty_dir(tmp_path):
    empty_dir = tmp_path / "empty_rules"
    empty_dir.mkdir()
    path = build_combined_rules_file(rules_dir=str(empty_dir))
    assert path is None


def test_build_combined_rules_file_raises_on_invalid_syntax(tmp_path):
    bad_dir = tmp_path / "bad_rules"
    bad_dir.mkdir()
    (bad_dir / "broken.yar").write_text("rule broken { this is not valid yara syntax")

    try:
        build_combined_rules_file(rules_dir=str(bad_dir))
        assert False, "expected YaraScanError"
    except YaraScanError as e:
        assert "compile" in str(e).lower()


def test_build_combined_rules_file_cleans_up_temp_file_on_failure(tmp_path, monkeypatch):
    """A failed validation (bad syntax or duplicate names) must not leave a
    stray temp file behind on every failed attempt."""
    import detection.yara_scanner as yara_scanner_module

    captured_paths = []
    original_mkstemp = yara_scanner_module.tempfile.mkstemp

    def spying_mkstemp(*args, **kwargs):
        fd, path = original_mkstemp(*args, **kwargs)
        captured_paths.append(path)
        return fd, path

    monkeypatch.setattr(yara_scanner_module.tempfile, "mkstemp", spying_mkstemp)

    bad_dir = tmp_path / "bad_rules_cleanup"
    bad_dir.mkdir()
    (bad_dir / "broken.yar").write_text("rule broken { not valid syntax at all")

    with pytest.raises(YaraScanError):
        build_combined_rules_file(rules_dir=str(bad_dir))

    assert len(captured_paths) == 1
    assert not os.path.exists(captured_paths[0])


def test_build_combined_rules_file_catches_duplicate_rule_name_across_files(tmp_path):
    """
    Regression test for a real bug: an earlier version validated each rule
    file under its own per-file namespace, which let two files defining a
    same-named rule pass validation cleanly while the actual concatenated
    file (compiled as one flat namespace, exactly as Volatility uses it)
    then failed at run-time with a confusing 'duplicated identifier' error
    surfacing from inside the Volatility subprocess instead of here.
    """
    dup_dir = tmp_path / "dup_rules"
    dup_dir.mkdir()
    (dup_dir / "file1.yar").write_text('rule Suspicious { strings: $a = "evil1" condition: $a }')
    (dup_dir / "file2.yar").write_text('rule Suspicious { strings: $b = "evil2" condition: $b }')

    try:
        build_combined_rules_file(rules_dir=str(dup_dir))
        assert False, "expected YaraScanError for duplicate rule name"
    except YaraScanError as e:
        assert "duplicated identifier" in str(e).lower() or "duplicate" in str(e).lower()
