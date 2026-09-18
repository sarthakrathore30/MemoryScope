"""
End-to-end scenario tests, mapped to TESTING_PLAN.docx section 6:

  E2E-01: Full happy-path investigation (upload -> analyze -> results -> report)
  E2E-02: Corrupted file handling (rejected gracefully, case marked 'failed')
  E2E-03: Multi-case handling (data isolated per case_id, no cross-contamination)
  E2E-04: Repeat analysis on same case (no duplicated records)

As with test_api.py, Volatility3 calls are mocked at the module boundary so
these tests run fast and deterministically while still exercising the real
FastAPI routes, pipeline orchestration, and SQLite persistence layer.
"""
import io
from unittest.mock import patch

from analysis.volatility_wrapper import ProcessInfo, ModuleInfo, NetworkConnectionInfo

from tests.conftest import create_case, upload_valid_image


def _sample_analysis_result():
    """A small but non-trivial fake Volatility result: one clean process,
    one hidden process, one suspicious process, one module, one connection.
    """
    return {
        "os_family": "windows",
        "processes": [
            ProcessInfo(pid=4, ppid=0, process_name="System"),
            ProcessInfo(pid=800, ppid=4, process_name="svchost.exe"),
        ],
        "processes_scan": [
            ProcessInfo(pid=4, ppid=0, process_name="System"),
            ProcessInfo(pid=800, ppid=4, process_name="svchost.exe"),
            ProcessInfo(pid=1234, ppid=800, process_name="backdoor.exe"),  # hidden
        ],
        "modules": [ModuleInfo(pid=1234, dll_name="ws2_32.dll", base_address="0x1000", module_size=2048)],
        "connections": [
            NetworkConnectionInfo(pid=1234, local_ip="10.0.0.9", local_port=4444,
                                   remote_ip="198.51.100.23", remote_port=443,
                                   protocol="TCP", state="ESTABLISHED"),
        ],
    }


# ---------------------------------------------------------------------------
# E2E-01: Full happy-path investigation
# ---------------------------------------------------------------------------

@patch("api.pipeline.run_full_analysis")
def test_e2e_01_full_happy_path_investigation(mock_run_analysis, client):
    mock_run_analysis.return_value = _sample_analysis_result()

    # Upload -> Analyze -> View results -> Generate report, checking
    # consistency of data at every stage.
    case = create_case(client, "E2E Happy Path")
    upload_resp = upload_valid_image(client, case["case_id"])
    assert upload_resp.status_code == 200
    assert upload_resp.json()["case"]["status"] == "pending"

    analyze_resp = client.post(f"/api/cases/{case['case_id']}/analyze")
    assert analyze_resp.status_code == 200
    assert analyze_resp.json()["case"]["status"] == "completed"
    assert analyze_resp.json()["process_count"] == 3
    assert analyze_resp.json()["ioc_count"] > 0

    results_resp = client.get(f"/api/cases/{case['case_id']}/results")
    assert results_resp.status_code == 200
    results = results_resp.json()
    assert len(results["processes"]) == 3
    assert any(p["is_hidden"] for p in results["processes"])
    assert len(results["network_connections"]) == 1
    assert len(results["modules"]) == 1

    # Report counts must match what /results reported (TC-RP-03 in spirit).
    report_resp = client.get(f"/api/cases/{case['case_id']}/report?format=json")
    assert report_resp.status_code == 200
    report_data = report_resp.json()
    assert report_data["summary"]["total_processes"] == len(results["processes"])
    assert report_data["summary"]["total_iocs"] == len(results["iocs"])


# ---------------------------------------------------------------------------
# E2E-02: Corrupted file handling
# ---------------------------------------------------------------------------

def test_e2e_02_corrupted_file_rejected_gracefully(client):
    case = create_case(client, "E2E Corrupted File")

    # Truncated file: below the minimum valid size threshold.
    tiny_file = io.BytesIO(b"\x00" * 100)
    resp = client.post(
        f"/api/cases/{case['case_id']}/upload",
        files={"file": ("truncated.raw", tiny_file, "application/octet-stream")},
    )

    # System rejects gracefully (400, not a crash/500) with a clear message.
    assert resp.status_code == 400
    assert resp.json()["detail"]  # non-empty, human-readable

    # Case is marked failed, not left in a partially-uploaded ambiguous state.
    case_check = client.get(f"/api/cases/{case['case_id']}").json()
    assert case_check["status"] == "failed"
    assert case_check["has_memory_image"] is False

    # System is still up and usable afterwards -- not crashed.
    assert client.get("/health").status_code == 200


# ---------------------------------------------------------------------------
# E2E-03: Multi-case handling / data isolation
# ---------------------------------------------------------------------------

@patch("api.pipeline.run_full_analysis")
def test_e2e_03_multi_case_data_isolation(mock_run_analysis, client):
    def result_for(pid_offset):
        return {
            "os_family": "windows",
            "processes": [ProcessInfo(pid=4, ppid=0, process_name="System"),
                          ProcessInfo(pid=pid_offset, ppid=4, process_name=f"proc_{pid_offset}.exe")],
            "processes_scan": [ProcessInfo(pid=4, ppid=0, process_name="System"),
                                ProcessInfo(pid=pid_offset, ppid=4, process_name=f"proc_{pid_offset}.exe")],
            "modules": [],
            "connections": [NetworkConnectionInfo(pid=pid_offset, local_ip="10.0.0.1", local_port=1,
                                                    remote_ip=f"203.0.113.{pid_offset % 250}", remote_port=80,
                                                    protocol="TCP", state="ESTABLISHED")],
        }

    case_a = create_case(client, "Case Alpha")
    case_b = create_case(client, "Case Bravo")

    upload_valid_image(client, case_a["case_id"], filename="alpha.raw")
    upload_valid_image(client, case_b["case_id"], filename="bravo.raw")

    mock_run_analysis.return_value = result_for(1001)
    client.post(f"/api/cases/{case_a['case_id']}/analyze")

    mock_run_analysis.return_value = result_for(2002)
    client.post(f"/api/cases/{case_b['case_id']}/analyze")

    results_a = client.get(f"/api/cases/{case_a['case_id']}/results").json()
    results_b = client.get(f"/api/cases/{case_b['case_id']}/results").json()

    pids_a = {p["pid"] for p in results_a["processes"]}
    pids_b = {p["pid"] for p in results_b["processes"]}

    # Case-specific process must appear only in its own case, not the other.
    assert 1001 in pids_a and 1001 not in pids_b
    assert 2002 in pids_b and 2002 not in pids_a

    # IOCs (derived from network connections) must also stay isolated per case.
    iocs_a_values = {i["ioc_value"] for i in results_a["iocs"]}
    iocs_b_values = {i["ioc_value"] for i in results_b["iocs"]}
    assert iocs_a_values.isdisjoint(iocs_b_values)


# ---------------------------------------------------------------------------
# E2E-04: Repeat analysis on same case
# ---------------------------------------------------------------------------

@patch("api.pipeline.run_full_analysis")
def test_e2e_04_repeat_analysis_does_not_duplicate_records(mock_run_analysis, client):
    mock_run_analysis.return_value = _sample_analysis_result()

    case = create_case(client, "E2E Repeat Analysis")
    upload_valid_image(client, case["case_id"])

    first = client.post(f"/api/cases/{case['case_id']}/analyze")
    assert first.status_code == 200
    first_results = client.get(f"/api/cases/{case['case_id']}/results").json()

    # Re-trigger analysis on the already-analyzed case with the same fake data.
    second = client.post(f"/api/cases/{case['case_id']}/analyze")
    assert second.status_code == 200
    second_results = client.get(f"/api/cases/{case['case_id']}/results").json()

    # Row counts must be identical, not doubled, after re-analysis.
    assert len(second_results["processes"]) == len(first_results["processes"]) == 3
    assert len(second_results["network_connections"]) == len(first_results["network_connections"]) == 1
    assert len(second_results["modules"]) == len(first_results["modules"]) == 1
    assert len(second_results["iocs"]) == len(first_results["iocs"])
