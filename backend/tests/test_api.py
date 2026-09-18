"""
API integration tests, mapped to TESTING_PLAN.docx:

  TC-API-01: POST /cases -> 201 with new case_id
  TC-API-02: POST /cases/{id}/upload -> 200, file stored, case updated
  TC-API-03: POST /cases/{id}/analyze -> status updates to 'completed'
  TC-API-04: GET /cases/{id}/results -> 200 with structured JSON
  TC-API-05: GET /cases/{id}/report -> report generated/downloadable
  TC-API-06: invalid case_id -> 404 with clear error message

Volatility3/YARA calls are mocked at the module boundary (same approach as
test_analysis.py) since these are fast integration tests of the API/DB
wiring, not of Volatility3 itself.

The `client` fixture used throughout is defined in conftest.py (shared with
test_e2e.py), which also exposes client.upload_dir/reports_dir so tests can
inspect files on disk directly -- necessary since the API intentionally
does not expose server-side file paths to clients (see CaseOut).
"""
import io
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis.volatility_wrapper import ProcessInfo, ModuleInfo, NetworkConnectionInfo
from db.database import get_db
import main


def _create_case(client, name="Integration Test Case"):
    resp = client.post("/api/cases", json={"case_name": name})
    assert resp.status_code == 201
    return resp.json()


def _upload_valid_image(client, case_id):
    fake_image = io.BytesIO(b"\x00" * (2 * 1024 * 1024))
    return client.post(
        f"/api/cases/{case_id}/upload",
        files={"file": ("sample.raw", fake_image, "application/octet-stream")},
    )


# ---------------------------------------------------------------------------
# TC-API-01
# ---------------------------------------------------------------------------

def test_tc_api_01_create_case(client):
    resp = client.post("/api/cases", json={"case_name": "My Investigation"})

    assert resp.status_code == 201
    body = resp.json()
    assert "case_id" in body
    assert body["case_name"] == "My Investigation"
    assert body["status"] == "pending"


def test_create_case_missing_name_rejected(client):
    resp = client.post("/api/cases", json={"case_name": "   "})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# TC-API-02
# ---------------------------------------------------------------------------

@patch("acquisition.profile_detector.detect_os_profile", return_value="Windows (Win10x64)")
def test_tc_api_02_upload_valid_image(mock_detect, client):
    case = _create_case(client)

    resp = _upload_valid_image(client, case["case_id"])

    assert resp.status_code == 200
    body = resp.json()
    assert body["case"]["has_memory_image"] is True
    assert "memory_image_ref" not in body["case"]  # server path must not be exposed to clients
    assert body["case"]["status"] == "pending"


def test_upload_unsupported_format_returns_400(client):
    case = _create_case(client)
    bad_file = io.BytesIO(b"just text" * 1000)

    resp = client.post(
        f"/api/cases/{case['case_id']}/upload",
        files={"file": ("notes.txt", bad_file, "text/plain")},
    )

    assert resp.status_code == 400
    assert "unsupported" in resp.json()["detail"].lower() or "format" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# TC-API-03
# ---------------------------------------------------------------------------

@patch("api.pipeline.run_full_analysis")
def test_tc_api_03_analyze_case_completes(mock_run_analysis, client):
    mock_run_analysis.return_value = {
        "os_family": "windows",
        "processes": [
            ProcessInfo(pid=4, ppid=0, process_name="System"),
            ProcessInfo(pid=620, ppid=4, process_name="smss.exe"),
        ],
        "processes_scan": [
            ProcessInfo(pid=4, ppid=0, process_name="System"),
            ProcessInfo(pid=620, ppid=4, process_name="smss.exe"),
            ProcessInfo(pid=1337, ppid=620, process_name="evil.exe"),  # hidden
        ],
        "modules": [ModuleInfo(pid=620, dll_name="ntdll.dll", base_address="0x1000", module_size=1024)],
        "connections": [
            NetworkConnectionInfo(pid=1337, local_ip="10.0.0.5", local_port=4444,
                                   remote_ip="203.0.113.9", remote_port=8080,
                                   protocol="TCP", state="ESTABLISHED"),
        ],
    }

    case = _create_case(client)
    upload_resp = _upload_valid_image(client, case["case_id"])
    assert upload_resp.status_code == 200

    resp = client.post(f"/api/cases/{case['case_id']}/analyze")

    assert resp.status_code == 200
    body = resp.json()
    assert body["case"]["status"] == "completed"
    assert body["process_count"] == 3
    assert body["ioc_count"] > 0


def test_analyze_without_upload_returns_400(client):
    case = _create_case(client)
    resp = client.post(f"/api/cases/{case['case_id']}/analyze")
    assert resp.status_code == 400


@patch("api.pipeline.run_full_analysis")
def test_analyze_failure_marks_case_failed(mock_run_analysis, client):
    from analysis.volatility_wrapper import VolatilityError
    mock_run_analysis.side_effect = VolatilityError("simulated volatility crash")

    case = _create_case(client)
    _upload_valid_image(client, case["case_id"])

    resp = client.post(f"/api/cases/{case['case_id']}/analyze")

    assert resp.status_code == 500
    case_check = client.get(f"/api/cases/{case['case_id']}")
    assert case_check.json()["status"] == "failed"


# ---------------------------------------------------------------------------
# TC-API-04
# ---------------------------------------------------------------------------

@patch("api.pipeline.run_full_analysis")
def test_tc_api_04_get_results(mock_run_analysis, client):
    mock_run_analysis.return_value = {
        "os_family": "windows",
        "processes": [ProcessInfo(pid=4, ppid=0, process_name="System")],
        "processes_scan": [ProcessInfo(pid=4, ppid=0, process_name="System")],
        "modules": [],
        "connections": [],
    }
    case = _create_case(client)
    _upload_valid_image(client, case["case_id"])
    client.post(f"/api/cases/{case['case_id']}/analyze")

    resp = client.get(f"/api/cases/{case['case_id']}/results")

    assert resp.status_code == 200
    body = resp.json()
    assert len(body["processes"]) == 1
    assert body["processes"][0]["pid"] == 4


# ---------------------------------------------------------------------------
# TC-API-05
# ---------------------------------------------------------------------------

@patch("api.pipeline.run_full_analysis")
def test_tc_api_05_get_json_report(mock_run_analysis, client):
    mock_run_analysis.return_value = {
        "os_family": "windows",
        "processes": [ProcessInfo(pid=4, ppid=0, process_name="System")],
        "processes_scan": [ProcessInfo(pid=4, ppid=0, process_name="System")],
        "modules": [],
        "connections": [],
    }
    case = _create_case(client)
    _upload_valid_image(client, case["case_id"])
    client.post(f"/api/cases/{case['case_id']}/analyze")

    resp = client.get(f"/api/cases/{case['case_id']}/report?format=json")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")


@patch("api.pipeline.run_full_analysis")
def test_get_pdf_report(mock_run_analysis, client):
    mock_run_analysis.return_value = {
        "os_family": "windows",
        "processes": [ProcessInfo(pid=4, ppid=0, process_name="System")],
        "processes_scan": [ProcessInfo(pid=4, ppid=0, process_name="System")],
        "modules": [],
        "connections": [],
    }
    case = _create_case(client)
    _upload_valid_image(client, case["case_id"])
    client.post(f"/api/cases/{case['case_id']}/analyze")

    resp = client.get(f"/api/cases/{case['case_id']}/report?format=pdf")

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"


# ---------------------------------------------------------------------------
# TC-API-06
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("endpoint,method", [
    ("/api/cases/99999", "get"),
    ("/api/cases/99999/analyze", "post"),
    ("/api/cases/99999/results", "get"),
    ("/api/cases/99999/report", "get"),
])
def test_tc_api_06_invalid_case_id_returns_404(client, endpoint, method):
    resp = getattr(client, method)(endpoint)

    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Case rename (PATCH)
# ---------------------------------------------------------------------------

def test_rename_case(client):
    case = _create_case(client, "Original Name")

    resp = client.patch(f"/api/cases/{case['case_id']}", json={"case_name": "Renamed Case"})

    assert resp.status_code == 200
    assert resp.json()["case_name"] == "Renamed Case"

    fetched = client.get(f"/api/cases/{case['case_id']}").json()
    assert fetched["case_name"] == "Renamed Case"


def test_rename_case_rejects_empty_name(client):
    case = _create_case(client)
    resp = client.patch(f"/api/cases/{case['case_id']}", json={"case_name": "   "})
    assert resp.status_code == 400


def test_rename_nonexistent_case_returns_404(client):
    resp = client.patch("/api/cases/99999", json={"case_name": "New Name"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Case deletion (DELETE)
# ---------------------------------------------------------------------------

def test_delete_case(client):
    case = _create_case(client, "To Be Deleted")

    resp = client.delete(f"/api/cases/{case['case_id']}")
    assert resp.status_code == 204

    # Case must genuinely be gone, not just marked inactive.
    get_resp = client.get(f"/api/cases/{case['case_id']}")
    assert get_resp.status_code == 404


def test_delete_case_removes_uploaded_file_from_disk(client):
    case = _create_case(client, "To Be Deleted With File")
    upload_resp = _upload_valid_image(client, case["case_id"])
    assert upload_resp.json()["case"]["has_memory_image"] is True

    # The API intentionally no longer exposes the server-side file path
    # (info disclosure fix) -- inspect the upload directory directly instead.
    uploaded_files = list(client.upload_dir.iterdir())
    assert len(uploaded_files) == 1
    saved_path = uploaded_files[0]
    assert saved_path.exists()

    resp = client.delete(f"/api/cases/{case['case_id']}")

    assert resp.status_code == 204
    assert not saved_path.exists()


def test_delete_nonexistent_case_returns_404(client):
    resp = client.delete("/api/cases/99999")
    assert resp.status_code == 404


def test_deleted_case_disappears_from_list(client):
    case_a = _create_case(client, "Case Alpha")
    case_b = _create_case(client, "Case Bravo")

    client.delete(f"/api/cases/{case_a['case_id']}")

    remaining = client.get("/api/cases").json()
    remaining_ids = {c["case_id"] for c in remaining}
    assert case_a["case_id"] not in remaining_ids
    assert case_b["case_id"] in remaining_ids


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def test_audit_log_records_case_lifecycle_events(client):
    case = _create_case(client, "Audit Trail Test")
    _upload_valid_image(client, case["case_id"])

    resp = client.get(f"/api/cases/{case['case_id']}/audit-log")

    assert resp.status_code == 200
    entries = resp.json()
    actions = [e["action"] for e in entries]
    assert "case_created" in actions
    assert any(a.startswith("image_uploaded") for a in actions)
    # Chronological order (oldest first) -- case_created must precede upload.
    assert actions.index("case_created") < next(
        i for i, a in enumerate(actions) if a.startswith("image_uploaded")
    )


def test_audit_log_nonexistent_case_returns_404(client):
    resp = client.get("/api/cases/99999/audit-log")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Audit chain verification
# ---------------------------------------------------------------------------

def test_audit_chain_verify_endpoint_valid_for_untouched_case(client):
    case = _create_case(client, "Chain Verify Test")
    _upload_valid_image(client, case["case_id"])

    resp = client.get(f"/api/cases/{case['case_id']}/audit-log/verify")

    assert resp.status_code == 200
    body = resp.json()
    assert body["is_valid"] is True
    assert body["broken_log_ids"] == []
    assert body["entry_count"] >= 2  # at least case_created + image_uploaded


def test_audit_chain_verify_detects_direct_db_tampering(client):
    """
    The actual scenario this protects against: someone bypasses the API
    entirely and edits the database directly. Exercises the full stack
    (API endpoint -> db.audit.verify_audit_chain), not just the unit-level
    hash chain logic already covered in test_audit.py.
    """
    case = _create_case(client, "Tamper Detection Test")

    from db.models import AuditLog
    db_gen = main.app.dependency_overrides[get_db]()
    db = next(db_gen)
    entry = db.query(AuditLog).filter(AuditLog.case_id == case["case_id"]).first()
    entry.action = "case_created_but_tampered_directly_in_db"
    db.commit()

    resp = client.get(f"/api/cases/{case['case_id']}/audit-log/verify")

    assert resp.status_code == 200
    body = resp.json()
    assert body["is_valid"] is False
    assert entry.log_id in body["broken_log_ids"]


def test_audit_chain_verify_nonexistent_case_returns_404(client):
    resp = client.get("/api/cases/99999/audit-log/verify")
    assert resp.status_code == 404
