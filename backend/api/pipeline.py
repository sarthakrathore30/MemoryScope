"""
Full analysis pipeline orchestration: Acquisition -> Analysis -> Detection ->
Database persistence, used by the POST /cases/{id}/analyze endpoint.

Covers the Data Flow section of SYSTEM_ARCHITECTURE_DESIGN_DOCUMENT.docx and
E2E-01 (full happy-path investigation) / E2E-02 (corrupted file handling) /
E2E-04 (repeat analysis on same case) from the Testing Plan.
"""

import json
import os

from sqlalchemy.orm import Session

from analysis.volatility_wrapper import run_full_analysis, VolatilityError
from detection.service import run_detection_pipeline, persist_detection_results
from detection.yara_scanner import build_combined_rules_file, YaraScanError
from db.database import utcnow
from db.models import Case, Module, NetworkConnection, ProcessRecord, IOC
from db.audit import append_audit_log


class PipelineError(Exception):
    """Raised when the analyze pipeline cannot complete for a case."""


def _log(db: Session, case_id: int, action: str) -> None:
    append_audit_log(db, case_id, action, performed_by="system")


def run_analysis_pipeline(db: Session, case: Case) -> dict:
    """
    Run the complete Acquisition->Analysis->Detection->Storage pipeline for
    an already-uploaded, validated case.

    On success: case.status -> 'completed'.
    On failure: case.status -> 'failed', exception re-raised as PipelineError
    so the API layer can return a clear error without crashing (FR reliability,
    E2E-02).

    Handles E2E-04 (repeat analysis): existing process/module/connection/IOC
    rows for this case are cleared before re-persisting fresh results, so
    re-running analysis does not silently duplicate records.
    """
    if not case.memory_image_ref:
        raise PipelineError("Case has no associated memory image to analyze.")

    case.status = "analyzing"
    case.updated_at = utcnow()
    db.commit()
    _log(db, case.case_id, "analysis_started")

    yara_rules_path = None
    try:
        yara_rules_path = build_combined_rules_file()
    except YaraScanError as exc:
        _log(db, case.case_id, f"yara_rules_compile_error:{exc}")
        # Fall through with yara_rules_path=None -- YARA scanning is skipped,
        # everything else still runs.

    try:
        raw = run_full_analysis(case.memory_image_ref, yara_rules_path=yara_rules_path)
    except VolatilityError as exc:
        case.status = "failed"
        case.updated_at = utcnow()
        db.commit()
        _log(db, case.case_id, f"analysis_failed:{exc}")
        raise PipelineError(f"Analysis failed: {exc}") from exc
    finally:
        if yara_rules_path and os.path.exists(yara_rules_path):
            os.remove(yara_rules_path)

    # E2E-04: clear any prior results for this case before re-persisting,
    # so repeat analysis doesn't duplicate rows.
    _clear_existing_case_data(db, case.case_id)

    if not case.os_profile or case.os_profile == "Unknown":
        case.os_profile = "Windows" if raw["os_family"] == "windows" else "Linux"

    if raw.get("system_metadata"):
        case.system_metadata = json.dumps(raw["system_metadata"])

    for warning in raw.get("warnings", []):
        _log(db, case.case_id, f"analysis_warning:{warning}")

    pipeline_result = run_detection_pipeline(
        pslist_procs=raw["processes"],
        psscan_procs=raw["processes_scan"],
        connections=raw["connections"],
        yara_matches=raw.get("yara_matches"),
        malfind_hits=raw.get("malfind_hits"),
    )

    pid_to_db_id = persist_detection_results(db, case.case_id, pipeline_result)

    _persist_modules_and_connections(db, pid_to_db_id, raw["modules"], raw["connections"])

    case.status = "completed"
    case.updated_at = utcnow()
    db.commit()
    _log(db, case.case_id, "analysis_completed")

    return {
        "process_count": len(pipeline_result["processes"]),
        "ioc_count": len(pipeline_result["iocs"]),
        "warnings": raw.get("warnings", []),
    }


def _clear_existing_case_data(db: Session, case_id: int) -> None:
    process_ids = [pid for (pid,) in db.query(ProcessRecord.process_id).filter(ProcessRecord.case_id == case_id).all()]
    if process_ids:
        db.query(Module).filter(Module.process_id.in_(process_ids)).delete(synchronize_session=False)
        db.query(NetworkConnection).filter(NetworkConnection.process_id.in_(process_ids)).delete(synchronize_session=False)
    db.query(IOC).filter(IOC.case_id == case_id).delete(synchronize_session=False)
    db.query(ProcessRecord).filter(ProcessRecord.case_id == case_id).delete(synchronize_session=False)
    db.commit()


def _persist_modules_and_connections(db: Session, pid_to_db_id: dict, modules: list, connections: list) -> None:
    for m in modules:
        db_process_id = pid_to_db_id.get(m.pid)
        if db_process_id is None:
            continue  # module belongs to a process not present in this run's process list
        db.add(Module(
            process_id=db_process_id,
            dll_name=m.dll_name,
            base_address=m.base_address,
            module_size=m.module_size,
        ))

    for c in connections:
        db_process_id = pid_to_db_id.get(c.pid)
        if db_process_id is None:
            continue
        db.add(NetworkConnection(
            process_id=db_process_id,
            local_ip=c.local_ip,
            local_port=c.local_port,
            remote_ip=c.remote_ip,
            remote_port=c.remote_port,
            protocol=c.protocol,
            state=c.state,
        ))

    db.commit()
