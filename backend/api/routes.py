"""
API Layer (FastAPI): exposes REST endpoints per
SYSTEM_ARCHITECTURE_DESIGN_DOCUMENT.docx section 4.2 and
SOFTWARE_REQUIREMENTS_SPECIFICATION.docx FR-1..FR-21.

Covers TC-API-01 through TC-API-06.
"""
import os

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from db.database import get_db, utcnow
from db.models import Case, ProcessRecord, Module, NetworkConnection, IOC, AuditLog
from db.audit import verify_audit_chain
from acquisition import service as acquisition_service
from acquisition.exceptions import AcquisitionError
from api.pipeline import run_analysis_pipeline, PipelineError
from reporting.service import generate_json_report, generate_pdf_report
from api.schemas import (
    CaseCreate, CaseRename, CaseOut, CaseResultsOut, UploadResponse, AnalyzeResponse,
    ProcessOut, ModuleOut, NetworkConnectionOut, IOCOut, AuditLogEntryOut, AuditChainVerification,
)

router = APIRouter()


def _get_case_or_404(db: Session, case_id: int) -> Case:
    """Shared lookup helper; raises 404 with a clear message (TC-API-06)."""
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail=f"Case with id {case_id} not found.")
    return case


@router.post("/cases", response_model=CaseOut, status_code=201)
def create_case(payload: CaseCreate, db: Session = Depends(get_db)):
    """TC-API-01: create a new case, returns 201 with the new case_id."""
    if not payload.case_name or not payload.case_name.strip():
        raise HTTPException(status_code=400, detail="case_name is required.")
    case = acquisition_service.create_case(db, payload.case_name.strip())
    return case


@router.get("/cases", response_model=list[CaseOut])
def list_cases(db: Session = Depends(get_db)):
    """List all cases (used by the frontend case list view, TC-FE-01)."""
    return db.query(Case).order_by(Case.created_at.desc()).all()


@router.get("/cases/{case_id}", response_model=CaseOut)
def get_case(case_id: int, db: Session = Depends(get_db)):
    return _get_case_or_404(db, case_id)


@router.patch("/cases/{case_id}", response_model=CaseOut)
def rename_case(case_id: int, payload: CaseRename, db: Session = Depends(get_db)):
    """Rename a case. Does not affect any analysis data."""
    case = _get_case_or_404(db, case_id)
    if not payload.case_name or not payload.case_name.strip():
        raise HTTPException(status_code=400, detail="case_name is required.")
    return acquisition_service.rename_case(db, case, payload.case_name.strip())


@router.delete("/cases/{case_id}", status_code=204)
def delete_case(case_id: int, db: Session = Depends(get_db)):
    """
    Permanently delete a case and all associated data (processes, modules,
    connections, IOCs, reports, audit logs) plus its files on disk.
    """
    case = _get_case_or_404(db, case_id)
    acquisition_service.delete_case(db, case)
    return None


@router.get("/cases/{case_id}/audit-log", response_model=list[AuditLogEntryOut])
def get_case_audit_log(case_id: int, db: Session = Depends(get_db)):
    """
    Chronological chain-of-custody log of every action taken on a case
    (FR-16, "Other Requirements" in the SRS: audit trail for forensic
    chain-of-custody). Oldest first, matching the order events occurred.
    """
    _get_case_or_404(db, case_id)
    return (
        db.query(AuditLog)
        .filter(AuditLog.case_id == case_id)
        .order_by(AuditLog.timestamp.asc())
        .all()
    )


@router.get("/cases/{case_id}/audit-log/verify", response_model=AuditChainVerification)
def verify_case_audit_log(case_id: int, db: Session = Depends(get_db)):
    """
    Verify the tamper-evidence hash chain covering this case's audit log
    (see db.audit.verify_audit_chain). A modified, deleted, or reordered
    historical entry will show up here as a hash mismatch.
    """
    _get_case_or_404(db, case_id)
    is_valid, broken_log_ids = verify_audit_chain(db, case_id)
    entry_count = db.query(AuditLog).filter(AuditLog.case_id == case_id).count()
    return AuditChainVerification(is_valid=is_valid, entry_count=entry_count, broken_log_ids=broken_log_ids)


@router.post("/cases/{case_id}/upload", response_model=UploadResponse)
def upload_memory_image(case_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    TC-API-02: upload a memory image for an existing case.

    Validates format/integrity (FR-2), then attempts OS profile detection
    (FR-3). Returns 200 with the updated case on success; 400 with a clear
    error message on validation failure (TC-AC-02, TC-AC-03).
    """
    case = _get_case_or_404(db, case_id)

    try:
        saved_file = acquisition_service.save_uploaded_file(case, file.filename, file.file)
        acquisition_service.validate_and_register_image(db, case, file.filename, saved_file)
    except AcquisitionError as exc:
        # save_uploaded_file can itself raise (e.g. oversized upload aborted
        # mid-stream) before validate_and_register_image ever runs, which is
        # the only place that normally marks the case failed -- do it here
        # too so the case's DB state is consistent regardless of which step
        # raised. Safe to call unconditionally: if validate_and_register_image
        # already set it, this is a harmless no-op re-assignment.
        case.status = "failed"
        case.updated_at = utcnow()
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc))

    try:
        acquisition_service.detect_and_store_profile(db, case)
    except Exception:
        # Profile detection failure shouldn't block the upload; the case
        # simply keeps os_profile = None/"Unknown" and can still be analyzed.
        pass

    db.refresh(case)
    return UploadResponse(case=case, message="Memory image uploaded and validated successfully.")


@router.post("/cases/{case_id}/analyze", response_model=AnalyzeResponse)
def analyze_case(case_id: int, db: Session = Depends(get_db)):
    """
    TC-API-03: trigger the full analysis pipeline for a case.

    Returns 200 with status 'completed' on success. On failure, the case is
    marked 'failed' and a 500 is returned with a clear error message
    (reliability requirement, E2E-02).
    """
    case = _get_case_or_404(db, case_id)

    if not case.memory_image_ref:
        raise HTTPException(status_code=400, detail="No memory image has been uploaded for this case yet.")

    try:
        stats = run_analysis_pipeline(db, case)
    except PipelineError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    db.refresh(case)
    return AnalyzeResponse(
        case=case,
        message="Analysis completed successfully." if not stats["warnings"] else "Analysis completed with warnings.",
        process_count=stats["process_count"],
        ioc_count=stats["ioc_count"],
        warnings=stats["warnings"],
    )


@router.get("/cases/{case_id}/results", response_model=CaseResultsOut)
def get_case_results(case_id: int, db: Session = Depends(get_db)):
    """TC-API-04: fetch structured processes/modules/connections/IOCs for a case."""
    case = _get_case_or_404(db, case_id)

    processes = db.query(ProcessRecord).filter(ProcessRecord.case_id == case_id).all()
    process_ids = [p.process_id for p in processes]

    modules = db.query(Module).filter(Module.process_id.in_(process_ids)).all() if process_ids else []
    connections = (
        db.query(NetworkConnection).filter(NetworkConnection.process_id.in_(process_ids)).all()
        if process_ids else []
    )
    iocs = db.query(IOC).filter(IOC.case_id == case_id).all()

    return CaseResultsOut(
        case=case,
        processes=[ProcessOut.model_validate(p) for p in processes],
        modules=[ModuleOut.model_validate(m) for m in modules],
        network_connections=[NetworkConnectionOut.model_validate(c) for c in connections],
        iocs=[IOCOut.model_validate(i) for i in iocs],
    )


@router.get("/cases/{case_id}/report")
def get_case_report(
    case_id: int,
    format: str = Query("json", pattern="^(json|pdf)$"),
    db: Session = Depends(get_db),
):
    """
    TC-API-05: generate and return a downloadable report for a case.

    format=json returns/generates a JSON report; format=pdf generates a PDF
    (FR-17, FR-18, TC-RP-01, TC-RP-02).
    """
    case = _get_case_or_404(db, case_id)

    if format == "pdf":
        file_path = generate_pdf_report(db, case)
        media_type = "application/pdf"
    else:
        file_path = generate_json_report(db, case)
        media_type = "application/json"

    return FileResponse(
        path=file_path,
        media_type=media_type,
        filename=os.path.basename(file_path),
    )
