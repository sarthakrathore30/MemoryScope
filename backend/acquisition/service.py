"""
Acquisition service: orchestrates saving an uploaded memory image, validating
it, creating a case record, and kicking off OS profile detection.

Covers FR-1, FR-2, FR-3 and TC-AC-01 through TC-AC-04.
"""
import hashlib
import os
import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from acquisition.exceptions import AcquisitionError, CorruptedImageError
from acquisition.validators import validate_memory_image, MAX_VALID_SIZE_BYTES
from acquisition.profile_detector import detect_os_profile
from db.database import utcnow
from db.models import Case
from db.audit import append_audit_log

UPLOAD_DIR = os.getenv("UPLOAD_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "uploads"))

_COPY_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB per read, keeps memory use flat regardless of file size


@dataclass
class SavedFile:
    path: str
    sha256_hash: str
    md5_hash: str


def _ensure_upload_dir() -> None:
    os.makedirs(UPLOAD_DIR, exist_ok=True)


def create_case(db: Session, case_name: str) -> Case:
    """Create a new case record with status 'pending' (TC-DB-01)."""
    case = Case(case_name=case_name, memory_image_ref="", status="pending")
    db.add(case)
    db.commit()
    db.refresh(case)
    _log_action(db, case.case_id, "case_created", performed_by="system")
    return case


def save_uploaded_file(case: Case, filename: str, file_obj) -> SavedFile:
    """
    Stream an uploaded file to disk under a case-specific, collision-safe name.

    Enforces MAX_VALID_SIZE_BYTES DURING the copy (checked after every chunk)
    rather than only after the full file is written -- an oversized upload
    is aborted and the partial file removed immediately once the limit is
    crossed, instead of first consuming disk space for the entire transfer
    only to reject it afterward.

    Also computes SHA256 and MD5 hashes of the file incrementally in the
    same pass (no separate re-read of the whole file needed), for chain-of-
    custody integrity verification -- a court-admissible forensic report
    needs to be able to prove the analyzed image is bit-for-bit identical to
    what was originally acquired.

    Returns a SavedFile with the destination path and both hashes. Does not
    validate format; call validate_and_register_image() afterwards.
    """
    _ensure_upload_dir()
    _, ext = os.path.splitext(filename)
    safe_name = f"case_{case.case_id}_{uuid.uuid4().hex[:8]}{ext.lower()}"
    dest_path = os.path.abspath(os.path.join(UPLOAD_DIR, safe_name))

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    total_written = 0
    try:
        with open(dest_path, "wb") as out_file:
            while True:
                chunk = file_obj.read(_COPY_CHUNK_SIZE)
                if not chunk:
                    break
                total_written += len(chunk)
                if total_written > MAX_VALID_SIZE_BYTES:
                    raise CorruptedImageError(
                        f"Upload aborted: exceeded the maximum accepted size "
                        f"({MAX_VALID_SIZE_BYTES} bytes) while still receiving data."
                    )
                sha256.update(chunk)
                md5.update(chunk)
                out_file.write(chunk)
    except CorruptedImageError:
        if os.path.exists(dest_path):
            os.remove(dest_path)
        raise

    return SavedFile(path=dest_path, sha256_hash=sha256.hexdigest(), md5_hash=md5.hexdigest())


def validate_and_register_image(db: Session, case: Case, filename: str, saved_file: SavedFile) -> Case:
    """
    Validate the uploaded memory image and update the case record accordingly.

    On success: case.status -> 'pending' (ready for analysis), memory_image_ref
    and both hashes set. On failure: case.status -> 'failed', the underlying
    file is removed, and the original AcquisitionError is re-raised so the
    API layer can return a clear error message (FR-2, TC-AC-02, TC-AC-03).
    """
    file_path = saved_file.path
    try:
        validate_memory_image(filename, file_path)
    except AcquisitionError:
        if os.path.exists(file_path):
            os.remove(file_path)
        case.status = "failed"
        case.updated_at = utcnow()
        db.commit()
        _log_action(db, case.case_id, "image_validation_failed", performed_by="system")
        raise

    case.memory_image_ref = file_path
    case.sha256_hash = saved_file.sha256_hash
    case.md5_hash = saved_file.md5_hash
    case.status = "pending"
    case.updated_at = utcnow()
    db.commit()
    db.refresh(case)
    _log_action(
        db, case.case_id,
        f"image_uploaded_and_validated:sha256={saved_file.sha256_hash}",
        performed_by="system",
    )
    return case


def detect_and_store_profile(db: Session, case: Case) -> Case:
    """
    Run OS profile detection against the case's memory image and persist the
    result (FR-3, TC-AC-04). Does not raise on detection failure; stores
    'Unknown' instead so the pipeline can continue.
    """
    profile = detect_os_profile(case.memory_image_ref)
    case.os_profile = profile
    case.updated_at = utcnow()
    db.commit()
    db.refresh(case)
    _log_action(db, case.case_id, f"os_profile_detected:{profile}", performed_by="system")
    return case


def rename_case(db: Session, case: Case, new_name: str) -> Case:
    """Update a case's display name (does not affect any analysis data)."""
    old_name = case.case_name
    case.case_name = new_name
    case.updated_at = utcnow()
    db.commit()
    db.refresh(case)
    _log_action(db, case.case_id, f"case_renamed:'{old_name}' -> '{new_name}'", performed_by="system")
    return case


def delete_case(db: Session, case: Case) -> None:
    """
    Permanently delete a case: its DB row (which cascades to processes,
    modules, network connections, IOCs, reports, and audit logs via the
    relationships defined in db.models), plus the actual uploaded memory
    image and any generated report files on disk, which the DB cascade
    cannot clean up on its own.

    Best-effort on file removal: a missing/already-deleted file on disk is
    not treated as an error, since the DB record is still the source of
    truth for whether the case existed.
    """
    from db.models import Report  # local import to avoid a circular import at module load time

    if case.memory_image_ref and os.path.exists(case.memory_image_ref):
        os.remove(case.memory_image_ref)

    for report in db.query(Report).filter(Report.case_id == case.case_id).all():
        if report.file_path and os.path.exists(report.file_path):
            os.remove(report.file_path)

    db.delete(case)
    db.commit()


def _log_action(db: Session, case_id: int, action: str, performed_by: str = None) -> None:
    append_audit_log(db, case_id, action, performed_by)
