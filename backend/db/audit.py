"""
Audit log service: creates chain-of-custody log entries with a tamper-
evident hash chain, and verifies that chain.

Real gap identified via security review: audit events were previously
stored with no integrity protection at all -- anyone with direct database
access could edit or delete an investigation's audit trail without leaving
any trace. Every AuditLog row now includes record_hash, a SHA-256 hash
covering the record's own content plus the previous record's hash (for the
same case), forming a hash chain: modifying, deleting, or reordering any
historical entry breaks its own hash and every hash after it, making
tampering detectable by recomputing and comparing.

This is NOT cryptographic non-repudiation (there's no signing key/identity
involved, so it can't prove *who* made a change) -- it proves *that* the
recorded sequence has or hasn't been altered since it was written, which is
the property a chain-of-custody log actually needs.

All audit log entries must be created through append_audit_log(), never by
constructing db.models.AuditLog directly, or the chain will have a gap that
verify_audit_chain() will report as broken from that point forward.
"""
import hashlib
from typing import List, Tuple

from sqlalchemy.orm import Session

from db.database import utcnow
from db.models import AuditLog


def _compute_record_hash(previous_hash: str, case_id: int, action: str, performed_by: str, timestamp) -> str:
    payload = f"{previous_hash}|{case_id}|{action}|{performed_by or ''}|{timestamp.isoformat()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_audit_log(db: Session, case_id: int, action: str, performed_by: str = None) -> AuditLog:
    """Create a new audit log entry, linked into this case's hash chain."""
    timestamp = utcnow()

    previous_entry = (
        db.query(AuditLog)
        .filter(AuditLog.case_id == case_id)
        .order_by(AuditLog.log_id.desc())
        .first()
    )
    previous_hash = previous_entry.record_hash if previous_entry and previous_entry.record_hash else ""

    record_hash = _compute_record_hash(previous_hash, case_id, action, performed_by, timestamp)

    entry = AuditLog(
        case_id=case_id, action=action, performed_by=performed_by,
        timestamp=timestamp, record_hash=record_hash,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def verify_audit_chain(db: Session, case_id: int) -> Tuple[bool, List[int]]:
    """
    Recompute each entry's hash from its stored content and the previous
    entry's hash, comparing against what's actually stored.

    Returns (is_valid, broken_log_ids). broken_log_ids lists the log_id of
    every entry whose recomputed hash doesn't match what's stored -- the
    first broken entry is where tampering (or a pre-hash-chain legacy
    entry with no record_hash) was introduced; entries after it will also
    show as broken as a direct consequence, since each hash depends on the
    previous one.
    """
    entries = (
        db.query(AuditLog)
        .filter(AuditLog.case_id == case_id)
        .order_by(AuditLog.log_id.asc())
        .all()
    )

    broken = []
    previous_hash = ""
    for entry in entries:
        expected_hash = _compute_record_hash(previous_hash, entry.case_id, entry.action, entry.performed_by, entry.timestamp)
        if entry.record_hash != expected_hash:
            broken.append(entry.log_id)
        # Chain forward using the STORED hash (not the recomputed one) so a
        # single tampered entry is reported once, rather than cascading
        # into a false "every subsequent entry is also broken" report when
        # only one entry was actually altered.
        previous_hash = entry.record_hash or expected_hash

    return (len(broken) == 0, broken)
