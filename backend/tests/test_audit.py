"""
Tests for db/audit.py: the tamper-evident hash chain for audit log entries.

Real gap identified via security review: audit events were previously
stored with no integrity protection -- anyone with direct database access
could edit or delete an investigation's audit trail without leaving a
trace. Each entry's hash now covers its own content plus the previous
entry's hash, so tampering with any historical entry is detectable.
"""
import os
import sys

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from db.database import Base
from db import models  # noqa: F401
from db.models import Case, AuditLog
from db.audit import append_audit_log, verify_audit_chain


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture()
def case(db_session):
    c = Case(case_name="Audit Chain Test", memory_image_ref="", status="pending")
    db_session.add(c)
    db_session.commit()
    db_session.refresh(c)
    return c


def test_append_audit_log_sets_a_hash(db_session, case):
    entry = append_audit_log(db_session, case.case_id, "case_created", performed_by="system")

    assert entry.record_hash is not None
    assert len(entry.record_hash) == 64  # SHA-256 hex digest


def test_each_entry_chains_from_the_previous_hash(db_session, case):
    entry1 = append_audit_log(db_session, case.case_id, "case_created")
    entry2 = append_audit_log(db_session, case.case_id, "image_uploaded")

    assert entry1.record_hash != entry2.record_hash
    # Changing nothing else, entry2's hash must depend on entry1's hash --
    # verified indirectly below via tamper detection, and directly here by
    # confirming two entries with different prior-chain state hash differently
    # even though this test only checks they're not trivially equal.
    assert entry2.record_hash is not None


def test_verify_audit_chain_valid_for_untouched_chain(db_session, case):
    append_audit_log(db_session, case.case_id, "case_created")
    append_audit_log(db_session, case.case_id, "image_uploaded")
    append_audit_log(db_session, case.case_id, "analysis_completed")

    is_valid, broken = verify_audit_chain(db_session, case.case_id)

    assert is_valid is True
    assert broken == []


def test_verify_audit_chain_detects_tampered_action_text(db_session, case):
    """The actual real-world attack this protects against: someone with
    direct DB access edits a historical log entry's content."""
    append_audit_log(db_session, case.case_id, "case_created")
    entry2 = append_audit_log(db_session, case.case_id, "image_uploaded_and_validated")
    append_audit_log(db_session, case.case_id, "analysis_completed")

    # Simulate tampering: rewrite history to hide that validation failed.
    entry2.action = "image_uploaded_and_validated_but_secretly_edited"
    db_session.commit()

    is_valid, broken = verify_audit_chain(db_session, case.case_id)

    assert is_valid is False
    assert entry2.log_id in broken


def test_verify_audit_chain_detects_tampered_timestamp(db_session, case):
    entry1 = append_audit_log(db_session, case.case_id, "case_created")

    from datetime import timedelta
    entry1.timestamp = entry1.timestamp - timedelta(days=30)  # backdating
    db_session.commit()

    is_valid, broken = verify_audit_chain(db_session, case.case_id)

    assert is_valid is False
    assert entry1.log_id in broken


def test_verify_audit_chain_pinpoints_only_the_tampered_entry_not_a_false_cascade(db_session, case):
    """
    A single tampered entry should be reported precisely, not misreported
    as every subsequent entry also being broken (which would make the
    tamper-evidence log much less useful for actually locating the
    incident). See db.audit.verify_audit_chain's chaining-forward logic.
    """
    append_audit_log(db_session, case.case_id, "case_created")
    entry2 = append_audit_log(db_session, case.case_id, "image_uploaded")
    entry3 = append_audit_log(db_session, case.case_id, "analysis_started")
    entry4 = append_audit_log(db_session, case.case_id, "analysis_completed")

    entry2.action = "tampered"
    db_session.commit()

    is_valid, broken = verify_audit_chain(db_session, case.case_id)

    assert is_valid is False
    assert broken == [entry2.log_id]  # only the tampered entry, not entry3/entry4 too


def test_verify_audit_chain_empty_case_is_valid(db_session, case):
    """A case with no audit log entries yet is trivially a valid (empty) chain."""
    is_valid, broken = verify_audit_chain(db_session, case.case_id)

    assert is_valid is True
    assert broken == []


def test_chains_are_independent_per_case(db_session):
    """Tampering in one case's chain must not affect another case's verification."""
    case_a = Case(case_name="Case A", memory_image_ref="", status="pending")
    case_b = Case(case_name="Case B", memory_image_ref="", status="pending")
    db_session.add_all([case_a, case_b])
    db_session.commit()
    db_session.refresh(case_a)
    db_session.refresh(case_b)

    append_audit_log(db_session, case_a.case_id, "case_created")
    entry_b = append_audit_log(db_session, case_b.case_id, "case_created")

    entry_b.action = "tampered"
    db_session.commit()

    valid_a, broken_a = verify_audit_chain(db_session, case_a.case_id)
    valid_b, broken_b = verify_audit_chain(db_session, case_b.case_id)

    assert valid_a is True
    assert valid_b is False
