"""
Unit tests for the Acquisition Module, mapped to TESTING_PLAN.docx:

  TC-AC-01: Upload valid memory image -> accepted, case created, status pending
  TC-AC-02: Upload corrupted/invalid file -> rejected with clear error
  TC-AC-03: Upload unsupported file type -> rejected with 'unsupported format'
  TC-AC-04: OS profile detection (smoke-tested separately; requires a real image)
"""
import hashlib
import io
import os
import sys

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from db.database import Base
from db import models  # noqa: F401 ensures models are registered on Base
from acquisition import service
from acquisition.exceptions import UnsupportedFormatError, CorruptedImageError


@pytest.fixture()
def db_session(tmp_path):
    """Isolated in-memory SQLite DB per test."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()
    yield session
    session.close()


@pytest.fixture()
def upload_dir(tmp_path, monkeypatch):
    d = tmp_path / "uploads"
    d.mkdir()
    monkeypatch.setattr(service, "UPLOAD_DIR", str(d))
    return str(d)


def test_tc_ac_01_valid_memory_image_accepted(db_session, upload_dir):
    case = service.create_case(db_session, "Test Case 01")
    assert case.status == "pending"

    # 2 MB of dummy bytes to pass the size heuristic; real content validation
    # of actual memory structures happens downstream in the Analysis module.
    fake_image = io.BytesIO(b"\x00" * (2 * 1024 * 1024))
    saved = service.save_uploaded_file(case, "sample.raw", fake_image)

    updated_case = service.validate_and_register_image(db_session, case, "sample.raw", saved)

    assert updated_case.status == "pending"
    assert updated_case.memory_image_ref == saved.path
    assert os.path.exists(saved.path)


def test_tc_ac_02_corrupted_truncated_file_rejected(db_session, upload_dir):
    case = service.create_case(db_session, "Test Case 02")

    # Truncated file: well under the minimum valid size threshold.
    tiny_file = io.BytesIO(b"\x00" * 100)
    saved = service.save_uploaded_file(case, "truncated.raw", tiny_file)

    with pytest.raises(CorruptedImageError):
        service.validate_and_register_image(db_session, case, "truncated.raw", saved)

    db_session.refresh(case)
    assert case.status == "failed"
    assert not os.path.exists(saved.path)  # rejected file should be cleaned up


def test_tc_ac_03_unsupported_file_type_rejected(db_session, upload_dir):
    case = service.create_case(db_session, "Test Case 03")

    fake_file = io.BytesIO(b"just some text content" * 1000)
    saved = service.save_uploaded_file(case, "notes.txt", fake_file)

    with pytest.raises(UnsupportedFormatError):
        service.validate_and_register_image(db_session, case, "notes.txt", saved)

    db_session.refresh(case)
    assert case.status == "failed"
    assert not os.path.exists(saved.path)


def test_empty_file_rejected(db_session, upload_dir):
    case = service.create_case(db_session, "Test Case Empty")
    empty_file = io.BytesIO(b"")
    saved = service.save_uploaded_file(case, "empty.mem", empty_file)

    with pytest.raises(CorruptedImageError):
        service.validate_and_register_image(db_session, case, "empty.mem", saved)


def test_oversized_upload_aborted_during_streaming(db_session, upload_dir, monkeypatch):
    """
    Enforces the max-size limit DURING the streaming write, not just after
    the full file has already been written to disk -- so an oversized
    upload is aborted early instead of first consuming disk space for the
    entire transfer. Uses a small monkeypatched limit + small chunk size so
    the test doesn't need to actually write gigabytes of data.
    """
    monkeypatch.setattr(service, "MAX_VALID_SIZE_BYTES", 1024)  # 1 KB limit for this test
    monkeypatch.setattr(service, "_COPY_CHUNK_SIZE", 256)  # small chunks so the limit is hit mid-stream

    case = service.create_case(db_session, "Test Case Oversized")
    oversized_file = io.BytesIO(b"\x00" * (10 * 1024))  # 10 KB, well over the 1 KB test limit

    with pytest.raises(CorruptedImageError, match="exceeded the maximum accepted size"):
        service.save_uploaded_file(case, "huge.raw", oversized_file)

    # The partial file must be cleaned up, not left behind consuming disk space.
    leftover_files = os.listdir(service.UPLOAD_DIR)
    assert leftover_files == []


def test_file_at_exactly_max_size_boundary_is_accepted(db_session, upload_dir, monkeypatch):
    """Boundary check: a file exactly at the limit must be accepted, not rejected."""
    monkeypatch.setattr(service, "MAX_VALID_SIZE_BYTES", 1024)
    monkeypatch.setattr(service, "_COPY_CHUNK_SIZE", 256)

    case = service.create_case(db_session, "Test Case Exact Boundary")
    exact_file = io.BytesIO(b"\x00" * 1024)  # exactly at the limit

    saved = service.save_uploaded_file(case, "exact.raw", exact_file)

    assert os.path.exists(saved.path)
    assert os.path.getsize(saved.path) == 1024


# ---------------------------------------------------------------------------
# Chain-of-custody: SHA256/MD5 hash computation (real gap found via security
# review -- forensic evidence needs cryptographic integrity hashes to prove
# the analyzed image is bit-for-bit identical to what was acquired).
# ---------------------------------------------------------------------------

def test_save_uploaded_file_computes_correct_sha256_and_md5(db_session, upload_dir):
    content = b"\x00\x01\x02\x03" * (1024 * 512)  # 2 MB of deterministic content
    expected_sha256 = hashlib.sha256(content).hexdigest()
    expected_md5 = hashlib.md5(content).hexdigest()

    case = service.create_case(db_session, "Hash Test Case")
    saved = service.save_uploaded_file(case, "sample.raw", io.BytesIO(content))

    assert saved.sha256_hash == expected_sha256
    assert saved.md5_hash == expected_md5


def test_hashes_persisted_on_case_after_successful_validation(db_session, upload_dir):
    content = b"\xAA\xBB\xCC\xDD" * (1024 * 512)
    expected_sha256 = hashlib.sha256(content).hexdigest()

    case = service.create_case(db_session, "Hash Persistence Test")
    saved = service.save_uploaded_file(case, "sample.raw", io.BytesIO(content))
    updated_case = service.validate_and_register_image(db_session, case, "sample.raw", saved)

    assert updated_case.sha256_hash == expected_sha256
    assert updated_case.md5_hash == saved.md5_hash
    assert len(updated_case.sha256_hash) == 64  # SHA-256 hex digest length
    assert len(updated_case.md5_hash) == 32  # MD5 hex digest length


def test_hashes_not_persisted_when_validation_fails(db_session, upload_dir):
    """A rejected (e.g. too-small) file's hashes must not end up on the case record."""
    case = service.create_case(db_session, "Hash Rejection Test")
    tiny_file = io.BytesIO(b"\x00" * 100)
    saved = service.save_uploaded_file(case, "truncated.raw", tiny_file)

    with pytest.raises(CorruptedImageError):
        service.validate_and_register_image(db_session, case, "truncated.raw", saved)

    db_session.refresh(case)
    assert case.sha256_hash is None
    assert case.md5_hash is None


# ---------------------------------------------------------------------------
# Magic-byte/signature validation (real gap found via security review: file
# validation previously relied on extension alone). Necessarily partial --
# raw physical memory dumps have no defined header at all, so only formats
# with an actual documented signature (.dmp, .lime) can be checked.
# ---------------------------------------------------------------------------

def test_dmp_with_valid_pagedump_signature_accepted(db_session, upload_dir):
    case = service.create_case(db_session, "Valid Crash Dump")
    content = b"PAGEDU64" + b"\x00" * (2 * 1024 * 1024)
    saved = service.save_uploaded_file(case, "memory.dmp", io.BytesIO(content))

    updated_case = service.validate_and_register_image(db_session, case, "memory.dmp", saved)

    assert updated_case.status == "pending"


def test_dmp_with_wrong_signature_rejected(db_session, upload_dir):
    """An executable or other file type renamed to .dmp must be caught by
    the signature check, not silently accepted based on extension alone."""
    case = service.create_case(db_session, "Fake Crash Dump")
    content = b"MZ\x90\x00" + b"\x00" * (2 * 1024 * 1024)  # PE/EXE header, not a crash dump
    saved = service.save_uploaded_file(case, "totally_a_dump.dmp", io.BytesIO(content))

    with pytest.raises(UnsupportedFormatError, match="valid .dmp header signature"):
        service.validate_and_register_image(db_session, case, "totally_a_dump.dmp", saved)

    db_session.refresh(case)
    assert case.status == "failed"


def test_dmp_32bit_signature_also_accepted(db_session, upload_dir):
    case = service.create_case(db_session, "32-bit Crash Dump")
    content = b"PAGEDUMP" + b"\x00" * (2 * 1024 * 1024)
    saved = service.save_uploaded_file(case, "memory32.dmp", io.BytesIO(content))

    updated_case = service.validate_and_register_image(db_session, case, "memory32.dmp", saved)

    assert updated_case.status == "pending"


def test_raw_extension_has_no_signature_requirement(db_session, upload_dir):
    """
    Raw physical memory dumps have no defined file header -- signature
    validation must be silently skipped for this extension, not rejected
    for 'missing' a signature that fundamentally doesn't exist for this
    format.
    """
    case = service.create_case(db_session, "Raw Dump No Signature")
    content = b"\x00" * (2 * 1024 * 1024)  # no particular header, as real RAM dumps have
    saved = service.save_uploaded_file(case, "memory.raw", io.BytesIO(content))

    updated_case = service.validate_and_register_image(db_session, case, "memory.raw", saved)

    assert updated_case.status == "pending"
