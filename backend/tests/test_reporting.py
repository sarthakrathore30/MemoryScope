"""
Unit tests for reporting/service.py.

Covers TC-RP-01/02/03 and a regression test for a real bug found via a
security review: ReportLab's Paragraph text is parsed as a small XML-like
markup language, so unescaped user-controlled content (most notably a case
name, which is fully user-controlled at case creation) could be silently
corrupted or have content stripped when rendered into a PDF report -- a
forensic report integrity problem, not just a cosmetic one.
"""
import os
import sys

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from db.database import Base
from db import models  # noqa: F401
from db.models import Case, ProcessRecord, IOC
from reporting.service import _safe, generate_pdf_report, generate_json_report, build_report_data


@pytest.fixture()
def db_session(tmp_path):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


# ---------------------------------------------------------------------------
# _safe(): the actual escaping logic
# ---------------------------------------------------------------------------

def test_safe_escapes_xml_special_characters():
    assert _safe("AT&T Investigation") == "AT&amp;T Investigation"
    assert _safe("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert _safe("normal text") == "normal text"


def test_safe_handles_none():
    assert _safe(None) == ""


def test_safe_converts_non_strings():
    assert _safe(123) == "123"
    assert _safe(True) == "True"


# ---------------------------------------------------------------------------
# Regression test: case names with XML special characters must not corrupt
# or crash PDF generation
# ---------------------------------------------------------------------------

def test_pdf_report_with_special_characters_in_case_name_does_not_crash(db_session, tmp_path, monkeypatch):
    import reporting.service as reporting_service
    monkeypatch.setattr(reporting_service, "REPORTS_DIR", str(tmp_path))

    case = Case(
        case_name="AT&T Investigation <script>alert(1)</script>",
        memory_image_ref="/uploads/x.vmem",
        status="completed",
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)

    proc = ProcessRecord(
        case_id=case.case_id, pid=1, ppid=0,
        process_name="evil<b>bold</b>.exe",
        is_hidden=True, suspicion_flag=True,
        suspicion_reason="Contains & an ampersand and <tags>",
    )
    db_session.add(proc)
    db_session.commit()
    db_session.refresh(proc)

    db_session.add(IOC(
        case_id=case.case_id, ioc_type="ip", ioc_value="1.2.3.4 & friends",
        source="<injected>source</injected>", related_process_id=proc.process_id,
    ))
    db_session.commit()

    # Must not raise -- this is the actual regression being guarded against.
    file_path = generate_pdf_report(db_session, case)

    assert os.path.exists(file_path)
    assert os.path.getsize(file_path) > 0

    # Verify the rendered text is the literal, uncorrupted original content
    # (not silently mangled/stripped), using an independent PDF text
    # extractor rather than trusting our own escaping logic circularly.
    # Checking for key literal fragments rather than one long unbroken
    # substring, since PDF table-cell word-wrap can insert whitespace
    # mid-word for unusually long strings -- a layout artifact, not data
    # corruption (the underlying content passed to Paragraph is correct).
    from pypdf import PdfReader
    reader = PdfReader(file_path)
    full_text = "\n".join(page.extract_text() for page in reader.pages)
    normalized = " ".join(full_text.split())

    assert "AT&T Investigation <script>alert(1)</script>" in normalized
    assert "evil<b>bold</b>" in normalized  # the tags themselves must survive literally, not be stripped
    assert "Contains & an ampersand and <tags>" in normalized
    assert "1.2.3.4 & friends" in normalized
    assert "<injected>source</injected>" in normalized


def test_json_report_with_special_characters_preserves_content_exactly(db_session, tmp_path, monkeypatch):
    """JSON has no markup-parsing concern, but confirm content survives exactly regardless."""
    import reporting.service as reporting_service
    monkeypatch.setattr(reporting_service, "REPORTS_DIR", str(tmp_path))

    case = Case(
        case_name="AT&T Investigation <script>alert(1)</script>",
        memory_image_ref="/uploads/x.vmem",
        status="completed",
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)

    file_path = generate_json_report(db_session, case)

    import json
    with open(file_path) as f:
        report = json.load(f)

    assert report["case"]["case_name"] == "AT&T Investigation <script>alert(1)</script>"
