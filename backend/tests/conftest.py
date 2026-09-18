"""Shared pytest fixtures for API/E2E integration tests."""
import io
import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from db.database import Base, get_db
from db import models  # noqa: F401
import main


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Spin up the FastAPI app against an isolated SQLite file DB and temp upload/report dirs."""
    db_path = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[get_db] = override_get_db

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()

    import acquisition.service as acquisition_service
    import reporting.service as reporting_service
    import api.rate_limit as rate_limit_module
    monkeypatch.setattr(acquisition_service, "UPLOAD_DIR", str(upload_dir))
    monkeypatch.setattr(reporting_service, "REPORTS_DIR", str(reports_dir))
    # Rate limiting's in-memory request log is a module-level global that
    # persists across every test in this pytest run (Python caches the
    # module import) -- without disabling it here, tests would start
    # failing with 429s once enough requests had accumulated across the
    # whole test session, entirely unrelated to what any individual test
    # is actually checking.
    monkeypatch.setattr(rate_limit_module, "RATE_LIMIT_ENABLED", False)

    with TestClient(main.app) as test_client:
        test_client.upload_dir = upload_dir  # exposed for tests that need to inspect files on disk
        test_client.reports_dir = reports_dir
        yield test_client

    main.app.dependency_overrides.clear()


def create_case(client, name="Integration Test Case"):
    resp = client.post("/api/cases", json={"case_name": name})
    assert resp.status_code == 201
    return resp.json()


def upload_valid_image(client, case_id, size_mb=2, filename="sample.raw"):
    fake_image = io.BytesIO(b"\x00" * (size_mb * 1024 * 1024))
    return client.post(
        f"/api/cases/{case_id}/upload",
        files={"file": (filename, fake_image, "application/octet-stream")},
    )
