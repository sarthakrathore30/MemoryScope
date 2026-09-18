"""
Tests for api/rate_limit.py.

These deliberately create their own isolated TestClient rather than using
the shared conftest.py fixture, since that fixture disables rate limiting
(necessary for every other test file, since the module-level in-memory
request log would otherwise accumulate across the whole pytest session).
Here we specifically want it enabled to verify the middleware itself works.
"""
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
import api.rate_limit as rate_limit_module


@pytest.fixture()
def rate_limited_client(tmp_path, monkeypatch):
    """Same isolated-DB setup as the shared client fixture, but with rate
    limiting left ENABLED and reset to a small, fast-to-hit limit."""
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

    # Reset module-level state so this test isn't affected by whatever
    # accumulated in _request_log from other tests sharing the same
    # imported module, and use small limits so the test runs fast.
    monkeypatch.setattr(rate_limit_module, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(rate_limit_module, "RATE_LIMIT_MAX_REQUESTS", 5)
    monkeypatch.setattr(rate_limit_module, "RATE_LIMIT_WINDOW_SECONDS", 60)
    monkeypatch.setattr(rate_limit_module, "RATE_LIMIT_EXPENSIVE_MAX_REQUESTS", 2)
    monkeypatch.setattr(rate_limit_module, "RATE_LIMIT_EXPENSIVE_WINDOW_SECONDS", 60)
    monkeypatch.setattr(rate_limit_module, "_request_log", rate_limit_module.defaultdict(rate_limit_module.deque))
    monkeypatch.setattr(rate_limit_module, "_expensive_request_log", rate_limit_module.defaultdict(rate_limit_module.deque))

    with TestClient(main.app) as test_client:
        yield test_client

    main.app.dependency_overrides.clear()


def test_requests_under_the_limit_all_succeed(rate_limited_client):
    for _ in range(5):
        resp = rate_limited_client.get("/health")
        assert resp.status_code == 200


def test_requests_over_the_general_limit_get_429(rate_limited_client):
    for _ in range(5):
        resp = rate_limited_client.get("/health")
        assert resp.status_code == 200

    resp = rate_limited_client.get("/health")

    assert resp.status_code == 429
    assert "rate limit" in resp.json()["detail"].lower()


def test_expensive_endpoints_have_their_own_stricter_limit(rate_limited_client):
    """
    Upload/analyze must be throttled more strictly than general traffic --
    2 requests allowed (test config) even though the general limit (5)
    hasn't been reached yet.
    """
    resp1 = rate_limited_client.post("/api/cases", json={"case_name": "Case 1"})
    resp2 = rate_limited_client.post("/api/cases", json={"case_name": "Case 2"})
    assert resp1.status_code == 201
    assert resp2.status_code == 201
    case_id = resp1.json()["case_id"]

    import io
    file1 = io.BytesIO(b"\x00" * (2 * 1024 * 1024))
    file2 = io.BytesIO(b"\x00" * (2 * 1024 * 1024))

    r1 = rate_limited_client.post(f"/api/cases/{case_id}/upload", files={"file": ("a.raw", file1)})
    r2 = rate_limited_client.post(f"/api/cases/{case_id}/upload", files={"file": ("b.raw", file2)})
    assert r1.status_code in (200, 400)  # either validates or fails validation, but isn't rate-limited yet
    assert r2.status_code in (200, 400)

    file3 = io.BytesIO(b"\x00" * (2 * 1024 * 1024))
    r3 = rate_limited_client.post(f"/api/cases/{case_id}/upload", files={"file": ("c.raw", file3)})

    assert r3.status_code == 429


def test_health_check_not_affected_by_expensive_endpoint_limit(rate_limited_client):
    """Hitting the expensive-endpoint limit must not throttle unrelated general traffic."""
    resp = rate_limited_client.post("/api/cases", json={"case_name": "Case"})
    case_id = resp.json()["case_id"]

    import io
    for i in range(2):
        f = io.BytesIO(b"\x00" * (2 * 1024 * 1024))
        rate_limited_client.post(f"/api/cases/{case_id}/upload", files={"file": (f"f{i}.raw", f)})

    # Expensive limit (2) is now exhausted, but general traffic should still work.
    resp = rate_limited_client.get("/health")
    assert resp.status_code == 200


def test_rate_limiting_disabled_flag_bypasses_all_limits(rate_limited_client, monkeypatch):
    monkeypatch.setattr(rate_limit_module, "RATE_LIMIT_ENABLED", False)

    for _ in range(20):
        resp = rate_limited_client.get("/health")
        assert resp.status_code == 200
