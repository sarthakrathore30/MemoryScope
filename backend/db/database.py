"""
Database engine and session configuration.

Uses SQLite for development. Because SQLAlchemy's ORM abstracts the dialect,
switching to PostgreSQL in production only requires changing DATABASE_URL
(e.g. postgresql+psycopg2://user:pass@host/dbname) -- no model/query changes.
"""
import os
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Default to a local SQLite file; override with env var for tests/production.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./memforensics.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def utcnow() -> datetime:
    """
    Return the current UTC time as a naive datetime (no tzinfo), matching the
    storage convention of the existing DateTime columns (which are not
    timezone-aware). Using datetime.now(timezone.utc) internally avoids the
    deprecation warning on datetime.utcnow() while keeping stored values
    identical in shape to before.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def get_db():
    """FastAPI dependency that yields a DB session and ensures it's closed."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables. Safe to call multiple times (no-op if tables exist)."""
    # Import models here so they're registered on Base.metadata before create_all.
    from db import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
