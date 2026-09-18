"""
ORM models for the Memory Forensics Platform.

Mirrors the schema defined in DATABASE_SCHEMA_DOCUMENT.docx:
cases -> processes -> (modules, network_connections)
cases -> iocs, reports, audit_logs
"""
import json

from sqlalchemy import (
    Column, Integer, String, Boolean, Float, Text, DateTime, ForeignKey, Index
)
from sqlalchemy.orm import relationship

from db.database import Base, utcnow


class Case(Base):
    __tablename__ = "cases"

    case_id = Column(Integer, primary_key=True, autoincrement=True)
    case_name = Column(String(255), nullable=False)
    memory_image_ref = Column(String(500), nullable=False)
    sha256_hash = Column(String(64), nullable=True)
    md5_hash = Column(String(32), nullable=True)
    os_profile = Column(String(100), nullable=True)
    system_metadata = Column(Text, nullable=True)  # JSON-encoded dict; see analysis.volatility_wrapper.extract_system_metadata
    status = Column(String(50), default="pending")  # pending/analyzing/completed/failed
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, nullable=True, onupdate=utcnow)

    processes = relationship("ProcessRecord", back_populates="case", cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="case", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="case", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="case", cascade="all, delete-orphan")

    @property
    def has_memory_image(self) -> bool:
        """
        Whether a memory image has been uploaded for this case, without
        exposing the actual server filesystem path (memory_image_ref) to
        API clients -- the absolute path reveals server directory structure
        (and, on a typical dev machine, the OS username in the path), which
        is unnecessary information disclosure. See api.schemas.CaseOut,
        which exposes this property instead of the raw path.
        """
        return bool(self.memory_image_ref)

    @property
    def system_info(self) -> dict:
        """
        Parsed view of system_metadata (stored as a raw JSON string column)
        for API consumption -- named differently from the column itself so
        Pydantic's from_attributes can expose a dict-typed field without
        colliding with the underlying string column of the same concept.
        See analysis.volatility_wrapper.extract_system_metadata.
        """
        if not self.system_metadata:
            return {}
        try:
            return json.loads(self.system_metadata)
        except (json.JSONDecodeError, TypeError):
            return {}


class ProcessRecord(Base):
    __tablename__ = "processes"

    process_id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.case_id"), nullable=False)
    pid = Column(Integer, nullable=False)
    ppid = Column(Integer, nullable=True)
    process_name = Column(String(255), nullable=False)
    create_time = Column(DateTime, nullable=True)
    is_hidden = Column(Boolean, default=False)
    suspicion_flag = Column(Boolean, default=False)
    suspicion_reason = Column(Text, nullable=True)
    risk_score = Column(Float, nullable=True)  # reserved for future ML scoring

    case = relationship("Case", back_populates="processes")
    modules = relationship("Module", back_populates="process", cascade="all, delete-orphan")
    network_connections = relationship(
        "NetworkConnection", back_populates="process", cascade="all, delete-orphan"
    )
    iocs = relationship("IOC", back_populates="related_process")

    __table_args__ = (
        # Fast lookup of processes per case (DATABASE_SCHEMA_DOCUMENT.docx section 6).
        Index("ix_processes_case_id_pid", "case_id", "pid"),
    )


class Module(Base):
    __tablename__ = "modules"

    module_id = Column(Integer, primary_key=True, autoincrement=True)
    process_id = Column(Integer, ForeignKey("processes.process_id"), nullable=False, index=True)
    dll_name = Column(String(255), nullable=False)
    base_address = Column(String(50), nullable=True)
    module_size = Column(Integer, nullable=True)
    is_suspicious = Column(Boolean, default=False)

    process = relationship("ProcessRecord", back_populates="modules")


class NetworkConnection(Base):
    __tablename__ = "network_connections"

    conn_id = Column(Integer, primary_key=True, autoincrement=True)
    process_id = Column(Integer, ForeignKey("processes.process_id"), nullable=False, index=True)
    local_ip = Column(String(45), nullable=True)
    local_port = Column(Integer, nullable=True)
    remote_ip = Column(String(45), nullable=True)
    remote_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    state = Column(String(50), nullable=True)

    process = relationship("ProcessRecord", back_populates="network_connections")


class IOC(Base):
    __tablename__ = "iocs"

    ioc_id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.case_id"), nullable=False)
    ioc_type = Column(String(50), nullable=False)  # ip, domain, hash, yara_rule
    ioc_value = Column(String(500), nullable=False)
    source = Column(String(255), nullable=True)
    related_process_id = Column(Integer, ForeignKey("processes.process_id"), nullable=True)
    detected_at = Column(DateTime, default=utcnow)

    case = relationship("Case", back_populates="iocs")
    related_process = relationship("ProcessRecord", back_populates="iocs")

    __table_args__ = (
        # Fast filtering by IOC type per case (DATABASE_SCHEMA_DOCUMENT.docx section 6).
        Index("ix_iocs_case_id_ioc_type", "case_id", "ioc_type"),
    )


class Report(Base):
    __tablename__ = "reports"

    report_id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.case_id"), nullable=False)
    file_path = Column(String(500), nullable=False)
    format = Column(String(10), nullable=False)  # PDF / JSON
    generated_at = Column(DateTime, default=utcnow)

    case = relationship("Case", back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    log_id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.case_id"), nullable=False)
    action = Column(String(255), nullable=False)
    performed_by = Column(String(100), nullable=True)
    timestamp = Column(DateTime, default=utcnow)
    # Tamper-evidence hash chain: sha256(previous_record_hash + this
    # record's own content). Modifying, deleting, or reordering any
    # historical entry breaks its own hash and every hash after it in the
    # chain for this case, making tampering with the chain-of-custody
    # trail detectable. See db.audit.append_audit_log / verify_audit_chain
    # -- always create AuditLog rows through append_audit_log, never
    # construct this model directly, or the chain will have a gap.
    record_hash = Column(String(64), nullable=True)

    case = relationship("Case", back_populates="audit_logs")

    __table_args__ = (
        # Fast retrieval of chronological logs (DATABASE_SCHEMA_DOCUMENT.docx section 6).
        Index("ix_audit_logs_case_id_timestamp", "case_id", "timestamp"),
    )
