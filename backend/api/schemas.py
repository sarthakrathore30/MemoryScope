"""Pydantic schemas for API request/response bodies."""
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class CaseCreate(BaseModel):
    case_name: str


class CaseRename(BaseModel):
    case_name: str


class AuditLogEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    log_id: int
    action: str
    performed_by: Optional[str] = None
    timestamp: Optional[datetime] = None


class AuditChainVerification(BaseModel):
    is_valid: bool
    entry_count: int
    broken_log_ids: List[int] = []


class CaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: int
    case_name: str
    has_memory_image: bool = False
    sha256_hash: Optional[str] = None
    md5_hash: Optional[str] = None
    os_profile: Optional[str] = None
    system_info: dict = {}
    status: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ProcessOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    process_id: int
    pid: int
    ppid: Optional[int] = None
    process_name: str
    is_hidden: bool
    suspicion_flag: bool
    suspicion_reason: Optional[str] = None


class ModuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    module_id: int
    process_id: int
    dll_name: str
    base_address: Optional[str] = None
    module_size: Optional[int] = None
    is_suspicious: bool


class NetworkConnectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    conn_id: int
    process_id: int
    local_ip: Optional[str] = None
    local_port: Optional[int] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: Optional[str] = None
    state: Optional[str] = None


class IOCOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ioc_id: int
    ioc_type: str
    ioc_value: str
    source: Optional[str] = None
    related_process_id: Optional[int] = None
    detected_at: Optional[datetime] = None


class CaseResultsOut(BaseModel):
    case: CaseOut
    processes: List[ProcessOut]
    modules: List[ModuleOut]
    network_connections: List[NetworkConnectionOut]
    iocs: List[IOCOut]


class UploadResponse(BaseModel):
    case: CaseOut
    message: str


class AnalyzeResponse(BaseModel):
    case: CaseOut
    message: str
    process_count: int
    ioc_count: int
    warnings: List[str] = []


class ErrorResponse(BaseModel):
    detail: str
