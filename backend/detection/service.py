"""
Detection service: orchestrates the full detection pipeline for a case and
persists results to the database.

Covers FR-7, FR-8, FR-9, FR-12, FR-13, FR-15, FR-16 and
TC-DT-01 through TC-DT-05.
"""
from typing import List, Optional

from sqlalchemy.orm import Session

from analysis.volatility_wrapper import ProcessInfo, NetworkConnectionInfo, YaraMatchInfo, MalfindHit
from detection.hidden_process import find_hidden_processes, is_hidden
from detection.heuristics import evaluate_all
from detection.ioc_extractor import (
    extract_from_yara_match_infos,
    extract_from_malfind_hits,
    extract_from_suspicious_processes,
    extract_from_hidden_processes,
    extract_network_iocs,
)
from db.models import ProcessRecord, IOC
from db.audit import append_audit_log


def run_detection_pipeline(
    pslist_procs: List[ProcessInfo],
    psscan_procs: List[ProcessInfo],
    connections: List[NetworkConnectionInfo],
    yara_matches: Optional[List[YaraMatchInfo]] = None,
    malfind_hits: Optional[List[MalfindHit]] = None,
) -> dict:
    """
    Pure/testable detection pipeline (no DB access): runs hidden-process
    comparison, suspicion heuristics (including YARA and malfind linkage),
    and IOC extraction, returning a structured result dict.

    yara_matches / malfind_hits: results of live in-memory scans performed
    by the Analysis module (analysis.volatility_wrapper.run_yara_scan /
    list_malfind_hits) against the actual image. Both are optional -- if
    the corresponding Volatility plugin was unavailable or no YARA rules
    were configured, detection still runs on hidden-process + heuristic
    findings alone.
    """
    yara_matches = yara_matches or []
    malfind_hits = malfind_hits or []

    merged_processes = find_hidden_processes(pslist_procs, psscan_procs)
    hidden_pids = [p.pid for p in merged_processes if is_hidden(p)]
    malfind_pids = {hit.pid for hit in malfind_hits if hit.pid is not None}

    suspicion_results = evaluate_all(merged_processes, hidden_pids=set(hidden_pids), malfind_pids=malfind_pids)

    iocs: list = []
    iocs.extend(extract_from_hidden_processes(hidden_pids))
    iocs.extend(extract_from_suspicious_processes(suspicion_results))
    iocs.extend(extract_from_yara_match_infos(yara_matches))
    iocs.extend(extract_from_malfind_hits(malfind_hits))
    iocs.extend(extract_network_iocs(connections))

    return {
        "processes": merged_processes,
        "hidden_pids": hidden_pids,
        "malfind_pids": malfind_pids,
        "suspicion_results": suspicion_results,
        "yara_matches": yara_matches,
        "iocs": iocs,
    }


def persist_detection_results(db: Session, case_id: int, pipeline_result: dict) -> dict:
    """
    Persist processes (with is_hidden/suspicion flags), and IOCs linked to
    case_id (FR-15, FR-16, TC-DB-02).

    Process records are created first so that IOCs referencing a PID can be
    linked via the correct DB-generated process_id (not the raw memory PID,
    which is not unique across cases).

    Returns the {pid: process_id} mapping so callers (e.g. the API analyze
    pipeline) can also link modules and network connections to the same
    DB-generated process rows.
    """
    suspicion_by_pid = {r.pid: r for r in pipeline_result["suspicion_results"]}
    hidden_pids = set(pipeline_result["hidden_pids"])

    pid_to_db_id = {}
    for proc in pipeline_result["processes"]:
        suspicion = suspicion_by_pid.get(proc.pid)
        record = ProcessRecord(
            case_id=case_id,
            pid=proc.pid,
            ppid=proc.ppid,
            process_name=proc.process_name,
            is_hidden=proc.pid in hidden_pids,
            suspicion_flag=bool(suspicion and suspicion.suspicious),
            suspicion_reason=suspicion.reason if suspicion and suspicion.suspicious else None,
        )
        db.add(record)
        db.flush()  # populate record.process_id without a full commit
        pid_to_db_id[proc.pid] = record.process_id

    for ioc in pipeline_result["iocs"]:
        db.add(IOC(
            case_id=case_id,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.ioc_value,
            source=ioc.source,
            related_process_id=pid_to_db_id.get(ioc.related_process_id),
        ))

    append_audit_log(db, case_id, "detection_pipeline_completed", performed_by="system")
    db.commit()
    return pid_to_db_id
