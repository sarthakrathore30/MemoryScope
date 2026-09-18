"""
IOC (Indicator of Compromise) extraction (FR-13, TC-DT-05).

Converts detection outputs (YARA matches, suspicious heuristic flags, and
hidden-process findings) into a normalized list of IOC dicts ready to be
persisted by the Case/Data Management layer as `iocs` table rows, each
linked to a case_id and optionally a related_process_id.
"""
from dataclasses import dataclass
from typing import List, Optional

from detection.yara_scanner import YaraMatch
from detection.heuristics import SuspicionResult


@dataclass
class IOCRecord:
    ioc_type: str          # ip, domain, hash, yara_rule
    ioc_value: str
    source: Optional[str] = None
    related_process_id: Optional[int] = None  # PID at extraction time; API layer maps to DB process_id


def extract_from_yara_matches(matches: List[YaraMatch], pid: Optional[int] = None) -> List[IOCRecord]:
    """Build IOC records from YARA rule matches (one IOC per matched rule)."""
    iocs = []
    for match in matches:
        iocs.append(IOCRecord(
            ioc_type="yara_rule",
            ioc_value=match.rule_name,
            source=f"YARA:{match.rule_name}",
            related_process_id=pid,
        ))
    return iocs


def extract_from_yara_match_infos(matches: list) -> List[IOCRecord]:
    """
    Build IOC records from live in-memory YARA scan results
    (analysis.volatility_wrapper.YaraMatchInfo), produced by scanning actual
    process memory regions inside the image via Volatility's own
    vadyarascan/vmayarascan plugins (FR-12, FR-13, TC-DT-02).
    """
    iocs = []
    for match in matches:
        iocs.append(IOCRecord(
            ioc_type="yara_rule",
            ioc_value=match.rule_name,
            source=f"YARA:{match.rule_name} @ {match.address}" if match.address else f"YARA:{match.rule_name}",
            related_process_id=match.pid,
        ))
    return iocs


def extract_from_malfind_hits(hits: list) -> List[IOCRecord]:
    """
    Build IOC records from anomalous memory regions detected by malfind
    (SRS FR-8's "anomalous memory regions" criterion) -- typically private,
    executable memory not backed by any file on disk, the classic signature
    of process hollowing or reflective code injection.
    """
    iocs = []
    for hit in hits:
        detail = f"address {hit.address}" if hit.address else "unspecified address"
        if hit.protection:
            detail += f", protection {hit.protection}"
        iocs.append(IOCRecord(
            ioc_type="anomalous_memory_region",
            ioc_value=str(hit.pid),
            source=f"malfind: {detail}",
            related_process_id=hit.pid,
        ))
    return iocs


def extract_from_suspicious_processes(results: List[SuspicionResult]) -> List[IOCRecord]:
    """Build IOC records from suspicious-process heuristic flags."""
    iocs = []
    for r in results:
        if r.suspicious:
            iocs.append(IOCRecord(
                ioc_type="suspicious_process",
                ioc_value=str(r.pid),
                source=r.reason,
                related_process_id=r.pid,
            ))
    return iocs


def extract_from_hidden_processes(hidden_pids: List[int]) -> List[IOCRecord]:
    """Build IOC records for processes flagged as hidden/unlinked."""
    return [
        IOCRecord(
            ioc_type="hidden_process",
            ioc_value=str(pid),
            source="pslist_vs_psscan_diff",
            related_process_id=pid,
        )
        for pid in hidden_pids
    ]


def extract_network_iocs(connections: list) -> List[IOCRecord]:
    """
    Build IOC records from remote IPs seen in extracted network connections.
    (Basic version: every non-empty remote IP becomes a candidate IOC; a
    future ML/threat-intel module can filter these down to only malicious ones.)
    """
    iocs = []
    seen = set()
    for conn in connections:
        remote_ip = getattr(conn, "remote_ip", None)
        if remote_ip and remote_ip not in seen and remote_ip not in ("0.0.0.0", "*", "::"):
            seen.add(remote_ip)
            iocs.append(IOCRecord(
                ioc_type="ip",
                ioc_value=remote_ip,
                source="network_connections",
                related_process_id=getattr(conn, "pid", None),
            ))
    return iocs
