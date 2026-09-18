"""
Reporting Module: aggregates case data into structured forensic reports and
exports them as JSON or PDF (FR-17, FR-18, TC-RP-01..03).
"""
import json
import os
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from db.database import utcnow
from db.models import Case, ProcessRecord, IOC, NetworkConnection, Module, Report

REPORTS_DIR = os.getenv(
    "REPORTS_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "reports")
)

# Explicit display labels for summary metrics -- avoids blindly title-casing
# keys, which mangles acronyms (e.g. "total_iocs".title() -> "Total Iocs").
SUMMARY_LABELS = {
    "total_processes": "Total Processes",
    "hidden_processes": "Hidden Processes",
    "suspicious_processes": "Suspicious Processes",
    "total_iocs": "Total IOCs",
    "total_network_connections": "Total Network Connections",
    "total_modules": "Total Modules",
}


class ReportingError(Exception):
    """Raised when a report cannot be generated (e.g. case not analyzed yet)."""


def _safe(value) -> str:
    """
    Escape a value for safe insertion into a ReportLab Paragraph.

    ReportLab's Paragraph text is parsed as a small XML-like markup language
    (supporting tags like <b>, <font>, <br/>). Any dynamic content containing
    XML special characters -- most notably a case name someone typed in,
    which is fully user-controlled -- can corrupt the rendered report:
    "AT&T Investigation" silently renders as "AT&T; Investigation" (the bare
    "&" gets parsed as a malformed entity), and unrecognized tags like
    "<script>" are silently stripped along with their content. For a
    forensics report, silently corrupting or dropping evidence text is a
    real integrity problem, not just a cosmetic one -- escape everything
    dynamic before it reaches a Paragraph.
    """
    if value is None:
        return ""
    return xml_escape(str(value))


def _ensure_reports_dir() -> None:
    os.makedirs(REPORTS_DIR, exist_ok=True)


def build_report_data(db: Session, case: Case) -> dict:
    """
    Aggregate all stored artifacts for a case into a single structured dict
    (FR-17). This is the single source of truth consumed by both the JSON
    and PDF exporters, guaranteeing their counts always match (TC-RP-03).
    """
    processes = db.query(ProcessRecord).filter(ProcessRecord.case_id == case.case_id).all()
    iocs = db.query(IOC).filter(IOC.case_id == case.case_id).all()
    process_ids = [p.process_id for p in processes]
    connections = (
        db.query(NetworkConnection).filter(NetworkConnection.process_id.in_(process_ids)).all()
        if process_ids else []
    )
    modules = (
        db.query(Module).filter(Module.process_id.in_(process_ids)).all()
        if process_ids else []
    )

    hidden_processes = [p for p in processes if p.is_hidden]
    suspicious_processes = [p for p in processes if p.suspicion_flag]

    return {
        "case": {
            "case_id": case.case_id,
            "case_name": case.case_name,
            "os_profile": case.os_profile,
            "status": case.status,
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "sha256_hash": case.sha256_hash,
            "md5_hash": case.md5_hash,
        },
        "summary": {
            "total_processes": len(processes),
            "hidden_processes": len(hidden_processes),
            "suspicious_processes": len(suspicious_processes),
            "total_iocs": len(iocs),
            "total_network_connections": len(connections),
            "total_modules": len(modules),
        },
        "processes": [
            {
                "pid": p.pid,
                "ppid": p.ppid,
                "process_name": p.process_name,
                "is_hidden": p.is_hidden,
                "suspicion_flag": p.suspicion_flag,
                "suspicion_reason": p.suspicion_reason,
            }
            for p in processes
        ],
        "iocs": [
            {
                "ioc_type": i.ioc_type,
                "ioc_value": i.ioc_value,
                "source": i.source,
                "related_process_id": i.related_process_id,
                "detected_at": i.detected_at.isoformat() if i.detected_at else None,
            }
            for i in iocs
        ],
        "network_connections": [
            {
                "process_id": c.process_id,
                "local_ip": c.local_ip,
                "local_port": c.local_port,
                "remote_ip": c.remote_ip,
                "remote_port": c.remote_port,
                "protocol": c.protocol,
                "state": c.state,
            }
            for c in connections
        ],
        "generated_at": utcnow().isoformat(),
    }


def generate_json_report(db: Session, case: Case) -> str:
    """Generate a JSON report file and record it in the reports table. Returns the file path."""
    _ensure_reports_dir()
    data = build_report_data(db, case)

    filename = f"case_{case.case_id}_report_{int(utcnow().timestamp())}.json"
    file_path = os.path.abspath(os.path.join(REPORTS_DIR, filename))

    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

    record = Report(case_id=case.case_id, file_path=file_path, format="JSON")
    db.add(record)
    db.commit()
    return file_path


def generate_pdf_report(db: Session, case: Case) -> str:
    """Generate a PDF report file summarizing key findings and record it in the reports table."""
    _ensure_reports_dir()
    data = build_report_data(db, case)

    filename = f"case_{case.case_id}_report_{int(utcnow().timestamp())}.pdf"
    file_path = os.path.abspath(os.path.join(REPORTS_DIR, filename))

    styles = getSampleStyleSheet()
    cell_style = ParagraphStyle("cell", parent=styles["Normal"], fontSize=8, leading=10)
    header_style = ParagraphStyle("header", parent=styles["Normal"], fontSize=8, leading=10, textColor=colors.white)

    doc = SimpleDocTemplate(file_path, pagesize=letter, leftMargin=48, rightMargin=48)
    usable_width = letter[0] - 96  # page width minus left+right margins
    story = []

    story.append(Paragraph("Memory Forensics Investigation Report", styles["Title"]))
    story.append(Spacer(1, 12))

    case_info = data["case"]
    story.append(Paragraph(f"Case: {_safe(case_info['case_name'])} (ID: {case_info['case_id']})", styles["Heading2"]))
    story.append(Paragraph(f"OS Profile: {_safe(case_info['os_profile']) or 'Unknown'}", styles["Normal"]))
    story.append(Paragraph(f"Status: {_safe(case_info['status'])}", styles["Normal"]))
    story.append(Paragraph(f"Generated: {_safe(data['generated_at'])}", styles["Normal"]))
    if case_info.get("sha256_hash"):
        story.append(Paragraph(f"SHA-256: {_safe(case_info['sha256_hash'])}", styles["Normal"]))
    if case_info.get("md5_hash"):
        story.append(Paragraph(f"MD5: {_safe(case_info['md5_hash'])}", styles["Normal"]))
    story.append(Spacer(1, 16))

    summary = data["summary"]
    story.append(Paragraph("Summary", styles["Heading2"]))
    summary_table_data = [["Metric", "Count"]] + [
        [SUMMARY_LABELS.get(k, k.replace("_", " ").title()), str(v)] for k, v in summary.items()
    ]
    summary_table = Table(summary_table_data, hAlign="LEFT", colWidths=[220, 80])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Flagged Processes (Hidden or Suspicious)", styles["Heading2"]))
    flagged = [p for p in data["processes"] if p["is_hidden"] or p["suspicion_flag"]]
    if flagged:
        # Fixed columns for PID/PPID/Hidden/Suspicious; Name and Reason share
        # the remaining width and wrap via Paragraph so nothing is silently
        # cut off (TC-RP-01: report must contain all key findings).
        fixed_width = 40 + 40 + 45 + 60
        remaining = usable_width - fixed_width
        name_width = remaining * 0.25
        reason_width = remaining * 0.75

        proc_table_data = [["PID", "PPID", "Name", "Hidden", "Suspicious", "Reason"]]
        for p in flagged:
            proc_table_data.append([
                str(p["pid"]), str(p["ppid"]),
                Paragraph(_safe(p["process_name"]), cell_style),
                "Yes" if p["is_hidden"] else "No",
                "Yes" if p["suspicion_flag"] else "No",
                Paragraph(_safe(p["suspicion_reason"]), cell_style),
            ])
        proc_table = Table(proc_table_data, hAlign="LEFT", colWidths=[40, 40, name_width, 45, 60, reason_width])
        proc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(proc_table)
    else:
        story.append(Paragraph("No hidden or suspicious processes detected.", styles["Normal"]))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Indicators of Compromise (IOCs)", styles["Heading2"]))
    if data["iocs"]:
        type_width = usable_width * 0.2
        value_width = usable_width * 0.4
        source_width = usable_width * 0.4

        ioc_table_data = [["Type", "Value", "Source"]]
        for i in data["iocs"]:
            ioc_table_data.append([
                i["ioc_type"],
                Paragraph(_safe(i["ioc_value"]), cell_style),
                Paragraph(_safe(i["source"]), cell_style),
            ])
        ioc_table = Table(ioc_table_data, hAlign="LEFT", colWidths=[type_width, value_width, source_width])
        ioc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(ioc_table)
    else:
        story.append(Paragraph("No IOCs detected.", styles["Normal"]))

    doc.build(story)

    record = Report(case_id=case.case_id, file_path=file_path, format="PDF")
    db.add(record)
    db.commit()
    return file_path
