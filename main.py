import os
import json
import html
import logging
import textwrap
import secrets
import calendar
from pathlib import Path
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Depends, status, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, field_validator
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from database import (
    save_report,
    get_recent_reports,
    get_report_stats,
    get_report_iocs,
    get_report_by_id,
    get_reports_for_month,
    update_report_status,
    save_audit_event,
    update_report_notes
    
)
from gmail_reader import get_gmail_message, send_report_email
from analyzer import analyze_phishing_email
from siem import send_to_splunk


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Louisburg Phishing Analyzer")
templates = Jinja2Templates(directory="templates")

API_KEY = os.environ.get("PHISHING_API_KEY", "dev-secret-key")
DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "ChangeThisPassword")
REPORT_RECIPIENT_EMAIL = os.environ.get(
    "REPORT_RECIPIENT_EMAIL",
    "rfolsom@louisburglibrary.org"
)

VALID_STATUSES = {
    "New",
    "Reviewed", 
    "False Positive", 
    "Confirmed Malicious",
    "Closed"
    }

security = HTTPBasic()


class AnalyzeRequest(BaseModel):
    messageId: str = ""
    userEmail: str = "unknown"
    emailData: Optional[dict] = None

class NotesUpdate(BaseModel):
    notes: str


class StatusUpdate(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def status_must_be_valid(cls, v: str) -> str:
        if v not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status '{v}'. Must be one of: {', '.join(sorted(VALID_STATUSES))}"
            )
        return v


def verify_api_key(x_api_key: str = Header(default="", alias="X-API-Key")) -> None:
    if not secrets.compare_digest(x_api_key, API_KEY):
        logger.warning("Rejected request with invalid API key.")
        raise HTTPException(status_code=401, detail="Unauthorized")


def verify_dashboard_login(
    credentials: HTTPBasicCredentials = Depends(security),
) -> str:
    username_ok = secrets.compare_digest(credentials.username, DASHBOARD_USERNAME)
    password_ok = secrets.compare_digest(credentials.password, DASHBOARD_PASSWORD)

    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid dashboard login",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username


def get_email_data_for_request(request: AnalyzeRequest) -> dict:
    """
    Staff-safe email loading.

    If Apps Script sends emailData, use that directly.
    Otherwise fall back to backend Gmail API token for single-user/local testing.
    """
    if request.emailData:
        email_data = dict(request.emailData)
        email_data["message_id"] = request.messageId
        email_data["from_apps_script"] = True
        return email_data

    try:
        email_data = get_gmail_message(request.messageId)
    except Exception:
        logger.exception("Failed to fetch Gmail message %s", request.messageId)
        raise HTTPException(
            status_code=502,
            detail="Failed to retrieve email from Gmail."
        )

    email_data["message_id"] = request.messageId
    email_data["from_apps_script"] = False
    return email_data


def build_report_body(
    request: AnalyzeRequest,
    email_data: dict,
    results: dict,
) -> str:
    findings_text = "\n".join(
        f"- {finding}" for finding in results.get("findings", [])
    )

    raw_headers_text = "\n".join(
        f"{h.get('name', '')}: {h.get('value', '')}"
        for h in email_data.get("raw_headers", [])
    )

    body_preview = email_data.get("body", "")
    if len(body_preview) > 3000:
        body_preview = body_preview[:3000] + "\n\n[Body truncated]"

    return (
        f"Phishing Report Submitted\n\n"
        f"Reported by: {request.userEmail}\n"
        f"Message ID: {request.messageId}\n\n"
        f"Sender: {email_data.get('from', '')}\n"
        f"Reply-To: {email_data.get('reply_to', '')}\n"
        f"Return-Path: {email_data.get('return_path', '')}\n"
        f"Subject: {email_data.get('subject', '')}\n"
        f"Date: {email_data.get('date', '')}\n\n"
        f"Risk Level: {results.get('risk_level')}\n"
        f"Score: {results.get('score')}\n\n"
        f"Findings:\n{findings_text}\n\n"
        f"Recommendation:\n{results.get('recommendation')}\n\n"
        f"--- Email Body Preview ---\n{body_preview}\n\n"
        f"--- Authentication Results ---\n{email_data.get('authentication_results', '')}\n\n"
        f"--- Received-SPF ---\n{email_data.get('received_spf', '')}\n\n"
        f"--- Raw Headers ---\n{raw_headers_text}\n"
    )


def process_report(request: AnalyzeRequest, email_data: dict, results: dict) -> None:
    report_body = build_report_body(request, email_data, results)

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = reports_dir / f"phishing_report_{timestamp}.txt"
    report_file.write_text(report_body, encoding="utf-8")
    

    save_report(
        message_id=request.messageId,
        sender=email_data.get("from", ""),
        subject=email_data.get("subject", ""),
        risk_level=results.get("risk_level", ""),
        score=results.get("score", 0),
        recommendation=results.get("recommendation", ""),
        iocs=results.get("iocs", {}),
        reported_by=("staff-user"
        if not request.userEmail or str(request.userEmail).lower() == "none"
        else request.userEmail
),
    )

    save_audit_event(
        action="report_submitted",
        actor=(
    "staff-user"
    if not request.userEmail or str(request.userEmail).lower() == "none"
    else request.userEmail
),
        details={
            "message_id": request.messageId,
            "sender": email_data.get("from", ""),
            "subject": email_data.get("subject", ""),
            "risk_level": results.get("risk_level", ""),
            "score": results.get("score", 0),
        },
    )

    try:
        send_to_splunk(
            {
                "event_type": "phishing_report",
                "message_id": request.messageId,
                "reported_by": request.userEmail,
                "sender": email_data.get("from", ""),
                "subject": email_data.get("subject", ""),
                "risk_level": results.get("risk_level", ""),
                "score": results.get("score", 0),
                "findings": results.get("findings", []),
                "iocs": results.get("iocs", {}),
                "recommendation": results.get("recommendation", ""),
            }
        )
    except Exception:
        logger.exception("Failed to forward event to Splunk.")

    try:
        send_report_email(
            to_email=REPORT_RECIPIENT_EMAIL,
            subject=f"Phishing Report: {email_data.get('subject', '')}",
            body=report_body,
        )
    except Exception:
        logger.exception("Failed to send report email.")


def _write_line(c, y, height, text, size=10, bold=False):
    if y < 60:
        c.showPage()
        y = height - 50

    font = "Helvetica-Bold" if bold else "Helvetica"
    c.setFont(font, size)
    c.drawString(50, y, str(text))
    return y - 16


def _write_wrapped(c, y, height, label, value):
    y = _write_line(c, y, height, label, 11, bold=True)

    for line in textwrap.wrap(str(value or ""), width=90):
        y = _write_line(c, y, height, line, 9)

    return y - 6


def generate_pdf(report: dict, iocs: dict, pdf_path: Path) -> None:
    c = canvas.Canvas(str(pdf_path), pagesize=letter)
    width, height = letter
    y = height - 50

    y = _write_line(c, y, height, "Louisburg Phishing Incident Report", 16, bold=True)
    y -= 10

    for label, key in [
        ("Created At", "created_at"),
        ("Message ID", "message_id"),
        ("Sender", "sender"),
        ("Subject", "subject"),
        ("Risk Level", "risk_level"),
        ("Score", "score"),
        ("Status", "status"),
        ("Recommendation", "recommendation"),
    ]:
        y = _write_wrapped(c, y, height, label, report.get(key, ""))

    y = _write_line(c, y, height, "Indicators of Compromise", 13, bold=True)
    y -= 6

    y = _write_line(c, y, height, "URLs", 11, bold=True)
    urls = iocs.get("urls", [])

    if urls:
        for url in urls:
            for line in textwrap.wrap(str(url), width=90):
                y = _write_line(c, y, height, "- " + line, 8)
    else:
        y = _write_line(c, y, height, "No URLs captured.", 9)

    y -= 8

    y = _write_line(c, y, height, "Attachments", 11, bold=True)
    attachments = iocs.get("attachments", [])

    if attachments:
        for attachment in attachments:
            for line in textwrap.wrap(str(attachment), width=90):
                y = _write_line(c, y, height, "- " + line, 8)
    else:
        y = _write_line(c, y, height, "No attachments captured.", 9)

    c.save()


@app.get("/")
def home():
    return {
        "status": "running",
        "app": "Louisburg Phishing Analyzer",
        "dashboard": "/dashboard",
        "docs": "/docs",
    }


@app.post("/analyze")
def analyze_email(
    request: AnalyzeRequest,
    _: None = Depends(verify_api_key),
):
    email_data = get_email_data_for_request(request)

    try:
        results = analyze_phishing_email(email_data) or {}
    except Exception:
        logger.exception("Analysis failed for message %s", request.messageId)
        raise HTTPException(status_code=500, detail="Email analysis failed.")

    return results


@app.post("/report")
def report_phishing(
    request: AnalyzeRequest,
    _: None = Depends(verify_api_key),
):
    email_data = get_email_data_for_request(request)

    try:
        results = analyze_phishing_email(email_data) or {}
    except Exception:
        logger.exception("Analysis failed for message %s", request.messageId)
        raise HTTPException(status_code=500, detail="Email analysis failed.")

    process_report(request, email_data, results)

    return {
        "status": "reported",
        "message": "Phishing report emailed to IT."
    }


@app.get("/api/report/{report_id}/iocs")
def report_iocs(
    report_id: int,
    username: str = Depends(verify_dashboard_login),
):
    iocs = get_report_iocs(report_id)
    save_audit_event(action="ioc_viewed", actor=username, report_id=report_id)
    return iocs


@app.get("/api/report/{report_id}/vt-enrich")
def vt_enrich(
    report_id: int,
    username: str = Depends(verify_dashboard_login),
):
    try:
        from virustotal_client import (
            check_url_reputation,
            check_file_hash_reputation,
        )

        iocs = get_report_iocs(report_id)
        urls = iocs.get("urls", [])
        attachments = iocs.get("attachments", [])

        url_results = []

        for url in urls:
            try:
                result = check_url_reputation(url)
                result["url"] = url
                url_results.append(result)
            except Exception:
                logger.exception("VT URL lookup failed for %s", url)
                url_results.append(
                    {
                        "url": url,
                        "available": False,
                        "score": 0,
                        "findings": ["Lookup error."],
                    }
                )

        attachment_results = []

        for attachment in attachments:
            file_hash = attachment.get("hash") if isinstance(attachment, dict) else None
            name = attachment.get("name") if isinstance(attachment, dict) else attachment

            if file_hash:
                try:
                    result = check_file_hash_reputation(file_hash)
                    result["name"] = name
                    result["hash"] = file_hash
                    attachment_results.append(result)
                except Exception:
                    logger.exception("VT hash lookup failed for %s", file_hash)
                    attachment_results.append(
                        {
                            "name": name,
                            "hash": file_hash,
                            "available": False,
                            "score": 0,
                            "findings": ["Lookup error."],
                        }
                    )
            else:
                attachment_results.append(
                    {
                        "name": name,
                        "hash": None,
                        "available": False,
                        "score": 0,
                        "findings": ["No hash available for VT lookup."],
                    }
                )

        save_audit_event(
            action="vt_enrichment_run",
            actor=username,
            report_id=report_id,
            details={
                "urls_checked": len(url_results),
                "attachments_checked": len(attachment_results),
            },
        )

        return {
            "urls": url_results,
            "attachments": attachment_results,
            "available": True,
        }

    except Exception as e:
        logger.exception("VT enrichment failed for report %s", report_id)

        return {
            "urls": [],
            "attachments": [],
            "available": False,
            "error": str(e),
        }

@app.post("/api/report/{report_id}/notes")
def set_report_notes(
    report_id: int,
    payload: NotesUpdate,
    username: str = Depends(verify_dashboard_login),
):
    update_report_notes(report_id, payload.notes)

    save_audit_event(
        action="notes_updated",
        actor=username,
        report_id=report_id,
        details={
            "notes_length": len(payload.notes)
        },
    )

    return {
        "status": "updated",
        "report_id": report_id
    }

@app.post("/api/report/{report_id}/status")
def set_report_status(
    report_id: int,
    payload: StatusUpdate,
    username: str = Depends(verify_dashboard_login),
):
    update_report_status(report_id, payload.status)

    save_audit_event(
        action="status_changed",
        actor=username,
        report_id=report_id,
        details={"new_status": payload.status},
    )

    return {
        "status": "updated",
        "report_id": report_id,
        "new_status": payload.status
    }

@app.get("/api/reports/monthly-summary/pdf")
def export_monthly_summary_pdf(
    username: str = Depends(verify_dashboard_login),
):
    now = datetime.now()
    year = now.year
    month = now.month
    month_name = calendar.month_name[month]

    reports = get_reports_for_month(year, month)

    total_reports = len(reports)
    dangerous = 0
    suspicious = 0
    medium = 0
    low = 0
    closed = 0
    false_positive = 0
    confirmed_malicious = 0

    top_senders = {}

    for report in reports:
        risk = report.get("risk_level", "")
        status_value = report.get("status", "")

        if risk == "Dangerous":
            dangerous += 1
        elif risk == "Suspicious":
            suspicious += 1
        elif risk == "Medium Risk":
            medium += 1
        else:
            low += 1

        if status_value == "Closed":
            closed += 1

        if status_value == "False Positive":
            false_positive += 1

        if status_value == "Confirmed Malicious":
            confirmed_malicious += 1

        sender = report.get("sender", "Unknown")
        top_senders[sender] = top_senders.get(sender, 0) + 1

    top_sender_list = sorted(
        top_senders.items(),
        key=lambda item: item[1],
        reverse=True
    )[:5]

    exports_dir = Path("reports") / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)

    pdf_path = exports_dir / f"monthly_phishing_summary_{year}_{month:02d}.pdf"

    c = canvas.Canvas(str(pdf_path), pagesize=letter)
    width, height = letter
    y = height - 50

    def line(text, size=10, bold=False):
        nonlocal y

        if y < 60:
            c.showPage()
            y = height - 50

        font = "Helvetica-Bold" if bold else "Helvetica"
        c.setFont(font, size)
        c.drawString(50, y, str(text))
        y -= 16

    line(f"Louisburg Monthly Phishing Summary - {month_name} {year}", 16, True)
    y -= 10

    line("Executive Summary", 13, True)
    line(f"Total phishing reports: {total_reports}")
    line(f"Dangerous reports: {dangerous}")
    line(f"Suspicious reports: {suspicious}")
    line(f"Medium risk reports: {medium}")
    line(f"Low risk reports: {low}")
    line(f"Confirmed malicious: {confirmed_malicious}")
    line(f"False positives: {false_positive}")
    line(f"Closed alerts: {closed}")

    y -= 10

    line("Top Reported Senders", 13, True)

    if top_sender_list:
        for sender, count in top_sender_list:
            wrapped_sender = textwrap.wrap(str(sender), width=75)

            if wrapped_sender:
                line(f"{count} report(s): {wrapped_sender[0]}")
                for extra_line in wrapped_sender[1:]:
                    line(f"    {extra_line}")
    else:
        line("No sender data available.")

    y -= 10

    line("Recent Reports", 13, True)

    for report in reports[:15]:
        subject = report.get("subject", "")
        risk = report.get("risk_level", "")
        status_value = report.get("status", "")
        sender = report.get("sender", "")

        line(f"{report.get('created_at', '')} | {risk} | {status_value}", 9, True)

        for wrapped in textwrap.wrap(f"Sender: {sender}", width=90):
            line(wrapped, 8)

        for wrapped in textwrap.wrap(f"Subject: {subject}", width=90):
            line(wrapped, 8)

        y -= 4

    c.save()

    save_audit_event(
        action="monthly_summary_exported",
        actor=username,
        details={
            "year": year,
            "month": month,
            "total_reports": total_reports
        }
    )

    return FileResponse(
        path=str(pdf_path),
        filename=f"monthly_phishing_summary_{year}_{month:02d}.pdf",
        media_type="application/pdf"
    )

@app.get("/api/report/{report_id}/pdf")
def export_report_pdf(
    report_id: int,
    username: str = Depends(verify_dashboard_login),
):
    report = get_report_by_id(report_id)

    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    save_audit_event(
        action="pdf_exported",
        actor=username,
        report_id=report_id,
        details={"subject": report.get("subject", "")},
    )

    iocs = get_report_iocs(report_id)

    exports_dir = Path("reports") / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)

    pdf_path = exports_dir / f"phishing_report_{report_id}.pdf"

    try:
        generate_pdf(report, iocs, pdf_path)
    except Exception:
        logger.exception("PDF generation failed for report %d", report_id)
        raise HTTPException(status_code=500, detail="PDF generation failed.")

    return FileResponse(
        path=str(pdf_path),
        filename=f"phishing_report_{report_id}.pdf",
        media_type="application/pdf",
    )


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    username: str = Depends(verify_dashboard_login),
):
    reports = get_recent_reports()
    stats = get_report_stats()

    rows = []

    for report in reports:
        risk_level = report.get("risk_level", "")
        score = report.get("score", 0)

        if risk_level == "Dangerous" or score >= 80:
            row_class = "danger-row"
        elif risk_level == "Suspicious" or score >= 40:
            row_class = "suspicious-row"
        elif risk_level == "Medium Risk" or score >= 10:
            row_class = "medium-row"
        else:
            row_class = "low-row"

        status_value = report.get("status") or "New"

        rows.append(
            {
                "id": str(report.get("id", "")),
                "created_at": html.escape(str(report.get("created_at", ""))),
                "risk_level": html.escape(str(risk_level)),
                "score": score,
                "sender": html.escape(str(report.get("sender", ""))),
                "reported_by": html.escape(str(report.get("reported_by") or "staff-user")),
                "subject": html.escape(str(report.get("subject", ""))),
                "message_id": html.escape(str(report.get("message_id", ""))),
                "status": status_value,
                "row_class": row_class,
                "analyst_notes": html.escape(str(report.get("analyst_notes", ""))),
            }
        )

    context = {
        "request": request,
        "rows": rows,
        "stats": stats,
        "valid_statuses": sorted(VALID_STATUSES),
        "risk_labels": json.dumps(list(stats.get("by_risk", {}).keys())),
        "risk_counts": json.dumps(list(stats.get("by_risk", {}).values())),
        "sender_labels": json.dumps(
            [s for s, _ in stats.get("top_senders", [])]
        ),
        "sender_counts": json.dumps(
            [c for _, c in stats.get("top_senders", [])]
        ),
    }

    return templates.TemplateResponse(
        name="dashboard.html",
        context=context,
        request=request,
    )