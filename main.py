from fastapi import FastAPI
from fastapi import Depends, status
from pydantic import BaseModel
from datetime import datetime
from pathlib import Path
from fastapi.responses import HTMLResponse
from fastapi import Header, HTTPException
import json
import html
import os
from fastapi.responses import FileResponse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import textwrap
from fastapi import Request, Form
from fastapi.responses import RedirectResponse
from itsdangerous import URLSafeSerializer, BadSignature
import secrets
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from database import (
    save_report,
    get_recent_reports,
    get_report_stats,
    get_report_iocs,
    get_report_by_id,
    update_report_status
)
from gmail_reader import get_gmail_message, send_report_email
from analyzer import analyze_phishing_email

API_KEY = os.getenv("PHISHING_API_KEY", "dev-secret-key")

security = HTTPBasic()

DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "ChangeThisPassword")


def verify_dashboard_login(
    credentials: HTTPBasicCredentials = Depends(security)
):
    username_ok = secrets.compare_digest(
        credentials.username,
        DASHBOARD_USERNAME
    )

    password_ok = secrets.compare_digest(
        credentials.password,
        DASHBOARD_PASSWORD
    )

    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid dashboard login",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username

def verify_api_key(x_api_key: str = Header(default="")):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized") 
    
app = FastAPI(title="Louisburg Phishing Analyzer")


class AnalyzeRequest(BaseModel):
    messageId: str
    userEmail: str = "unknown"


@app.get("/")
def home():
    return {
        "status": "running",
        "app": "Louisburg Phishing Analyzer",
        "dashboard": "/dashboard",
        "docs": "/docs"
    }


@app.post("/analyze")
def analyze_email(
    request: AnalyzeRequest,
    x_api_key: str = Header(default="", alias="X-API-Key")
):
    verify_api_key(x_api_key)

    email_data = get_gmail_message(request.messageId)
    email_data["message_id"] = request.messageId

    results = analyze_phishing_email(email_data) or {}
    return results


@app.post("/report")
def report_phishing(request: AnalyzeRequest, x_api_key: str = Header(default="", alias="X-API-Key")):
    verify_api_key(x_api_key)
    email_data = get_gmail_message(request.messageId)
    email_data["message_id"] = request.messageId

    results = analyze_phishing_email(email_data) or {}

    findings_text = "\n".join(
        f"- {finding}" for finding in results.get("findings", [])
    )

    raw_headers_text = "\n".join(
        f"{header.get('name', '')}: {header.get('value', '')}"
        for header in email_data.get("raw_headers", [])
    )

    email_body_preview = email_data.get("body", "")

    if len(email_body_preview) > 3000:
        email_body_preview = email_body_preview[:3000] + "\n\n[Body truncated]"

    report_body = f"""
Phishing Report Submitted

Reported by: {request.userEmail}
Message ID: {request.messageId}

Sender: {email_data.get("from", "")}
Reply-To: {email_data.get("reply_to", "")}
Return-Path: {email_data.get("return_path", "")}
Subject: {email_data.get("subject", "")}
Date: {email_data.get("date", "")}

Risk Level: {results.get("risk_level")}
Score: {results.get("score")}

Findings:
{findings_text}

Recommendation:
{results.get("recommendation")}

--- Email Body Preview ---
{email_body_preview}

--- Authentication Results ---
{email_data.get("authentication_results", "")}

--- Received-SPF ---
{email_data.get("received_spf", "")}

--- Raw Headers ---
{raw_headers_text}
"""

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
        iocs=results.get("iocs", {})
    )

    send_report_email(
        to_email="rfolsom@louisburglibrary.org",
        subject=f"Phishing Report: {email_data.get('subject', '')}",
        body=report_body
    )

    return {
        "status": "reported",
        "message": "Phishing report emailed to IT."
    }


@app.get("/api/report/{report_id}/iocs")
def report_iocs(
    report_id: int,
    username: str = Depends(verify_dashboard_login)
):
    return get_report_iocs(report_id)


@app.post("/api/report/{report_id}/status")
def set_report_status(
    report_id: int,
    payload: dict,
    username: str = Depends(verify_dashboard_login)
):
    new_status = payload.get("status", "New")
    update_report_status(report_id, new_status)

    return {
        "status": "updated",
        "report_id": report_id,
        "new_status": new_status
    }
@app.get("/api/report/{report_id}/pdf")
def export_report_pdf(
    report_id: int,
    username: str = Depends(verify_dashboard_login)
):
    report = get_report_by_id(report_id)

    if not report:
        return {"error": "Report not found"}

    iocs = get_report_iocs(report_id)

    exports_dir = Path("reports") / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)

    pdf_path = exports_dir / f"phishing_report_{report_id}.pdf"

    c = canvas.Canvas(str(pdf_path), pagesize=letter)
    width, height = letter

    y = height - 50

    def write_line(text, size=10, bold=False):
        nonlocal y

        if y < 60:
            c.showPage()
            y = height - 50

        font = "Helvetica-Bold" if bold else "Helvetica"
        c.setFont(font, size)
        c.drawString(50, y, str(text))
        y -= 16

    def write_wrapped(label, value):
        nonlocal y
        write_line(label, 11, True)

        for line in textwrap.wrap(str(value or ""), width=90):
            write_line(line, 9, False)

        y -= 6

    write_line("Louisburg Phishing Incident Report", 16, True)
    y -= 10

    write_wrapped("Created At", report.get("created_at", ""))
    write_wrapped("Message ID", report.get("message_id", ""))
    write_wrapped("Sender", report.get("sender", ""))
    write_wrapped("Subject", report.get("subject", ""))
    write_wrapped("Risk Level", report.get("risk_level", ""))
    write_wrapped("Score", report.get("score", ""))
    write_wrapped("Status", report.get("status", "New"))
    write_wrapped("Recommendation", report.get("recommendation", ""))

    write_line("Indicators of Compromise", 13, True)
    y -= 6

    write_line("URLs", 11, True)
    urls = iocs.get("urls", [])

    if urls:
        for url in urls:
            for line in textwrap.wrap(str(url), width=90):
                write_line("- " + line, 8)
    else:
        write_line("No URLs captured.", 9)

    y -= 8

    write_line("Attachments", 11, True)
    attachments = iocs.get("attachments", [])

    if attachments:
        for attachment in attachments:
            for line in textwrap.wrap(str(attachment), width=90):
                write_line("- " + line, 8)
    else:
        write_line("No attachments captured.", 9)

    c.save()

    return FileResponse(
        path=str(pdf_path),
        filename=f"phishing_report_{report_id}.pdf",
        media_type="application/pdf"
    )


@app.get("/dashboard", response_class=HTMLResponse, dependencies=[Depends(verify_dashboard_login)])
def dashboard():
    reports = get_recent_reports()
    stats = get_report_stats()

    rows_html = ""

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

        report_id = str(report.get("id", ""))
        created_at = html.escape(str(report.get("created_at", "")))
        sender = html.escape(str(report.get("sender", "")))
        subject = html.escape(str(report.get("subject", "")))
        message_id = html.escape(str(report.get("message_id", "")))
        status_value = report.get("status", "New") or "New"

        def selected(value):
            return "selected" if value == status_value else ""

        rows_html += f"""
<tr class="{row_class}">
    <td>{created_at}</td>
    <td>{html.escape(str(risk_level))}</td>
    <td>{score}</td>
    <td>{sender}</td>
    <td>{subject}</td>
    <td>
        <button
            onclick="showIocs(this)"
            data-report-id="{report_id}"
            data-subject="{subject}"
            data-sender="{sender}"
            data-message-id="{message_id}">
            View IOCs
        </button>
    </td>
    <td>
        <select onchange="updateStatus(this, '{report_id}')">
            <option value="New" {selected("New")}>New</option>
            <option value="Reviewed" {selected("Reviewed")}>Reviewed</option>
            <option value="False Positive" {selected("False Positive")}>False Positive</option>
            <option value="Confirmed Malicious" {selected("Confirmed Malicious")}>Confirmed Malicious</option>
        </select>
    </td>
    <td>
    <a class="pdf-link"
       href="/api/report/{report_id}/pdf"
       target="_blank">
       Export PDF
    </a>
</td>
</tr>
"""

    risk_labels = json.dumps(list(stats.get("by_risk", {}).keys()))
    risk_counts = json.dumps(list(stats.get("by_risk", {}).values()))

    sender_labels = json.dumps([sender for sender, count in stats.get("top_senders", [])])
    sender_counts = json.dumps([count for sender, count in stats.get("top_senders", [])])

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
<title>Louisburg Phishing Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
body {{
    font-family: Arial, sans-serif;
    background-color: #0f172a;
    color: #e5e7eb;
    margin: 0;
    padding: 30px;
}}

h1, h2 {{
    color: #f8fafc;
}}
.pdf-link {{
    color: white !important;
    text-decoration: none;
    font-weight: bold;
}}

.pdf-link:visited {{
    color: white !important;
}}

.pdf-link:hover {{
    color: #d1d5db !important;
    text-decoration: underline;
}}
.cards {{
    display: flex;
    gap: 20px;
    margin-bottom: 25px;
}}

.card, .chart-card {{
    background: #111827;
    padding: 20px;
    border-radius: 12px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.35);
    border: 1px solid #1f2937;
}}

.card {{
    flex: 1;
}}

.charts {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 25px;
    margin-bottom: 30px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    background: #111827;
    border: 1px solid #1f2937;
}}

th {{
    background: #1e40af;
    color: white;
    padding: 12px;
    text-align: left;
}}

td {{
    padding: 12px;
    border-bottom: 1px solid #1f2937;
    color: #d1d5db;
}}

.danger-row {{
    background-color: rgba(127, 29, 29, 0.45);
}}

.suspicious-row {{
    background-color: rgba(146, 64, 14, 0.35);
}}

.medium-row {{
    background-color: rgba(133, 77, 14, 0.25);
}}

.low-row {{
    background-color: rgba(20, 83, 45, 0.20);
}}

tr:hover {{
    background-color: #1f2937;
}}

button {{
    background-color: #2563eb;
    color: white;
    border: none;
    padding: 8px 12px;
    border-radius: 6px;
    cursor: pointer;
}}

button:hover {{
    background-color: #1d4ed8;
}}

input, select {{
    background: #111827;
    color: #e5e7eb;
    border: 1px solid #374151;
    border-radius: 6px;
}}

.modal {{
    display: none;
    position: fixed;
    z-index: 999;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0,0,0,0.75);
}}

.modal-content {{
    background-color: #111827;
    margin: 8% auto;
    padding: 25px;
    border: 1px solid #374151;
    width: 60%;
    border-radius: 12px;
    color: #e5e7eb;
    max-height: 75vh;
    overflow-y: auto;
}}

.close {{
    color: #f87171;
    float: right;
    font-size: 28px;
    font-weight: bold;
    cursor: pointer;
}}

.ioc-list {{
    background: #0f172a;
    border: 1px solid #1f2937;
    border-radius: 8px;
    padding: 12px 24px;
}}
</style>
</head>

<body>
<h1>Louisburg Phishing Dashboard</h1>

<div class="cards">
    <div class="card">
        <h2>Total Reports</h2>
        <p style="font-size:32px;">{stats.get("total_reports", 0)}</p>
    </div>

    <div class="card">
        <h2>Risk Types</h2>
        <p>{len(json.loads(risk_labels))}</p>
    </div>

    <div class="card">
        <h2>Top Senders Tracked</h2>
        <p>{len(json.loads(sender_labels))}</p>
    </div>
</div>

<div class="charts">
    <div class="chart-card">
        <h2>Reports by Risk</h2>
        <div style="max-width:300px; height:300px; margin:auto;">
            <canvas id="riskChart"></canvas>
        </div>
    </div>

    <div class="chart-card">
        <h2>Top Senders</h2>
        <canvas id="senderChart"></canvas>
    </div>
</div>

<h2>Recent Reports</h2>

<div style="margin-bottom: 15px; display: flex; gap: 10px;">
    <input type="text" id="searchInput" placeholder="Search sender or subject..."
        onkeyup="filterReports()" style="padding: 10px; width: 300px;">

    <select id="riskFilter" onchange="filterReports()" style="padding: 10px;">
        <option value="">All Risks</option>
        <option value="Dangerous">Dangerous</option>
        <option value="Suspicious">Suspicious</option>
        <option value="Medium Risk">Medium Risk</option>
        <option value="Low Risk">Low Risk</option>
    </select>
</div>

<table id="reportsTable">
<tr>
    <th>Time</th>
    <th>Risk</th>
    <th>Score</th>
    <th>Sender</th>
    <th>Subject</th>
    <th>IOCs</th>
    <th>Status</th>
    <th>PDF</th>
</tr>
{rows_html}
</table>

<div id="iocModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeIocModal()">&times;</span>
        <h2>IOC Details</h2>

        <p><strong>Subject:</strong> <span id="iocSubject"></span></p>
        <p><strong>Sender:</strong> <span id="iocSender"></span></p>
        <p><strong>Message ID:</strong> <span id="iocMessageId"></span></p>

        <hr>

        <h3>URLs</h3>
        <ul id="iocUrls" class="ioc-list"></ul>

        <h3>Attachments</h3>
        <ul id="iocAttachments" class="ioc-list"></ul>
    </div>
</div>

<script>
const riskLabels = {risk_labels};
const riskCounts = {risk_counts};
const senderLabels = {sender_labels};
const senderCounts = {sender_counts};

new Chart(document.getElementById("riskChart"), {{
    type: "pie",
    data: {{
        labels: riskLabels,
        datasets: [{{ data: riskCounts }}]
    }},
    options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{
            legend: {{
                labels: {{ color: "white" }}
            }}
        }}
    }}
}});

new Chart(document.getElementById("senderChart"), {{
    type: "bar",
    data: {{
        labels: senderLabels,
        datasets: [{{
            label: "Reports",
            data: senderCounts
        }}]
    }},
    options: {{
        plugins: {{
            legend: {{
                labels: {{ color: "white" }}
            }}
        }},
        scales: {{
            x: {{ ticks: {{ color: "white" }} }},
            y: {{
                beginAtZero: true,
                ticks: {{ color: "white", precision: 0 }}
            }}
        }}
    }}
}});

async function showIocs(button) {{
    const reportId = button.getAttribute("data-report-id");

    document.getElementById("iocSubject").innerText =
        button.getAttribute("data-subject") || "";

    document.getElementById("iocSender").innerText =
        button.getAttribute("data-sender") || "";

    document.getElementById("iocMessageId").innerText =
        button.getAttribute("data-message-id") || "";

    const urlList = document.getElementById("iocUrls");
    const attachmentList = document.getElementById("iocAttachments");

    urlList.innerHTML = "<li>Loading...</li>";
    attachmentList.innerHTML = "<li>Loading...</li>";

    document.getElementById("iocModal").style.display = "block";

    try {{
        const response = await fetch("/api/report/" + reportId + "/iocs");
        const iocs = await response.json();

        const urls = iocs.urls || [];
        const attachments = iocs.attachments || [];

        urlList.innerHTML = urls.length
            ? urls.map(url => "<li>" + escapeHtml(url) + "</li>").join("")
            : "<li>No URLs captured.</li>";

        attachmentList.innerHTML = attachments.length
            ? attachments.map(item => "<li>" + escapeHtml(item) + "</li>").join("")
            : "<li>No attachments captured.</li>";
    }} catch (error) {{
        urlList.innerHTML = "<li>Error loading IOC data.</li>";
        attachmentList.innerHTML = "";
    }}
}}

function closeIocModal() {{
    document.getElementById("iocModal").style.display = "none";
}}

function escapeHtml(value) {{
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}}

function filterReports() {{
    const searchValue = document.getElementById("searchInput").value.toLowerCase();
    const riskValue = document.getElementById("riskFilter").value;
    const rows = document.getElementById("reportsTable").getElementsByTagName("tr");

    for (let i = 1; i < rows.length; i++) {{
        const cells = rows[i].getElementsByTagName("td");
        if (cells.length === 0) continue;

        const risk = cells[1].innerText;
        const sender = cells[3].innerText.toLowerCase();
        const subject = cells[4].innerText.toLowerCase();

        const matchesSearch = sender.includes(searchValue) || subject.includes(searchValue);
        const matchesRisk = riskValue === "" || risk === riskValue;

        rows[i].style.display = matchesSearch && matchesRisk ? "" : "none";
    }}
}}

async function updateStatus(selectElement, reportId) {{
    const newStatus = selectElement.value;

    await fetch("/api/report/" + reportId + "/status", {{
        method: "POST",
        headers: {{
            "Content-Type": "application/json"
        }},
        body: JSON.stringify({{
            status: newStatus
        }})
    }});
}}

window.onclick = function(event) {{
    const modal = document.getElementById("iocModal");
    if (event.target === modal) {{
        modal.style.display = "none";
    }}
}}

setInterval(function() {{
    window.location.reload();
}}, 300000);
</script>

</body>
</html>
"""

    return HTMLResponse(content=html_content)