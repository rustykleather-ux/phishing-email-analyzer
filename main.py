from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from pathlib import Path
from fastapi.responses import HTMLResponse

from database import save_report, get_recent_reports, get_report_stats
from gmail_reader import get_gmail_message, send_report_email
from analyzer import analyze_phishing_email

app = FastAPI(title="Louisburg Phishing Analyzer")


class AnalyzeRequest(BaseModel):
    messageId: str
    userEmail: str = "unknown"


@app.post("/analyze")
def analyze_email(request: AnalyzeRequest):
    email_data = get_gmail_message(request.messageId)
    email_data["message_id"] = request.messageId

    results = analyze_phishing_email(email_data) or {}
    return results

@app.post("/report")
def report_phishing(request: AnalyzeRequest):
    email_data = get_gmail_message(request.messageId)
    email_data["message_id"] = request.messageId

    results = analyze_phishing_email(email_data)

    findings_text = "\n".join(
        f"- {finding}" for finding in results.get("findings", [])
    )

    raw_headers_text = "\n".join(
        f"{header.get('name', '')}: {header.get('value', '')}"
        for header in email_data.get("raw_headers", [])
    )

    email_body_preview = email_data.get("body", "")

    if len(email_body_preview) > 3000:
        email_body_preview = (
            email_body_preview[:3000] + "\n\n[Body truncated]"
        )

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

    report_file.write_text(
        report_body,
        encoding="utf-8"
    )

    save_report(
        message_id=request.messageId,
        sender=email_data.get("from", ""),
        subject=email_data.get("subject", ""),
        risk_level=results.get("risk_level", ""),
        score=results.get("score", 0),
        recommendation=results.get("recommendation", "")
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


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    reports = get_recent_reports()
    stats = get_report_stats()

    rows_html = ""

    for report in reports:
        rows_html += f"""
        <tr>
            <td>{report.get("created_at", "")}</td>
            <td>{report.get("risk_level", "")}</td>
            <td>{report.get("score", "")}</td>
            <td>{report.get("sender", "")}</td>
            <td>{report.get("subject", "")}</td>
        </tr>
        """

    risk_html = ""

    for risk, count in stats.get("by_risk", {}).items():
        risk_html += f"<li><strong>{risk}</strong>: {count}</li>"

    sender_html = ""

    for sender, count in stats.get("top_senders", []):
        sender_html += f"<li><strong>{sender}</strong>: {count}</li>"

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Louisburg Phishing Dashboard</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f4f6f8;
            margin: 0;
            padding: 30px;
        }}

        h1 {{
            color: #222;
        }}

        .cards {{
            display: flex;
            gap: 20px;
            margin-bottom: 25px;
        }}

        .card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            flex: 1;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}

        th {{
            background: #1a73e8;
            color: white;
            padding: 12px;
            text-align: left;
        }}

        td {{
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }}
    </style>
</head>

<body>

    <h1>Louisburg Phishing Dashboard</h1>

    <div class="cards">

        <div class="card">
            <h2>Total Reports</h2>
            <p style="font-size:32px;">
                {stats.get("total_reports", 0)}
            </p>
        </div>

        <div class="card">
            <h2>Reports by Risk</h2>
            <ul>
                {risk_html}
            </ul>
        </div>

        <div class="card">
            <h2>Top Senders</h2>
            <ul>
                {sender_html}
            </ul>
        </div>

    </div>

    <h2>Recent Reports</h2>

    <table>
        <tr>
            <th>Time</th>
            <th>Risk</th>
            <th>Score</th>
            <th>Sender</th>
            <th>Subject</th>
        </tr>

        {rows_html}

    </table>

</body>
</html>
"""

    return HTMLResponse(content=html)