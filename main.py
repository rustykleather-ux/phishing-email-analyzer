from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from pathlib import Path
from fastapi.responses import HTMLResponse

from database import save_report, get_recent_reports, get_report_stats, get_report_iocs, update_report_status
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

@app.post("/api/report/{report_id}/update_status")
def set_report_status(report_id: int, payload: dict):
        status = payload.get("status", "New")
        update_report_status(report_id, status)


        return{
         "status": "updated",
         "report_id": report_id,
         "new_status": status
    }
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    reports = get_recent_reports()
    stats = get_report_stats()

    rows_html = ""

    for report in reports:
        risk_level = report.get("risk_level", "")
        score = report.get("score", 0)

        row_class = ""

        if risk_level == "Dangerous" or score >= 80:
            row_class = "danger-row"
        elif risk_level == "Suspicious" or score >= 40:
            row_class = "suspicious-row"
        elif risk_level == "Medium Risk" or score >= 10:
            row_class = "medium-row"
        else:
            row_class = "low-row"

        rows_html += f"""
        <tr class="{row_class}">
        <td>{report.get("created_at", "")}</td>
        <td>{risk_level}</td>
        <td>{score}</td>
        <td>{report.get("sender", "")}</td>
        <td>{report.get("subject", "")}</td>

        <td>
    <button onclick="showIocs(
        `{report.get("subject", "")}`,
        `{report.get("sender", "")}`,
        `{report.get("message_id", "")}`
    )">
        View IOCs
    </button>
</td>

    <td>
    <select onchange="updateStatus(this, '{report.get("id", "")}')">
        <option value="New">New</option>
        <option value="Reviewed">Reviewed</option>
        <option value="False Positive">False Positive</option>
        <option value="Confirmed Malicious">Confirmed Malicious</option>
    </select>
</td>
    d>
</tr>
"""

    risk_labels = list(stats.get("by_risk", {}).keys())
    risk_counts = list(stats.get("by_risk", {}).values())

    sender_labels = [sender for sender, count in stats.get("top_senders", [])]
    sender_counts = [count for sender, count in stats.get("top_senders", [])]

    html = f"""
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
{{ }}
    .modal {{
    display: none;
    position: fixed;
    z-index: 999;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    overflow: auto;
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
    box-shadow: 0 4px 20px rgba(0,0,0,0.5);
}}

.close {{
    color: #f87171;
    float: right;
    font-size: 28px;
    font-weight: bold;
    cursor: pointer;
}}

.close:hover {{
    color: #ef4444;
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

    .danger-row:hover,
    .suspicious-row:hover,
    .medium-row:hover,
    .low-row:hover {{
    background-color: #1f2937;
    }}

    }}
    h1, h2 {{
        color: #f8fafc;
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
    max-height: 400px;
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
        box-shadow: 0 2px 12px rgba(0,0,0,0.35);
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

    tr:hover {{
        background-color: #1f2937;
    }}

    ul {{
        padding-left: 20px;
    }}

    a {{
        color: #60a5fa;
    }}

    function showIocs(subject, sender, messageId) {{
    document.getElementById("iocSubject").innerText = subject;
    document.getElementById("iocSender").innerText = sender;
    document.getElementById("iocMessageId").innerText = messageId;

    document.getElementById("iocModal").style.display = "block";
}}

function closeIocModal() {{
    document.getElementById("iocModal").style.display = "none";
}}

window.onclick = function(event) {{
    const modal = document.getElementById("iocModal");

    if (event.target === modal) {{
        modal.style.display = "none";
    }}
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
            <h2>Risk Types</h2>
            <p>{len(risk_labels)}</p>
        </div>

        <div class="card">
            <h2>Top Senders Tracked</h2>
            <p>{len(sender_labels)}</p>
        </div>
    </div>

    <div class="charts">
        <div class="chart-card">
            <h2>Reports by Risk</h2>
            <div style="max-width: 300px; margin: auto;">
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
    <input
        type="text"
        id="searchInput"
        placeholder="Search sender or subject..."
        onkeyup="filterReports()"
        style="padding: 10px; width: 300px;"
    >

    <select
        id="riskFilter"
        onchange="filterReports()"
        style="padding: 10px;"
    >
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
        </tr>
        {rows_html}
    </table>

    <script>
        const riskLabels = {risk_labels};
        const riskCounts = {risk_counts};

        const senderLabels = {sender_labels};
        const senderCounts = {sender_counts};

        new Chart(document.getElementById("riskChart"), {{
            type: "pie",
            data: {{
                labels: riskLabels,
                datasets: [{{
                    data: riskCounts
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false
            }},
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
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            precision: 0
                        }}
                    }}
                }}
            }}
        }});
    windows.oneclick = function(event) {{
    const modal = document.getElementById("iocModal");
    if (event.target === modal) {{
        modal.style.display = "none";
    }}
}}

setInterval(() => {{
    window.location.reload();
}}, 300000);

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

</script>



<div id="iocModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeIocModal()">&times;</span>
        <h2>IOC Details</h2>

        <p><strong>Subject:</strong> <span id="iocSubject"></span></p>
        <p><strong>Sender:</strong> <span id="iocSender"></span></p>
        <p><strong>Message ID:</strong> <span id="iocMessageId"></span></p>

        <hr>

        <p>
            IOC extraction display is ready. Next we can connect this to stored URLs,
            attachment names, and hashes from the database.
        </p>
    </div>
</div>
</body>
</html>
"""

    return HTMLResponse(content=html)