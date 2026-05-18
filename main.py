from fastapi import FastAPI
from pydantic import BaseModel

from gmail_reader import get_gmail_message, send_report_email
from analyzer import analyze_phishing_email

app = FastAPI(title="Louisburg Phishing Analyzer")


class AnalyzeRequest(BaseModel):
    messageId: str
    userEmail: str = "unknown"


@app.post("/analyze")
def analyze_email(request: AnalyzeRequest):
    email_data = get_gmail_message(request.messageId)
    results = analyze_phishing_email(email_data)
    return results


@app.post("/report")
def report_phishing(request: AnalyzeRequest):
    email_data = get_gmail_message(request.messageId)
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

    send_report_email(
        to_email="rfolsom@louisburglibrary.org",
        subject=f"Phishing Report: {email_data.get('subject', '')}",
        body=report_body
    )

    return {
        "status": "reported",
        "message": "Phishing report emailed to IT."
    }
