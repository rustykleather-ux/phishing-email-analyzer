from fastapi import FastAPI
from pydantic import BaseModel

from gmail_reader import get_gmail_message
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

    print("\n=== PHISHING REPORT SUBMITTED ===")
    print(f"Message ID: {request.messageId}")
    print(f"Sender: {email_data.get('from', '')}")
    print(f"Subject: {email_data.get('subject', '')}")
    print(f"Risk Level: {results.get('risk_level')}")
    print(f"Score: {results.get('score')}")

    print("Findings:")

    for finding in results.get("findings", []):
        print(f"- {finding}")

    return {
        "status": "reported",
        "message": "Phishing report received."
    }
