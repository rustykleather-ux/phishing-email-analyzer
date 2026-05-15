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
