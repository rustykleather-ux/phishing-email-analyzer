import os
import base64
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def encode_url_id(url):
    url_bytes = url.encode("utf-8")
    encoded = base64.urlsafe_b64encode(url_bytes).decode("utf-8")
    return encoded.strip("=")


def check_url_reputation(url):
    if not VT_API_KEY:
        return {
            "available": False,
            "score": 0,
            "findings": ["VirusTotal API key not configured."]
        }

    headers = {
        "x-apikey": VT_API_KEY
    }

    url_id = encode_url_id(url)

    response = requests.get(
        f"{VT_BASE_URL}/urls/{url_id}",
        headers=headers,
        timeout=15
    )

    if response.status_code == 404:
        return {
            "available": True,
            "score": 0,
            "findings": [f"VirusTotal has no existing report for URL: {url}"]
        }

    if response.status_code != 200:
        return {
            "available": False,
            "score": 0,
            "findings": [f"VirusTotal lookup failed: HTTP {response.status_code}"]
        }

    data = response.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    score = 0
    findings = []

    if malicious > 0:
        score += malicious * 20
        findings.append(f"VirusTotal malicious detections: {malicious}")

    if suspicious > 0:
        score += suspicious * 10
        findings.append(f"VirusTotal suspicious detections: {suspicious}")

    if not findings:
        findings.append("VirusTotal URL reputation: no malicious detections.")

    return {
        "available": True,
        "score": score,
        "findings": findings
    }