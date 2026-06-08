import re 
import json
from pathlib import Path
from urllib.parse import urlparse
from gmail_reader import get_attachment_sha256
from virustotal_client import check_file_hash_reputation
from virustotal_client import check_url_reputation
from urllib.parse import urlparse
from threat_intel import check_virustotal_url

EMAIL_FILE = Path(__file__).parent.parent / "samples" / "phishing_email.txt"


def read_email():
    with open(EMAIL_FILE, "r", encoding="utf-8") as file:
        return file.read()


def extract_urls(text):
    urls = re.findall(r"https?://[^\s<>\"]+", text)

    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,;:)'\">")
        cleaned_urls.append(url)

    return list(dict.fromkeys(cleaned_urls))


def extract_sender(text):
    match = re.search(r"From:\s*(.*)", text)
    return match.group(1) if match else "Unknown"


def calculate_risk_score(urls, keywords, domain_findings, suspicious_tlds):
    score = 0
    score += len(urls) * 2
    score += len(keywords)
    score += len(domain_findings) * 3
    score += len(suspicious_tlds) * 3
    return score


def detect_suspicious_domain(sender):
    suspicious_patterns = ["micr0soft", "paypa1", "arnazon", ".ru", ".xyz"]
    return [p for p in suspicious_patterns if p.lower() in sender.lower()]


def detect_suspicious_keywords(text):
    keywords = [
        "urgent",
        "password",
        "verify",
        "suspend",
        "compromised",
        "click",
        "login"
    ]
    return [k for k in keywords if k.lower() in text.lower()]


def risk_rating(score):
    if score >= 80:
        return "Dangerous"
    elif score >= 40:
        return "Suspicious"
    elif score >= 10:
        return "Medium Risk"
    return "Low Risk"


def extract_ip_addresses(text):
    return re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)


def extract_email_domains(text):
    emails = re.findall(
        r"[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        text
    )
    return list(set(emails))


def detect_suspicious_tlds(domains):
    suspicious_tlds = [".ru", ".xyz", ".top", ".zip", ".click", ".info"]
    findings = []

    for domain in domains:
        for tld in suspicious_tlds:
            if domain.lower().endswith(tld):
                findings.append(domain)

    return findings


def analyze_url_reputation(url):
    score = 0
    findings = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    full_url = url.lower()

    ignored_domains = [
        "ecp.yusercontent.com",
        "ci3.googleusercontent.com",
        "static.punchbowl.com",
        "googleusercontent.com",
        "gstatic.com"
    ]

    if any(ignored in domain for ignored in ignored_domains):
        return 0, []

    suspicious_tlds = [".ru", ".xyz", ".top", ".zip", ".click", ".info"]
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]

    if full_url.startswith("http://"):
        score += 20
        findings.append(f"Non-HTTPS URL detected: {url}")

    if any(domain.endswith(tld) for tld in suspicious_tlds):
        score += 30
        findings.append(f"Suspicious URL TLD detected: {domain}")

    if any(shortener == domain for shortener in shorteners):
        score += 25
        findings.append(f"URL shortener detected: {domain}")

    if "@" in url:
        score += 40
        findings.append(f"URL contains @ symbol: {url}")

    if domain.count("-") >= 2:
        score += 15
        findings.append(f"Domain contains multiple hyphens: {domain}")

    if any(fake in domain for fake in ["micr0soft", "paypa1", "arnazon"]):
        score += 50
        findings.append(f"Lookalike brand domain detected: {domain}")

    return score, findings


def analyze_attachment_risk(attachment):
    filename = attachment.get("filename", "")
    mime_type = attachment.get("mime_type", "")
    size = attachment.get("size", 0)
    ext = Path(filename.lower()).suffix

    score = 0
    findings = []

    dangerous_extensions = {
        ".exe", ".js", ".vbs", ".bat", ".cmd", ".ps1",
        ".scr", ".hta", ".jar", ".msi", ".iso", ".img"
    }

    macro_extensions = {".docm", ".xlsm", ".pptm"}
    archive_extensions = {".zip", ".rar", ".7z"}

    if ext in dangerous_extensions:
        score += 90
        findings.append(f"High-risk executable/script attachment: {filename}")

    elif ext in macro_extensions:
        score += 60
        findings.append(f"Macro-enabled Office attachment: {filename}")

    elif ext in archive_extensions:
        score += 40
        findings.append(f"Compressed archive attachment: {filename}")

    elif ext in {".html", ".htm"}:
        score += 45
        findings.append(f"HTML attachment may be used for credential phishing: {filename}")

    elif ext == ".pdf":
        score += 5
        findings.append(f"PDF attachment detected: {filename}")

    if filename.lower().count(".") >= 2:
        score += 35
        findings.append(f"Double-extension filename detected: {filename}")

    if size and size > 10 * 1024 * 1024:
        score += 10
        findings.append(f"Large attachment detected: {filename}")

    if ext == ".pdf" and mime_type and "pdf" not in mime_type.lower():
        score += 30
        findings.append(f"MIME type mismatch detected: {filename}")

    return score, findings


def analyze_email_authentication(auth_results, received_spf):
    score = 0
    findings = []

    auth_text = ((auth_results or "") + " " + (received_spf or "")).lower()

    if "spf=fail" in auth_text:
        score += 40
        findings.append("SPF authentication failed.")
    elif "spf=softfail" in auth_text:
        score += 20
        findings.append("SPF soft fail detected.")
    elif "spf=pass" in auth_text:
        findings.append("SPF passed.")

    if "dkim=fail" in auth_text:
        score += 40
        findings.append("DKIM authentication failed.")
    elif "dkim=pass" in auth_text:
        findings.append("DKIM passed.")

    if "dmarc=fail" in auth_text:
        score += 50
        findings.append("DMARC authentication failed.")
    elif "dmarc=pass" in auth_text:
        findings.append("DMARC passed.")

    return score, findings


def analyze_phishing_email(email_data):
    email_text = (
        email_data.get("subject", "") + "\n\n" +
        email_data.get("body", "") + "\n\n" +
        email_data.get("snippet", "")
    )

    sender = email_data.get("from", "")
    auth_results = email_data.get("authentication_results", "")
    received_spf = email_data.get("received_spf", "")
    attachments = email_data.get("attachments", [])

    trusted_senders = [
        "iii.com"
    ]

    is_trusted_sender = any(
        trusted_domain in sender.lower()
        for trusted_domain in trusted_senders
    )

    email_domains = extract_email_domains(email_text)
    suspicious_tlds = detect_suspicious_tlds(email_domains)
    urls = extract_urls(email_text)
    keywords = detect_suspicious_keywords(email_text)
    domain_findings = detect_suspicious_domain(sender)
    ip_addresses = extract_ip_addresses(email_text)

    risk_score = calculate_risk_score(
        urls,
        keywords,
        domain_findings,
        suspicious_tlds
    )

    findings = []

    auth_score, auth_findings = analyze_email_authentication(
        auth_results,
        received_spf
    )
    risk_score += auth_score
    findings.extend(auth_findings)

    findings.append(f"Sender: {sender}")
    findings.append(f"Subject: {email_data.get('subject', '')}")

    if urls:
        findings.append(f"URLs detected: {len(urls)}")

        for url in urls:
            local_url_score, local_url_findings = analyze_url_reputation(url)
            risk_score += local_url_score
            findings.extend(local_url_findings)

            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            ignored_vt_domains = [
                "ecp.yusercontent.com",
                "ci3.googleusercontent.com",
                "static.punchbowl.com",
                "googleusercontent.com",
                "gstatic.com"
            ]

            if not any(ignored in domain for ignored in ignored_vt_domains):
                vt_result = check_url_reputation(url)
                vt_score = vt_result.get("score", 0)
                vt_findings = vt_result.get("findings", [])

                risk_score += vt_score

                for vt_finding in vt_findings:
                    if "no existing report" not in vt_finding.lower():
                        findings.append(vt_finding)

    if keywords:
        findings.append(f"Suspicious keywords: {', '.join(keywords)}")

    if suspicious_tlds:
        findings.append(f"Suspicious TLDs detected: {', '.join(suspicious_tlds)}")

    if domain_findings:
        findings.append(f"Suspicious sender/domain indicators: {', '.join(domain_findings)}")

    if ip_addresses:
        findings.append(f"IP addresses detected: {', '.join(ip_addresses)}")

        if attachments:
            findings.append(f"Email contains {len(attachments)} attachment(s).")

    for attachment in attachments:
        attachment_score, attachment_findings = analyze_attachment_risk(attachment)
        risk_score += attachment_score
        findings.extend(attachment_findings)

        attachment_id = attachment.get("attachment_id", "")
        filename = attachment.get("filename", "")
        message_id = email_data.get("message_id", "")

        if attachment_id and message_id:
            file_hash = get_attachment_sha256(message_id, attachment_id)

            if file_hash:
                findings.append(f"Attachment SHA256 for {filename}: {file_hash}")

                vt_file_result = check_file_hash_reputation(file_hash)
                risk_score += vt_file_result.get("score", 0)

                for vt_finding in vt_file_result.get("findings", []):
                    if "no existing report" not in vt_finding.lower():
                        findings.append(vt_finding)

    if is_trusted_sender and risk_score < 40:
        findings.append("Sender matches trusted vendor list.")
        risk_score = max(0, risk_score - 10)

    risk_level = risk_rating(risk_score)

    if risk_score >= 80:
        risk_level = "Dangerous"
        recommendation = "Do not click links or open attachments. Report this email to IT."

    elif risk_score >= 40:
        risk_level = "Suspicious"
        recommendation = "This email appears suspicious. Verify the sender before interacting."

    elif risk_score >= 10:
        risk_level = "Medium Risk"
        recommendation = "Exercise caution with this email."

    else:
        risk_level = "Low Risk"
        recommendation = "No major phishing indicators found, but continue to use caution."

    enriched_urls = []

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        vt_result = check_virustotal_url(url)

        url_info = {
            "url": url,
            "domain": domain,
            "uses_https": url.lower().startswith("https://"),
            "is_shortener": domain in [
                "bit.ly",
                "tinyurl.com",
                "t.co",
                "goo.gl",
                "ow.ly",
                "is.gd",
                "buff.ly",
                "rebrand.ly"

            ],
            "virustotal":  vt_result
        }

        enriched_urls.append(url_info)

    iocs = {
        "urls": urls,
        "enriched_urls": enriched_urls,
        "attachments": [
            attachment.get("filename", "")
            for attachment in attachments
        ]
    }
        
    

    return {
        "risk_level": risk_level,
        "score": risk_score,
        "findings": findings,
        "recommendation": recommendation,
        "iocs": iocs
    }

def save_to_json(data, filename="../reports/phishing_report.json"):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


if __name__ == "__main__":
    print("This analyzer is meant to be called by main.py through FastAPI.")
