import re
import json
 
from pathlib import Path 

EMAIL_FILE = Path(__file__).parent.parent / "samples" / "phishing_email.txt"

 
def read_email():
    with open(EMAIL_FILE, "r", encoding="utf-8") as file:
        return file.read()


def extract_urls(text):
    return re.findall(r'https?://[^\s]+', text)


def extract_sender(text):
    match = re.search(r'From:\s*(.*)', text)
    if match:
        return match.group(1)

    return "Unknown"

def calculate_risk_score(urls, keywords, domain_findings, suspicious_tlds):
    score = 0
    
    score += len(urls) * 2
    score += len(keywords)
    score += len(domain_findings) * 3
    score += len(suspicious_tlds) * 3
    
    return score

def detect_suspicious_domain(sender):
    suspicious_patterns = [
        "micr0soft",
        "paypa1",
        "arnazon",
        ".ru",
        ".xyz"
    ]
    
    findings = []
    
    for pattern in suspicious_patterns:
        if pattern.lower() in sender.lower():
            findings.append(pattern)
            
    return findings            

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

    findings = []

    for keyword in keywords:
        if keyword.lower() in text.lower():
            findings.append(keyword)

    return findings

def risk_rating(score):
    if score >= 10:
        return "HIGH RISK"
    elif score >= 5:
        return "MEDIUM RISK"
    return "LOW RISK"

def extract_ip_addresses(text):
    return re.findall(
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        text
    )

def extract_email_domains(text):
    emails = re.findall(
        r'[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        text
    )

    return list(set(emails))

def detect_suspicious_tlds(domains):
    suspicious_tlds = [
        ".ru",
        ".xyz",
        ".top",
        ".zip",
        ".click",
        ".info"
    ]

    findings = []

    for domain in domains:
        for tld in suspicious_tlds:
            if domain.lower().endswith(tld):
                findings.append(domain)

    return findings
   
def save_to_json(data, filename="../reports/phishing_report.json"):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

def save_to_html(data, filename="../reports/phishing_report.html"):
    html = f"""
    <html>
    <head>
        <title>Phishing Email Analysis Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
            }}
            h1 {{
                color: #333;
            }}
            .risk {{
                padding: 15px;
                font-size: 22px;
                font-weight: bold;
                border-radius: 8px;
                margin-bottom: 20px;
            }}
            .high {{
                background-color: #ffcccc;
                color: #990000;
            }}
            .medium {{
                background-color: #fff0b3;
                color: #8a6d00;
            }}
            .low {{
                background-color: #ccffcc;
                color: #006600;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                margin-bottom: 25px;
            }}
            th, td {{
                border: 1px solid #ccc;
                padding: 10px;
                text-align: left;
                vertical-align: top;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            ul {{
                margin-top: 0;
            }}
        </style>
    </head>
    <body>
        <h1>Phishing Email Analysis Report</h1>

        <div class="risk {data.get("risk_rating", "").lower().split()[0]}">
            Risk Rating: {data.get("risk_rating")} | Score: {data.get("risk_score")}
        </div>

        <h2>Summary</h2>
        <table>
            <tr><th>Field</th><th>Value</th></tr>
            <tr><td>Sender</td><td>{data.get("sender")}</td></tr>
            <tr><td>Risk Score</td><td>{data.get("risk_score")}</td></tr>
            <tr><td>Risk Rating</td><td>{data.get("risk_rating")}</td></tr>
        </table>

        <h2>Indicators of Compromise</h2>
        <table>
            <tr><th>Category</th><th>Findings</th></tr>
            <tr><td>Email Domains</td><td>{"<br>".join(data.get("email_domains", []))}</td></tr>
            <tr><td>Suspicious TLDs</td><td>{"<br>".join(data.get("suspicious_tlds", []))}</td></tr>
            <tr><td>IP Addresses</td><td>{"<br>".join(data.get("ip_addresses", []))}</td></tr>
            <tr><td>URLs</td><td>{"<br>".join(data.get("urls", []))}</td></tr>
            <tr><td>Suspicious Keywords</td><td>{"<br>".join(data.get("keywords", []))}</td></tr>
            <tr><td>Domain Findings</td><td>{"<br>".join(data.get("domain_findings", []))}</td></tr>
        </table>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as file:
        file.write(html)

def main():
    email_text = read_email()

    sender = extract_sender(email_text)

    email_domains = extract_email_domains(email_text)

    suspicious_tlds = detect_suspicious_tlds(email_domains)
 
    urls = extract_urls(email_text)

    keywords = detect_suspicious_keywords(email_text)

    domain_findings = detect_suspicious_domain(sender)

    risk_score = calculate_risk_score(
        urls,
        keywords,
        domain_findings,
        suspicious_tlds
    )

    rating = risk_rating(risk_score)
    
    ip_addresses = extract_ip_addresses(email_text)
    
    results = {
        "sender": sender,
        "email_domains": email_domains,
        "suspicious_tlds": suspicious_tlds,
        "ip_addresses": ip_addresses,
        "urls": urls,
        "keywords": keywords,
        "domain_findings": domain_findings,
        "risk_score": risk_score,
        "risk_rating": rating
    }

    save_to_json(results)
    save_to_html(results)

    print("\n=== PHISHING EMAIL ANALYSIS ===\n")

    print("Sender:")
    print(sender)

    print("\nEmail Domains:")
    for domain in email_domains:
        print("-", domain)

    print("\nSuspicious TLDs:")
    for domain in suspicious_tlds:
        print("-", domain)

    print("\nIP Addresses:")
    for ip in ip_addresses:
        print("-", ip)

    print("\nSuspicious URLs:")
    for url in urls:
        print("-", url)

    print("\nSuspicious Keywords:")
    for keyword in keywords:
        print("-", keyword)

    print("\nSuspicious Domain Indicators:")
    for item in domain_findings:
        print("-", item)

    print("\nRisk Score:", risk_score)
    print("Risk Rating:", rating)
    
    if __name__ == "__main__":
        main()
