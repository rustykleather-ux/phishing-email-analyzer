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
