import re

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

def calculate_risk_score(urls, keywords, domain_findings):
    score = 0
    
    score += len(urls) * 2
    score += len(keywords)
    score += len(domain_findings) * 3
    
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


def main():
    email_text = read_email()

    sender = extract_sender(email_text)

    urls = extract_urls(email_text)

    keywords = detect_suspicious_keywords(email_text)

    domain_findings = detect_suspicious_domain(sender)

    risk_score = calculate_risk_score(
        urls,
        keywords,
        domain_findings
    )

    print("\n=== PHISHING EMAIL ANALYSIS ===\n")

    print("Sender:")
    print(sender)

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


if __name__ == "__main__":
    main()
