import re

from pathlib import Path

EMAIL_FILE = Path(__file__).parent.parent / "samples" / "phishing_email.txt"


def read_email():
    with open(EMAIL_FILE, "r", encoding="utf-8") as file:
        return file.read()


def extract_urls(text):
    return re.findall(r'https?://[^\s]+', text)


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

    urls = extract_urls(email_text)
    keywords = detect_suspicious_keywords(email_text)

    print("\n=== PHISHING EMAIL ANALYSIS ===\n")

    print("Suspicious URLs:")
    for url in urls:
        print("-", url)

    print("\nSuspicious Keywords:")
    for keyword in keywords:
        print("-", keyword)


if __name__ == "__main__":
    main()
