Louisburg Phishing Analyzer

A Gmail-integrated phishing detection and incident response platform built with:

FastAPI
Gmail Add-ons
SQLite
VirusTotal API
Chart.js
Google Apps Script

Designed to help library staff quickly analyze suspicious emails, extract indicators of compromise (IOCs), and manage phishing investigations through a centralized SOC-style dashboard.

Features
Gmail Add-on Integration
Analyze suspicious emails directly inside Gmail
One-click phishing reporting
Risk scoring and verdict display
Phishing Detection Engine

Detects:

SPF failures
DKIM issues
suspicious keywords
URL shorteners
non-HTTPS links
malicious URLs via VirusTotal
suspicious attachments
phishing indicators in headers
IOC Extraction

Extracts:

URLs
attachment filenames
message IDs
sender details
Analyst Dashboard

Interactive dashboard with:

Dark mode UI
Auto-refresh
Search and filtering
IOC modal viewer
Risk charts
Top sender tracking
Analyst workflow statuses
Analyst Workflow

Track reports as:

New
Reviewed
False Positive
Confirmed Malicious
Security
API key authentication
Protected backend endpoints
Dashboard-ready architecture
