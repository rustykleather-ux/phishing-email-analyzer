import base64
import os.path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from email.mime.text import MIMEText
import hashlib

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send"
]
def get_gmail_service():
    creds = None

    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json",
                SCOPES
            )
            creds = flow.run_local_server(port=0)

        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def decode_base64url(data):
    if not data:
        return ""

    padded = data + "=" * (-len(data) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode("utf-8"))
    return decoded.decode("utf-8", errors="replace")


def get_header(headers, name):
    for header in headers:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", "")
    return ""


def walk_parts(part, bodies, attachments):
    filename = part.get("filename", "")
    mime_type = part.get("mimeType", "")
    body = part.get("body", {})

    if filename:
        attachments.append({
            "filename": filename,
            "mime_type": mime_type,
            "size": body.get("size", 0),
            "attachment_id": body.get("attachmentId", "")
        })

    data = body.get("data")
    if data and mime_type in ["text/plain", "text/html"]:
        bodies.append(decode_base64url(data))

    for child in part.get("parts", []):
        walk_parts(child, bodies, attachments)

##Email Report To IT##

def send_report_email(to_email, subject, body):
    service = get_gmail_service()

    message = MIMEText(body)
    message["to"] = to_email
    message["subject"] = subject

    raw_message = base64.urlsafe_b64encode(
        message.as_bytes()
    ).decode("utf-8")

    sent_message = service.users().messages().send(
        userId="me",
        body={"raw": raw_message}
    ).execute()

    return sent_message



def get_gmail_message(message_id):
    service = get_gmail_service()

    message = service.users().messages().get(
        userId="me",
        id=message_id,
        format="full"
    ).execute()

    payload = message.get("payload", {})
    headers = payload.get("headers", [])

    bodies = []
    attachments = []

    walk_parts(payload, bodies, attachments)

    return {
        "id": message.get("id", ""),
        "thread_id": message.get("threadId", ""),
        "snippet": message.get("snippet", ""),
        "from": get_header(headers, "From"),
        "to": get_header(headers, "To"),
        "subject": get_header(headers, "Subject"),
        "date": get_header(headers, "Date"),
        "return_path": get_header(headers, "Return-Path"),
        "reply_to": get_header(headers, "Reply-To"),
        "authentication_results": get_header(headers, "Authentication-Results"),
        "received_spf": get_header(headers, "Received-SPF"),
        "body": "\n\n".join(bodies),
        "attachments": attachments,
        "raw_headers": headers
    }


def get_attachment_bytes(message_id, attachment_id):
    service = get_gmail_service()

    attachment = service.users().messages().attachments().get(
        userId="me",
        messageId=message_id,
        id=attachment_id
    ).execute()

    data = attachment.get("data", "")

    if not data:
        return b""

    padded = data + "=" * (-len(data) % 4)

    return base64.urlsafe_b64decode(
        padded.encode("utf-8")
    )
if __name__ == "__main__":
    service = get_gmail_service()
    print("Authentication successful.")

def get_attachment_sha256(message_id, attachment_id):
    file_bytes = get_attachment_bytes(
        message_id,
        attachment_id
    )

    if not file_bytes:
        return ""

    return hashlib.sha256(file_bytes).hexdigest()

