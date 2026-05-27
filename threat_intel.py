import os
import base64
import requests

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()


def get_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_virustotal_url(url):
    if not VT_API_KEY:
        return {
            "enabled": False,
            "status": "not_configured",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }

    url_id = get_url_id(url)

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )

        if response.status_code == 404:
            return {
                "enabled": True,
                "status": "not_found",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0
            }

        if response.status_code != 200:
            return {
                "enabled": True,
                "status": "error",
                "http_status": response.status_code,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0
            }

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get(
            "last_analysis_stats", {}
        )

        return {
            "enabled": True,
            "status": "found",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }

    except Exception as error:
        return {
            "enabled": True,
            "status": "exception",
            "error": str(error),
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }