import os
import requests

SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL").strip()
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN").strip()


def send_to_splunk(event):
    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        return {
            "enabled": False,
            "message": "Splunk HEC URL or Token not configured."    
            
        }
    
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "event": event, 
        "sourcetype": "phishing_analyzer",
        "source": "louisburg_phishing_analyzer",
        "index": "main"
    }

    try:
        response = requests.post(
            SPLUNK_HEC_URL,
            headers=headers,
            json=payload,
            timeout=10,
            verify=False
        )

        return {
            "enabled": True,
            "status_code": response.status_code,
            "response": response.text   
        }
    
    except Exception as error:
        return {
            "enabled": True,
            "error": str(error)    
        }
        