from fastapi.testclient import TestClient
from main import app
from siem import send_to_splunk


client = TestClient(app)



def test_home_page():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "running"


def test_dashboard_requires_login():
    response = client.get("/dashboard")
    assert response.status_code == 401


def test_dashboard_with_login():
    response = client.get(
        "/dashboard",
        auth=("admin", "ChangeThisPassword")
    )
    assert response.status_code == 200
    assert "Louisburg Phishing Dashboard" in response.text

def test_splunk_disabled_when_not_configured():
    result = send_to_splunk({
        "event_type": "test"
    })

    assert result["enabled"] is False


def test_analyze_requires_api_key():
    response = client.post(
        "/analyze",
        json={
            "messageId": "test-message",
            "userEmail": "test@example.com"
        }
    )
    assert response.status_code == 401
