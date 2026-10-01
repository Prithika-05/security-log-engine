from datetime import datetime

import pytest

from siem.alerting.webhook import WebhookNotification
from siem.models.alert import SecurityAlert


class FakeHttpClient:
    def __init__(self) -> None:
        self.requests = []

    async def post(self, url: str, *, json: dict) -> None:
        self.requests.append(
            {
                "url": url,
                "json": json,
            }
        )

@pytest.mark.asyncio
async def test_webhook_sends_alert():
    client = FakeHttpClient()

    notification = WebhookNotification(
        client=client,
        url="https://example.test/webhook",
    )

    alert = SecurityAlert(
        timestamp=datetime.fromisoformat(
            "2026-10-01T10:00:00"
        ),
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="5 failed login attempts",
    )

    await notification.send(alert)

    assert len(client.requests) == 1

    request = client.requests[0]

    assert request["url"] == "https://example.test/webhook"
    assert request["json"]["alert_type"] == "BRUTE_FORCE"
    assert request["json"]["severity"] == "HIGH"
    assert request["json"]["source_ip"] == "10.0.0.5"