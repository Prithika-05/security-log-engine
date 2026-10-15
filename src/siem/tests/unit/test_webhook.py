import asyncio  # Added to prevent NameError inside TimeoutClient
from datetime import datetime

import pytest

from siem.alerting.webhook import WebhookNotification
from siem.exceptions import NotificationError
from siem.models.alert import SecurityAlert

class FakeHttpClient:
    def __init__(self) -> None:
        self.requests = []

    async def post(self, url, json=None, *args, **kwargs):
        self.requests.append(
            {
                "url": url,
                "json": json,
            }
        )

class FailingHttpClient:
    async def post(self, url, json=None, *args, **kwargs):
        raise ConnectionError("Connection refused")

class FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code

class StatusCodeClient:
    def __init__(self) -> None:
        self.calls = 0

    async def post(self, url, json=None, *args, **kwargs):  # Fixed indentation here
        self.calls += 1

        if self.calls < 3:
            return FakeResponse(503)

        return FakeResponse(200)
    
class TimeoutClient:
    def __init__(self):
        self.calls = 0

    async def post(self, url, json=None, *args, **kwargs):  # Standardised parameters
        self.calls += 1
        await asyncio.sleep(10)

class RetryClient:
    def __init__(self):
        self.calls = 0

    async def post(self, url, json=None, *args, **kwargs):
        self.calls += 1

        if self.calls < 3:
            raise ConnectionError("temporary failure")

class FakeSleep:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)

class RecordingClient:
    def __init__(self) -> None:
        self.calls = []

    async def post(self, url, json=None, headers=None, *args, **kwargs):  
        self.calls.append({
            "payload": json,
            "headers": headers,
        })

        if len(self.calls) == 1:
            return FakeResponse(503)

        return FakeResponse(200)

@pytest.mark.asyncio
async def test_webhook_converts_connection_error():
    client = FailingHttpClient()

    # 1. Bind 'alert' to a valid SecurityAlert instance
    alert = SecurityAlert(
        timestamp=datetime.now(),
        alert_type="brute_force",
        severity="high",
        source_ip="10.0.0.8",
        description="Testing connection errors"
    )

    notification = WebhookNotification(
        client=client, # 2. Make sure this points to your failing client mock
        url="https://example.test/webhook",
        timeout_seconds=0.01,
        max_retries=2,
    )

    with pytest.raises(NotificationError):
        await notification.send(alert)

@pytest.mark.asyncio
async def test_webhook_retries_without_real_sleep():
    client = RetryClient()  # Your existing fake client
    fake_sleep = FakeSleep()

    notification = WebhookNotification(
        client=client,
        url="https://example.test/webhook",
        max_retries=3,
        sleep=fake_sleep,
    )

    await notification.send(make_test_alert())

    assert client.calls == 3
    assert fake_sleep.delays == [1, 2]

@pytest.mark.asyncio
async def test_webhook_retries_server_errors():
    client = StatusCodeClient()
    fake_sleep = FakeSleep()

    notification = WebhookNotification(
        client=client,
        url="https://example.test/webhook",
        max_retries=3,
        sleep=fake_sleep,
    )

    await notification.send(make_test_alert())

    assert client.calls == 3
    assert fake_sleep.delays == [1, 2]


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

@pytest.mark.asyncio
async def test_webhook_does_not_retry_bad_request():
    client = StatusCodeClient()
       
    # Define a quick mock response structure that returns 400
    class MockResponse:
        status = 400
        status_code = 400

    # Force the client's post method to return our 400 error response
    async def mock_post(*args, **kwargs):
        client.calls += 1
        return MockResponse()
    client.post = mock_post

    fake_sleep = FakeSleep()

    notification = WebhookNotification(
        client=client,
        url="https://example.test/webhook",
        max_retries=3,
        sleep=fake_sleep,
    )

    with pytest.raises(NotificationError):
        await notification.send(make_test_alert())

    assert client.calls == 1
    assert fake_sleep.delays == []

def make_test_alert() -> SecurityAlert:
    return SecurityAlert(
        timestamp=datetime.now(),
        alert_type="brute_force",
        severity="high",
        source_ip="10.0.0.8",
        description="Testing retry logic"
    )

@pytest.mark.asyncio
async def test_webhook_reuses_idempotency_key_on_retry():
    client = RecordingClient()
    fake_sleep = FakeSleep()
    alert = make_test_alert()

    notification = WebhookNotification(
        client=client,
        url="https://example.test/webhook",
        max_retries=2,
        sleep=fake_sleep,
    )

    await notification.send(alert)

    assert len(client.calls) == 2

    first = client.calls[0]
    second = client.calls[1]

    assert first["payload"]["alert_id"] == alert.alert_id
    assert second["payload"]["alert_id"] == alert.alert_id

    assert (
        first["headers"]["Idempotency-Key"]
        == second["headers"]["Idempotency-Key"]
    )
