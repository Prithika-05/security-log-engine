import asyncio
from collections.abc import Awaitable, Callable

from siem.exceptions import NotificationError
from siem.models.alert import SecurityAlert


class WebhookNotification:
    def __init__(
        self,
        client,
        url: str,
        timeout_seconds: float = 5.0,
        max_retries: int = 3,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError(
                "timeout_seconds must be greater than zero"
            )

        if max_retries < 0:
            raise ValueError(
                "max_retries must not be negative"
            )

        self.client = client
        self.url = url
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.sleep = sleep
        
    async def send(self, alert: SecurityAlert) -> None:
        payload = {
            "timestamp": alert.timestamp.isoformat(),
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "source_ip": alert.source_ip,
            "description": alert.description,
        }

        for attempt in range(self.max_retries + 1):
            try:
                await asyncio.wait_for(
                    self.client.post(
                        self.url,
                        json=payload,
                    ),
                    timeout=self.timeout_seconds,
                )

                return

            except (ConnectionError, TimeoutError) as exc:
                if attempt == self.max_retries:
                    raise NotificationError(
                        f"Failed to send alert to {self.url}"
                    ) from exc

                delay = 2**attempt

                await asyncio.sleep(delay)
