from siem.exceptions import NotificationError
from siem.models.alert import SecurityAlert


class WebhookNotification:
    def __init__(self, client, url: str) -> None:
        self.client = client
        self.url = url

    async def send(self, alert: SecurityAlert) -> None:
        payload = {
            "timestamp": alert.timestamp.isoformat(),
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "source_ip": alert.source_ip,
            "description": alert.description,
        }

        try:
            await self.client.post(
                self.url,
                json=payload,
            )
        except (ConnectionError, TimeoutError) as exc:
            raise NotificationError(
                f"Failed to send alert to {self.url}"
            ) from exc