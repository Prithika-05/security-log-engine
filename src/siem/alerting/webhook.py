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

        await self.client.post(
            self.url,
            json=payload,
        )