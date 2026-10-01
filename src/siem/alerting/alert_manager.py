from siem.alerting.notifications import NotificationChannel
from siem.alerting.rate_limiter import RateLimiter
from siem.exceptions import NotificationError
from siem.models.alert import SecurityAlert


class AlertManager:
    def __init__(
        self,
        rate_limiter: RateLimiter,
        notification: NotificationChannel,
    ) -> None:
        self.rate_limiter = rate_limiter
        self.notification = notification

    async def send(self, alert: SecurityAlert) -> None:
        if not self.rate_limiter.allowed(alert.source_ip):
            return

        try:
            await self.notification.send(alert)
        except NotificationError as exc:
            print(f"Notification failed: {exc}")