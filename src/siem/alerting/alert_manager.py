import logging

from siem.alerting.notifications import NotificationChannel
from siem.alerting.rate_limiter import RateLimiter
from siem.exceptions import NotificationError
from siem.models.alert import SecurityAlert

# 8. Initialize the logger using the module's namespace
logger = logging.getLogger(__name__)


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
            # Log when a notification gets dropped by the rate limiter
            logger.info(
                "Alert rate-limited: type=%s source_ip=%s",
                alert.alert_type,
                alert.source_ip,
            )
            return

        try:
            await self.notification.send(alert)
        except NotificationError as exc:
            # Replace print() with structured error logging
            logger.error(
                "Notification failed: %s",
                exc,
            )
