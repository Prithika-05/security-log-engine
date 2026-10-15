import asyncio
import logging
from collections.abc import Sequence

from siem.alerting.notifications import NotificationChannel
from siem.alerting.rate_limiter import RateLimiter
from siem.exceptions import NotificationError
from siem.models.alert import SecurityAlert
from siem.observability.metrics import Metrics

logger = logging.getLogger(__name__)


class AlertManager:
    # 5. Apply bounded concurrency to notifications
    def __init__(
        self,
        rate_limiter: RateLimiter,
        notifications: Sequence[NotificationChannel],
        max_concurrent_notifications: int = 10,
        metrics=None,
    ) -> None:
        self.rate_limiter = rate_limiter
        self.notifications = notifications
        self.notification_semaphore = asyncio.Semaphore(max_concurrent_notifications)
        self.metrics = metrics if metrics is not None else Metrics()

    # 6. Create a helper method
    async def _send_notification(
        self,
        notification: NotificationChannel,
        alert: SecurityAlert,
    ) -> None:
        async with self.notification_semaphore:
            try:
                await notification.send(alert)
            except NotificationError as exc:
                logger.error(
                    "Notification failed: %s",
                    exc,
                )

    async def send(self, alert: SecurityAlert) -> None:
        if not self.rate_limiter.allowed(alert.source_ip):
            logger.info(
                "Alert rate-limited: type=%s source_ip=%s",
                alert.alert_type,
                alert.source_ip,
            )
            return

        # Fire off all notification channels under the semaphore's control
        await asyncio.gather(
            *(
                self._send_notification(notification, alert)
                for notification in self.notifications
            )
        )
