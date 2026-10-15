from typing import Protocol

from siem.models.alert import SecurityAlert


class NotificationChannel(Protocol):
    async def send(self, alert: SecurityAlert) -> None: ...
