from siem.models.alert import SecurityAlert


class ConsoleNotification:
    async def send(self, alert: SecurityAlert) -> None:
        print(
            f"[{alert.severity}] "
            f"{alert.alert_type} "
            f"from {alert.source_ip}: "
            f"{alert.description}"
        )
