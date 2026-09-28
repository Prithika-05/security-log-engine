from siem.alerting.rate_limiter import rate_limit
from siem.models.alert import SecurityAlert

class   AlertManager:
    def trigger_alert(self, alert: SecurityAlert) -> None:
        """Invoked by the engine to process alerts."""
        self.send(alert)

    @rate_limit(cooldown_seconds=60)
    async def send(self, alert: SecurityAlert) -> None:
        print(
            f"[{alert.severity}] "
            f"{alert.alert_type} "
            f"from {alert.source_ip}: "
            f"{alert.description}"
        )
