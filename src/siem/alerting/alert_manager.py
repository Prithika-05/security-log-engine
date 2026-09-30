from datetime import datetime
from siem.alerting.rate_limiter import RateLimiter  # <-- Update import
from siem.models.alert import SecurityAlert

class AlertManager:
    def __init__(self) -> None:
        # Initialize the rate limiter with a 60-second cooldown and a clock function
        self.limiter = RateLimiter(cooldown_seconds=60, clock=datetime.now)

    async def trigger_alert(self, alert: SecurityAlert) -> None:
        """Invoked by the engine to process alerts."""
        if self.limiter.allowed():
            await self.send(alert)

    async def send(self, alert: SecurityAlert) -> None:
        print(
            f"[{alert.severity}] "
            f"{alert.alert_type} "
            f"({alert.source_ip}) "
            f"{alert.description}"
        )
