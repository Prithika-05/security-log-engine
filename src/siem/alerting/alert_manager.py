from siem.alerting.rate_limiter import RateLimiter
from siem.models.alert import SecurityAlert


class AlertManager:
    def __init__(self, rate_limiter: RateLimiter) -> None:
        self.rate_limiter = rate_limiter

    async def send(self, alert: SecurityAlert) -> None:
        if not self.rate_limiter.allowed(alert.source_ip):
            return

        print(
            f"[{alert.severity}] "
            f"{alert.alert_type} "
            f"from {alert.source_ip}: "
            f"{alert.description}"
        )