from siem.models.alert import SecurityAlert

class AlertManager:
    def trigger_alert(self, alert: SecurityAlert) -> None:
        """Invoked by the engine to process alerts."""
        self.send(alert)

    def send(self, alert: SecurityAlert) -> None:
        print(
            f"[{alert.severity}] "
            f"{alert.alert_type} "
            f"from {alert.source_ip}: "
            f"{alert.description}"
        )
