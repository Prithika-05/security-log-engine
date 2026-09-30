import asyncio
import time

import pytest

from siem.models.alert import SecurityAlert


class SlowAlertManager:
    def __init__(self) -> None:
        self.sent: list[SecurityAlert] = []

    async def send(self, alert: SecurityAlert) -> None:
        await asyncio.sleep(0.05)
        self.sent.append(alert)

    @pytest.mark.asyncio
    async def test_alerts_are_sent_concurrently():
        manager = SlowAlertManager()

        alerts = [
            SecurityAlert(
                timestamp=None,
                alert_type="TEST",
                severity="LOW",
                source_ip=f"10.0.0.{i}",
                description="test",
            )
            for i in range(3)
        ]

        start = time.perf_counter()

        await asyncio.gather(
            *(manager.send(alert) for alert in alerts)
        )

        elapsed = time.perf_counter() - start

        assert len(manager.sent) == 3
        assert elapsed < 0.12