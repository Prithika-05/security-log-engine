import asyncio
from datetime import datetime

import pytest

from siem.core.engine import SecurityEngine
from siem.models.alert import SecurityAlert


class FailingAlertManager:
    def __init__(self) -> None:
        self.sent: list[SecurityAlert] = []

    async def send(self, alert: SecurityAlert) -> None:
        if alert.source_ip == "10.0.0.2":
            raise RuntimeError("Notification service failed")

        await asyncio.sleep(0.01)

        self.sent.append(alert)

    @pytest.mark.asyncio
    async def test_worker_continues_after_delivery_error():
        manager = FailingAlertManager()

        engine = SecurityEngine(
            detectors=[],
            alert_manager=manager,
            worker_count=1,
            queue_size=10,
        )

        queue: asyncio.Queue[SecurityAlert] = asyncio.Queue()

        worker = asyncio.create_task(engine._alert_worker(queue))

        timestamp = datetime.fromisoformat("2026-10-01T10:00:00")

        alerts = [
            SecurityAlert(
                timestamp=timestamp,
                alert_type="TEST",
                severity="LOW",
                source_ip="10.0.0.1",
                description="first",
            ),
            SecurityAlert(
                timestamp=timestamp,
                alert_type="TEST",
                severity="LOW",
                source_ip="10.0.0.2",
                description="fails",
            ),
            SecurityAlert(
                timestamp=timestamp,
                alert_type="TEST",
                severity="LOW",
                source_ip="10.0.0.3",
                description="third",
            ),
        ]

        for alert in alerts:
            await queue.put(alert)

        await queue.join()

        assert len(manager.sent) == 2
        assert manager.sent[0].source_ip == "10.0.0.1"
        assert manager.sent[1].source_ip == "10.0.0.3"

        worker.cancel()

        await asyncio.gather(
            worker,
            return_exceptions=True,
        )

        @pytest.mark.asyncio
        async def test_worker_can_be_cancelled():
            manager = FailingAlertManager()

            engine = SecurityEngine(
                detectors=[],
                alert_manager=manager,
            )

            queue: asyncio.Queue[SecurityAlert] = asyncio.Queue()

            worker = asyncio.create_task(engine._alert_worker(queue))

            worker.cancel()

            with pytest.raises(asyncio.CancelledError):
                await worker
