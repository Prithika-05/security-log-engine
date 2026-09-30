import asyncio
from datetime import datetime

import pytest

from siem.models.alert import SecurityAlert


class RecordingAlertManager:
    def __init__(self) -> None:
        self.alerts: list[SecurityAlert] = []

    async def send(self, alert: SecurityAlert) -> None:
        await asyncio.sleep(0.01)
        self.alerts.append(alert)


@pytest.mark.asyncio
async def test_workers_process_all_alerts():
    from siem.core.engine import SecurityEngine

    manager = RecordingAlertManager()

    engine = SecurityEngine(
        detectors=[],
        alert_manager=manager,
        worker_count=3,
    )

    queue: asyncio.Queue[SecurityAlert] = asyncio.Queue()

    workers = engine._start_workers(queue)

    alerts = [
        SecurityAlert(
            timestamp=datetime.fromisoformat(
                "2026-09-30T10:00:00"
            ),
            alert_type="TEST",
            severity="LOW",
            source_ip=f"10.0.0.{index}",
            description="test",
        )
        for index in range(5)
    ]

    for alert in alerts:
        await queue.put(alert)

    await queue.join()

    for worker in workers:
        worker.cancel()

    await asyncio.gather(
        *workers,
        return_exceptions=True,
    )

    assert len(manager.alerts) == 5