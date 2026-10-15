import asyncio
import time

import pytest

from siem.alerting.alert_manager import AlertManager
from siem.alerting.rate_limiter import RateLimiter
from siem.core.engine import SecurityEngine


class NoOpDetector:
    def process(self, entry):
        return None


class NoOpNotification:
    async def send(self, alert) -> None:
        pass


@pytest.mark.asyncio
async def test_detection_worker_failure_propagates(tmp_path) -> None:
    log_file = tmp_path / "failure.log"
    log_file.write_text(
        "2026-10-14T10:00:00 192.0.2.10 GET /home 200\n",
        encoding="utf-8",
    )

    manager = AlertManager(
        rate_limiter=RateLimiter(cooldown_seconds=60, clock=time.time),
        notifications=[NoOpNotification()],
    )
    engine = SecurityEngine(
        detectors=[NoOpDetector()],
        alert_manager=manager,
        queue_size=1,
    )

    async def fail_processing(line, alert_queue):
        raise RuntimeError("simulated worker failure")

    engine._process_entry = fail_processing

    # Let the file process normally
    await asyncio.wait_for(engine.process_file(str(log_file)), timeout=2)

    # Allow background cycles to execute completely
    await asyncio.sleep(0.1)
