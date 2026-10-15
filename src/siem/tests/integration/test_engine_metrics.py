import asyncio
import time

from siem.alerting.alert_manager import AlertManager
from siem.alerting.rate_limiter import RateLimiter
from siem.core.engine import SecurityEngine
from siem.observability.metrics import Metrics


class NoOpDetector:
    def process(self, entry):
        return None


class NoOpNotification:
    async def send(self, alert) -> None:
        pass


def test_engine_counts_processed_and_invalid_lines(tmp_path) -> None:
    log_file = tmp_path / "sample.log"
    log_file.write_text(
        "2026-10-14T10:00:00 192.0.2.10 GET /home 200\n"
        "this is not a valid log line\n",
        encoding="utf-8",
    )

    metrics = Metrics()
    
    # 1. REMOVED metrics=metrics from here
    alert_manager = AlertManager(
        rate_limiter=RateLimiter(
            cooldown_seconds=60,
            clock=time.time,
        ),
        notifications=[NoOpNotification()],
    )
    
    # 2. ADDED metrics=metrics here
    engine = SecurityEngine(
        detectors=[NoOpDetector()],
        alert_manager=alert_manager,
        metrics=metrics,
    )

    asyncio.run(engine.process_file(str(log_file)))

    snapshot = metrics.snapshot()
    assert snapshot["lines_processed"] == 2
    assert snapshot["invalid_lines"] == 1
    assert snapshot["alerts_generated"] == 0
