import pytest
from datetime import datetime                    # <-- Added missing import
from unittest.mock import AsyncMock
from siem.alerting.alert_manager import AlertManager
from siem.core.engine import SecurityEngine
from siem.detection.brute_force import BruteForceDetector
from siem.alerting.rate_limiter import RateLimiter

class FakeAlertManager(AlertManager):
    def __init__(self):
        self.alerts = []

    async def send(self, alert):
        self.alerts.append(alert)

@pytest.mark.asyncio
async def test_engine_processes_file(tmp_path):
    log_file = tmp_path / "sample.log"

    log_file.write_text(
        "\n".join(
            [
                "2026-09-25T10:00:00 10.0.0.5 POST /login 401",
                "2026-09-25T10:00:01 10.0.0.5 POST /login 401",
                "2026-09-25T10:00:02 10.0.0.5 POST /login 401",
                "2026-09-25T10:00:03 10.0.0.5 POST /login 401",
                "2026-09-25T10:00:04 10.0.0.5 POST /login 401",
            ]
        ),
        encoding="utf-8",
    )

    detector = BruteForceDetector(
        threshold=5,
        window_seconds=60,
    )

    alert_manager = FakeAlertManager()

    engine = SecurityEngine(
        detectors=[detector],
        alert_manager=alert_manager,
    )

    await engine.process_file(str(log_file))

    assert len(alert_manager.alerts) == 1
    # Update this line:
    assert alert_manager.alerts[0].alert_type == "Brute Force Detected"

def test_engine_rejects_zero_workers():
    with pytest.raises(ValueError):
        SecurityEngine(
            detectors=[],
            alert_manager=None,
            worker_count=0,
        )

def test_engine_rejects_invalid_queue_size():
    with pytest.raises(ValueError):
        SecurityEngine(
            detectors=[],
            alert_manager=None,
            queue_size=0,
        )
