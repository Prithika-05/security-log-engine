import pytest
from datetime import datetime                    
from unittest.mock import AsyncMock
from unittest.mock import Mock
from siem.alerting.alert_manager import AlertManager
from siem.core.engine import SecurityEngine
from siem.detection.brute_force import BruteForceDetector
from siem.alerting.rate_limiter import RateLimiter
from siem.detection.scanner import ScannerDetector

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

class FakeNotification:
    def __init__(self) -> None:
        self.alerts = []

    async def send(self, alert):
        self.alerts.append(alert)


@pytest.mark.asyncio
async def test_full_brute_force_pipeline(tmp_path):
    log_file = tmp_path / "security.log"
 
    log_file.write_text(
        "\n".join(
            [
                "2026-09-24T10:00:01 10.0.0.5 POST /login 401",
                "2026-09-24T10:00:02 10.0.0.5 POST /login 401",
                "2026-09-24T10:00:03 10.0.0.5 POST /login 401",
                "2026-09-24T10:00:04 10.0.0.5 POST /login 401",
                "2026-09-24T10:00:05 10.0.0.5 POST /login 401",
            ]
        ),
        encoding="utf-8",
    )

    detector = BruteForceDetector(
        threshold=5,
        window_seconds=60,
    )

    notification = FakeNotification()

    clock = Mock()
    # Mock the time/now method if RateLimiter references it, e.g., clock.now.return_value = datetime.now()
    
    # FIX: Pass clock as a keyword argument to avoid the TypeError
    rate_limiter = RateLimiter(
        cooldown_seconds=60,
        clock=clock, 
    )

    alert_manager = AlertManager(
        rate_limiter=rate_limiter,
        notifications=[notification],
    )

    engine = SecurityEngine(
        detectors=[detector],
        alert_manager=alert_manager,
        worker_count=3,
        queue_size=10,
    )

    await engine.process_file(
        str(log_file)
    )

    assert len(notification.alerts) == 1

    alert = notification.alerts[0]

    assert alert.alert_type == "BRUTE_FORCE"
    assert alert.severity == "HIGH"
    assert alert.source_ip == "10.0.0.5"
    assert "5 failed login attempts" in alert.description

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

@pytest.mark.asyncio
async def test_full_scanner_pipeline(tmp_path):
    log_file = tmp_path / "security.log"

    log_file.write_text(
        "\n".join(
            [
                "2026-09-24T10:00:01 10.0.0.8 GET /admin 404",
                "2026-09-24T10:00:02 10.0.0.8 GET /.env 404",
                "2026-09-24T10:00:03 10.0.0.8 GET /config 404",
            ]
        ),
        encoding="utf-8",
    )

    detector = ScannerDetector(
        threshold=3,
        window_seconds=60,
    )

    notification = FakeNotification()

    clock = Mock()
    rate_limiter = RateLimiter(
        cooldown_seconds=60,
        clock=clock, 
    )

    alert_manager = AlertManager(
        rate_limiter=rate_limiter,
        notifications=[notification],
    )

    engine = SecurityEngine(
        detectors=[detector],
        alert_manager=alert_manager,
        worker_count=3,
        queue_size=10,
    )

    await engine.process_file(
        str(log_file)
    )

    assert len(notification.alerts) == 1

    alert = notification.alerts[0]

    assert alert.alert_type == "SCANNING"
    assert alert.severity == "MEDIUM"
    assert alert.source_ip == "10.0.0.8"