import pytest
from datetime import datetime                    # <-- Added missing import
from unittest.mock import AsyncMock
from siem.alerting.alert_manager import AlertManager
from siem.core.engine import SecurityEngine
from siem.detection.brute_force import BruteForceDetector
from siem.alerting.rate_limiter import RateLimiter

@pytest.mark.asyncio
async def test_engine_detects_brute_force_with_mock(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text(
        "\n".join([
            "2026-09-25T10:00:01 10.0.0.5 POST /login 401",
            "2026-09-25T10:00:02 10.0.0.5 POST /login 401",
            "2026-09-25T10:00:03 10.0.0.5 POST /login 401",
            "2026-09-25T10:00:04 10.0.0.5 POST /login 401",
            "2026-09-25T10:00:05 10.0.0.5 POST /login 401",
        ]),
        encoding="utf-8",
    )

    detector = BruteForceDetector(threshold=5, window_seconds=60)
    
    # Correctly initialize the rate limiter with required positional arguments
    rate_limiter = RateLimiter(cooldown_seconds=60, clock=datetime.now)
    alert_manager = AlertManager(rate_limiter=rate_limiter) 
    
    # Spy/Mock the 'send' method called by the engine
    alert_manager.send = AsyncMock()

    engine = SecurityEngine(detectors=[detector], alert_manager=alert_manager)
    
    # Process the file asynchronously
    await engine.process_file(str(log_file))

    # Assert that the alert function was invoked exactly once
    alert_manager.send.assert_called_once()

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
