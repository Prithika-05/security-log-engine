import pytest
from unittest.mock import AsyncMock  # <-- Changed from Mock to AsyncMock
from siem.alerting.alert_manager import AlertManager
from siem.core.engine import SecurityEngine
from siem.detection.brute_force import BruteForceDetector

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
    alert_manager = AlertManager()

    # Spy/Mock the 'send' method called by the engine
    alert_manager.send = AsyncMock()  # <-- Updated to target 'send' as an AsyncMock

    engine = SecurityEngine(detectors=[detector], alert_manager=alert_manager)
    
    # Process the file asynchronously
    await engine.process_file(str(log_file))  # <-- Added 'await' here

    # Assert that the alert function was invoked exactly once
    alert_manager.send.assert_called_once()  # <-- Updated assertion target
