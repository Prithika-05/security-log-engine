from unittest.mock import Mock
from siem.alerting.alert_manager import AlertManager
from siem.core.engine import SecurityEngine
from siem.detection.brute_force import BruteForceDetector

def test_engine_detects_brute_force_with_mock(tmp_path):
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
    
    # Spy/Mock the method that sends out alerts (e.g., 'trigger_alert' or 'send')
    alert_manager.trigger_alert = Mock()

    engine = SecurityEngine(detector=detector, alert_manager=alert_manager)
    engine.process_file(str(log_file))

    # Assert that the alert function was invoked exactly once
    alert_manager.trigger_alert.assert_called_once()
