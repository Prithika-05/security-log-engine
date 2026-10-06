import pytest

from siem.config import Settings
from siem.config import load_settings

def test_default_settings():
    settings = Settings()

    assert settings.brute_force_threshold == 5
    assert settings.scanner_threshold == 3
    assert settings.alert_cooldown_seconds == 60


def test_invalid_brute_force_threshold():
    with pytest.raises(ValueError):
        Settings(brute_force_threshold=0)


def test_invalid_scanner_window():
    with pytest.raises(ValueError):
        Settings(scanner_window_seconds=0)

def test_load_settings_from_environment(monkeypatch):
    monkeypatch.setenv(
        "ALERT_WORKER_COUNT",
        "5",
    )
    monkeypatch.setenv(
        "QUEUE_SIZE",
        "5000",
    )

    settings = load_settings()

    assert settings.alert_worker_count == 5
    assert settings.queue_size == 5000