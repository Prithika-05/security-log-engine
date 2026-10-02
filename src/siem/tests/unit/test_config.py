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
    monkeypatch.setenv("BRUTE_FORCE_THRESHOLD", "10")
    monkeypatch.setenv("SCANNER_THRESHOLD", "7")
    monkeypatch.setenv("ALERT_COOLDOWN_SECONDS", "120")

    settings = load_settings()

    assert settings.brute_force_threshold == 10
    assert settings.scanner_threshold == 7
    assert settings.alert_cooldown_seconds == 120