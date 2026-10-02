import pytest

from siem.config import Settings


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