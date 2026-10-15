from datetime import datetime

import pytest

from siem.exceptions import StorageError
from siem.models.alert import SecurityAlert
from siem.storage.alert_repository import SQLiteAlertRepository


def make_alert() -> SecurityAlert:
    return SecurityAlert(
        timestamp=datetime.fromisoformat("2026-09-24T10:00:00"),
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="5 failed login attempts",
    )


def test_save_and_retrieve_alert(tmp_path):
    database_path = tmp_path / "alerts.db"
    repository = SQLiteAlertRepository(database_path)

    alert = make_alert()

    repository.save(alert)

    saved_alerts = repository.get_all()

    assert len(saved_alerts) == 1
    assert saved_alerts[0] == alert


def test_saving_same_alert_twice_does_not_duplicate_it(tmp_path):
    repository = SQLiteAlertRepository(tmp_path / "alerts.db")

    alert = make_alert()

    repository.save(alert)
    repository.save(alert)

    saved_alerts = repository.get_all()

    assert len(saved_alerts) == 1
    assert saved_alerts[0].alert_id == alert.alert_id


def test_repository_stores_alerts_across_instances(tmp_path):
    database_path = tmp_path / "alerts.db"

    first_repository = SQLiteAlertRepository(database_path)
    alert = make_alert()

    first_repository.save(alert)

    second_repository = SQLiteAlertRepository(database_path)

    assert second_repository.get_all() == [alert]


def test_empty_database_returns_empty_list(tmp_path):
    repository = SQLiteAlertRepository(tmp_path / "alerts.db")

    assert repository.get_all() == []


def test_filter_alerts_by_severity(tmp_path):
    repository = SQLiteAlertRepository(tmp_path / "alerts.db")

    high_alert = make_alert()

    medium_alert = SecurityAlert(
        timestamp=datetime.fromisoformat("2026-09-24T10:01:00"),
        alert_type="SCANNING",
        severity="MEDIUM",
        source_ip="10.0.0.8",
        description="Suspicious endpoints requested",
    )

    repository.save(high_alert)
    repository.save(medium_alert)

    results = repository.get_all(severity="HIGH")

    assert len(results) == 1
    assert results[0].alert_type == "BRUTE_FORCE"


def test_severity_filter_is_case_insensitive(tmp_path):
    repository = SQLiteAlertRepository(tmp_path / "alerts.db")

    repository.save(make_alert())

    results = repository.get_all(severity="high")

    assert len(results) == 1


def test_save_raises_storage_error_when_database_is_unavailable(
    tmp_path,
):
    database_path = tmp_path / "missing" / "alerts.db"

    repository = SQLiteAlertRepository.__new__(SQLiteAlertRepository)
    repository.database_path = database_path

    with pytest.raises(StorageError):
        repository.save(make_alert())
