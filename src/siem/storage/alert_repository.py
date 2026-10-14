import sqlite3
from pathlib import Path

from siem.models.alert import SecurityAlert
from datetime import datetime

class SQLiteAlertRepository:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize_database()

    def _initialize_database(self) -> None:
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    description TEXT NOT NULL
                )
                """
            )

    def save(self, alert: SecurityAlert) -> None:
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO alerts (
                    alert_id,
                    timestamp,
                    alert_type,
                    severity,
                    source_ip,
                    description
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.timestamp.isoformat(),
                    alert.alert_type,
                    alert.severity,
                    alert.source_ip,
                    alert.description,
                ),
            )

    def get_all(self) -> list[SecurityAlert]:
        with sqlite3.connect(self.database_path) as connection:
            rows = connection.execute(
                """
                SELECT
                    alert_id,
                    timestamp,
                    alert_type,
                    severity,
                    source_ip,
                    description
                FROM alerts
                ORDER BY timestamp, alert_id
                """
            ).fetchall()

        return [
            SecurityAlert(
                alert_id=row[0],
                timestamp=__import__(
                    "datetime"
                ).datetime.fromisoformat(row[1]),
                alert_type=row[2],
                severity=row[3],
                source_ip=row[4],
                description=row[5],
            )
            for row in rows
        ]