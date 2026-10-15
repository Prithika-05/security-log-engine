import sqlite3
from datetime import datetime
from pathlib import Path

from siem.exceptions import StorageError
from siem.models.alert import SecurityAlert


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
        try:
            with sqlite3.connect(self.database_path) as connection:
                connection.execute(
                    """
                    INSERT INTO alerts (
                        alert_id,
                        timestamp,
                        alert_type,
                        severity,
                        source_ip,
                        description
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(alert_id) DO NOTHING
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
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to save alert {alert.alert_id}") from exc

    def get_all(
        self,
        severity: str | None = None,
    ) -> list[SecurityAlert]:
        query = """
            SELECT
                alert_id,
                timestamp,
                alert_type,
                severity,
                source_ip,
                description
            FROM alerts
        """

        parameters: tuple[str, ...] = ()

        if severity is not None:
            query += " WHERE severity = ?"
            parameters = (severity.upper(),)

        query += " ORDER BY timestamp, alert_id"

        with sqlite3.connect(self.database_path) as connection:
            rows = connection.execute(
                query,
                parameters,
            ).fetchall()

        return [
            SecurityAlert(
                alert_id=row[0],
                timestamp=datetime.fromisoformat(row[1]),
                alert_type=row[2],
                severity=row[3],
                source_ip=row[4],
                description=row[5],
            )
            for row in rows
        ]
