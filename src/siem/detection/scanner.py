from collections import defaultdict
from datetime import datetime, timedelta

from siem.models.alert import SecurityAlert
from siem.models.log_entry import LogEntry


SUSPICIOUS_PATHS = {
    "/admin",
    "/.env",
    "/config",
    "/backup.sql",
}


class ScannerDetector:
    def __init__(
        self,
        threshold: int = 3,
        window_seconds: int = 60,
    ) -> None:
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

        self.requests: dict[
            str,
            list[tuple[datetime, str]],
        ] = defaultdict(list)

    def process(self, entry: LogEntry) -> SecurityAlert | None:
        if entry.path not in SUSPICIOUS_PATHS:
            return None

        requests = self.requests[entry.ip_address]

        requests.append((entry.timestamp, entry.path))

        cutoff = entry.timestamp - self.window

        self.requests[entry.ip_address] = [
            (timestamp, path)
            for timestamp, path in requests
            if timestamp >= cutoff
        ]

        recent_paths = {
            path
            for _, path in self.requests[entry.ip_address]
        }

        if len(recent_paths) >= self.threshold:
            return SecurityAlert(
                timestamp=entry.timestamp,
                alert_type="SCANNING",
                severity="MEDIUM",
                source_ip=entry.ip_address,
                description=(
                    f"Requested {len(recent_paths)} "
                    "suspicious endpoints within "
                    f"{self.window.total_seconds():.0f} seconds"
                ),
            )

        return None