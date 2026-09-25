from datetime import datetime

from siem.exceptions import InvalidLogFormatException
from siem.models.log_entry import LogEntry


def parse_log_line(line: str) -> LogEntry:
    parts = line.split()

    if len(parts) != 5:
        raise InvalidLogFormatException(
            f"Expected 5 fields, got {len(parts)}: {line!r}"
        )

    try:
        timestamp = datetime.fromisoformat(parts[0])
        status_code = int(parts[4])
    except ValueError as exc:
        raise InvalidLogFormatException(
            f"Invalid log data: {line!r}"
        ) from exc

    return LogEntry(
        timestamp=timestamp,
        ip_address=parts[1],
        method=parts[2],
        path=parts[3],
        status_code=status_code,
    )