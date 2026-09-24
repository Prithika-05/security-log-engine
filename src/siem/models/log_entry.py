from datetime import datetime

from siem.models.log_entry import LogEntry


def parse_log_line(line: str) -> LogEntry:
    parts = line.split()

    timestamp = datetime.fromisoformat(parts[0])
    ip_address = parts[1]
    method = parts[2]
    path = parts[3]
    status_code = int(parts[4])

    return LogEntry(
        timestamp=timestamp,
        ip_address=ip_address,
        method=method,
        path=path,
        status_code=status_code,
    )