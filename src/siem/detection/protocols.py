from typing import Protocol

from siem.models.alert import SecurityAlert
from siem.models.log_entry import LogEntry


class Detector(Protocol):
    def process(self, entry: LogEntry) -> SecurityAlert | None: ...
