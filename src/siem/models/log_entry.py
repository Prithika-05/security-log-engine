from dataclasses import dataclass
from datetime import datetime


@dataclass
class LogEntry: 
    timestamp: datetime
    ip_address: str
    method: str
    path: str
    status_code: int
