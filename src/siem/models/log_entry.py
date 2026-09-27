from datetime import datetime
from dataclasses import dataclass

@dataclass
class LogEntry: 
    timestamp: datetime
    ip_address: str
    method: str
    path: str
    status_code: int
