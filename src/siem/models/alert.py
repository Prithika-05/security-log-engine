from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityAlert:
    timestamp: datetime
    alert_type: str
    severity: str
    source_ip: str
    description: str