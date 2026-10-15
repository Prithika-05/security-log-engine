from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4


@dataclass
class SecurityAlert:
    timestamp: datetime
    alert_type: str
    severity: str
    source_ip: str
    description: str
    alert_id: str = field(default_factory=lambda: str(uuid4()))
