from collections import defaultdict
from datetime import timedelta
from typing import Optional
from siem.models.alert import SecurityAlert
from siem.models.log_entry import LogEntry

class BruteForceDetector:
    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # Tracks lists of failure timestamps per IP address
        self.history = defaultdict(list)

    def process(self, entry: LogEntry) -> Optional[dict]:
        # 1. Only evaluate failed logins (status code 401)
        if entry.status_code != 401:
            return None

        ip = entry.ip_address
        current_time = entry.timestamp

        # 2. Append the current failed attempt timestamp to history
        self.history[ip].append(current_time)

        # 3. Clean up attempts outside the sliding time window
        cutoff_time = current_time - timedelta(seconds=self.window_seconds)
        self.history[ip] = [t for t in self.history[ip] if t > cutoff_time]

        # 4. Check if the threshold is met or exceeded
               # 4. Check if the threshold is met or exceeded
        if len(self.history[ip]) >= self.threshold:
            # Return an object instance instead of a plain dict
            return SecurityAlert(
                timestamp=current_time,  # <-- Add this required parameter
                alert_type="Brute Force Detected",
                source_ip=ip,
                description=f"Multiple failed login attempts ({len(self.history[ip])}) detected.",
                severity="HIGH"
            )



        return None
