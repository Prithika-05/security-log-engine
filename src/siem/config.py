import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 60

    scanner_threshold: int = 3
    scanner_window_seconds: int = 60

    alert_cooldown_seconds: int = 60

    alert_worker_count: int = 3
    queue_size: int = 1000

    webhook_timeout_seconds: float = 5.0
    webhook_max_retries: int = 3

    def __post_init__(self) -> None:
        if self.brute_force_threshold <= 0:
            raise ValueError(
                "brute_force_threshold must be greater than zero"
            )

        if self.brute_force_window_seconds <= 0:
            raise ValueError(
                "brute_force_window_seconds must be greater than zero"
            )

        if self.scanner_threshold <= 0:
            raise ValueError(
                "scanner_threshold must be greater than zero"
            )

        if self.scanner_window_seconds <= 0:
            raise ValueError(
                "scanner_window_seconds must be greater than zero"
            )

        if self.alert_cooldown_seconds <= 0:
            raise ValueError(
                "alert_cooldown_seconds must be greater than zero"
            )

        if self.alert_worker_count <= 0:
            raise ValueError(
                "alert_worker_count must be greater than zero"
            )

        if self.queue_size <= 0:
            raise ValueError(
                "queue_size must be greater than zero"
            )
        
        if self.webhook_timeout_seconds <= 0:
            raise ValueError(
                "webhook_timeout_seconds must be greater than zero"
            )

        if self.webhook_max_retries < 0:
            raise ValueError(
                "webhook_max_retries must not be negative"
            )


def load_settings() -> Settings:
    return Settings(
        brute_force_threshold=int(
            os.environ.get("BRUTE_FORCE_THRESHOLD", "5")
        ),
        brute_force_window_seconds=int(
            os.environ.get("BRUTE_FORCE_WINDOW_SECONDS", "60")
        ),
        scanner_threshold=int(
            os.environ.get("SCANNER_THRESHOLD", "3")
        ),
        scanner_window_seconds=int(
            os.environ.get("SCANNER_WINDOW_SECONDS", "60")
        ),
        alert_cooldown_seconds=int(
            os.environ.get("ALERT_COOLDOWN_SECONDS", "60")
        ),
        alert_worker_count=int(
            os.environ.get("ALERT_WORKER_COUNT", "3")
        ),
        queue_size=int(
            os.environ.get("QUEUE_SIZE", "1000")
        ),
        webhook_timeout_seconds=float(
            os.environ.get(
                "WEBHOOK_TIMEOUT_SECONDS",
                "5.0",
            )
        ),
        webhook_max_retries=int(
            os.environ.get(
                "WEBHOOK_MAX_RETRIES",
                "3",
            )
        ),
    )