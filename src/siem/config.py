from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 60

    scanner_threshold: int = 3
    scanner_window_seconds: int = 60

    alert_cooldown_seconds: int = 60

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