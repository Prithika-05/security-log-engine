from collections import Counter


class Metrics:
    """Collect process-local counters for the security log engine."""

    METRIC_NAMES = (
        "lines_processed",
        "invalid_lines",
        "alerts_generated",
        "notifications_attempted",
        "notifications_succeeded",
        "notification_failures",
        "alerts_rate_limited",
    )

    def __init__(self) -> None:
        self._counters: Counter[str] = Counter(
            {name: 0 for name in self.METRIC_NAMES}
        )

    def increment(self, name: str, amount: int = 1) -> None:
        if name not in self.METRIC_NAMES:
            raise ValueError(f"Unknown metric: {name}")
        if amount < 0:
            raise ValueError("Metric increments cannot be negative")
        self._counters[name] += amount

    def snapshot(self) -> dict[str, int]:
        """Return a copy so callers cannot modify internal counters."""
        return dict(self._counters)