import asyncio
import logging

from siem.alerting.alert_manager import AlertManager
from siem.core.engine import SecurityEngine
from siem.detection.brute_force import BruteForceDetector
from siem.detection.scanner import ScannerDetector
from siem.alerting.console import ConsoleNotification

notification = ConsoleNotification()

alert_manager = AlertManager(
    rate_limiter=rate_limiter,
    notification=notification,
)

async def main() -> None:
    detectors = [
        BruteForceDetector(threshold=5, window_seconds=60),
        ScannerDetector(threshold=3, window_seconds=60),
    ]

    rate_limiter = RateLimiter(
        cooldown_seconds=60,
    )

    notification = ConsoleNotification()

    alert_manager = AlertManager(
        rate_limiter=rate_limiter,
        notification=notification,
    )

    engine = SecurityEngine(
        detectors=detectors,
        alert_manager=alert_manager,
    )

    await engine.process_file("data/sample.log")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())