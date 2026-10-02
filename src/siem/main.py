import asyncio
import logging
import time

from siem.alerting.alert_manager import AlertManager
from siem.core.engine import SecurityEngine
from siem.detection.brute_force import BruteForceDetector
from siem.detection.scanner import ScannerDetector
from siem.alerting.console import ConsoleNotification

from siem.config import Settings  
from siem.alerting.rate_limiter import RateLimiter  

async def main() -> None:
    settings = Settings()

    detectors = [
        BruteForceDetector(
            threshold=settings.brute_force_threshold,
            window_seconds=settings.brute_force_window_seconds,
        ),
        ScannerDetector(
            threshold=settings.scanner_threshold,
            window_seconds=settings.scanner_window_seconds,
        ),
    ]

    rate_limiter = RateLimiter(
        cooldown_seconds=settings.alert_cooldown_seconds,
        clock=time, 
    )

    # 1. Change this to a single instance instead of a list
    notification = ConsoleNotification()

    # 2. Pass it as 'notification' instead of 'notifications'
    alert_manager = AlertManager(
        rate_limiter=rate_limiter,
        notification=notification,
    )

    engine = SecurityEngine(
        detectors=detectors,
        alert_manager=alert_manager,
    )

    await engine.process_file("src/siem/data/sample.log")
    
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
