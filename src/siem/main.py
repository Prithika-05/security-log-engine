import argparse
import asyncio
import logging
import time

from siem.alerting.alert_manager import AlertManager
from siem.alerting.console import ConsoleNotification
from siem.alerting.rate_limiter import RateLimiter
from siem.config import load_settings
from siem.core.engine import SecurityEngine
from siem.detection.brute_force import BruteForceDetector
from siem.detection.scanner import ScannerDetector
from siem.logging_config import configure_logging 
from pathlib import Path
from siem.storage.alert_repository import SQLiteAlertRepository
from siem.observability.metrics   import Metrics 



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Security Log Analytics Engine"
    )

    parser.add_argument(
        "--log-file",
        required=True,
        help="Path to the log file to process",
    )

    return parser.parse_args()


async def run_engine(log_file: Path) -> None:
    settings = load_settings()
    metrics = Metrics()

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
        clock=time.time,
    )

    notifications = [
        ConsoleNotification(),
    ]

    alert_manager = AlertManager(
        rate_limiter=rate_limiter,
        notifications=notifications,
        metrics=metrics,
    )

    engine = SecurityEngine(
        detectors=detectors,
        alert_manager=alert_manager,
        worker_count=settings.alert_worker_count,
        queue_size=settings.queue_size,
        metrics=metrics,
    )

    await engine.process_file(str(log_file))


async def main() -> None:
    configure_logging()
    args = parse_args()

    log_file = Path(args.log_file)

    if not log_file.is_file():
        raise SystemExit(
            f"Error: log file does not exist or is not a file: {log_file}"
        )

    await run_engine(log_file)

def run_cli() -> None:
    """Synchronous wrapper to boot the asyncio event loop."""
    asyncio.run(main())

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
