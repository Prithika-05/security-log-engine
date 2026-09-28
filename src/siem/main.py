import asyncio

from siem.alerting.alert_manager import AlertManager
from siem.core.engine import SecurityEngine
from siem.detection.brute_force import BruteForceDetector
from siem.detection.scanner import ScannerDetector


async def main() -> None:
    detectors = [
        BruteForceDetector(threshold=5, window_seconds=60),
        ScannerDetector(threshold=3, window_seconds=60),
    ]

    alert_manager = AlertManager()

    engine = SecurityEngine(
        detectors=detectors,
        alert_manager=alert_manager,
    )

    await engine.process_file("data/sample.log")


if __name__ == "__main__":
    asyncio.run(main())