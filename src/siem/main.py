from siem.alerting.alert_manager import AlertManager
from siem.core.engine import SecurityEngine
from siem.detection.brute_force import BruteForceDetector


def main() -> None:
    detectors = [
        BruteForceDetector(
            threshold=5,
            window_seconds=60,
        ),
    ]

    alert_manager = AlertManager()

    engine = SecurityEngine(
        detectors=detectors,
        alert_manager=alert_manager,
    )

    engine.process_file("data/sample.log")


if __name__ == "__main__":
    main()