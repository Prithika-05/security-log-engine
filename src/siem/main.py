from siem.alerting.alert_manager import AlertManager
from siem.core.engine import SecurityEngine
from siem.detection.brute_force import BruteForceDetector


def main() -> None:
    detector = BruteForceDetector(
        threshold=5,
        window_seconds=60,
    )

    alert_manager = AlertManager()

    engine = SecurityEngine(
        detector=detector,
        alert_manager=alert_manager,
    )

    engine.process_file("src/data/sample.log")


if __name__ == "__main__":
    main()