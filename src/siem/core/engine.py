from siem.alerting.alert_manager import AlertManager
from siem.detection.brute_force import BruteForceDetector
from siem.exceptions import InvalidLogFormatException
from siem.ingestion.file_reader import read_log_file
from siem.parsing.log_parser import parse_log_line


class SecurityEngine:
    def __init__(
        self,
        detector: BruteForceDetector,
        alert_manager: AlertManager,
    ) -> None:
        self.detector = detector
        self.alert_manager = alert_manager

    def process_file(self, path: str) -> None:
        for line in read_log_file(path):
            try:
                entry = parse_log_line(line)
            except InvalidLogFormatException as exc:
                print(f"Invalid log: {exc}")
                continue

            alert = self.detector.process(entry)

            if alert is not None:
                self.alert_manager.trigger_alert(alert)