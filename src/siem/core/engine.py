from collections.abc import Sequence

from siem.alerting.alert_manager import AlertManager
from siem.detection.protocols import Detector
from siem.exceptions import InvalidLogFormatException
from siem.ingestion.file_reader import read_log_file
from siem.parsing.log_parser import parse_log_line


class SecurityEngine:
    def __init__(
        self,
        detectors: Sequence[Detector],
        alert_manager: AlertManager,
    ) -> None:
        self.detectors = detectors
        self.alert_manager = alert_manager

    def process_file(self, path: str) -> None:
        for line in read_log_file(path):
            try:
                entry = parse_log_line(line)
            except InvalidLogFormatException as exc:
                print(f"Invalid log: {exc}")
                continue

            for detector in self.detectors:
                alert = detector.process(entry)

                if alert is not None:
                    self.alert_manager.send(alert)