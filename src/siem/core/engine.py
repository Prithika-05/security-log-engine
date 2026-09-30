import asyncio
from collections.abc import Sequence

from siem.alerting.alert_manager import AlertManager
from siem.detection.protocols import Detector
from siem.exceptions import InvalidLogFormatException
from siem.ingestion.file_reader import read_log_file
from siem.models.alert import SecurityAlert
from siem.parsing.log_parser import parse_log_line


class SecurityEngine:
    def __init__(
        self,
        detectors: Sequence[Detector],
        alert_manager: AlertManager,
        worker_count: int = 3,
    ) -> None:
        self.detectors = detectors
        self.alert_manager = alert_manager
        self.worker_count = worker_count

    async def _alert_worker(
        self,
        queue: asyncio.Queue[SecurityAlert],
    ) -> None:
        while True:
            alert = await queue.get()

            try:
                await self.alert_manager.send(alert)
            finally:
                queue.task_done()

    def _start_workers(
        self,
        queue: asyncio.Queue[SecurityAlert],
    ) -> list[asyncio.Task[None]]:
        return [
            asyncio.create_task(self._alert_worker(queue))
            for _ in range(self.worker_count)
        ]

    async def process_file(self, path: str) -> None:
        queue: asyncio.Queue[SecurityAlert] = asyncio.Queue()

        workers = self._start_workers(queue)

        try:
            for line in read_log_file(path):
                try:
                    entry = parse_log_line(line)
                except InvalidLogFormatException as exc:
                    print(f"Invalid log: {exc}")
                    continue

                for detector in self.detectors:
                    alert = detector.process(entry)

                    if alert is not None:
                        await queue.put(alert)

            await queue.join()

        finally:
            for worker in workers:
                worker.cancel()

            await asyncio.gather(
                *workers,
                return_exceptions=True,
            )