import asyncio
import logging
from collections.abc import Sequence

from siem.alerting.alert_manager import AlertManager
from siem.detection.protocols import Detector
from siem.exceptions import InvalidLogFormatException
from siem.ingestion.file_reader import read_log_file
from siem.models.alert import SecurityAlert
from siem.parsing.log_parser import parse_log_line

logger = logging.getLogger(__name__)


class SecurityEngine:

    def __init__(
        self,
        detectors: Sequence[Detector],
        alert_manager: AlertManager,
        worker_count: int = 3,
        queue_size: int = 1000,
    ) -> None:
        if worker_count < 1:
            raise ValueError("worker_count must be at least 1")

        if queue_size < 1:
            raise ValueError("queue_size must be at least 1")

        self.detectors = detectors
        self.alert_manager = alert_manager
        self.worker_count = worker_count
        self.queue_size = queue_size

    async def _alert_worker(
        self,
        queue: asyncio.Queue[SecurityAlert],
    ) -> None:
        while True:
            alert = await queue.get()

            try:
                await self.alert_manager.send(alert)

            except asyncio.CancelledError:
                raise

            except Exception as exc:
                print(f"Alert delivery failed for {alert.source_ip}: {exc}")

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
        # 6. Log engine activity
        logger.info("Processing log file: %s", path)

        queue: asyncio.Queue[SecurityAlert] = asyncio.Queue()

        workers = self._start_workers(queue)

        try:
            for line in read_log_file(path):
                try:
                    entry = parse_log_line(line)
                except InvalidLogFormatException as exc:
                    # 7. Replace invalid-log print()
                    logger.warning("Invalid log: %s", exc)
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
