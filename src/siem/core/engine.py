import asyncio
import logging
from collections.abc import Sequence

from siem.alerting.alert_manager import AlertManager
from siem.detection.protocols import Detector
from siem.exceptions import (
    InvalidLogFormatException,
    NotificationError,
)
from siem.ingestion.file_reader import read_log_file
from siem.models.alert import SecurityAlert
from siem.parsing.log_parser import parse_log_line
from siem.storage.alert_repository import SQLiteAlertRepository

logger = logging.getLogger(__name__)


class SecurityEngine:
    def __init__(
        self,
        detectors: Sequence[Detector],
        alert_manager: AlertManager,
        worker_count: int = 3,
        queue_size: int = 1000,
        alert_repository: SQLiteAlertRepository | None = None,
        metrics: Any | None = None,
    ) -> None:
        if worker_count < 1:
            raise ValueError("worker_count must be at least 1")

        if queue_size < 1:
            raise ValueError("queue_size must be at least 1")

        self.metrics = metrics
        self.detectors = detectors
        self.alert_manager = alert_manager
        self.worker_count = worker_count
        self.queue_size = queue_size
        self.alert_repository = alert_repository  # Ensured repository is saved

    async def _process_entry(
        self,
        line: str,
        alert_queue: asyncio.Queue[SecurityAlert],
    ) -> None:
        try:
            entry = parse_log_line(line)
            if self.metrics is not None:
                self.metrics.increment("lines_processed")
        except InvalidLogFormatException as exc:
            logger.warning("Invalid log: %s", exc)
            if self.metrics is not None:
                self.metrics.increment("lines_processed")
                self.metrics.increment("invalid_lines")
            return

        for detector in self.detectors:
            alert = detector.process(entry)

            if alert is not None:
                logger.info(
                    "Alert generated: type=%s source_ip=%s severity=%s",
                    alert.alert_type,
                    alert.source_ip,
                    alert.severity,
                )

                if self.alert_repository is not None:
                    self.alert_repository.save(alert)

                await alert_queue.put(alert)

    async def _worker(
        self,
        queue: asyncio.Queue[str],
        alert_queue: asyncio.Queue[SecurityAlert],
    ) -> None:
        try:
            while True:
                line = await queue.get()

                try:
                    await self._process_entry(
                        line,
                        alert_queue,
                    )
                except asyncio.CancelledError:
                    break
                finally:
                    queue.task_done()  # Fixed local variable name

        except asyncio.CancelledError:
            logger.info("Detection worker shutting down")
            raise

    async def _alert_worker(
        self,
        alert_queue: asyncio.Queue[SecurityAlert],
    ) -> None:
        try:
            while True:
                alert = await alert_queue.get()

                try:
                    await self.alert_manager.send(alert)

                except asyncio.CancelledError:
                    raise

                except NotificationError as exc:
                    logger.error(
                        "Alert delivery failed for %s: %s",
                        alert.source_ip,
                        exc,
                    )

                finally:
                    alert_queue.task_done()

        except asyncio.CancelledError:
            logger.info("Alert worker shutting down")
            raise

    def _start_alert_workers(
        self,
        alert_queue: asyncio.Queue[SecurityAlert],
    ) -> list[asyncio.Task[None]]:
        return [
            asyncio.create_task(self._alert_worker(alert_queue))
            for _ in range(self.worker_count)
        ]

    async def process_file(self, path: str) -> None:
        logger.info(
            "Processing log file: %s",
            path,
        )

        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=self.queue_size)

        alert_queue: asyncio.Queue[SecurityAlert] = asyncio.Queue(
            maxsize=self.queue_size
        )

        detection_worker = asyncio.create_task(
            self._worker(
                queue,
                alert_queue,
            )
        )

        alert_workers = self._start_alert_workers(alert_queue)

        try:
            for line in read_log_file(path):
                await queue.put(line)

            await queue.join()
            await alert_queue.join()

        finally:
            detection_worker.cancel()

            for worker in alert_workers:
                worker.cancel()

            await asyncio.gather(
                detection_worker,
                *alert_workers,
                return_exceptions=True,
            )
