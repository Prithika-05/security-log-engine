class InvalidLogFormatException(Exception):
    """Raised when a log line does not match the expected format."""


class NotificationError(Exception):
    """Raised when notification delivery fails."""

class WebhookHTTPError(NotificationError):
    """Raised when a webhook returns an unsuccessful HTTP status."""

    def __init__(
        self,
        status_code: int,
        message: str,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code