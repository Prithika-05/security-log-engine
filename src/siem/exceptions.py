class InvalidLogFormatException(Exception):
    """Raised when a log line does not match the expected format."""


class NotificationError(Exception):
    """Raised when notification delivery fails."""