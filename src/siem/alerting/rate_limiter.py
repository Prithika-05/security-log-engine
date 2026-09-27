from datetime import datetime, timedelta
from functools import wraps
from typing import Callable, Any


def rate_limit(cooldown_seconds: int):
    last_called: datetime | None = None
    cooldown = timedelta(seconds=cooldown_seconds)

    def decorator(function: Callable[..., Any]):
        @wraps(function)
        def wrapper(*args, **kwargs):
            nonlocal last_called

            now = datetime.now()

            if last_called is not None:
                if now - last_called < cooldown:
                    return None

            last_called = now

            return function(*args, **kwargs)

        return wrapper

    return decorator