from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable

# 1. MAKE SURE THIS IS EXACTLY 'rate_limit' (not rate_limiter)
def rate_limit(cooldown_seconds: int):
    last_called = None

    def decorator(function: Callable[..., Any]):
        @wraps(function)
        async def wrapper(*args, **kwargs):
            nonlocal last_called

            now = datetime.now()
            if last_called and now - last_called < timedelta(seconds=cooldown_seconds):
                return

            last_called = now
            return await function(*args, **kwargs)

        return wrapper

    return decorator
