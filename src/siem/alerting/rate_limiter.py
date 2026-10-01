from typing import Callable, Any
from datetime import datetime

class RateLimiter:
    def __init__(self, cooldown_seconds: int, clock: Callable[[], datetime]) -> None:
        self.cooldown_seconds = cooldown_seconds
        self.clock = clock
        # Change from a single timestamp to a tracking dictionary
        self.last_called_per_key = {} 

    def allowed(self, key: str = "default") -> bool: # Added a default value to handle empty calls safely
        # Handle cases where clock is passed as a class/object instead of a callable method
        now = self.clock() if callable(self.clock) else self.clock.now()
        
        last_called = self.last_called_per_key.get(key)
        
        if last_called and (now - last_called).total_seconds() < self.cooldown_seconds:
            return False
            
        self.last_called_per_key[key] = now
        return True
