# =============================================================================
# utils/rate_limit.py — Thread-safe in-memory rate limiter for auth endpoints
# =============================================================================
import threading
import time
from collections import defaultdict

from config import Config


class SlidingWindowRateLimiter:
    """Sliding-window in-memory rate limiter with per-key attempt tracking."""

    def __init__(self, max_attempts: int | None = None, window_seconds: int | None = None):
        self.max_attempts = max_attempts or getattr(Config, "AUTH_RATE_LIMIT_MAX_ATTEMPTS", 5)
        self.window_seconds = window_seconds or getattr(Config, "AUTH_RATE_LIMIT_WINDOW_SECONDS", 60)
        self._lock = threading.Lock()
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._lockouts: dict[str, float] = {}

    def is_rate_limited(self, key: str) -> tuple[bool, int]:
        """
        Check if the key is currently rate-limited.
        Returns: (is_limited, retry_after_seconds)
        """
        now = time.time()
        with self._lock:
            # Check lockout
            lockout_until = self._lockouts.get(key, 0)
            if lockout_until > now:
                return True, int(lockout_until - now) + 1

            # Prune expired attempts
            cutoff = now - self.window_seconds
            timestamps = [t for t in self._attempts.get(key, []) if t > cutoff]
            self._attempts[key] = timestamps

            if len(timestamps) >= self.max_attempts:
                # Trigger lockout
                self._lockouts[key] = now + self.window_seconds
                return True, self.window_seconds

            return False, 0

    def record_failure(self, key: str) -> tuple[bool, int]:
        """
        Record a failed attempt for the key.
        Returns: (is_now_limited, retry_after_seconds)
        """
        now = time.time()
        with self._lock:
            cutoff = now - self.window_seconds
            timestamps = [t for t in self._attempts.get(key, []) if t > cutoff]
            timestamps.append(now)
            self._attempts[key] = timestamps

            if len(timestamps) >= self.max_attempts:
                self._lockouts[key] = now + self.window_seconds
                return True, self.window_seconds

            return False, 0

    def reset(self, key: str) -> None:
        """Reset attempts for a key after successful authentication."""
        with self._lock:
            self._attempts.pop(key, None)
            self._lockouts.pop(key, None)

    def get_failure_count(self, key: str) -> int:
        """Get the count of active failures for a key in the current window."""
        now = time.time()
        with self._lock:
            cutoff = now - self.window_seconds
            return len([t for t in self._attempts.get(key, []) if t > cutoff])

    def clear(self) -> None:
        """Clear all entries (useful in testing)."""
        with self._lock:
            self._attempts.clear()
            self._lockouts.clear()


# Global rate limiter instances for authentication endpoints
login_rate_limiter = SlidingWindowRateLimiter()
register_rate_limiter = SlidingWindowRateLimiter(max_attempts=10, window_seconds=60)
