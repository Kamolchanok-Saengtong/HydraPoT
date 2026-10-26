"""
core/key_rotation.py — rotate through several API keys when one runs out.

Part C burns a lot of quota (2,000+ cloud commands, then judging every arm).
Friends donate keys, so we read a NUMBERED group from the environment and move
to the next key the moment one is exhausted (HTTP 429 / "insufficient_quota").

Env scheme (add as many as you have — just bump the number):
    DEEPSEEK_API_KEY_1, DEEPSEEK_API_KEY_2, ...     # Part C cloud model
    JUDGE_API_KEY_1,    JUDGE_API_KEY_2,    ...     # Part C judge model

    pool = KeyPool("JUDGE_API_KEY", fallback_env="OPENAI_API_KEY")
    key  = pool.current()
    ... call the API ...
    if is_quota_error(status, text) and pool.rotate(key):
        key = pool.current()        # retry with the next key
"""
import os
import threading

# Substrings that mean "this key is out of quota" — rotate to the next one.
_QUOTA_SIGNS = ("insufficient_quota", "quota", "rate limit", "rate_limit",
                "too many requests", "exceeded")


def load_keys(prefix: str, fallback_env: str = None) -> list:
    """Collect PREFIX_1, PREFIX_2, … then the bare PREFIX, then fallback_env."""
    keys = []
    i = 1
    while True:
        v = os.environ.get(f"{prefix}_{i}")
        if not v:
            break
        keys.append(v)
        i += 1
    for extra in (os.environ.get(prefix), os.environ.get(fallback_env or "")):
        if extra and extra not in keys:
            keys.append(extra)
    return keys


def is_quota_error(status_code=None, text: str = "") -> bool:
    """True if the response means the current key is exhausted/limited."""
    if status_code == 429:
        return True
    low = (text or "").lower()
    return any(s in low for s in _QUOTA_SIGNS)


class KeyPool:
    """A list of keys with a current pointer; rotate() advances on exhaustion.

    Thread-safe: callers run the judge with concurrency, so several threads may
    hit the same exhausted key at once. rotate(failed_key) only advances if the
    pool is still on that key, so concurrent failures rotate ONCE, not N times.
    """

    def __init__(self, prefix: str, fallback_env: str = None):
        self.prefix = prefix
        self.keys = load_keys(prefix, fallback_env)
        self._i = 0
        self._lock = threading.Lock()

    def __len__(self):
        return len(self.keys)

    def current(self):
        return self.keys[self._i] if self.keys else None

    def rotate(self, failed_key=None) -> bool:
        """Advance past `failed_key`. Returns True if a new key is now active."""
        with self._lock:
            if failed_key is not None and self.current() != failed_key:
                return True                     # another thread already rotated
            if self._i + 1 < len(self.keys):
                self._i += 1
                return True
            return False                        # no keys left
