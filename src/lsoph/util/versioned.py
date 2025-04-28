"""
Provides a base class and decorators for simple version tracking and
thread-safe access using locks. Useful for UI updates based on state changes.
"""

import threading
from functools import wraps


class Versioned:
    """
    Base class for objects whose state changes should be trackable via a version number.
    Includes a reentrant lock for thread safety when modifying or accessing state.
    """

    def __init__(self):
        """Initializes version to 0 and creates a reentrant lock."""
        self._version: int = 0
        # Use RLock for reentrancy: no deadlocks if entered twice by the same thread
        self._lock: threading.RLock = threading.RLock()

    def change(self):
        """
        Manually increments the version number.
        """
        with self._lock:
            self._version += 1

    @property
    def version(self) -> int:
        """
        Returns the current version number of this object.
        """
        with self._lock:
            return self._version

    def __hash__(self) -> int:
        """
        Makes Versioned objects hashable based on identity and current version.
        Useful for caching mechanisms that depend on object state.
        """
        with self._lock:
            return hash((id(self), self._version))


class AbortUpdate(Exception):
    """
    Raise this exception if you want to exit a @changes decorated method
    without incrementing the version
    """

    pass


def changes(method):
    """
    Decorate state mutating methods with this.
    """

    @wraps(method)
    def wrapper(self: Versioned, *args, **kwargs):
        with self._lock:
            result = method(self, *args, **kwargs)
            self._version += 1

        return result

    return wrapper


def waits(method):
    """
    Decorate state awaiting methods with this
    """

    @wraps(method)
    def wrapper(self: Versioned, *args, **kwargs):
        with self._lock:
            result = method(self, *args, **kwargs)
        return result

    return wrapper
