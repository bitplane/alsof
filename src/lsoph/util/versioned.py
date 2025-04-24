# Filename: src/lsoph/util/versioned.py
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
        # Use RLock for reentrancy: allows a thread holding the lock to acquire it again.
        # Useful if a locked method calls another locked method on the same object.
        self._lock: threading.RLock = threading.RLock()

    def change(self):
        """
        Manually increments the version number.
        Acquires the lock to ensure atomic update.
        """
        with self._lock:
            self._version += 1

    @property
    def version(self) -> int:
        """
        Returns the current version number of this object.
        Acquires the lock for thread-safe read.
        """
        # Reading the version should also be protected by the lock for consistency.
        with self._lock:
            return self._version

    def __hash__(self) -> int:
        """
        Makes Versioned objects hashable based on identity and current version.
        Useful for caching mechanisms that depend on object state.
        Acquires the lock for thread-safe read of version.
        """
        with self._lock:
            # Hash includes object id and version for uniqueness based on state
            return hash((id(self), self._version))


def changes(method):
    """
    Decorator for methods that modify the state of a Versioned object.
    Acquires the object's lock, executes the method, and then increments
    the version number atomically.
    """

    @wraps(method)
    def wrapper(self: Versioned, *args, **kwargs):
        # Ensure the decorated method is called on an instance of Versioned or subclass
        if not isinstance(self, Versioned):
            raise TypeError(
                "The @changes decorator must be used on methods of Versioned subclasses."
            )

        with (
            self._lock
        ):  # Acquire lock before executing method and incrementing version
            result = method(self, *args, **kwargs)
            # Increment version *after* the method completes successfully
            self._version += 1
        return result

    return wrapper


def waits(method):
    """
    Decorator for methods that access the state of a Versioned object
    but do not modify it.
    Acquires the object's lock before executing the method to ensure
    thread-safe reads, especially if accessing multiple attributes.
    """

    @wraps(method)
    def wrapper(self: Versioned, *args, **kwargs):
        # Ensure the decorated method is called on an instance of Versioned or subclass
        if not isinstance(self, Versioned):
            raise TypeError(
                "The @waits decorator must be used on methods of Versioned subclasses."
            )

        with self._lock:  # Acquire lock for the duration of the method execution
            result = method(self, *args, **kwargs)
        return result

    return wrapper
