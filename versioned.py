import threading
from functools import wraps


class Versioned:
    """
    Inherit this class to store a version number on each change.
    """

    def __init__(self):
        self._version = 0
        self._lock = threading.RLock()

    def change(self):
        """
        Call this if you changed something and need to blow caches
        """
        with self._lock:
            self._version += 1

    @property
    def version(self):
        """
        Return the version number of this object.
        """
        return self._version

    def __hash__(self) -> int:
        """
        Versionable objects are cacheable ones
        """
        return hash((id(self), self.version))


def changes(method):
    """
    Decorate methods with this if they make changes to the object
    """

    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            result = method(self, *args, **kwargs)
            self._version += 1
        return result

    return wrapper


def waits(method):
    """
    Decorate methods with this if they need to wait for changes
    """

    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            result = method(self, *args, **kwargs)
        return result

    return wrapper
