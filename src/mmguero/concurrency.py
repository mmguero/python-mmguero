"""Thread-safe primitives: an atomic integer and a self-locking OrderedDict, both usable as context managers."""

from collections import OrderedDict
from multiprocessing import RawValue
from threading import Lock


class AtomicInt:
    """A thread-safe integer that also doubles as a context manager.

    Entering the context increments the value and exiting decrements it,
    e.g. for tracking a live count of concurrent operations.
    """

    def __init__(self, value=0):
        """Initialize the atomic integer with the given starting value and an internal lock.

        Args:
            value (int, optional): Initial integer value. Defaults to 0.
        """
        self._val = RawValue('i', value)
        self._lock = Lock()

    def increment(self):
        """Atomically increment the value by one.

        Returns:
            int: The value after incrementing.
        """
        with self._lock:
            self._val.value += 1
            return self._val.value

    def decrement(self):
        """Atomically decrement the value by one.

        Returns:
            int: The value after decrementing.
        """
        with self._lock:
            self._val.value -= 1
            return self._val.value

    def value(self):
        """Return the current value under lock.

        Returns:
            int: The current value.
        """
        with self._lock:
            return self._val.value

    def __enter__(self):
        """Increment the value on entering the context.

        Returns:
            int: The value after incrementing (same as increment()).
        """
        return self.increment()

    def __exit__(self, type, value, traceback):
        """Decrement the value on exiting the context.

        Args:
            type: Exception type, if any (unused).
            value: Exception instance, if any (unused).
            traceback: Exception traceback, if any (unused).

        Returns:
            int: The value after decrementing.
        """
        return self.decrement()


# an OrderedDict that locks itself and unlocks itself as a context manager
class ContextLockedOrderedDict(OrderedDict):
    """An OrderedDict that acquires its own lock on entry and releases it on exit.

    Use as a `with` block to guard read/modify/write sequences against
    concurrent access from other threads.
    """

    def __init__(self, *args, **kwargs):
        """Initialize the ordered dict and its internal lock.

        Args:
            *args: Positional arguments forwarded to collections.OrderedDict.
            **kwargs: Keyword arguments forwarded to collections.OrderedDict.
        """
        super().__init__(*args, **kwargs)
        self._lock = Lock()

    def __enter__(self):
        """Acquire the lock for use in a `with` block.

        Returns:
            ContextLockedOrderedDict: self, now locked.
        """
        self._lock.acquire()
        return self

    def __exit__(self, type, value, traceback):
        """Release the lock on exiting the context.

        Args:
            type: Exception type, if any (unused).
            value: Exception instance, if any (unused).
            traceback: Exception traceback, if any (unused).

        Returns:
            ContextLockedOrderedDict: self, now unlocked.
        """
        self._lock.release()
        return self
