"""Runtime introspection helpers: main script path/dir, calling function name, unwrapping decorated callables."""

import functools
import inspect
import os
import sys
import shutil
from typing import Optional


def get_main_script_path() -> Optional[str]:
    """Return the absolute path to the original top-level Python script
    that started execution (the "main" script), handling various
    invocation methods and packaging scenarios.

    Returns:
        str or None: The script path, or None if it can't be determined (e.g. interactive shell).
    """
    import __main__

    # Case 1: Frozen app (PyInstaller, cx_Freeze, etc.)
    if getattr(sys, 'frozen', False):
        return os.path.abspath(sys.executable)

    # Case 2: Normal script or module invocation
    if hasattr(__main__, "__file__"):
        return os.path.abspath(__main__.__file__)

    # Case 3: sys.argv[0] fallback (covers direct + relative execution)
    argv0 = sys.argv[0]
    if argv0:
        if not os.path.isabs(argv0):
            resolved = shutil.which(argv0)
            if resolved:
                return os.path.abspath(resolved)
        return os.path.abspath(argv0)

    # Case 4: Interactive shell or embedded Python
    return None


def get_main_script_dir() -> Optional[str]:
    """Return the directory containing the main script.

    Returns:
        str or None: Directory containing the main script, or None if it can't be determined.
    """
    if mpath := get_main_script_path():
        return os.path.dirname(os.path.abspath(mpath))
    return None


# return the name of the calling function as a string
def get_function_name(depth=0):
    """Return the name of the calling function as a string.

    Args:
        depth (int, optional): Number of stack frames above the caller to look up. 0 returns the caller's own name. Defaults to 0.

    Returns:
        str or None: The function name, or None on failure.
    """
    try:
        frame = inspect.currentframe()
        for _ in range(depth + 1):
            if frame is None:
                return None
            frame = frame.f_back
        return frame.f_code.co_name if frame else None
    except Exception:
        return None
    finally:
        del frame


# Returns the raw underlying function behind a method, classmethod, staticmethod, or functools.partial/wrapped method.
def unwrap_method(method):
    """Returns the raw underlying function behind a method, classmethod, staticmethod, or functools.partial/wrapped method.

    Args:
        method (callable): A classmethod, staticmethod, functools.partial/partialmethod, or functools.wraps-decorated callable.

    Returns:
        callable: The underlying plain function.
    """

    # Handle classmethod / staticmethod
    if isinstance(method, (classmethod, staticmethod)):
        method = method.__func__

    # Unwrap functools.partial, wraps, etc.
    while hasattr(method, "__wrapped__"):
        method = method.__wrapped__

    # functools.partialmethod stores the underlying function in `func`
    if isinstance(method, functools.partial):
        method = method.func

    return method
