"""mmguero - Seth Grover's useful Python helpers"""

# python3 -m black --line-length 120 --skip-string-normalization
# python3 -m flake8 --ignore=E203,E501,E402,F401,F403,W503

from importlib.metadata import version, PackageNotFoundError

_package_name = __name__

try:
    __version__ = version(_package_name)
except PackageNotFoundError:
    __version__ = None

from .output import *
from .data import *
from .strings import *
from .crypto import *
from .filesystem import *
from .archive import *
from .process import *
from .network import *
from .platforms import *
from .system import *
from .dialog import *
from .concurrency import *
from .introspect import *
from .cli import *
from .caselessdictionary import *

__all__ = sorted(
    [
        name
        for name, obj in globals().items()
        if not name.startswith("_") and getattr(obj, "__module__", _package_name).startswith(_package_name + '.')
    ],
    key=str.casefold,
)
