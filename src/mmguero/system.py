"""OS/platform detection, dynamic module import with optional pip-install prompting, git clone, and logging configuration."""

import getpass
import logging
import os
import platform
import site
import sys
import importlib

from collections import defaultdict
from typing import Optional

try:
    from pwd import getpwuid
except Exception:
    getpwuid = None


try:
    from shutil import which as _shutil_which

    _has_which = True
except Exception:
    _has_which = False

from .dialog import yes_or_no
from .output import eprint
from .platforms import PLATFORM_DARWIN, PLATFORM_LINUX, PLATFORM_LINUX_UBUNTU, PLATFORM_MAC, PLATFORM_WINDOWS
from .process import run_process


# determine if a program/script exists and is executable in the system path
def which(cmd, debug=False):
    """Determine if a program/script exists and is executable in the system path.

    Args:
        cmd (str): Command/program name to look for.
        debug (bool, optional): Print a debug line with the result. Defaults to False.

    Returns:
        bool: True if `cmd` is found and executable somewhere on PATH.
    """
    if _has_which:
        result = _shutil_which(cmd) is not None
    else:
        result = any(os.access(os.path.join(path, cmd), os.X_OK) for path in os.environ["PATH"].split(os.pathsep))
    if debug:
        eprint(f"which({_has_which}) {cmd} returned {result}")
    return result


# attempt dynamic imports, prompting for install via pip if possible
_dyn_imports = defaultdict(lambda: None)


def dynamic_import(import_name, pip_pkg_name, interactive=False, debug=False, silent=True):
    """Attempt dynamic imports, prompting for install via pip if possible.

    Args:
        import_name (str): Module name to import, as passed to importlib.import_module.
        pip_pkg_name (str): PyPI package name to install if the import fails.
        interactive (bool, optional): Prompt the user before attempting a pip install. Defaults to False.
        debug (bool, optional): Print debug information. Defaults to False.
        silent (bool, optional): Suppress all status messages. Defaults to True.

    Returns:
        module or None: The imported module, or None if it couldn't be imported or installed.
    """
    debug = debug and not silent

    # see if we've already imported it
    if not _dyn_imports[import_name]:
        # if not, attempt the import
        try:
            tmp_import = importlib.import_module(import_name)
            if tmp_import:
                _dyn_imports[import_name] = tmp_import
                return _dyn_imports[import_name]
        except Exception:
            pass

        # see if we can help out by installing the module

        py_platform = sys.platform.lower()
        py_exec = sys.executable
        pip_cmd = "pip3"
        if not (pip_found := which(pip_cmd, debug=debug)):
            err, out = run_process([sys.executable, '-m', 'pip', '--version'], debug=debug)
            if out and (pip_found := (err == 0)):
                pip_cmd = [sys.executable, '-m', 'pip']

        if not silent:
            eprint(f"The {pip_pkg_name} module is required under Python {platform.python_version()} ({py_exec})")

        if interactive and pip_found:
            if yes_or_no(f"Importing the {pip_pkg_name} module failed. Attempt to install via {pip_cmd}?"):
                install_cmd = None

                if py_platform in [PLATFORM_LINUX, PLATFORM_DARWIN, PLATFORM_MAC]:
                    # for linux/mac, we're going to try to figure out if this python is owned by root or the script user
                    if getpass.getuser() == getpwuid(os.stat(py_exec).st_uid).pw_name:
                        # we're running a user-owned python, regular pip should work
                        install_cmd = [pip_cmd, "install", pip_pkg_name]
                    else:
                        # python is owned by system, so make sure to pass the --user flag
                        install_cmd = [pip_cmd, "install", "--user", pip_pkg_name]
                else:
                    # on windows (or whatever other platform this is) I don't know any other way other than pip
                    install_cmd = [pip_cmd, "install", pip_pkg_name]

                err, out = run_process(install_cmd, debug=debug)
                if err == 0:
                    if not silent:
                        eprint(f"Installation of {pip_pkg_name} module apparently succeeded")
                    importlib.reload(site)
                    importlib.invalidate_caches()
                    try:
                        tmp_import = importlib.import_module(import_name)
                        if tmp_import:
                            _dyn_imports[import_name] = tmp_import
                    except Exception as e:
                        if not silent:
                            eprint(f"Importing the {import_name} module still failed: {e}")
                elif not silent:
                    eprint(f"Installation of {import_name} module failed: {out}")

    if not _dyn_imports[import_name] and not silent:
        eprint(
            "System-wide installation varies by platform and Python configuration. Please consult platform-specific documentation for installing Python modules."
        )

    return _dyn_imports[import_name]


# create a local git clone
def git_clone(
    url,
    local_dir,
    depth=2147483647,
    recursive=True,
    single_branch=False,
    recurse_submodules=True,
    shallow_submodules=True,
    no_tags=False,
    interactive=False,
):
    """Create a local git clone.

    Args:
        url (str): Repository URL to clone.
        local_dir (str): Destination directory.
        depth (int, optional): Commit depth to fetch. Defaults to effectively unlimited.
        recursive (bool, optional): Passed through to GitPython's clone_from kwargs. Defaults to True.
        single_branch (bool, optional): Clone only a single branch. Defaults to False.
        recurse_submodules (bool, optional): Clone submodules recursively. Defaults to True.
        shallow_submodules (bool, optional): Use shallow clones for submodules. Defaults to True.
        no_tags (bool, optional): Don't fetch tags. Defaults to False.
        interactive (bool, optional): Passed to dynamic_import() for the 'GitPython' dependency. Defaults to False.
    """
    git = dynamic_import("git", "GitPython", interactive=interactive)

    git.Repo.clone_from(
        url,
        local_dir,
        **{
            "depth": depth,
            "recursive": recursive,
            "single-branch": single_branch,
            "recurse-submodules": recurse_submodules,
            "shallow-submodules": shallow_submodules,
            "no-tags": no_tags,
        },
    )


# return information about this OS distribution
def distro_info() -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Return information about this OS distribution.

    Returns:
        tuple[str|None, str|None, str|None, str|None]: (distro, codename, ubuntu_codename, release).
    """
    distro = None
    codename = None
    ubuntu_codename = None
    release = None
    plat = sys.platform.lower()

    if plat.startswith(PLATFORM_LINUX):
        os_release_info = {}

        # if the distro library can do it for us, prefer that
        if distro_lib := dynamic_import("distro", "distro"):
            distro = distro_lib.id()
            codename = distro_lib.codename()
            release = distro_lib.version()
            os_release_info = distro_lib.os_release_info()

        # check /etc/os-release values
        if not os_release_info:
            if os.path.isfile('/etc/os-release'):
                with open("/etc/os-release", 'r') as f:
                    for line in f:
                        try:
                            k, v = line.rstrip().split("=", 1)
                            os_release_info[k.lower()] = v.strip('"')
                        except Exception:
                            pass

        if os_release_info:
            if not distro:
                if os_release_info.get('id'):
                    distro = os_release_info['id'].lower().split()[0]
                elif os_release_info.get('name'):
                    distro = os_release_info['name'].lower().split()[0]

            if not codename:
                if os_release_info.get('version_codename'):
                    codename = os_release_info['version_codename'].lower().split()[0]
                elif os_release_info.get('codename'):
                    codename = os_release_info['codename'].lower().split()[0]

            if (not release) and os_release_info.get('version_id'):
                release = os_release_info['version_id'].lower().split()[0]

            if not ubuntu_codename:
                if os_release_info.get('ubuntu_version_codename'):
                    ubuntu_codename = os_release_info['ubuntu_version_codename'].lower().split()[0]
                elif os_release_info.get('ubuntu_codename'):
                    ubuntu_codename = os_release_info['ubuntu_codename'].lower().split()[0]
                elif codename and (distro == PLATFORM_LINUX_UBUNTU):
                    ubuntu_codename = codename

        # try lsb_release
        if (not all([distro, codename, release])) and which('lsb_release'):
            if not distro:
                err, out = run_process(['lsb_release', '-is'], stderr=False)
                if (err == 0) and out:
                    distro = out[0].lower()

            if not codename:
                err, out = run_process(['lsb_release', '-cs'], stderr=False)
                if (err == 0) and out:
                    codename = out[0].lower()

            if not release:
                err, out = run_process(['lsb_release', '-rs'], stderr=False)
                if (err == 0) and out:
                    release = out[0].lower()

        # try release-specific files
        if not distro:
            if distro_file := next(
                (
                    path
                    for path in [
                        '/etc/rocky-release',
                        '/etc/almalinux-release',
                        '/etc/centos-release',
                        '/etc/redhat-release',
                        '/etc/issue',
                    ]
                    if os.path.isfile(path)
                ),
                None,
            ):
                with open(distro_file, 'r') as f:
                    distro_vals = f.read().lower().split()
                    distro_nums = [x for x in distro_vals if x[0].isdigit()]
                    distro = distro_vals[0]
                    if (not release) and (len(distro_nums) > 0):
                        release = distro_nums[0]

    elif plat.startswith(PLATFORM_DARWIN) or plat.startswith(PLATFORM_MAC):
        distro = PLATFORM_MAC
        release = platform.mac_ver()[0]

    elif plat.startswith("win"):
        distro = PLATFORM_WINDOWS
        release = platform.release()

    if not distro:
        distro = plat

    return distro, codename, ubuntu_codename, release


def get_verbosity_env_var_count(var_name):
    """Read a verbosity count from an environment variable.

    Args:
        var_name (str): Name of the environment variable to read.

    Returns:
        int: Number of 'v' flags represented by the variable's value (0 if unset or invalid).
    """
    if var_name:
        verbose_env_val = os.getenv(var_name, "")
        verbose_env_val = f"-{'v' * int(verbose_env_val)}" if verbose_env_val.isdigit() else verbose_env_val
        return (
            verbose_env_val.count("v") if verbose_env_val.startswith("-") and set(verbose_env_val[1:]) <= {"v"} else 0
        )
    else:
        return 0


def set_logging(
    log_level_str,
    flag_level_count,
    logger=None,
    set_traceback_limit=False,
    logfmt='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
):
    """
    Configures logging based on a log level string or verbosity count.

    Usage example (with argparse and environment variables):
    =====================================================
    parser = argparse.ArgumentParser(
        description='\n'.join([]),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        usage=f'{script_name} <arguments>',
    )
    verbose_env_val = os.getenv("VERBOSITY", "")
    verbose_env_val = f"-{'v' * int(verbose_env_val)}" if verbose_env_val.isdigit() else verbose_env_val
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=(
            verbose_env_val.count("v") if verbose_env_val.startswith("-") and set(verbose_env_val[1:]) <= {"v"} else 0
        ),
        help='Increase log level verbosity (e.g., -v, -vv, etc.)',
    )
    parser.add_argument(
        '--loglevel',
        '-l',
        metavar='<critical|error|warning|info|debug>',
        type=str,
        default=os.getenv("LOGLEVEL", ""),
        help='Set log level directly (e.g., --loglevel=debug)',
    )
    try:
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    log_level = set_logging(args.loglevel, args.verbose, set_traceback_limit=True)
    =====================================================

    Args:
        log_level_str (str): A string like 'debug', 'info', etc. May be None.
        flag_level_count (int): Number of -v flags passed (0–5).
        logger (logging.Logger, optional): If provided, configures this logger
                                           instead of the global root logger.

    Returns:
        int: The final effective logging level (e.g., logging.DEBUG).
    """

    # level-based logging verbosity
    cli_level = None
    if log_level_str:
        cli_level = {
            'CRITICAL': logging.CRITICAL,
            'ERROR': logging.ERROR,
            'WARNING': logging.WARNING,
            'INFO': logging.INFO,
            'DEBUG': logging.DEBUG,
        }.get(log_level_str.strip().upper(), logging.CRITICAL)

    # flag-based logging verbosity
    flag_level = max(logging.NOTSET, min(logging.CRITICAL - (10 * flag_level_count), logging.CRITICAL))

    # final log level: pick more verbose (lower number)
    log_level = min(flag_level, cli_level) if cli_level is not None else flag_level

    # Configure logging
    if logger is None:
        # Set global logging config (root logger)
        logging.basicConfig(
            level=log_level,
            format=logfmt,
            datefmt=datefmt,
        )
    else:
        # Configure a specific logger
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                logfmt,
                datefmt=datefmt,
            )
        )
        logger.setLevel(log_level)
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.propagate = False  # Don't double-log to the root logger

    if set_traceback_limit and (log_level > logging.DEBUG):
        sys.tracebacklimit = 0

    return log_level
