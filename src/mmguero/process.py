"""Subprocess execution helpers: run a command and capture exit code/stdout/stderr, with retry support."""

import sys
import time

from subprocess import PIPE, Popen, run as SubProcessRun

from .data import flatten, get_iterable
from .output import eprint


# run command with arguments and return its exit code, stdout, and stderr
def check_output_input(*popenargs, **kwargs):
    """Run command with arguments and return its exit code, stdout, and stderr.

    Args:
        *popenargs: Positional arguments passed to subprocess.Popen.
        **kwargs: Keyword arguments passed to Popen; 'input' (if given) is piped to stdin, and 'stdout'/'stderr' may not be supplied directly.

    Returns:
        tuple[int, bytes, bytes]: (returncode, stdout, stderr).

    Raises:
        ValueError: If 'stdout' or 'stderr' is supplied, or if both 'stdin' and 'input' are supplied.
    """
    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden')

    if 'stderr' in kwargs:
        raise ValueError('stderr argument not allowed, it will be overridden')

    if 'input' in kwargs and kwargs['input']:
        if 'stdin' in kwargs:
            raise ValueError('stdin and input arguments may not both be used')
        inputdata = kwargs['input']
        kwargs['stdin'] = PIPE
    else:
        inputdata = None
    kwargs.pop('input', None)

    process = Popen(*popenargs, stdout=PIPE, stderr=PIPE, **kwargs)
    try:
        output, errput = process.communicate(inputdata)
    except Exception:
        process.kill()
        process.wait()
        raise

    retcode = process.poll()

    return retcode, output, errput


# run command with arguments and return its exit code, stdout, and stderr
def run_process(
    command,
    stdout=True,
    stderr=True,
    stdin=None,
    retry=0,
    retry_sleep_sec=5,
    cwd=None,
    env=None,
    debug=False,
    logger=None,
):
    """Run command with arguments and return its exit code, stdout, and stderr.

    Args:
        command (str or list): Command (and arguments) to run.
        stdout (bool, optional): Include stdout in the returned output. Defaults to True.
        stderr (bool, optional): Include stderr in the returned output. Defaults to True.
        stdin (str, optional): Text to send to the process's stdin.
        retry (int, optional): Number of retries on non-zero exit. Defaults to 0.
        retry_sleep_sec (int, optional): Seconds to sleep between retries. Defaults to 5.
        cwd (str, optional): Working directory for the subprocess.
        env (dict, optional): Environment variables for the subprocess.
        debug (bool, optional): Log a debug line with the command and result. Defaults to False.
        logger (logging.Logger, optional): Logger to use for debug output instead of stderr.

    Returns:
        tuple[int, list[str]]: (return code, combined output lines).
    """
    retcode = -1
    output = []
    flat_command = list(flatten(get_iterable(command)))

    try:
        # run the command
        retcode, cmdout, cmderr = check_output_input(
            flat_command,
            input=stdin.encode() if stdin else None,
            cwd=cwd,
            env=env,
        )

        # split the output on newlines to return a list
        if stderr and (len(cmderr) > 0):
            output.extend(cmderr.decode(sys.getdefaultencoding()).split('\n'))
        if stdout and (len(cmdout) > 0):
            output.extend(cmdout.decode(sys.getdefaultencoding()).split('\n'))

    except (FileNotFoundError, OSError, IOError):
        if stderr:
            output.append(f"Command {flat_command} not found or unable to execute")

    if debug:
        dbg_str = (
            f"{flat_command} ({stdin[:80] + bool(stdin[80:]) * '...' if stdin else ''}) returned {retcode}: {output}"
        )
        if logger is not None:
            logger.debug(dbg_str)
        else:
            eprint(dbg_str)

    if (retcode != 0) and retry and (retry > 0):
        # sleep then retry
        time.sleep(retry_sleep_sec)
        return run_process(
            flat_command,
            stdout,
            stderr,
            stdin,
            retry - 1,
            retry_sleep_sec,
            cwd,
            env,
            debug,
            logger,
        )
    else:
        return retcode, output


# execute a shell process returning its exit code and output
def run_sub_process(command, stdout=True, stderr=False, stdin=None, timeout=60):
    """Execute a shell process returning its exit code and output.

    Args:
        command (str): Shell command to execute.
        stdout (bool, optional): Include stdout in the returned output. Defaults to True.
        stderr (bool, optional): Include stderr in the returned output. Defaults to False.
        stdin (str, optional): Text to send to the process's stdin.
        timeout (int, optional): Seconds to wait before timing out. Defaults to 60.

    Returns:
        tuple[int, list[str]]: (return code, output lines).
    """
    retcode = -1
    output = []
    p = SubProcessRun(
        [command],
        input=stdin,
        universal_newlines=True,
        capture_output=True,
        shell=True,
        timeout=timeout,
    )
    if p:
        retcode = p.returncode
        if stderr and p.stderr:
            output.extend(p.stderr.splitlines())
        if stdout and p.stdout:
            output.extend(p.stdout.splitlines())

    return retcode, output
