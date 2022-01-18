#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import contextlib
import getpass
import importlib
import json
import os
import platform
import re
import socket
import sys
import time

from collections import defaultdict
from collections.abc import Iterable
from subprocess import PIPE, STDOUT, Popen, CalledProcessError

try:
    from pwd import getpwuid
except ImportError:
    getpwuid = None

try:
    from shutil import which

    HasWhich = True
except ImportError:
    HasWhich = False


###################################################################################################
PLATFORM_WINDOWS = "Windows"
PLATFORM_MAC = "Darwin"
PLATFORM_LINUX = "Linux"
PLATFORM_LINUX_CENTOS = "centos"
PLATFORM_LINUX_DEBIAN = "debian"
PLATFORM_LINUX_FEDORA = "fedora"
PLATFORM_LINUX_UBUNTU = "ubuntu"
PLATFORM_LINUX_RASPBIAN = "raspbian"

###################################################################################################
# chdir to directory as context manager, returning automatically
@contextlib.contextmanager
def pushd(directory):
    prevDir = os.getcwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(prevDir)


###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    sys.stderr.flush()


###################################################################################################
# safe deep get for a dictionary
#
# Example:
#   d = {'meta': {'status': 'OK', 'status_code': 200}}
#   deep_get(d, ['meta', 'status_code'])          # => 200
#   deep_get(d, ['garbage', 'status_code'])       # => None
#   deep_get(d, ['meta', 'garbage'], default='-') # => '-'
def deep_get(d, keys, default=None):
    assert type(keys) is list
    if d is None:
        return default
    if not keys:
        return d
    return deep_get(d.get(keys[0]), keys[1:], default)


###################################################################################################
# if the object is an iterable, return it, otherwise return a tuple with it as a single element.
# useful if you want to user either a scalar or an array in a loop, etc.
def get_iterable(x):
    if isinstance(x, Iterable) and not isinstance(x, str):
        return x
    else:
        return (x,)


###################################################################################################
# get interactive user response to Y/N question
def YesOrNo(question, default=None, forceInteraction=False, acceptDefault=False):

    if default == True:
        questionStr = f"\n{question} (Y/n): "
    elif default == False:
        questionStr = f"\n{question} (y/N): "
    else:
        questionStr = f"\n{question} (y/n): "

    if acceptDefault and (default is not None) and (not forceInteraction):
        reply = ""
    else:
        while True:
            reply = str(input(questionStr)).lower().strip()
            if (len(reply) > 0) or (default is not None):
                break

    if len(reply) == 0:
        reply = "y" if default else "n"

    if reply[0] == "y":
        return True
    elif reply[0] == "n":
        return False
    else:
        return YesOrNo(question, default=default)


###################################################################################################
# get interactive user response
def AskForString(question, default=None, forceInteraction=False, acceptDefault=False):

    if acceptDefault and (default is not None) and (not forceInteraction):
        reply = default
    else:
        reply = str(input(f"\n{question}: ")).strip()

    return reply


###################################################################################################
# get interactive password (without echoing)
def AskForPassword(prompt):
    reply = getpass.getpass(prompt=prompt)
    return reply


###################################################################################################
# convenient boolean argument parsing
def str2bool(v):
    if v.lower() in ("yes", "true", "t", "y", "1"):
        return True
    elif v.lower() in ("no", "false", "f", "n", "0"):
        return False
    else:
        raise ValueError("Boolean value expected")


###################################################################################################
# determine if a program/script exists and is executable in the system path
def Which(cmd, debug=False):
    global HasWhich
    if HasWhich:
        result = which(cmd) is not None
    else:
        result = any(os.access(os.path.join(path, cmd), os.X_OK) for path in os.environ["PATH"].split(os.pathsep))
    if debug:
        eprint(f"Which({HasWhich}) {cmd} returned {result}")
    return result


###################################################################################################
# nice human-readable file sizes
def SizeHumanFormat(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}{'Yi'}{suffix}"


###################################################################################################
# test if a remote port is open
def TestSocket(host, port):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(10)
        if sock.connect_ex((host, port)) == 0:
            return True
        else:
            return False


###################################################################################################
# is this string valid json? if so, load and return it
def LoadStrIfJson(jsonStr):
    try:
        return json.loads(jsonStr)
    except ValueError as e:
        return None


###################################################################################################
# run command with arguments and return its exit code, stdout, and stderr
def CheckOutputInput(*popenargs, **kwargs):

    if "stdout" in kwargs:
        raise ValueError("stdout argument not allowed, it will be overridden")

    if "stderr" in kwargs:
        raise ValueError("stderr argument not allowed, it will be overridden")

    if "input" in kwargs and kwargs["input"]:
        if "stdin" in kwargs:
            raise ValueError("stdin and input arguments may not both be used")
        inputdata = kwargs["input"]
        kwargs["stdin"] = PIPE
    else:
        inputdata = None
    kwargs.pop("input", None)

    process = Popen(*popenargs, stdout=PIPE, stderr=PIPE, **kwargs)
    try:
        output, errput = process.communicate(inputdata)
    except:
        process.kill()
        process.wait()
        raise

    retcode = process.poll()

    return retcode, output, errput


###################################################################################################
# run command with arguments and return its exit code, stdout, and stderr
def RunProcess(
    command,
    stdout=True,
    stderr=True,
    stdin=None,
    retry=0,
    retrySleepSec=5,
    cwd=None,
    env=None,
    debug=False,
):

    retcode = -1
    output = []

    try:
        # run the command
        retcode, cmdout, cmderr = CheckOutputInput(command, input=stdin.encode() if stdin else stdin, cwd=cwd, env=env)

        # split the output on newlines to return a list
        if stderr and (len(cmderr) > 0):
            output.extend(cmderr.decode(sys.getdefaultencoding()).split("\n"))
        if stdout and (len(cmdout) > 0):
            output.extend(cmdout.decode(sys.getdefaultencoding()).split("\n"))

    except (FileNotFoundError, OSError, IOError) as e:
        if stderr:
            output.append(f"Command {command} not found or unable to execute")

    if debug:
        eprint(f"{command}({stdin[:80] + bool(stdin[80:]) * '...' if stdin else ''}) returned {retcode}: {output}")

    if (retcode != 0) and retry and (retry > 0):
        # sleep then retry
        time.sleep(retrySleepSec)
        return RunProcess(command, stdout, stderr, stdin, retry - 1, retrySleepSec, cwd, env, debug)
    else:
        return retcode, output


###################################################################################################
# attempt dynamic imports, prompting for install via pip if possible
DynImports = defaultdict(lambda: None)


def DoDynamicImport(importName, pipPkgName, interactive=False, debug=False):
    global DynImports

    # see if we've already imported it
    if not DynImports[importName]:

        # if not, attempt the import
        try:
            tmpImport = importlib.import_module(importName)
            if tmpImport:
                DynImports[importName] = tmpImport
                return DynImports[importName]
        except ImportError as e:
            pass

        # see if we can help out by installing the module

        pyPlatform = platform.system()
        pyExec = sys.executable
        pipCmd = "pip3"
        if not Which(pipCmd, debug=debug):
            pipCmd = "pip"

        eprint(f"The {pipPkgName} module is required under Python {platform.python_version()} ({pyExec})")

        if interactive and Which(pipCmd, debug=debug):
            if YesOrNo(f"Importing the {pipPkgName} module failed. Attempt to install via {pipCmd}?"):
                installCmd = None

                if (pyPlatform == PLATFORM_LINUX) or (pyPlatform == PLATFORM_MAC):
                    # for linux/mac, we're going to try to figure out if this python is owned by root or the script user
                    if getpass.getuser() == getpwuid(os.stat(pyExec).st_uid).pw_name:
                        # we're running a user-owned python, regular pip should work
                        installCmd = [pipCmd, "install", pipPkgName]
                    else:
                        # python is owned by system, so make sure to pass the --user flag
                        installCmd = [pipCmd, "install", "--user", pipPkgName]
                else:
                    # on windows (or whatever other platform this is) I don't know any other way other than pip
                    installCmd = [pipCmd, "install", pipPkgName]

                err, out = RunProcess(installCmd, debug=debug)
                if err == 0:
                    eprint(f"Installation of {pipPkgName} module apparently succeeded")
                    try:
                        tmpImport = importlib.import_module(importName)
                        if tmpImport:
                            DynImports[importName] = tmpImport
                    except ImportError as e:
                        eprint(f"Importing the {importName} module still failed: {e}")
                else:
                    eprint(f"Installation of {importName} module failed: {out}")

    if not DynImports[importName]:
        eprint(
            "System-wide installation varies by platform and Python configuration. Please consult platform-specific documentation for installing Python modules."
        )

    return DynImports[importName]


###################################################################################################
# download to file
def DownloadToFile(url, local_filename, chunk_bytes=4096, interactive=False, debug=False):
    requests = DoDynamicImport("requests", "requests", interactive=interactive, debug=debug)

    r = requests.get(url, stream=True, allow_redirects=True)
    with open(local_filename, "wb") as f:
        for chunk in r.iter_content(chunk_bytes=chunk_size):
            if chunk:
                f.write(chunk)
    fExists = os.path.isfile(local_filename)
    fSize = os.path.getsize(local_filename)
    if debug:
        eprint(
            f"Download of {url} to {local_filename} {'succeeded' if fExists else 'failed'} ({SizeHumanFormat(fSize)})"
        )
    return fExists and (fSize > 0)


###################################################################################################
# create a local git clone
def GitClone(
    url,
    local_dir,
    depth=2147483647,
    recursive=True,
    singleBranch=False,
    recurseSubmodules=True,
    shallowSubmodules=True,
    noTags=False,
    interactive=False,
):
    git = DoDynamicImport("git", "GitPython", interactive=interactive)

    git.Repo.clone_from(
        url,
        local_dir,
        **{
            "depth": depth,
            "recursive": recursive,
            "single-branch": singleBranch,
            "recurse-submodules": recurseSubmodules,
            "shallow-submodules": shallowSubmodules,
            "no-tags": noTags,
        },
    )


###################################################################################################
# recursively remove empty subfolders
def RemoveEmptyFolders(path, removeRoot=True):
    if not os.path.isdir(path):
        return

    files = os.listdir(path)
    if len(files):
        for f in files:
            fullpath = os.path.join(path, f)
            if os.path.isdir(fullpath):
                RemoveEmptyFolders(fullpath)

    files = os.listdir(path)
    if len(files) == 0 and removeRoot:
        try:
            os.rmdir(path)
        except:
            pass


###################################################################################################
if __name__ == "__main__":
    eprint("H̵e̷l̷l̵o̸,̸ ̵w̶o̵r̸l̴d̷!̸")
