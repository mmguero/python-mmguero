#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# python3 -m black --line-length 120 --skip-string-normalization
# python3 -m flake8 --ignore=E203,E501,E402,F401,F403,W503

import contextlib
import getpass
import hashlib
import fnmatch
import importlib
import importlib.metadata
import importlib.util
import inspect
import json
import logging
import mmap
import os
import platform
import re
import site
import socket
import string
import sys
import tempfile
import time

from base64 import b64decode
from datetime import datetime
from collections import defaultdict, namedtuple, OrderedDict
from enum import IntEnum, IntFlag, auto
from multiprocessing import RawValue
from subprocess import PIPE, Popen, CalledProcessError, run as SubProcessRun
from threading import Lock
from types import GeneratorType, FunctionType, LambdaType

try:
    from collections.abc import Iterable
except ImportError:
    from collections import Iterable

try:
    from datetime import UTC as utc_time_zone
except ImportError:
    from datetime import timezone

    utc_time_zone = timezone.utc

try:
    from pwd import getpwuid
except Exception:
    getpwuid = None

try:
    from shutil import which as _shutil_which

    _has_which = True
except Exception:
    _has_which = False

_dialog = None
_main_dialog = None

###################################################################################################
PLATFORM_WINDOWS = "Windows"
PLATFORM_MAC = "Darwin"
PLATFORM_LINUX = "Linux"
PLATFORM_LINUX_ALMA = "almalinux"
PLATFORM_LINUX_AMAZON = "amazon"
PLATFORM_LINUX_CENTOS = "centos"
PLATFORM_LINUX_DEBIAN = "debian"
PLATFORM_LINUX_FEDORA = "fedora"
PLATFORM_LINUX_RASPBIAN = "raspbian"
PLATFORM_LINUX_ROCKY = "rocky"
PLATFORM_LINUX_UBUNTU = "ubuntu"


###################################################################################################
def _dialog_init():
    global _dialog
    global _main_dialog
    try:
        if not _dialog:
            from dialog import dialog as _dialog

        if not _main_dialog:
            _main_dialog = _dialog(dialog='dialog', autowidgetsize=True)
    except ImportError:
        _dialog = None
        _main_dialog = None


_dialog_init()


class UserInputDefaultsBehavior(IntFlag):
    DEFAULTS_PROMPT = auto()
    DEFAULTS_ACCEPT = auto()
    DEFAULTS_NON_INTERACTIVE = auto()


class UserInterfaceMode(IntFlag):
    INTERACTION_DIALOG = auto()
    INTERACTION_INPUT = auto()


class _DialogBackException(Exception):
    pass


class _DialogCanceledException(Exception):
    pass


class BoolOrExtra(IntEnum):
    FALSE = 0
    TRUE = 1
    EXTRA = 2


###################################################################################################
# atomic integer class and context manager
class AtomicInt:
    def __init__(self, value=0):
        self._val = RawValue('i', value)
        self._lock = Lock()

    def increment(self):
        with self._lock:
            self._val.value += 1
            return self._val.value

    def decrement(self):
        with self._lock:
            self._val.value -= 1
            return self._val.value

    def value(self):
        with self._lock:
            return self._val.value

    def __enter__(self):
        return self.increment()

    def __exit__(self, type, value, traceback):
        return self.decrement()


###################################################################################################
# an OrderedDict that locks itself and unlocks itself as a context manager
class ContextLockedOrderedDict(OrderedDict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lock = Lock()

    def __enter__(self):
        self._lock.acquire()
        return self

    def __exit__(self, type, value, traceback):
        self._lock.release()
        return self


###################################################################################################
# a context manager for entering a directory and leaving it upon leaving the context
@contextlib.contextmanager
def pushd(directory):
    prev_dir = os.getcwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(prev_dir)


###################################################################################################
# a context manager returning a temporary filename which is deleted upon leaving the context
@contextlib.contextmanager
def temporary_filename(suffix=None):
    try:
        f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        tmp_name = f.name
        f.close()
        yield tmp_name
    finally:
        os.unlink(tmp_name)


###################################################################################################
# open a file and close it, updating its access time
def touch(filename):
    open(filename, 'a').close()
    os.utime(filename, None)


###################################################################################################
# append strings to a text file
def append_to_file(filename, value):
    with open(filename, "a") as f:
        if isinstance(value, Iterable) and not isinstance(value, str):
            f.write('\n'.join(value))
        else:
            f.write(value)


###################################################################################################
# "pop" lines from the beginning of a file
def pop_line(file_name, count=1):
    result = []
    with open(file_name, 'r+') as f:
        for i in range(0, count):
            result.append(f.readline())
        data = f.read()
        f.seek(0)
        f.write(data)
        f.truncate()
    return result if (len(result) != 1) else result[0]


###################################################################################################
# read the contents of a file, first assuming text (with encoding), optionally falling back to binary
def file_contents(filename, encoding='utf-8', binary_fallback=False):
    if os.path.isfile(filename):
        decode_err = False

        try:
            with open(filename, 'r', encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, AttributeError):
            if binary_fallback:
                decode_err = True
            else:
                raise

        if decode_err and binary_fallback:
            with open(filename, 'rb') as f:
                return f.read()

    else:
        return None


###################################################################################################
# use memory-mapped files and count "\n" (fastest for many small files as it avoids subprocess overhead)
def count_lines_mmap(file_path):
    try:
        if os.path.getsize(file_path):
            with open(file_path, "r") as f:
                return file_path, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ).read().count(b"\n")
        else:
            return file_path, 0
    except Exception as e:
        print(f"Error counting lines of {file_path}: {e}", file=sys.stderr)
        return file_path, 0


###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
    filtered_args = (
        {k: v for (k, v) in kwargs.items() if k not in ('timestamp', 'flush')} if isinstance(kwargs, dict) else {}
    )
    if "timestamp" in kwargs and kwargs["timestamp"]:
        print(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            *args,
            file=sys.stderr,
            **filtered_args,
        )
    else:
        print(*args, file=sys.stderr, **filtered_args)
    if "flush" in kwargs and kwargs["flush"]:
        sys.stderr.flush()


###################################################################################################
# print a list of lists into a nice table
def tablify(matrix, file=sys.stdout):
    col_max_len = {i: max(map(len, inner)) for i, inner in enumerate(zip(*matrix))}
    for row in matrix:
        for col, data in enumerate(row):
            print(f"{data:{col_max_len[col]}}", end=" | ", file=file)
        print(file=file)


###################################################################################################
# convenient boolean argument parsing
def str2bool(v):
    if isinstance(v, bool):
        return v
    elif isinstance(v, str):
        if v.lower() in ("yes", "true", "t", "y", "1"):
            return True
        elif v.lower() in ("no", "false", "f", "n", "0", ""):
            return False
        else:
            raise ValueError("Boolean value expected")
    elif not v:
        return False
    else:
        raise ValueError("Boolean value expected")


def str2bool_or_extra(v):
    if isinstance(v, bool):
        return BoolOrExtra.TRUE if v else BoolOrExtra.FALSE
    elif isinstance(v, str):
        if v.lower() in ("yes", "true", "t", "y", "1"):
            return BoolOrExtra.TRUE
        elif v.lower() in ("no", "false", "f", "n", "0"):
            return BoolOrExtra.FALSE
        elif v.lower() in ("b", "back", "p", "previous", "e", "extra"):
            return BoolOrExtra.EXTRA
        else:
            raise ValueError("BoolOrExtra value expected")
    else:
        raise ValueError("BoolOrExtra value expected")


###################################################################################################
# convenient boolean argument parsing
def val2bool(v):
    try:
        if v is None:
            return False
        elif isinstance(v, bool):
            return v
        elif isinstance(v, str):
            if v.lower() in ("yes", "true", "t", "y"):
                return True
            elif v.lower() in ("no", "false", "f", "n"):
                return False
            else:
                raise ValueError(f'Boolean value expected (got {v})')
        else:
            raise ValueError(f'Boolean value expected (got {v})')
    except Exception:
        # just pitch it back and let the caller worry about it
        return v


###################################################################################################
# urlencode each character of a string
def aggressive_url_encode(val):
    return "".join("%{0:0>2}".format(format(ord(char), "x")) for char in val)


###################################################################################################
# any character in the string is in string.whitespace
def contains_whitespace(s):
    return True in [c in s for c in string.whitespace]


###################################################################################################
def custom_make_translation(text, translation):
    regex = re.compile('|'.join(map(re.escape, translation)))
    return regex.sub(lambda match: translation[match.group(0)], text)


###################################################################################################
# remove ANSI escape sequences
def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


###################################################################################################
# EVP_BytesToKey - create key compatible with openssl enc
# reference: https://github.com/openssl/openssl/blob/6f0ac0e2f27d9240516edb9a23b7863e7ad02898/crypto/evp/evp_key.c#L74
#            https://gist.github.com/chrono-meter/d122cbefc6f6248a0af554995f072460
_EVP_KEY_SIZE = 32
_OPENSSL_ENC_MAGIC = b'Salted__'
_PKCS5_SALT_LEN = 8


def evp_bytes_to_key(key_length: int, iv_length: int, md, salt: bytes, data: bytes, count: int = 1) -> (bytes, bytes):
    assert data
    assert salt == b'' or len(salt) == _PKCS5_SALT_LEN

    md_buf = b''
    key = b''
    iv = b''
    addmd = 0

    while key_length > len(key) or iv_length > len(iv):
        c = md()
        if addmd:
            c.update(md_buf)
        addmd += 1
        c.update(data)
        c.update(salt)
        md_buf = c.digest()
        for i in range(1, count):
            md_buf = md(md_buf)

        md_buf2 = md_buf

        if key_length > len(key):
            key, md_buf2 = key + md_buf2[: key_length - len(key)], md_buf2[key_length - len(key) :]

        if iv_length > len(iv):
            iv = iv + md_buf2[: iv_length - len(iv)]

    return key, iv


###################################################################################################
def escape_for_curl(s):
    return s.translate(
        str.maketrans(
            {
                '"': r'\"',
                "\\": r"\\",
                "\t": r"\t",
                "\n": r"\n",
                "\r": r"\r",
                "\v": r"\v",
            }
        )
    )


def unescape_for_curl(s):
    return custom_make_translation(
        s,
        {
            r'\"': '"',
            r"\t": "\t",
            r"\n": "\n",
            r"\r": "\r",
            r"\v": "\v",
            r"\\": "\\",
        },
    )


###################################################################################################
# parse a curl-formatted config file, with special handling for user:password and URL
# see https://everything.curl.dev/cmdline/configfile
# e.g.:
#
# given .opensearch.primary.curlrc containing:
# -
# user: "sikari:changethis"
# insecure
# -
#
# parse_curl_file('.opensearch.primary.curlrc') returns:
#   {
#    'user': 'sikari',
#    'password': 'changethis',
#    'insecure': ''
#   }
def parse_curl_file(curl_cfg_file_name):
    result = defaultdict(lambda: '')
    if os.path.isfile(curl_cfg_file_name):
        item_reg_ex = re.compile(r'^([^\s:=]+)((\s*[:=]?\s*)(.*))?$')
        with open(curl_cfg_file_name, 'r') as f:
            all_lines = [x.strip().lstrip('-') for x in f.readlines() if not x.startswith('#')]
        for line in all_lines:
            found = item_reg_ex.match(line)
            if found is not None:
                key = found.group(1)
                value = unescape_for_curl(found.group(4).lstrip('"').rstrip('"'))
                if (key == 'user') and (':' in value):
                    split_val = value.split(':', 1)
                    result[key] = split_val[0]
                    if len(split_val) > 1:
                        result['password'] = split_val[1]
                else:
                    result[key] = value

    return result


###################################################################################################
# safe deep get for a dictionary
#
# Example:
#   d = {'meta': {'status': 'OK', 'status_code': 200}}
#   deep_get(d, ['meta', 'status_code'])          # => 200
#   deep_get(d, ['garbage', 'status_code'])       # => None
#   deep_get(d, ['meta', 'garbage'], default='-') # => '-'
def deep_get(d, keys, default=None):
    k = get_iterable(keys)
    if d is None:
        return default
    if not keys:
        return d
    return deep_get(d.get(k[0]), k[1:], default)


###################################################################################################
# convenience routine for setting-getting a value into a dictionary
def deep_set(d, keys, value, delete_if_none=False):
    k = get_iterable(keys)
    for key in k[:-1]:
        if (key not in d) or (not isinstance(d[key], dict)):
            d[key] = dict()
        d = d[key]
    d[k[-1]] = value
    if delete_if_none and (value is None):
        d.pop(k[-1], None)


###################################################################################################
# Recursively merges 'source' dict into 'destination' dict. Values from 'source' override those
#    in 'destination' at the same path.
def deep_merge(source, destination):
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(destination.get(key), dict):
            destination[key] = deep_merge(value, destination[key])
        else:
            destination[key] = value
    return destination


def deep_merge_in_place(source, destination):
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(destination.get(key), dict):
            deep_merge(value, destination[key])
        else:
            destination[key] = value


###################################################################################################
# recursive dictionary key search
def dict_search(d, target):
    val = filter(
        None, [[b] if a == target else dict_search(b, target) if isinstance(b, dict) else None for a, b in d.items()]
    )
    return [i for b in val for i in b]


###################################################################################################
# given a dict, return the first value sorted by value
def min_hash_value_by_value(x):
    return next(
        iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[1])}.values())),
        None,
    )


###################################################################################################
# given a dict, return the first value sorted by key
def min_hash_value_by_key(x):
    return next(
        iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[0])}.values())),
        None,
    )


###################################################################################################
# given a dict, return the last value sorted by value
def max_hash_value_by_value(x):
    try:
        *_, last = iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[1])}.values()))
    except Exception:
        last = None
    return last


###################################################################################################
# given a dict, return the last value sorted by key
def max_hash_value_by_key(x):
    try:
        *_, last = iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[0])}.values()))
    except Exception:
        last = None
    return last


###################################################################################################
# flatten a collection, but don't split strings
def flatten(coll):
    for i in coll:
        if isinstance(i, Iterable) and not isinstance(i, str):
            for subc in flatten(i):
                yield subc
        else:
            yield i


###################################################################################################
# if the object is an iterable, return it, otherwise return a tuple with it as a single element.
# useful if you want to user either a scalar or an array in a loop, etc.
def get_iterable(x):
    if isinstance(x, Iterable) and not isinstance(x, str):
        return x
    else:
        return (x,)


###################################################################################################
# remove "empty" items from a collection
def remove_falsy(obj):
    if isinstance(obj, dict):
        return {k: v for k, v in ((k, remove_falsy(v)) for k, v in obj.items()) if v}
    elif isinstance(obj, list):
        return [v for v in (remove_falsy(i) for i in obj) if v]
    else:
        return obj if obj else None


###################################################################################################
# attempt to clear the screen
def clear_screen():
    try:
        os.system("clear" if platform.system() != PLATFORM_WINDOWS else "cls")
    except Exception:
        pass


###################################################################################################
# get interactive user response to Y/N question
def yes_or_no(
    question,
    default=None,
    default_behavior=UserInputDefaultsBehavior.DEFAULTS_PROMPT,
    ui_mode=UserInterfaceMode.INTERACTION_DIALOG | UserInterfaceMode.INTERACTION_INPUT,
    clear_screen=False,
    yes_label='Yes',
    no_label='No',
    extra_label=None,
):
    result = None

    if (default is not None) and (
        (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT)
        and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_NON_INTERACTIVE)
    ):
        reply = ""

    elif (ui_mode & UserInterfaceMode.INTERACTION_DIALOG) and (_main_dialog is not None):
        default_yes = (default is not None) and str2bool_or_extra(default)
        # by default the "extra" button is between "Yes" and "No" which looks janky, IMO.
        #   so we're going to switch things around a bit.
        yes_labelTmp = yes_label.capitalize() if default_yes else no_label.capitalize()
        no_labelTmp = no_label.capitalize() if default_yes else yes_label.capitalize()
        reply_map = {}
        if has_extra_label := (extra_label is not None):
            reply_map[_dialog.EXTRA] = _dialog.CANCEL
            reply_map[_dialog.CANCEL] = _dialog.EXTRA
        reply = _main_dialog.yesno(
            str(question),
            yes_label=str(yes_labelTmp),
            no_label=str(extra_label) if has_extra_label else str(no_labelTmp),
            extra_button=has_extra_label,
            extra_label=str(no_labelTmp) if has_extra_label else str(extra_label),
        )
        reply = reply_map.get(reply, reply)
        if default_yes:
            reply = 'y' if (reply == _dialog.OK) else ('e' if (reply == _dialog.EXTRA) else 'n')
        else:
            reply = 'n' if (reply == _dialog.OK) else ('e' if (reply == _dialog.EXTRA) else 'y')

    elif ui_mode & UserInterfaceMode.INTERACTION_INPUT:
        if (default is not None) and default_behavior & UserInputDefaultsBehavior.DEFAULTS_PROMPT:
            if str2bool_or_extra(default):
                question_str = f"\n{question} (Y{'' if yes_label == 'Yes' else ' (' + yes_label + ')'} / n{'' if no_label == 'No' else ' (' + no_label + ')'}): "
            else:
                question_str = f"\n{question} (y{'' if yes_label == 'Yes' else ' (' + yes_label + ')'} / N{'' if no_label == 'No' else ' (' + no_label + ')'}): "
        else:
            question_str = f"\n{question} (Y{'' if yes_label == 'Yes' else ' (' + yes_label + ')'} / N{'' if no_label == 'No' else ' (' + no_label + ')'}): "

        while True:
            reply = str(input(question_str)).lower().strip()
            if len(reply) > 0:
                try:
                    str2bool_or_extra(reply)
                    break
                except ValueError:
                    pass
            elif (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT) and (default is not None):
                break

    else:
        raise RuntimeError("No user interfaces available")

    if (len(reply) == 0) and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT):
        reply = "y" if (default is not None) and str2bool_or_extra(default) else "n"

    if clear_screen is True:
        clear_screen()

    try:
        result = str2bool_or_extra(reply)
    except ValueError:
        result = yes_or_no(
            question,
            default=default,
            ui_mode=ui_mode,
            default_behavior=default_behavior - UserInputDefaultsBehavior.DEFAULTS_ACCEPT,
            clear_screen=clear_screen,
            yes_label=yes_label,
            no_label=no_label,
            extra_label=extra_label,
        )

    if result == BoolOrExtra.EXTRA:
        raise _DialogBackException(question)

    return bool(result)


###################################################################################################
# get interactive user response
def ask_for_string(
    question,
    default=None,
    default_behavior=UserInputDefaultsBehavior.DEFAULTS_PROMPT,
    ui_mode=UserInterfaceMode.INTERACTION_DIALOG | UserInterfaceMode.INTERACTION_INPUT,
    clear_screen=False,
    extra_label=None,
):
    if (default is not None) and (
        (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT)
        and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_NON_INTERACTIVE)
    ):
        reply = default

    elif (ui_mode & UserInterfaceMode.INTERACTION_DIALOG) and (_main_dialog is not None):
        code, reply = _main_dialog.inputbox(
            str(question),
            init=(
                default
                if (default is not None) and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_PROMPT)
                else ""
            ),
            extra_button=(extra_label is not None),
            extra_label=str(extra_label),
        )
        if (code == _dialog.CANCEL) or (code == _dialog.ESC):
            raise _DialogCanceledException(question)
        elif code == _dialog.EXTRA:
            raise _DialogBackException(question)
        else:
            reply = reply.strip()

    elif ui_mode & UserInterfaceMode.INTERACTION_INPUT:
        reply = str(
            input(
                f"\n{question}{f' ({default})' if (default is not None) and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_PROMPT) else ''}: "
            )
        ).strip()
        if (
            (len(reply) == 0)
            and (default is not None)
            and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT)
        ):
            reply = default

    else:
        raise RuntimeError("No user interfaces available")

    if clear_screen is True:
        clear_screen()

    return reply


###################################################################################################
# get interactive password (without echoing)
def ask_for_password(
    prompt,
    default=None,
    default_behavior=UserInputDefaultsBehavior.DEFAULTS_PROMPT,
    ui_mode=UserInterfaceMode.INTERACTION_DIALOG | UserInterfaceMode.INTERACTION_INPUT,
    clear_screen=False,
    extra_label=None,
):
    if (default is not None) and (
        (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT)
        and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_NON_INTERACTIVE)
    ):
        reply = default

    elif (ui_mode & UserInterfaceMode.INTERACTION_DIALOG) and (_main_dialog is not None):
        code, reply = _main_dialog.passwordbox(
            str(prompt),
            insecure=True,
            extra_button=(extra_label is not None),
            extra_label=str(extra_label),
        )
        if (code == _dialog.CANCEL) or (code == _dialog.ESC):
            raise _DialogCanceledException(prompt)
        elif code == _dialog.EXTRA:
            raise _DialogBackException(prompt)

    elif ui_mode & UserInterfaceMode.INTERACTION_INPUT:
        reply = getpass.getpass(prompt=f"{prompt}: ")

    else:
        raise RuntimeError("No user interfaces available")

    if clear_screen is True:
        clear_screen()

    return reply


###################################################################################################
# Choose one of many.
# choices - an iterable of (tag, item, status) tuples where status specifies the initial
# selected/unselected state of each entry; can be True or False, 1 or 0, "on" or "off"
# (True, 1 and "on" meaning selected), or any case variation of these two strings.
# No more than one entry should be set to True.
def choose_one(
    prompt,
    choices=[],
    default_behavior=UserInputDefaultsBehavior.DEFAULTS_PROMPT,
    ui_mode=UserInterfaceMode.INTERACTION_DIALOG | UserInterfaceMode.INTERACTION_INPUT,
    clear_screen=False,
    extra_label=None,
):
    valid_choices = [x for x in choices if len(x) == 3 and isinstance(x[0], str) and isinstance(x[2], bool)]
    defaulted = next(iter([x for x in valid_choices if x[2] is True]), None)

    if (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT) and (
        default_behavior & UserInputDefaultsBehavior.DEFAULTS_NON_INTERACTIVE
    ):
        reply = defaulted[0] if defaulted is not None else ""

    elif (ui_mode & UserInterfaceMode.INTERACTION_DIALOG) and (_main_dialog is not None):
        code, reply = _main_dialog.radiolist(
            str(prompt),
            choices=valid_choices,
            extra_button=(extra_label is not None),
            extra_label=str(extra_label),
        )
        if code == _dialog.CANCEL or code == _dialog.ESC:
            raise _DialogCanceledException(prompt)
        elif code == _dialog.EXTRA:
            raise _DialogBackException(prompt)

    elif ui_mode & UserInterfaceMode.INTERACTION_INPUT:
        index = 0
        for choice in valid_choices:
            index = index + 1
            print(
                f"{index}: {choice[0]}{f' - {choice[1]}' if isinstance(choice[1], str) and len(choice[1]) > 0 else ''}"
            )
        while True:
            input_raw = input(
                f"{prompt}{f' ({defaulted[0]})' if (defaulted is not None) and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_PROMPT) else ''}: "
            ).strip()
            if (
                (len(input_raw) == 0)
                and (defaulted is not None)
                and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT)
            ):
                reply = defaulted[0]
                break
            elif (len(input_raw) > 0) and input_raw.isnumeric():
                input_index = int(input_raw) - 1
                if input_index > -1 and input_index < len(valid_choices):
                    reply = valid_choices[input_index][0]
                    break

    else:
        raise RuntimeError("No user interfaces available")

    if clear_screen is True:
        clear_screen()

    return reply


###################################################################################################
# Choose multiple of many
# choices - an iterable of (tag, item, status) tuples where status specifies the initial
# selected/unselected state of each entry; can be True or False, 1 or 0, "on" or "off"
# (True, 1 and "on" meaning selected), or any case variation of these two strings.
def choose_multiple(
    prompt,
    choices=[],
    default_behavior=UserInputDefaultsBehavior.DEFAULTS_PROMPT,
    ui_mode=UserInterfaceMode.INTERACTION_DIALOG | UserInterfaceMode.INTERACTION_INPUT,
    clear_screen=False,
    extra_label=None,
):
    valid_choices = [x for x in choices if len(x) == 3 and isinstance(x[0], str) and isinstance(x[2], bool)]
    defaulted = [x[0] for x in valid_choices if x[2] is True]

    if (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT) and (
        default_behavior & UserInputDefaultsBehavior.DEFAULTS_NON_INTERACTIVE
    ):
        reply = defaulted

    elif (ui_mode & UserInterfaceMode.INTERACTION_DIALOG) and (_main_dialog is not None):
        code, reply = _main_dialog.checklist(
            str(prompt),
            choices=valid_choices,
            extra_button=(extra_label is not None),
            extra_label=str(extra_label),
        )
        if code == _dialog.CANCEL or code == _dialog.ESC:
            raise _DialogCanceledException(prompt)
        elif code == _dialog.EXTRA:
            raise _DialogBackException(prompt)

    elif ui_mode & UserInterfaceMode.INTERACTION_INPUT:
        allowed_chars = set(string.digits + ',' + ' ')
        default_val_list_str = ",".join(defaulted)
        print("0: NONE")
        index = 0
        for choice in valid_choices:
            index = index + 1
            print(
                f"{index}: {choice[0]}{f' - {choice[1]}' if isinstance(choice[1], str) and len(choice[1]) > 0 else ''}"
            )
        while True:
            input_raw = input(
                f"{prompt}{f' ({default_val_list_str})' if (len(default_val_list_str) > 0) and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_PROMPT) else ''}: "
            ).strip()
            if (
                (len(input_raw) == 0)
                and (len(defaulted) > 0)
                and (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT)
            ):
                reply = defaulted
                break
            elif input_raw == '0':
                reply = []
                break
            elif (len(input_raw) > 0) and (set(input_raw) <= allowed_chars):
                reply = []
                selected_indexes = list(set([int(x.strip()) - 1 for x in input_raw.split(',') if (len(x.strip())) > 0]))
                for idx in selected_indexes:
                    if idx > -1 and idx < len(valid_choices):
                        reply.append(valid_choices[idx][0])
                if len(reply) > 0:
                    break

    else:
        raise RuntimeError("No user interfaces available")

    if clear_screen is True:
        clear_screen()

    return reply


###################################################################################################
# display a message to the user without feedback
def display_message(
    message,
    default_behavior=UserInputDefaultsBehavior.DEFAULTS_PROMPT,
    ui_mode=UserInterfaceMode.INTERACTION_DIALOG | UserInterfaceMode.INTERACTION_INPUT,
    clear_screen=False,
    extra_label=None,
):
    reply = False

    if (default_behavior & UserInputDefaultsBehavior.DEFAULTS_ACCEPT) and (
        default_behavior & UserInputDefaultsBehavior.DEFAULTS_NON_INTERACTIVE
    ):
        reply = True

    elif (ui_mode & UserInterfaceMode.INTERACTION_DIALOG) and (_main_dialog is not None):
        code = _main_dialog.msgbox(
            str(message),
            extra_button=(extra_label is not None),
            extra_label=str(extra_label),
        )
        if (code == _dialog.CANCEL) or (code == _dialog.ESC):
            raise _DialogCanceledException(message)
        elif code == _dialog.EXTRA:
            raise _DialogBackException(message)
        else:
            reply = True

    else:
        print(f"\n{message}")
        reply = True

    if clear_screen is True:
        clear_screen()

    return reply


###################################################################################################
# display streaming content via _dialog.programbox
def display_program_box(
    file_path=None,
    file_flags=0,
    file_descriptor=None,
    text=None,
    clear_screen=False,
    extra_label=None,
):
    reply = False

    if _main_dialog is not None:
        code = _main_dialog.programbox(
            file_path=file_path,
            file_flags=file_flags,
            fd=file_descriptor,
            text=text,
            width=78,
            height=20,
            extra_button=(extra_label is not None),
            extra_label=str(extra_label),
        )
        if (code == _dialog.CANCEL) or (code == _dialog.ESC):
            raise _DialogCanceledException()
        elif code == _dialog.EXTRA:
            raise _DialogBackException()
        else:
            reply = True

            if clear_screen is True:
                clear_screen()

    return reply


###################################################################################################
# decode a string as base64 only if it starts with base64:, otherwise just return
def base64_decode_if_prefixed(s: str):
    if s.startswith('base64:'):
        return b64decode(s[7:]).decode('utf-8')
    else:
        return s


###################################################################################################
# strip a prefix from the beginning of a string if needed
def remove_prefix(text, prefix):
    if (len(prefix) > 0) and text.startswith(prefix):
        return text[len(prefix) :]
    else:
        return text


###################################################################################################
# strip a suffix from the end of a string if needed
def remove_suffix(text, suffix):
    if (len(suffix) > 0) and text.endswith(suffix):
        return text[: len(text) - len(suffix)]
    else:
        return text


###################################################################################################
# return true if os.path.samefile, also False on exception
def same_file_or_dir(path1, path2):
    try:
        return os.path.samefile(path1, path2)
    except Exception:
        return False


###################################################################################################
# determine if a program/script exists and is executable in the system path
def which(cmd, debug=False):
    if _has_which:
        result = _shutil_which(cmd) is not None
    else:
        result = any(os.access(os.path.join(path, cmd), os.X_OK) for path in os.environ["PATH"].split(os.pathsep))
    if debug:
        eprint(f"which({_has_which}) {cmd} returned {result}")
    return result


###################################################################################################
# calculate a sha256 hash of a file
def sha256_sum(filename):
    try:
        h = hashlib.sha256()
        b = bytearray(64 * 1024)
        mv = memoryview(b)
        with open(filename, 'rb', buffering=0) as f:
            for n in iter(lambda: f.readinto(mv), 0):
                h.update(mv[:n])
        return h.hexdigest()
    except Exception:
        return None


###################################################################################################
# calculate SHAKE256 hash of a file
def shakey_sum(filename, digest_len=8):
    try:
        with open(filename, 'rb', buffering=0) as f:
            return hashlib.file_digest(f, 'shake_256').hexdigest(digest_len)
    except Exception:
        return None


###################################################################################################
# nice human-readable file sizes
def size_human_format(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}{'Yi'}{suffix}"


###################################################################################################
# test if a remote port is open
def test_socket(host, port):
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(10)
        if sock.connect_ex((host, port)) == 0:
            return True
        else:
            return False


###################################################################################################
# return the primary IP (the one with a default route) on the local box
def get_primary_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # this IP doesn't have to be reachable
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


###################################################################################################
# attempt to decode a string as JSON, returning the object if it decodes and None otherwise
def load_str_if_json(json_str):
    try:
        return json.loads(json_str)
    except ValueError:
        return None


###################################################################################################
# attempt to decode a file (given by handle) as JSON, returning the object if it decodes and
# None otherwise. Also, if attempt_lines=True, attempt to handle cases of a file containing
# individual lines of valid JSON.
def load_file_if_json(file_handle, attempt_lines=False):
    if file_handle is not None:

        try:
            result = json.load(file_handle)
        except ValueError:
            result = None

        if (result is None) and attempt_lines:
            file_handle.seek(0)
            result = []
            for line in file_handle:
                try:
                    result.append(json.loads(line))
                except ValueError:
                    pass
            if not result:
                result = None

    else:
        result = None

    return result


###################################################################################################
# JSON serializer with better support for objects
def json_obj_serializer(obj):
    if isinstance(obj, datetime):
        return obj.astimezone(utc_time_zone).isoformat()

    elif isinstance(obj, GeneratorType):
        return [json_obj_serializer(item) for item in obj]

    elif isinstance(obj, list):
        return [json_obj_serializer(item) for item in obj]

    elif isinstance(obj, dict):
        return {key: json_obj_serializer(value) for key, value in obj.items()}

    elif isinstance(obj, set):
        return {json_obj_serializer(item) for item in obj}

    elif isinstance(obj, tuple):
        return tuple(json_obj_serializer(item) for item in obj)

    elif isinstance(obj, FunctionType):
        return f"function {obj.__name__}" if obj.__name__ != "<lambda>" else "lambda"

    elif isinstance(obj, LambdaType):
        return "lambda"

    elif (not hasattr(obj, "__str__") or obj.__str__ is object.__str__) and (
        not hasattr(obj, "__repr__") or obj.__repr__ is object.__repr__
    ):
        return obj.__class__.__name__

    else:
        return str(obj)


###################################################################################################
# run command with arguments and return its exit code, stdout, and stderr
def check_output_input(*popenargs, **kwargs):
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


###################################################################################################
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


###################################################################################################
# execute a shell process returning its exit code and output
def run_sub_process(command, stdout=True, stderr=False, stdin=None, timeout=60):
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


###################################################################################################
# return the name of the calling function as a string
def get_function_name(depth=0):
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


###################################################################################################
# attempt dynamic imports, prompting for install via pip if possible
_dyn_imports = defaultdict(lambda: None)


def dynamic_import(import_name, pip_pkg_name, interactive=False, debug=False):
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

        py_platform = platform.system()
        py_exec = sys.executable
        pip_cmd = "pip3"
        if not (pip_found := which(pip_cmd, debug=debug)):
            err, out = run_process([sys.executable, '-m', 'pip', '--version'], debug=debug)
            if out and (pip_found := (err == 0)):
                pip_cmd = [sys.executable, '-m', 'pip']

        eprint(f"The {pip_pkg_name} module is required under Python {platform.python_version()} ({py_exec})")

        if interactive and pip_found:
            if yes_or_no(f"Importing the {pip_pkg_name} module failed. Attempt to install via {pip_cmd}?"):
                install_cmd = None

                if (py_platform == PLATFORM_LINUX) or (py_platform == PLATFORM_MAC):
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
                    eprint(f"Installation of {pip_pkg_name} module apparently succeeded")
                    importlib.reload(site)
                    importlib.invalidate_caches()
                    try:
                        tmp_import = importlib.import_module(import_name)
                        if tmp_import:
                            _dyn_imports[import_name] = tmp_import
                    except Exception as e:
                        eprint(f"Importing the {import_name} module still failed: {e}")
                else:
                    eprint(f"Installation of {import_name} module failed: {out}")

    if not _dyn_imports[import_name]:
        eprint(
            "System-wide installation varies by platform and Python configuration. Please consult platform-specific documentation for installing Python modules."
        )

    return _dyn_imports[import_name]


###################################################################################################
# download to file
def download_to_file(url, local_filename, chunk_size=4096, interactive=False, debug=False):
    requests = dynamic_import("requests", "requests", interactive=interactive, debug=debug)

    r = requests.get(url, stream=True, allow_redirects=True)
    with open(local_filename, "wb") as f:
        for chunk in r.iter_content(chunk_size=chunk_size):
            if chunk:
                f.write(chunk)
    f_exists = os.path.isfile(local_filename)
    f_size = os.path.getsize(local_filename)
    if debug:
        eprint(
            f"Download of {url} to {local_filename} {'succeeded' if f_exists else 'failed'} ({size_human_format(f_size)})"
        )
    return f_exists and (f_size > 0)


###################################################################################################
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


###################################################################################################
# "chown -R" a file or directory
def chown_recursive(path, uid, gid):
    os.chown(path, int(uid), int(gid))
    if os.path.isdir(path):
        for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
            for dname in dirnames:
                os.chown(os.path.join(dirpath, dname), int(uid), int(gid))
            for fname in filenames:
                os.chown(os.path.join(dirpath, fname), int(uid), int(gid), follow_symlinks=False)


###################################################################################################
# recursively delete a directory tree while excluding specific files based on glob-style patterns
def rmtree_except(path, exclude_patterns=None, ignore_errors=False):
    if exclude_patterns is None:
        exclude_patterns = []

    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            full_path = os.path.join(root, name)
            if not any(fnmatch.fnmatch(name, pattern) for pattern in exclude_patterns):
                try:
                    os.remove(full_path)
                except Exception:
                    if not ignore_errors:
                        raise

        for name in dirs:
            full_path = os.path.join(root, name)
            try:
                os.rmdir(full_path)
            except OSError:
                pass
            except Exception:
                if not ignore_errors:
                    raise

    try:
        os.rmdir(path)
    except OSError:
        pass
    except Exception:
        if not ignore_errors:
            raise


###################################################################################################
# recursively remove empty subfolders
def remove_empty_folders(path, remove_root=True):
    if not os.path.isdir(path):
        return

    files = os.listdir(path)
    if len(files):
        for f in files:
            fullpath = os.path.join(path, f)
            if os.path.isdir(fullpath):
                remove_empty_folders(fullpath)

    files = os.listdir(path)
    if len(files) == 0 and remove_root:
        try:
            os.rmdir(path)
        except Exception:
            pass


###################################################################################################
def get_verbosity_env_var_count(var_name):
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


###################################################################################################


def main():
    package_name = __package__ or "mmguero"

    try:
        metadata = importlib.metadata.metadata(package_name)
        version = metadata.get("Version", "unknown")
        summary = metadata.get("Summary", "")

        # Extract all project URLs (Hatchling puts them here)
        project_urls = []
        for key, value in metadata.items():
            if key.lower() == "project-url":
                project_urls.append(value)

    except importlib.metadata.PackageNotFoundError:
        version = "source"
        summary = "Seth Grover's useful Python helpers (uninstalled source tree)"
        project_urls = []

    print(f"\n🧰 {package_name} v{version}")
    if summary:
        print(f"   {summary}")

    if project_urls:
        print("\n🌐 Project URLs:")
        for entry in project_urls:
            print(f"   {entry}")

    print("\n📦 Public functions and classes:")

    module = sys.modules[package_name]
    public_items = []

    for name in getattr(module, "__all__", []):
        obj = getattr(module, name, None)
        if inspect.isfunction(obj):
            public_items.append(f"  ⚙️  {name}()")
        elif inspect.isclass(obj):
            public_items.append(f"  🧱 {name}")
        else:
            public_items.append(f"  🔹 {name}")

    if public_items:
        print("\n".join(public_items))
    else:
        print("  (none found)")
    print()

    sys.exit(0)
