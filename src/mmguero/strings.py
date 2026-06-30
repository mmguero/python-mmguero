"""String manipulation: bool parsing, encoding/escaping, curl config parsing, base64 helpers."""

import glob
import os
import re
import string

from base64 import b64encode, b64decode, binascii
from collections import defaultdict
from .clihints import _exclude_from_cli


@_exclude_from_cli
def str2bool(v):
    """Convenient boolean argument parsing.

    Args:
        v (str or bool): Value to interpret as a boolean.

    Returns:
        bool: The interpreted boolean value.

    Raises:
        ValueError: If `v` is a string that doesn't match a recognized boolean value.
    """
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


@_exclude_from_cli
def val2bool(v):
    """Convenient boolean argument parsing.

    Args:
        v (any): Value to interpret as a boolean.

    Returns:
        bool or original type: The interpreted boolean, or `v` itself unchanged if it couldn't be interpreted.
    """
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


def aggressive_url_encode(val):
    """Urlencode each character of a string.

    Args:
        val (str): String to percent-encode.

    Returns:
        str: The percent-encoded string.
    """
    return "".join("%{0:0>2}".format(format(ord(char), "x")) for char in val)


def contains_whitespace(s):
    """Check whether any character in the string is in string.whitespace.

    Args:
        s (str): String to check.

    Returns:
        bool: True if `s` contains any whitespace character.
    """
    return True in [c in s for c in string.whitespace]


@_exclude_from_cli
def custom_make_translation(text, translation):
    """Apply a multi-character string translation.

    Args:
        text (str): String to transform.
        translation (dict[str, str]): Mapping of substrings to their replacements.

    Returns:
        str: `text` with each occurrence of a key in `translation` replaced by its value.
    """
    regex = re.compile('|'.join(map(re.escape, translation)))
    return regex.sub(lambda match: translation[match.group(0)], text)


def escape_ansi(line):
    """Remove ANSI escape sequences from a string.

    Args:
        line (str): String that may contain ANSI escape sequences.

    Returns:
        str: `line` with ANSI escape sequences removed.
    """
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


def escape_for_curl(s):
    """Escape a string for safe inclusion in a curl config file or command line.

    Args:
        s (str): String to escape.

    Returns:
        str: `s` with quotes, backslashes, and whitespace control characters escaped.
    """
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
    """Reverse escape_for_curl.

    Args:
        s (str): String containing curl-style backslash escapes.

    Returns:
        str: `s` with escape sequences converted back to literal characters.
    """
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


def parse_curl_file(curl_cfg_file_name):
    """Parse a curl-formatted config file, with special handling for user:password and URL.
    (see https://everything.curl.dev/cmdline/configfile)

    Args:
        curl_cfg_file_name (str): Path to a curl-formatted config file.

    Returns:
        defaultdict[str, str]: Parsed option/value pairs, with a combined 'user:password' value split into separate 'user' and 'password' keys.
    """
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


def base64_decode_if_prefixed(s: str):
    """Decode a string if it starts with the 'base64:' prefix.

    Args:
        s (str): String that may be prefixed with 'base64:'.

    Returns:
        str: The decoded string if `s` was prefixed, otherwise `s` unchanged.
    """
    if s.startswith('base64:'):
        return b64decode(s[7:]).decode('utf-8')
    else:
        return s


def base64_encode_files_in_dir(directory, pattern):
    """Return a dict mapping relative file paths to Base64-encoded contents
    for all files in the given directory (recursively) matching the glob pattern.
    Example:
        /tmp/foobar/app.env           -> "app.env"
        /tmp/foobar/barbaz/what.env   -> "barbaz/what.env"

    Args:
        directory (str): Root directory to search recursively.
        pattern (str): Glob pattern (e.g. '*.env') matching files to encode.

    Returns:
        dict[str, str]: Mapping of relative file paths to Base64-encoded contents.
    """
    result = {}
    # Enable recursive search with **
    search_pattern = os.path.join(directory, "**", pattern)
    for filepath in glob.glob(search_pattern, recursive=True):
        if os.path.isfile(filepath):
            with open(filepath, "rb") as f:
                encoded = b64encode(f.read()).decode("utf-8")
            rel_path = os.path.relpath(filepath, directory)
            result[rel_path] = encoded
    return result


@_exclude_from_cli
def base64_decode_files_to_dir(encoded_dict, dest_dir):
    """Given a dict mapping relative paths to Base64-encoded contents,
    recreate the files under dest_dir.

    - Creates dest_dir and subdirectories if they don’t exist
    - Skips entries that fail Base64 decoding

    Args:
        encoded_dict (dict[str, str]): Mapping of relative paths to Base64-encoded contents.
        dest_dir (str): Destination directory to recreate the files under (created if needed).
    """
    os.makedirs(dest_dir, exist_ok=True)

    for rel_path, b64data in encoded_dict.items():
        try:
            decoded = b64decode(b64data, validate=True)
        except (binascii.Error, ValueError):
            continue

        full_path = os.path.join(dest_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        try:
            with open(full_path, "wb") as f:
                f.write(decoded)
        except Exception:
            continue


def remove_prefix(text, prefix):
    """Strip a prefix from the beginning of a string if needed.

    Args:
        text (str): String to strip from.
        prefix (str): Prefix to remove if present.

    Returns:
        str: `text` without the leading `prefix`, or `text` unchanged if it didn't start with it.
    """
    if (len(prefix) > 0) and text.startswith(prefix):
        return text[len(prefix) :]
    else:
        return text


def remove_suffix(text, suffix):
    """Strip a suffix from the end of a string if needed.

    Args:
        text (str): String to strip from.
        suffix (str): Suffix to remove if present.

    Returns:
        str: `text` without the trailing `suffix`, or `text` unchanged if it didn't end with it.
    """
    if (len(suffix) > 0) and text.endswith(suffix):
        return text[: len(text) - len(suffix)]
    else:
        return text
