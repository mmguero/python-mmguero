"""Filesystem helpers: context managers, file read/write/touch, recursive chown/rmtree/cleanup."""

import contextlib
import fnmatch
import mmap
import os
import sys
import tempfile

try:
    from collections.abc import Iterable
except ImportError:
    from collections import Iterable


# a context manager for entering a directory and leaving it upon leaving the context
@contextlib.contextmanager
def pushd(directory):
    """Context manager that changes into a directory and restores the previous working
    directory on exit.

    Args:
        directory (str): Path to change into for the duration of the context.

    Yields:
        None: Nothing; the previous working directory is restored on exit.
    """
    prev_dir = os.getcwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(prev_dir)


# a context manager returning a temporary filename which is deleted upon leaving the context
@contextlib.contextmanager
def temporary_filename(suffix=None):
    """Context manager yielding a temporary filename that is deleted when the context exits.

    Args:
        suffix (str, optional): Suffix to use for the generated filename (e.g. '.tar.gz'). Defaults to None.

    Yields:
        str: Path to the temporary file.
    """
    try:
        f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        tmp_name = f.name
        f.close()
        yield tmp_name
    finally:
        os.unlink(tmp_name)


# open a file and close it, updating its access time
def touch(filename):
    """Create the file if it doesn't exist and update its access/modification time, like the `touch` command.

    Args:
        filename (str): Path to the file to create (if needed) and touch.
    """
    open(filename, 'a').close()
    os.utime(filename, None)


# append strings to a text file
def append_to_file(filename, value):
    """Append a value to a text file.

    Args:
        filename (str): Path to the file to append to.
        value (str or Iterable[str]): Text to append, or an iterable of lines joined with newlines.
    """
    with open(filename, "a") as f:
        if isinstance(value, Iterable) and not isinstance(value, str):
            f.write('\n'.join(value))
        else:
            f.write(value)


# "pop" lines from the beginning of a file
def pop_line(file_name, count=1):
    """ "Pop" line(s) from the beginning of a file, rewriting the remainder in place.

    Args:
        file_name (str): Path to the file to pop lines from.
        count (int, optional): Number of lines to remove from the start. Defaults to 1.

    Returns:
        str or list[str]: The popped line as a string if count == 1, otherwise a list of popped lines.
    """
    result = []
    with open(file_name, 'r+') as f:
        for i in range(0, count):
            result.append(f.readline())
        data = f.read()
        f.seek(0)
        f.write(data)
        f.truncate()
    return result if (len(result) != 1) else result[0]


# read the contents of a file, first assuming text (with encoding), optionally falling back to binary
def file_contents(filename, encoding='utf-8', binary_fallback=False):
    """Read the contents of a file, first assuming text, optionally falling back to binary.

    Args:
        filename (str): Path to the file to read.
        encoding (str, optional): Text encoding to try first. Defaults to 'utf-8'.
        binary_fallback (bool, optional): If True, re-read as raw bytes when text decoding fails instead of raising. Defaults to False.

    Returns:
        str, bytes, or None: The file contents, or None if the file doesn't exist.
    """
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


# use memory-mapped files and count "\n" (fastest for many small files as it avoids subprocess overhead)
def count_lines_mmap(file_path):
    """Count newline characters in a file using a memory-mapped read.

    Args:
        file_path (str): Path to the file to count newlines in.

    Returns:
        tuple[str, int]: The file path and its newline count (0 on error or if the file is empty).
    """
    try:
        if os.path.getsize(file_path):
            with open(file_path, "r") as f:
                return file_path, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ).read().count(b"\n")
        else:
            return file_path, 0
    except Exception as e:
        print(f"Error counting lines of {file_path}: {e}", file=sys.stderr)
        return file_path, 0


# return true if os.path.samefile, also False on exception
def same_file_or_dir(path1, path2):
    """Return true if os.path.samefile, also False on exception.

    Args:
        path1 (str): First path to compare.
        path2 (str): Second path to compare.

    Returns:
        bool: True if both paths refer to the same file or directory, False otherwise (including on error).
    """
    try:
        return os.path.samefile(path1, path2)
    except Exception:
        return False


# "chown -R" a file or directory
def chown_recursive(path, uid, gid):
    """ "chown -R" a file or directory.

    Args:
        path (str): File or directory to chown.
        uid (int or str): Target user ID.
        gid (int or str): Target group ID.
    """
    os.chown(path, int(uid), int(gid))
    if os.path.isdir(path):
        for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
            for dname in dirnames:
                os.chown(os.path.join(dirpath, dname), int(uid), int(gid))
            for fname in filenames:
                os.chown(os.path.join(dirpath, fname), int(uid), int(gid), follow_symlinks=False)


# recursively delete a directory tree while excluding specific files based on glob-style patterns
def rmtree_except(path, exclude_patterns=None, ignore_errors=False):
    """Recursively delete a directory tree while excluding specific files based on glob-style patterns.

    Args:
        path (str): Directory tree to delete.
        exclude_patterns (list[str], optional): Glob patterns of filenames to keep instead of deleting. Defaults to None (no exclusions).
        ignore_errors (bool, optional): Suppress exceptions raised during deletion. Defaults to False.
    """
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


# recursively remove empty subfolders
def remove_empty_folders(path, remove_root=True):
    """Recursively remove empty subfolders.

    Args:
        path (str): Directory to clean up.
        remove_root (bool, optional): Also remove `path` itself if it ends up empty. Defaults to True.
    """
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
