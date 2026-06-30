"""Basic networking helpers: socket reachability checks, primary IP detection, file download."""

import contextlib
import os
import socket

from .output import eprint, size_human_format
from .system import dynamic_import


def test_socket(host, port):
    """Test if a remote port is open.

    Args:
        host (str): Hostname or IP address to connect to.
        port (int): TCP port to test.

    Returns:
        bool: True if the connection succeeds within a 10-second timeout, False otherwise.
    """
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(10)
        if sock.connect_ex((host, port)) == 0:
            return True
        else:
            return False


def get_primary_ip():
    """Return the primary IP (the one with a default route) on the local box.

    Returns:
        str: The primary outbound IP address, or '127.0.0.1' if it can't be determined.
    """
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


def download_to_file(url, local_filename, chunk_size=4096, interactive=False, debug=False):
    """Download to file.

    Args:
        url (str): URL to download.
        local_filename (str): Path to write the downloaded content to.
        chunk_size (int, optional): Bytes per streamed chunk. Defaults to 4096.
        interactive (bool, optional): Passed to dynamic_import() for the 'requests' dependency. Defaults to False.
        debug (bool, optional): Print a debug line with the result. Defaults to False.

    Returns:
        bool: True if the resulting file exists and is non-empty.
    """
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
