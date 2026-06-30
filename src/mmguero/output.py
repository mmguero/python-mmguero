"""Console/stream output helpers: stderr printing, table formatting, human-readable sizes."""

import sys

from datetime import datetime


# print to stderr
def eprint(*args, **kwargs):
    """Print to stderr.

    Args:
        *args: Values to print, passed through to the builtin print().
        **kwargs: Keyword arguments passed to print(), plus 'timestamp' (bool) to prefix a timestamp and 'flush' (bool) to flush stderr afterward.
    """
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


# print a list of lists into a nice table
def tablify(matrix, file=sys.stdout, do_sort=False, first_row_is_header=False, do_header_divider=False):
    """Print a list of lists as a nice, aligned table.

    Args:
        matrix (list[list]): Rows of cell values to print as a table.
        file (file-like, optional): Stream to print to. Defaults to sys.stdout.
        do_sort (bool, optional): Sort the data rows before printing. Defaults to False.
        first_row_is_header (bool, optional): Treat the first row of `matrix` as a header row. Defaults to False.
        do_header_divider (bool, optional): Print a divider line under the header row. Defaults to False.
    """
    # If the matrix is empty, there's nothing to do
    if not matrix:
        return

    # 1. Handle Header vs Data logic
    if first_row_is_header:
        header = matrix[0]
        rows = list(matrix[1:])  # Copy remaining rows to avoid mutating original
    else:
        header = None
        rows = list(matrix)

    # 2. Sort the rows if requested
    if do_sort:
        rows.sort()

    # 3. Reconstruct the display list
    final_matrix = [header] + rows if header else rows

    # 4. Calculate column widths
    colMaxLen = {i: max(map(len, inner)) for i, inner in enumerate(zip(*final_matrix))}

    # 5. Print the table
    for i, row in enumerate(final_matrix):
        for col, data in enumerate(row):
            print(f"{data:{colMaxLen[col]}}", end=" | ", file=file)
        print(file=file)

        # Print a divider line under the header
        if do_header_divider and first_row_is_header and i == 0:
            divider = "-+-".join("-" * colMaxLen[c] for c in range(len(row)))
            print(f"{divider}-|", file=file)


# nice human-readable file sizes
def size_human_format(num, suffix="B"):
    """Nice human-readable file sizes.

    Args:
        num (int or float): Size in bytes.
        suffix (str, optional): Unit suffix to append. Defaults to 'B'.

    Returns:
        str: Human-readable formatted size (e.g. '1.5MiB').
    """
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}{'Yi'}{suffix}"
