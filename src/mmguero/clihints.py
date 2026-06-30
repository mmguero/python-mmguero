# src/mmguero/clihints.py
"""Internal marker for excluding functions from the auto-generated Fire CLI surface."""


def _exclude_from_cli(func):
    """Mark a function so cli.main()'s command-builder skips it."""
    func._mmguero_no_cli = True
    return func
