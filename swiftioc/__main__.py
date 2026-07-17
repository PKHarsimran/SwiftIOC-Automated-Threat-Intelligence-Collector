"""Entry point for ``python -m swiftioc``."""
import sys

from .cli import main

if __name__ == "__main__":
    rc = main()
    if rc:
        sys.exit(rc)
