"""Module executed as ``python -m swiftioc``."""
from __future__ import annotations

from .cli import main


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
