"""Command line interface for SwiftIOC."""
from __future__ import annotations

from .core import main as core_main


def main() -> int:
    """Entry point used by ``python -m swiftioc`` and console scripts."""
    return core_main()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
