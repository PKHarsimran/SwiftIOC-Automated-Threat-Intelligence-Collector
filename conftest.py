"""Ensure the repository root is importable as `swiftioc` regardless of how
pytest is invoked.

`python -m pytest` implicitly prepends the current working directory to
`sys.path`, so `import swiftioc` resolves when run that way. The plain
`pytest` console-script entry point (used in CI) does not do this, and
`tests/` has no `__init__.py`, so pytest's rootdir-insertion only adds
`tests/` to `sys.path` — not the repo root where `swiftioc.py` lives. A
top-level conftest.py is always imported by pytest, and its directory is
added to `sys.path` as a side effect, which makes the import work in both
invocation styles.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
