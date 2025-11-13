"""SwiftIOC core package."""
from __future__ import annotations

from .core import (
    Indicator,
    append_gh_summary,
    collect_from_yaml,
    configure_logging,
    main,
    register_parser,
    type_breakdown,
    type_counts,
    top_tags,
)

__all__ = [
    "Indicator",
    "append_gh_summary",
    "collect_from_yaml",
    "configure_logging",
    "main",
    "register_parser",
    "type_breakdown",
    "type_counts",
    "top_tags",
]

__version__ = "0.1.0"
