"""Keep recognizable collected credentials out of public IOC exports.

This is a narrow Google API-key safeguard, not a general secret scanner.
Dropping the whole record preserves exact-match IOC semantics: replacing a
credential inside a URL would create a URL that was never observed.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict
from typing import List, Tuple
from urllib.parse import unquote

from .models import Indicator


_GOOGLE_API_KEY = re.compile(r"AIza[0-9A-Za-z_-]{35}")


def filter_public_rows(rows: List[Indicator]) -> Tuple[List[Indicator], int]:
    """Omit rows containing a Google-key-shaped value, without logging it.

Inspect metadata and nested provider evidence as well as indicator identity.
Decode URL escapes once for credential-bearing query parameters. Never mutate
the caller's snapshot, including the baseline used by SOC Delta.
"""
    public = []
    for row in rows:
        serialized = json.dumps(asdict(row), ensure_ascii=False)
        if not _GOOGLE_API_KEY.search(unquote(serialized)):
            public.append(row)
    return public, len(rows) - len(public)
