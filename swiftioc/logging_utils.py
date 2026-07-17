"""Console/file logging setup."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from .http_client import logger
from .models import iso, now_utc


# ---------------- logging ----------------
class JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {"ts": iso(now_utc()), "level": record.levelname, "name": record.name, "msg": record.getMessage()}
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(console_level: int, *, log_file: Optional[Path], file_level: int, fmt: str) -> None:
    logger.setLevel(min(console_level, file_level))
    for h in list(logger.handlers):
        logger.removeHandler(h)
    ch = logging.StreamHandler()
    ch.setLevel(console_level)
    ch.setFormatter(logging.Formatter("%(levelname)s | %(message)s"))
    logger.addHandler(ch)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(file_level)
        fh.setFormatter(JsonLineFormatter() if fmt == "json" else logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
        logger.addHandler(fh)
