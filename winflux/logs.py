"""Node logging: levels, rotating file and secret REDACTION.

Project rules: never log message/transaction bodies, passwords, seeds, private keys, recovery
keys or wallet contents. Errors coming from the network (peer or HTTP client) log only the exception TYPE, not
the message; `ValidationError` messages (public protocol rules) may appear. As an additional defense, all
text goes through `redact()` before being written, even if someone logs something inappropriate by mistake.
"""
import logging
import re
import sys
from logging.handlers import RotatingFileHandler

from .errors import ValidationError

LEVELS = {"debug": logging.DEBUG, "info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}

_REDACTIONS = [
    (re.compile(r"(?i)\b(authorization)\s*[:=]\s*[^\r\n]+"), r"\1: [REDACTED]"),
    (re.compile(r"(?i)\bbearer\s+\S+"), "Bearer [REDACTED]"),
    (re.compile(r"wflxk1-[a-z2-7\- ]{8,}", re.I), "wflxk1-[REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|secret|seed|private[_ -]?key|"
                r"recovery|mnemonic|token)\b(\s*[=:]\s*|\s+)([^\s,;]+)"),
     r"\1\2[REDACTED]"),
    (re.compile(r"(?i)\b(secret|seed|priv(?:ate)?)_?key\"?\s*:\s*\"[^\"]*\""), r'\1_key": "[REDACTED]"'),
]


def redact(text: str) -> str:
    for rx, rep in _REDACTIONS:
        text = rx.sub(rep, text)
    return text


class RedactingFormatter(logging.Formatter):
    def format(self, record):
        return redact(super().format(record))        # covers message AND traceback


def exc_label(e: BaseException) -> str:
    """Safe label for logging an exception: protocol rule (text) or just the type (network/IO/unexpected)."""
    return str(e)[:200] if isinstance(e, ValidationError) else type(e).__name__


def setup_logging(level: str = "info", logfile: str | None = None, stream=None) -> logging.Logger:
    """Configures the "winflux" logger (idempotent). Default `stream`: stdout."""
    if level not in LEVELS:
        raise ValueError(f"invalid log level: {level} (use {', '.join(LEVELS)})")
    lg = logging.getLogger("winflux")
    lg.setLevel(LEVELS[level])
    lg.propagate = False
    for h in list(lg.handlers):
        lg.removeHandler(h)
        h.close()
    fmt = RedactingFormatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%dT%H:%M:%S")
    handlers = [logging.StreamHandler(stream or sys.stdout)]
    if logfile:
        handlers.append(RotatingFileHandler(logfile, maxBytes=5_000_000, backupCount=3, encoding="utf-8"))
    for h in handlers:
        h.setFormatter(fmt)
        lg.addHandler(h)
    return lg


def make_log(component: str = "node"):
    """Returns `log(msg, level="info")`, the interface used by Node/P2P/API."""
    lg = logging.getLogger(f"winflux.{component}")

    def log(msg: str, level: str = "info") -> None:
        lg.log(LEVELS.get(level, logging.INFO), "%s", msg)
    return log


def noop_log(msg: str, level: str = "info") -> None:
    return None
