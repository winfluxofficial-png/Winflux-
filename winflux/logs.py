"""Logging do nó: níveis, arquivo com rotação e REDAÇÃO de segredos.

Regras do projeto: nunca registrar corpo de mensagens/transações, senhas, sementes, chaves privadas, chaves de
recuperação nem conteúdo de carteiras. Erros vindos da rede (peer ou cliente HTTP) registram só o TIPO da exceção, não
a mensagem; mensagens de `ValidationError` (regras públicas do protocolo) podem aparecer. Como defesa adicional, todo
texto passa por `redact()` antes de ser gravado, mesmo que alguém logue algo indevido por engano.
"""
import logging
import re
import sys
from logging.handlers import RotatingFileHandler

from .errors import ValidationError

LEVELS = {"debug": logging.DEBUG, "info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}

_REDACTIONS = [
    (re.compile(r"(?i)\b(authorization)\s*[:=]\s*[^\r\n]+"), r"\1: [REDIGIDO]"),
    (re.compile(r"(?i)\bbearer\s+\S+"), "Bearer [REDIGIDO]"),
    (re.compile(r"wflxk1-[a-z2-7\- ]{8,}", re.I), "wflxk1-[REDIGIDO]"),
    (re.compile(r"(?i)\b(password|passwd|senha|secret|segredo|seed|semente|private[_ -]?key|chave[_ -]?privada|"
                r"recovery|recupera[cç][aã]o|mnemonic|token)\b(\s*[=:]\s*|\s+)([^\s,;]+)"),
     r"\1\2[REDIGIDO]"),
    (re.compile(r"(?i)\b(secret|seed|priv(?:ate)?)_?key\"?\s*:\s*\"[^\"]*\""), r'\1_key": "[REDIGIDO]"'),
]


def redact(text: str) -> str:
    for rx, rep in _REDACTIONS:
        text = rx.sub(rep, text)
    return text


class RedactingFormatter(logging.Formatter):
    def format(self, record):
        return redact(super().format(record))        # cobre mensagem E traceback


def exc_label(e: BaseException) -> str:
    """Rótulo seguro para logar uma exceção: regra do protocolo (texto) ou só o tipo (rede/IO/inesperado)."""
    return str(e)[:200] if isinstance(e, ValidationError) else type(e).__name__


def setup_logging(level: str = "info", logfile: str | None = None, stream=None) -> logging.Logger:
    """Configura o logger "winflux" (idempotente). `stream` padrão: stdout."""
    if level not in LEVELS:
        raise ValueError(f"nível de log inválido: {level} (use {', '.join(LEVELS)})")
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
    """Devolve `log(msg, level="info")`, a interface usada por Node/P2P/API."""
    lg = logging.getLogger(f"winflux.{component}")

    def log(msg: str, level: str = "info") -> None:
        lg.log(LEVELS.get(level, logging.INFO), "%s", msg)
    return log


def noop_log(msg: str, level: str = "info") -> None:
    return None
