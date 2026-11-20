"""Exceções do projeto Winflux."""


class WinfluxError(Exception):
    """Base de todos os erros do projeto."""


class ValidationError(WinfluxError):
    """Dado (transação, bloco, mensagem) viola as regras do protocolo."""


class StorageError(WinfluxError):
    """Falha ou corrupção na persistência local."""


class WalletError(WinfluxError):
    """Erro de carteira (senha incorreta, keystore inválido...)."""


class InsufficientFunds(WalletError):
    """Saldo insuficiente para montar a transação."""
