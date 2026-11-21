"""Winflux project exceptions."""


class WinfluxError(Exception):
    """Base of all the project's errors."""


class ValidationError(WinfluxError):
    """Data (transaction, block, message) violates the protocol rules."""


class StorageError(WinfluxError):
    """Failure or corruption in local persistence."""


class WalletError(WinfluxError):
    """Wallet error (wrong password, invalid keystore...)."""


class InsufficientFunds(WalletError):
    """Insufficient funds to build the transaction."""
