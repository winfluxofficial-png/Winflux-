"""Carteira: keystore cifrado em arquivo."""
import json
import os

from ..crypto.keys import KDF_N_DEFAULT, KeyPair, decrypt_keystore, encrypt_keystore
from ..errors import WalletError


class Wallet:
    def __init__(self, keypair: KeyPair):
        self.keypair = keypair

    @property
    def address(self) -> str:
        return self.keypair.address

    @classmethod
    def create(cls) -> "Wallet":
        return cls(KeyPair.generate())

    def save(self, path: str, password: str, kdf_n: int = KDF_N_DEFAULT) -> None:
        ks = encrypt_keystore(self.keypair, password, kdf_n)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # nunca sobrescreve
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(ks, f, indent=2)

    @classmethod
    def load(cls, path: str, password: str) -> "Wallet":
        try:
            with open(path, "r", encoding="utf-8") as f:
                ks = json.load(f)
        except (OSError, ValueError):
            raise WalletError("não foi possível ler o keystore") from None
        return cls(decrypt_keystore(ks, password))
