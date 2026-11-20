"""SIMULADOR de hardware seguro (Android Keystore/StrongBox) para testes. NÃO é segurança real.

Modela as propriedades de que as garantias dependem (docs/security-assumptions.md, H1):
  - a chave NÃO é exportável (não há API de exportação; o objeto não pode ser copiado nem serializado);
  - chave de USO ÚNICO: depois de assinar uma vez, é apagada no hardware (restaurar backup do app não a traz de volta);
  - atestação assinada por uma raiz de teste, com nível de segurança e desafio.
Também modela o ADVERSÁRIO: `break_single_use()` representa hardware comprometido que assina de novo.
"""
import os
from dataclasses import dataclass

from ..crypto.keys import KeyPair, P256KeyPair
from ..errors import WinfluxError
from .attestation import device_statement_bytes, key_statement_bytes


class HardwareError(WinfluxError):
    """Operação recusada pelo hardware simulado."""


class SimulatedRoot:
    """Raiz de atestação de TESTE (no mundo real: raízes do fabricante, fixadas no verificador)."""

    def __init__(self, seed: bytes | None = None):
        self._kp = KeyPair(seed or os.urandom(32))

    @property
    def public_key(self) -> bytes:
        return self._kp.public_key

    def provision(self, level: str = "strongbox", *, not_before: int = 0, not_after: int = 2**40,
                  seed: bytes | None = None) -> "SimulatedHardware":
        dev = KeyPair(seed or os.urandom(32))
        stmt = {"device_pubkey": dev.public_hex, "level_max": level, "not_before": not_before, "not_after": not_after}
        sig = self._kp.sign(device_statement_bytes(stmt)).hex()
        return SimulatedHardware(self.public_key.hex(), dev, stmt, sig, level)


@dataclass(frozen=True)
class KeyHandle:
    """Referência a uma chave dentro do hardware (a chave privada nunca sai de lá)."""
    hardware: "SimulatedHardware"
    handle: str
    key_type: str
    public_key: bytes
    attestation: dict

    @property
    def public_hex(self) -> str:
        return self.public_key.hex()

    def sign(self, message: bytes) -> bytes:
        return self.hardware._sign(self.handle, message)


class SimulatedHardware:
    def __init__(self, root_hex: str, device_kp: KeyPair, device_stmt: dict, device_sig: str, level: str):
        self._root_hex, self._dev, self._dev_stmt, self._dev_sig = root_hex, device_kp, device_stmt, device_sig
        self.level = level
        self._keys: dict[str, dict] = {}
        self._tampered = False
        self._counter = 0

    # --- não clonável / não exportável
    def __copy__(self):
        raise HardwareError("o hardware não pode ser copiado")

    def __deepcopy__(self, memo):
        raise HardwareError("o hardware não pode ser copiado")

    def __reduce__(self):
        raise HardwareError("o hardware não pode ser serializado")

    def export_key(self, handle: str):
        raise HardwareError("chave não exportável")

    # --- operações
    def break_single_use(self) -> None:
        """ADVERSÁRIO: hardware comprometido deixa assinar de novo (a atestação continua dizendo uso único)."""
        self._tampered = True

    def generate_key(self, key_type: str, challenge: bytes, *, single_use: bool = True, not_before: int = 0,
                     not_after: int = 2**40) -> KeyHandle:
        if key_type not in ("p256", "ed25519"):
            raise HardwareError("tipo de chave não suportado")
        self._counter += 1
        kp = P256KeyPair() if key_type == "p256" else KeyPair(os.urandom(32))
        h = f"k{self._counter}"
        # "software" não impõe uso único; TEE/StrongBox impõem se single_use for pedido
        impose = single_use and self.level != "software"
        self._keys[h] = {"kp": kp, "impose": impose}
        stmt = {"key_type": key_type, "pubkey": kp.public_hex, "challenge": challenge.hex(), "level": self.level,
                "single_use": impose, "not_before": not_before, "not_after": not_after}
        att = {"v": 1, "key": stmt, "key_sig": self._dev.sign(key_statement_bytes(stmt)).hex(),
               "device": dict(self._dev_stmt), "device_sig": self._dev_sig, "root": self._root_hex}
        return KeyHandle(self, h, key_type, kp.public_key, att)

    def _sign(self, handle: str, message: bytes) -> bytes:
        k = self._keys.get(handle)
        if k is None:
            raise HardwareError("chave inexistente ou já usada (uso único)")
        sig = k["kp"].sign(message)
        if k["impose"] and not self._tampered:
            del self._keys[handle]          # apagada no hardware: nenhuma restauração a traz de volta
        return sig

    def has_key(self, handle: str) -> bool:
        return handle in self._keys
