"""SIMULATOR of secure hardware (Android Keystore/StrongBox) for tests. It is NOT real security.

Models the properties the guarantees depend on (docs/security-assumptions.md, H1):
  - the key is NOT exportable (there is no export API; the object cannot be copied or serialized);
  - SINGLE-USE key: after signing once, it is erased in the hardware (restoring an app backup does not bring it back);
  - attestation signed by a test root, with security level and challenge.
It also models the ADVERSARY: `break_single_use()` represents compromised hardware that signs again.
"""
import os
from dataclasses import dataclass

from ..crypto.keys import KeyPair, P256KeyPair
from ..errors import WinfluxError
from .attestation import device_statement_bytes, key_statement_bytes


class HardwareError(WinfluxError):
    """Operation refused by the simulated hardware."""


class SimulatedRoot:
    """TEST attestation root (in the real world: manufacturer roots, pinned in the verifier)."""

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
    """Reference to a key inside the hardware (the private key never leaves it)."""
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

    # --- not clonable / not exportable
    def __copy__(self):
        raise HardwareError("the hardware cannot be copied")

    def __deepcopy__(self, memo):
        raise HardwareError("the hardware cannot be copied")

    def __reduce__(self):
        raise HardwareError("the hardware cannot be serialized")

    def export_key(self, handle: str):
        raise HardwareError("non-exportable key")

    # --- operations
    def break_single_use(self) -> None:
        """ADVERSARY: compromised hardware lets it sign again (the attestation still says single use)."""
        self._tampered = True

    def generate_key(self, key_type: str, challenge: bytes, *, single_use: bool = True, not_before: int = 0,
                     not_after: int = 2**40) -> KeyHandle:
        if key_type not in ("p256", "ed25519"):
            raise HardwareError("unsupported key type")
        self._counter += 1
        kp = P256KeyPair() if key_type == "p256" else KeyPair(os.urandom(32))
        h = f"k{self._counter}"
        # "software" does not enforce single use; TEE/StrongBox do if single_use is requested
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
            raise HardwareError("nonexistent key or already used (single use)")
        sig = k["kp"].sign(message)
        if k["impose"] and not self._tampered:
            del self._keys[handle]          # erased in the hardware: no restore brings it back
        return sig

    def has_key(self, handle: str) -> bool:
        return handle in self._keys
