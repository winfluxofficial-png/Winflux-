"""Ed25519 keys and encrypted keystore (scrypt + AES-256-GCM)."""
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..errors import WalletError
from .address import pubkey_to_address

KDF_N_DEFAULT = 2**15
_KDF_N_MAX = 2**20
MIN_PASSWORD_LEN = 8


class KeyPair:
    """Ed25519 key pair derived from a 32-byte seed."""

    key_type = "ed25519"

    def __init__(self, seed: bytes):
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self._seed = bytes(seed)
        self._priv = Ed25519PrivateKey.from_private_bytes(self._seed)
        self.public_key: bytes = self._priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(os.urandom(32))

    @property
    def seed(self) -> bytes:
        return self._seed

    @property
    def public_hex(self) -> str:
        return self.public_key.hex()

    @property
    def address(self) -> str:
        return pubkey_to_address(self.public_key)

    def sign(self, message: bytes) -> bytes:
        return self._priv.sign(message)

    def __repr__(self) -> str:  # never leak the seed in logs
        return f"KeyPair(address={self.address})"


def verify_signature(pubkey: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))


def encrypt_keystore(keypair: KeyPair, password: str, n: int = KDF_N_DEFAULT) -> dict:
    if len(password) < MIN_PASSWORD_LEN:
        raise WalletError(f"the password must have at least {MIN_PASSWORD_LEN} characters")
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _derive(password, salt, n, 8, 1)
    ct = AESGCM(key).encrypt(nonce, keypair.seed, keypair.address.encode())
    return {
        "version": 1,
        "kdf": "scrypt",
        "kdf_params": {"n": n, "r": 8, "p": 1, "salt": salt.hex()},
        "cipher": "aes-256-gcm",
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
        "address": keypair.address,
        "public_key": keypair.public_hex,
    }


def decrypt_keystore(ks: dict, password: str) -> KeyPair:
    try:
        if ks["version"] != 1 or ks["kdf"] != "scrypt" or ks["cipher"] != "aes-256-gcm":
            raise WalletError("unsupported keystore format")
        p = ks["kdf_params"]
        n, r, par = int(p["n"]), int(p["r"]), int(p["p"])
        if not (2 <= n <= _KDF_N_MAX) or n & (n - 1) or r != 8 or par != 1:
            raise WalletError("invalid KDF parameters")
        key = _derive(password, bytes.fromhex(p["salt"]), n, r, par)
        seed = AESGCM(key).decrypt(bytes.fromhex(ks["nonce"]),
                                   bytes.fromhex(ks["ciphertext"]),
                                   ks["address"].encode())
    except WalletError:
        raise
    except InvalidTag:
        raise WalletError("wrong password or tampered keystore") from None
    except (KeyError, ValueError, TypeError, AttributeError):
        raise WalletError("malformed keystore") from None
    kp = KeyPair(seed)
    if kp.address != ks["address"]:
        raise WalletError("inconsistent keystore")
    return kp


# ---------- P-256 (ECDSA): hardware keys (Android Keystore / Secure Enclave) ----------
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class P256KeyPair:
    """P-256 ECDSA key (reference for tests; in production the key lives in hardware)."""

    key_type = "p256"

    def __init__(self, private_value: int | None = None):
        if private_value is None:
            self._priv = ec.generate_private_key(ec.SECP256R1())
        else:
            self._priv = ec.derive_private_key(private_value, ec.SECP256R1())
        self.public_key: bytes = self._priv.public_key().public_bytes(
            Encoding.X962, PublicFormat.CompressedPoint)

    @property
    def public_hex(self) -> str:
        return self.public_key.hex()

    def sign(self, message: bytes) -> bytes:
        """Raw r||s signature (64 bytes) with low S (canonical form)."""
        r, s = utils.decode_dss_signature(self._priv.sign(message, ec.ECDSA(hashes.SHA256())))
        if s > _P256_N // 2:
            s = _P256_N - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def __repr__(self) -> str:
        return "P256KeyPair(<hidden>)"


def verify_p256(pubkey: bytes, signature: bytes, message: bytes) -> bool:
    """Verifies P-256 ECDSA requiring low S (rejects the malleable (r, n-s) variant)."""
    if len(signature) != 64:
        return False
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (1 <= r < _P256_N and 1 <= s <= _P256_N // 2):
        return False
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkey)
        pub.verify(utils.encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_device_signature(key_type: str, pubkey: bytes, signature: bytes, message: bytes) -> bool:
    if key_type == "ed25519":
        return verify_signature(pubkey, signature, message)
    if key_type == "p256":
        return verify_p256(pubkey, signature, message)
    return False
