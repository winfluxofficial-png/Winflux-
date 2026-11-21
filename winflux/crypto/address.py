"""WFLX addresses: "wflx1" + base32(hash160(pubkey) + checksum)."""
import base64

from .hashing import sha256

PREFIX = "wflx1"


def _checksum(h: bytes) -> bytes:
    return sha256(b"WFLX-ADDR-V1" + h)[:4]


def _encode(h: bytes) -> str:
    raw = base64.b32encode(h + _checksum(h)).decode("ascii").lower().rstrip("=")
    return PREFIX + raw


def pubkey_to_address(pubkey: bytes) -> str:
    if len(pubkey) != 32:
        raise ValueError("public key must be 32 bytes")
    return _encode(sha256(pubkey)[:20])


def is_valid_address(addr) -> bool:
    if not isinstance(addr, str) or not addr.startswith(PREFIX):
        return False
    body = addr[len(PREFIX):]
    if not body.isascii() or body != body.lower():
        return False
    try:
        raw = base64.b32decode(body.upper() + "=" * (-len(body) % 8))
    except Exception:
        return False
    if len(raw) != 24 or raw[20:] != _checksum(raw[:20]):
        return False
    return _encode(raw[:20]) == addr  # canonical form


def address_from_hash(h: bytes) -> str:
    if len(h) != 20:
        raise ValueError("hash must be 20 bytes")
    return _encode(h)


def address_to_hash(addr: str) -> bytes:
    if not is_valid_address(addr):
        raise ValueError("invalid address")
    body = addr[len(PREFIX):]
    return base64.b32decode(body.upper() + "=" * (-len(body) % 8))[:20]
