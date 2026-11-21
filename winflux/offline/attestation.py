"""Key attestation: proof that a key lives in hardware, with certain properties.

SIMULATED FORMAT (JSON), with the same semantics as Android key attestation: a trusted root signs the device
certificate, the device signs a statement about the key (type, challenge, security level, single use,
validity). The real Android verifier (X.509 chain, KeyDescription extension, revocation) comes in Phase B behind the
same `verify_attestation` interface. See docs/security-assumptions.md (H1, H2).

Levels: "software" < "tee" < "strongbox". Only TEE/StrongBox WITH single use count as hardware level.
"""
import re
from dataclasses import dataclass

from ..crypto.hashing import canonical_json, sha256
from ..crypto.keys import verify_signature
from ..errors import ValidationError

LEVELS = {"software": 0, "tee": 1, "strongbox": 2}
KEY_TYPES = ("ed25519", "p256")
_HEX = re.compile(r"^[0-9a-f]*$")
KEY_DOMAIN = b"WFLX-ATT-KEY-V1"
DEVICE_DOMAIN = b"WFLX-ATT-DEVICE-V1"


def key_statement_bytes(stmt: dict) -> bytes:
    return KEY_DOMAIN + canonical_json(stmt)


def device_statement_bytes(stmt: dict) -> bytes:
    return DEVICE_DOMAIN + canonical_json(stmt)


@dataclass(frozen=True)
class AttestationResult:
    level: str
    single_use: bool
    device_id: str
    key_type: str
    pubkey: str
    challenge: str

    @property
    def is_hardware(self) -> bool:
        return self.single_use and LEVELS[self.level] >= LEVELS["tee"]


def _int(x) -> int:
    if not isinstance(x, int) or isinstance(x, bool) or not 0 <= x <= 2**63:
        raise ValidationError("invalid integer field in the attestation")
    return x


def _hex(x, n: int | None = None) -> str:
    if not (isinstance(x, str) and _HEX.match(x) and (n is None or len(x) == n)):
        raise ValidationError("invalid hexadecimal field in the attestation")
    return x


def _keys(d, keys: set) -> dict:
    if not isinstance(d, dict) or set(d) != keys:
        raise ValidationError("invalid attestation structure")
    return d


def verify_attestation(att, *, roots, now: int, revoked=frozenset(), expect_pubkey: str | None = None,
                       expect_key_type: str | None = None, expect_challenge: str | None = None) -> AttestationResult:
    """Verifies the root -> device -> key chain. Raises ValidationError if ANYTHING does not match.

    `roots`: trusted Ed25519 public keys (bytes). `revoked`: revoked device ids (local cache).
    """
    a = _keys(att, {"v", "key", "key_sig", "device", "device_sig", "root"})
    if a["v"] != 1:
        raise ValidationError("unsupported attestation version")
    root = bytes.fromhex(_hex(a["root"], 64))
    if root not in set(roots):
        raise ValidationError("untrusted attestation root")
    dev = _keys(a["device"], {"device_pubkey", "level_max", "not_before", "not_after"})
    dpub = bytes.fromhex(_hex(dev["device_pubkey"], 64))
    if not (isinstance(dev["level_max"], str) and dev["level_max"] in LEVELS):
        raise ValidationError("invalid maximum level")
    _int(dev["not_before"]); _int(dev["not_after"])
    if not verify_signature(root, bytes.fromhex(_hex(a["device_sig"], 128)), device_statement_bytes(dev)):
        raise ValidationError("device certificate does not match the root")
    if not dev["not_before"] <= now <= dev["not_after"]:
        raise ValidationError("device certificate outside validity")
    device_id = sha256(dpub).hex()
    if device_id in revoked:
        raise ValidationError("revoked device")
    k = _keys(a["key"], {"key_type", "pubkey", "challenge", "level", "single_use", "not_before", "not_after"})
    if not (isinstance(k["key_type"], str) and k["key_type"] in KEY_TYPES):
        raise ValidationError("invalid key type in the attestation")
    _hex(k["pubkey"]); _hex(k["challenge"])
    if not (isinstance(k["level"], str) and k["level"] in LEVELS) or not isinstance(k["single_use"], bool):
        raise ValidationError("invalid key properties")
    _int(k["not_before"]); _int(k["not_after"])
    if not verify_signature(dpub, bytes.fromhex(_hex(a["key_sig"], 128)), key_statement_bytes(k)):
        raise ValidationError("key statement does not match the device")
    if not k["not_before"] <= now <= k["not_after"]:
        raise ValidationError("key attestation outside its validity")
    if LEVELS[k["level"]] > LEVELS[dev["level_max"]]:
        raise ValidationError("key level above what the device can attest")
    if expect_pubkey is not None and k["pubkey"] != expect_pubkey:
        raise ValidationError("the attestation is for another key")
    if expect_key_type is not None and k["key_type"] != expect_key_type:
        raise ValidationError("the attestation is for another key type")
    if expect_challenge is not None and k["challenge"] != expect_challenge:
        raise ValidationError("attestation challenge does not match (attestation for another request)")
    return AttestationResult(k["level"], k["single_use"], device_id, k["key_type"], k["pubkey"], k["challenge"])
