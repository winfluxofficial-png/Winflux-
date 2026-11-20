"""Atestação de chave: prova de que uma chave vive em hardware, com certas propriedades.

FORMATO SIMULADO (JSON), com a mesma semântica da atestação de chave do Android: uma raiz confiável assina o certificado
do dispositivo, o dispositivo assina uma declaração sobre a chave (tipo, desafio, nível de segurança, uso único,
validade). O verificador real do Android (cadeia X.509, extensão KeyDescription, revogação) entra na Fase B atrás da
mesma interface `verify_attestation`. Ver docs/security-assumptions.md (H1, H2).

Níveis: "software" < "tee" < "strongbox". Só TEE/StrongBox COM uso único contam como nível de hardware.
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
        raise ValidationError("campo inteiro inválido na atestação")
    return x


def _hex(x, n: int | None = None) -> str:
    if not (isinstance(x, str) and _HEX.match(x) and (n is None or len(x) == n)):
        raise ValidationError("campo hexadecimal inválido na atestação")
    return x


def _keys(d, keys: set) -> dict:
    if not isinstance(d, dict) or set(d) != keys:
        raise ValidationError("estrutura da atestação inválida")
    return d


def verify_attestation(att, *, roots, now: int, revoked=frozenset(), expect_pubkey: str | None = None,
                       expect_key_type: str | None = None, expect_challenge: str | None = None) -> AttestationResult:
    """Verifica a cadeia raiz -> dispositivo -> chave. Levanta ValidationError se QUALQUER coisa não confere.

    `roots`: chaves públicas Ed25519 confiáveis (bytes). `revoked`: ids de dispositivo revogados (cache local).
    """
    a = _keys(att, {"v", "key", "key_sig", "device", "device_sig", "root"})
    if a["v"] != 1:
        raise ValidationError("versão de atestação não suportada")
    root = bytes.fromhex(_hex(a["root"], 64))
    if root not in set(roots):
        raise ValidationError("raiz de atestação não confiável")
    dev = _keys(a["device"], {"device_pubkey", "level_max", "not_before", "not_after"})
    dpub = bytes.fromhex(_hex(dev["device_pubkey"], 64))
    if not (isinstance(dev["level_max"], str) and dev["level_max"] in LEVELS):
        raise ValidationError("nível máximo inválido")
    _int(dev["not_before"]); _int(dev["not_after"])
    if not verify_signature(root, bytes.fromhex(_hex(a["device_sig"], 128)), device_statement_bytes(dev)):
        raise ValidationError("certificado do dispositivo não confere com a raiz")
    if not dev["not_before"] <= now <= dev["not_after"]:
        raise ValidationError("certificado do dispositivo fora da validade")
    device_id = sha256(dpub).hex()
    if device_id in revoked:
        raise ValidationError("dispositivo revogado")
    k = _keys(a["key"], {"key_type", "pubkey", "challenge", "level", "single_use", "not_before", "not_after"})
    if not (isinstance(k["key_type"], str) and k["key_type"] in KEY_TYPES):
        raise ValidationError("tipo de chave inválido na atestação")
    _hex(k["pubkey"]); _hex(k["challenge"])
    if not (isinstance(k["level"], str) and k["level"] in LEVELS) or not isinstance(k["single_use"], bool):
        raise ValidationError("propriedades da chave inválidas")
    _int(k["not_before"]); _int(k["not_after"])
    if not verify_signature(dpub, bytes.fromhex(_hex(a["key_sig"], 128)), key_statement_bytes(k)):
        raise ValidationError("declaração da chave não confere com o dispositivo")
    if not k["not_before"] <= now <= k["not_after"]:
        raise ValidationError("atestação da chave fora da validade")
    if LEVELS[k["level"]] > LEVELS[dev["level_max"]]:
        raise ValidationError("nível da chave acima do que o dispositivo pode atestar")
    if expect_pubkey is not None and k["pubkey"] != expect_pubkey:
        raise ValidationError("a atestação é de outra chave")
    if expect_key_type is not None and k["key_type"] != expect_key_type:
        raise ValidationError("a atestação é de outro tipo de chave")
    if expect_challenge is not None and k["challenge"] != expect_challenge:
        raise ValidationError("desafio da atestação não confere (atestação de outro pedido)")
    return AttestationResult(k["level"], k["single_use"], device_id, k["key_type"], k["pubkey"], k["challenge"])
