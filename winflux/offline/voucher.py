"""Voucher offline: promessa assinada pela chave do cofre ("a vaga i paga a ao receptor R").

Layout binário FIXO (sem ambiguidade de serialização, cabe em QR/BLE/NFC):

    corpo (111 bytes) = versão(1) ‖ hash_chain_id(32) ‖ vault_id(32) ‖ vaga(u16) ‖ valor(u64)
                        ‖ hash160_receptor(20) ‖ request_id(16)
    voucher (175 B)   = corpo ‖ assinatura(64)

A identidade do voucher (`hash`) cobre SÓ o corpo: assinaturas ECDSA são maleáveis e uma
variante da assinatura não pode contar como "outro voucher".
"""
import struct
from dataclasses import dataclass

from ..crypto.address import address_from_hash, address_to_hash, is_valid_address
from ..crypto.hashing import sha256
from ..errors import ValidationError

VERSION = 1
BODY_LEN = 111
SIG_LEN = 64
TOTAL_LEN = BODY_LEN + SIG_LEN
SIGN_DOMAIN = b"WFLX-VOUCHER-V1"
ID_DOMAIN = b"WFLX-VOUCHER-ID-V1"
_FMT = ">B32s32sHQ20s16s"
assert struct.calcsize(_FMT) == BODY_LEN


def chain_id_hash(chain_id: str) -> bytes:
    return sha256(b"WFLX-CHAIN-ID-V1" + chain_id.encode("utf-8"))


@dataclass(frozen=True)
class Voucher:
    chain_id_hash: bytes
    vault_id: str          # hex 64
    slot: int
    amount: int            # unidades
    receiver_hash: bytes   # hash160 do endereço do receptor
    request_id: bytes      # 16 bytes escolhidos pelo receptor (amarra o voucher ao pedido)
    signature: bytes = b""
    version: int = VERSION

    def body(self) -> bytes:
        try:
            return struct.pack(_FMT, self.version, self.chain_id_hash, bytes.fromhex(self.vault_id),
                               self.slot, self.amount, self.receiver_hash, self.request_id)
        except (struct.error, ValueError, TypeError) as e:
            raise ValidationError(f"voucher com campos inválidos: {e}") from None

    def signing_message(self) -> bytes:
        return SIGN_DOMAIN + self.body()

    @property
    def hash(self) -> str:
        return sha256(ID_DOMAIN + self.body()).hex()

    @property
    def receiver_address(self) -> str:
        return address_from_hash(self.receiver_hash)

    def to_bytes(self) -> bytes:
        return self.body() + self.signature

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Voucher":
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != TOTAL_LEN:
            raise ValidationError("voucher com tamanho inválido")
        ver, cid, vid, slot, amount, rh, req = struct.unpack(_FMT, bytes(raw[:BODY_LEN]))
        if ver != VERSION:
            raise ValidationError("versão de voucher não suportada")
        return cls(cid, vid.hex(), slot, amount, rh, req, bytes(raw[BODY_LEN:]), ver)

    @classmethod
    def issue(cls, device_key, chain_id: str, vault_id: str, slot: int, amount: int,
              receiver_address: str, request_id: bytes) -> "Voucher":
        """Emite e assina um voucher com a chave do dispositivo (`device_key.sign`)."""
        if not is_valid_address(receiver_address):
            raise ValidationError("endereço do receptor inválido")
        v = cls(chain_id_hash(chain_id), vault_id, slot, amount, address_to_hash(receiver_address),
                request_id)
        return cls(v.chain_id_hash, v.vault_id, v.slot, v.amount, v.receiver_hash, v.request_id,
                   device_key.sign(v.signing_message()))
