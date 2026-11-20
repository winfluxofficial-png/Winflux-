"""Bloco: cabeçalho + transações. O hash cobre só o cabeçalho."""
import re
from dataclasses import dataclass

from ..crypto.hashing import canonical_json, merkle_root, sha256_hex
from ..errors import ValidationError
from .state_root import EMPTY_VAULT_ROOT
from .transaction import Transaction

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
ZERO_HASH = "0" * 64
MAX_TXS_PARSE = 10_000


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


@dataclass
class Block:
    height: int
    prev_hash: str
    timestamp: int
    merkle_root: str
    producer: str            # pubkey hex do produtor (PoA); "" no gênese
    nonce: int               # reservado para PoW (Etapa 5)
    meta: str                # gênese: hash dos parâmetros da rede
    transactions: tuple
    signature: str = ""      # assinatura do produtor sobre o hash (PoA)
    state_root: str = EMPTY_VAULT_ROOT  # raiz Merkle do registro de cofres APÓS o bloco

    def header(self) -> dict:
        return {"height": self.height, "prev_hash": self.prev_hash,
                "timestamp": self.timestamp, "merkle_root": self.merkle_root,
                "producer": self.producer, "nonce": self.nonce, "meta": self.meta,
                "state_root": self.state_root}

    @property
    def hash(self) -> str:
        return sha256_hex(b"WFLX-BLOCK-HEADER-V1" + canonical_json(self.header()))

    def compute_merkle(self) -> str:
        return merkle_root([t.txid for t in self.transactions])

    @classmethod
    def build(cls, height, prev_hash, timestamp, producer, transactions, nonce=0, meta="",
              state_root=EMPTY_VAULT_ROOT) -> "Block":
        txs = tuple(transactions)
        return cls(height, prev_hash, timestamp, merkle_root([t.txid for t in txs]),
                   producer, nonce, meta, txs, state_root=state_root)

    def to_dict(self) -> dict:
        d = self.header()
        d["signature"] = self.signature
        d["transactions"] = [t.to_dict() for t in self.transactions]
        return d

    @classmethod
    def from_dict(cls, d) -> "Block":
        try:
            keys = {"height", "prev_hash", "timestamp", "merkle_root", "producer",
                    "nonce", "meta", "signature", "transactions", "state_root"}
            if not isinstance(d, dict) or set(d) != keys:
                raise ValidationError("campos do bloco inválidos")
            for k in ("height", "timestamp", "nonce"):
                if not _is_int(d[k]) or d[k] < 0:
                    raise ValidationError(f"{k} inválido")
            for k in ("prev_hash", "merkle_root", "state_root"):
                if not (isinstance(d[k], str) and _HEX64.match(d[k])):
                    raise ValidationError(f"{k} inválido")
            if not (isinstance(d["producer"], str) and (d["producer"] == "" or _HEX64.match(d["producer"]))):
                raise ValidationError("produtor inválido")
            if not (isinstance(d["signature"], str) and (d["signature"] == "" or _HEX128.match(d["signature"]))):
                raise ValidationError("assinatura inválida")
            if not isinstance(d["meta"], str) or len(d["meta"]) > 128:
                raise ValidationError("meta inválido")
            if not isinstance(d["transactions"], list) or len(d["transactions"]) > MAX_TXS_PARSE:
                raise ValidationError("transações inválidas")
            txs = tuple(Transaction.from_dict(t) for t in d["transactions"])
            return cls(d["height"], d["prev_hash"], d["timestamp"], d["merkle_root"],
                       d["producer"], d["nonce"], d["meta"], txs, d["signature"], d["state_root"])
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"bloco malformado: {type(e).__name__}") from None
