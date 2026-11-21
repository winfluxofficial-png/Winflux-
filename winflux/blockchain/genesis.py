"""Genesis block configuration and construction."""
import json
from dataclasses import dataclass

from ..crypto.address import is_valid_address
from ..crypto.hashing import canonical_json, sha256_hex
from ..errors import ValidationError
from .block import ZERO_HASH, Block
from .params import ChainParams
from .transaction import Transaction, TxOutput


@dataclass(frozen=True)
class GenesisConfig:
    params: ChainParams
    timestamp: int
    allocations: tuple  # ((address, units), ...)

    def __post_init__(self):
        total = 0
        for addr, amount in self.allocations:
            if not is_valid_address(addr):
                raise ValidationError(f"invalid address in the genesis: {addr}")
            if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
                raise ValidationError("invalid allocation in the genesis")
            total += amount
        if total > self.params.max_supply:
            raise ValidationError("genesis exceeds the maximum supply")

    @property
    def total(self) -> int:
        return sum(a for _, a in self.allocations)

    def to_dict(self) -> dict:
        return {"params": self.params.to_dict(), "timestamp": self.timestamp,
                "allocations": [{"address": a, "amount": v} for a, v in self.allocations]}

    @classmethod
    def from_dict(cls, d: dict) -> "GenesisConfig":
        try:
            allocs = tuple((x["address"], x["amount"]) for x in d["allocations"])
            return cls(ChainParams.from_dict(d["params"]), d["timestamp"], allocs)
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"malformed genesis.json: {e}") from None


def load_genesis_config(path: str) -> GenesisConfig:
    with open(path, "r", encoding="utf-8") as f:
        return GenesisConfig.from_dict(json.load(f))


def save_genesis_config(cfg: GenesisConfig, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg.to_dict(), f, indent=2)


def build_genesis_block(cfg: GenesisConfig) -> Block:
    cb = Transaction(cfg.params.chain_id, (),
                     tuple(TxOutput(v, a) for a, v in cfg.allocations),
                     coinbase_height=0, payload={"prev_hash": ZERO_HASH})
    return Block.build(0, ZERO_HASH, cfg.timestamp, "", [cb], meta=cfg.params.commitment())


def genesis_fingerprint(params: ChainParams, timestamp: int, allocations) -> str:
    """8 hex digits that identify the genesis WITHOUT using the chain_id (to derive a unique chain_id).

    Two different geneses with the same chain_id would allow replay between networks when the
    coinbases coincide (the coinbase txid only depends on chain_id, height and outputs).
    """
    d = params.to_dict()
    d.pop("chain_id")
    blob = canonical_json({"params": d, "timestamp": timestamp,
                           "allocations": [[a, v] for a, v in allocations]})
    return sha256_hex(b"WFLX-GENESIS-FP-V1" + blob)[:8]
