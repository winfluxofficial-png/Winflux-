"""UTXO transaction. Values are always integers (units; 1 WFLX = 10**8)."""
import re
from dataclasses import dataclass
from functools import cached_property

from ..crypto.hashing import canonical_json, sha256_hex
from ..errors import ValidationError

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
KINDS = ("transfer", "vault_open", "voucher_claim", "vault_refund", "note_claim")
MAX_INPUTS_PARSE = 1000
MAX_OUTPUTS_PARSE = 1000
SIGN_DOMAIN = b"WFLX-TX-SIGN-V1"


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


@dataclass(frozen=True)
class TxInput:
    txid: str
    index: int
    pubkey: str = ""      # 32-byte hex (empty in the coinbase)
    signature: str = ""   # 64-byte hex; does NOT enter the txid


@dataclass(frozen=True)
class TxOutput:
    value: int
    address: str


@dataclass(frozen=True)
class Transaction:
    chain_id: str
    inputs: tuple
    outputs: tuple
    coinbase_height: int | None = None  # != None => coinbase transaction
    version: int = 1
    kind: str = "transfer"              # ver KINDS
    payload: dict | None = None         # coinbase: {"prev_hash"}; vaults: see blockchain/vaults.py

    @property
    def is_coinbase(self) -> bool:
        return self.coinbase_height is not None

    def body(self) -> dict:
        """Content that defines the txid (without signatures)."""
        return {
            "version": self.version,
            "chain_id": self.chain_id,
            "coinbase_height": self.coinbase_height,
            "kind": self.kind,
            "payload": self.payload,
            "inputs": [{"txid": i.txid, "index": i.index, "pubkey": i.pubkey}
                       for i in self.inputs],
            "outputs": [{"value": o.value, "address": o.address} for o in self.outputs],
        }

    @cached_property
    def txid(self) -> str:
        return sha256_hex(b"WFLX-TXID-V1" + canonical_json(self.body()))

    def signing_message(self) -> bytes:
        # The txid already commits to chain_id, inputs and outputs => anti-replay between networks.
        return SIGN_DOMAIN + bytes.fromhex(self.txid)

    def to_dict(self) -> dict:
        d = self.body()
        d["inputs"] = [{"txid": i.txid, "index": i.index, "pubkey": i.pubkey,
                        "signature": i.signature} for i in self.inputs]
        return d

    def size(self) -> int:
        return len(canonical_json(self.to_dict()))

    @classmethod
    def from_dict(cls, d) -> "Transaction":
        """Strict parsing: rejects extra fields, wrong types and absurd sizes."""
        try:
            if not isinstance(d, dict) or set(d) != {
                    "version", "chain_id", "coinbase_height", "kind", "payload", "inputs", "outputs"}:
                raise ValidationError("invalid transaction fields")
            if not _is_int(d["version"]):
                raise ValidationError("invalid version")
            if not isinstance(d["chain_id"], str) or not 0 < len(d["chain_id"]) <= 64:
                raise ValidationError("invalid chain_id")
            ch = d["coinbase_height"]
            if ch is not None and (not _is_int(ch) or ch < 0):
                raise ValidationError("invalid coinbase_height")
            kind, payload = d["kind"], d["payload"]
            if kind not in KINDS:
                raise ValidationError("unknown transaction type")
            if kind == "transfer":
                if ch is None and payload is not None:
                    raise ValidationError("a plain transfer has no payload")
                if ch is not None and not (isinstance(payload, dict) and set(payload) == {"prev_hash"}
                                           and isinstance(payload["prev_hash"], str)
                                           and _HEX64.match(payload["prev_hash"])):
                    raise ValidationError("coinbase must commit to the previous block hash")
            else:
                if ch is not None or not isinstance(payload, dict):
                    raise ValidationError("vault transaction requires a payload and cannot be a coinbase")
                canonical_json(payload)  # JSON types only, no NaN; failure => ValidationError below
            ins, outs = d["inputs"], d["outputs"]
            if not isinstance(ins, list) or not isinstance(outs, list):
                raise ValidationError("invalid inputs/outputs")
            if len(ins) > MAX_INPUTS_PARSE or len(outs) > MAX_OUTPUTS_PARSE:
                raise ValidationError("transaction too large")
            inputs = []
            for i in ins:
                if not isinstance(i, dict) or set(i) != {"txid", "index", "pubkey", "signature"}:
                    raise ValidationError("malformed input")
                if not (isinstance(i["txid"], str) and _HEX64.match(i["txid"])):
                    raise ValidationError("invalid input txid")
                if not _is_int(i["index"]) or not 0 <= i["index"] < MAX_OUTPUTS_PARSE:
                    raise ValidationError("invalid input index")
                if not (isinstance(i["pubkey"], str) and (i["pubkey"] == "" or _HEX64.match(i["pubkey"]))):
                    raise ValidationError("invalid pubkey")
                if not (isinstance(i["signature"], str) and (i["signature"] == "" or _HEX128.match(i["signature"]))):
                    raise ValidationError("invalid signature")
                inputs.append(TxInput(i["txid"], i["index"], i["pubkey"], i["signature"]))
            outputs = []
            for o in outs:
                if not isinstance(o, dict) or set(o) != {"value", "address"}:
                    raise ValidationError("malformed output")
                if not _is_int(o["value"]) or not isinstance(o["address"], str):
                    raise ValidationError("output with invalid types")
                outputs.append(TxOutput(o["value"], o["address"]))
            return cls(d["chain_id"], tuple(inputs), tuple(outputs), ch, d["version"], kind, payload)
        except ValidationError:
            raise
        except Exception as e:  # extra defense against bizarre inputs
            raise ValidationError(f"malformed transaction: {type(e).__name__}") from None
