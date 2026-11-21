"""Checkpoints and vault proofs for OFFLINE verification (A1).

A *checkpoint* is a block header signed by an authority (PoA): it carries the `state_root` of the vault
registry. A *vault proof* shows, in a few hundred bytes, that slot `i` of vault `V` exists, with certain
parameters and state, in the `state_root` of a checkpoint. The receiver verifies everything without consulting the network.

Assumed limits (see docs/security-assumptions.md): the proof only shows the state AT the checkpoint; a payer can
present an old checkpoint, so the receiver keeps the newest checkpoint it has seen (CheckpointStore) and
rejects older proofs; PoA has no finality, so a "checkpoint" only proves the authority signed.
"""
import re
from dataclasses import dataclass

from ..blockchain import state_root as SR
from ..blockchain.block import Block
from ..blockchain.vaults import KEY_TYPES
from ..crypto.address import is_valid_address
from ..crypto.hashing import canonical_json
from ..errors import ValidationError
from .voucher import chain_id_hash

PROOF_VERSION = 1
_HEX = re.compile(r"^[0-9a-f]*$")


# ------------------------------------------------------------------ strict field validation
def _int(x, lo=0, hi=2**63) -> int:
    if not isinstance(x, int) or isinstance(x, bool) or not lo <= x <= hi:
        raise ValidationError("invalid integer field in the proof")
    return x


def _hex(x, n: int, allow_empty=False) -> str:
    if allow_empty and x == "":
        return x
    if not (isinstance(x, str) and len(x) == n and _HEX.match(x)):
        raise ValidationError("invalid hexadecimal field in the proof")
    return x


def _keys(d, keys: set) -> dict:
    if not isinstance(d, dict) or set(d) != keys:
        raise ValidationError("invalid proof structure")
    return d


def _path(p) -> list:
    if not isinstance(p, list) or len(p) > SR.MAX_PATH:
        raise ValidationError("invalid Merkle path")
    return [bytes.fromhex(_hex(x, 64)) for x in p]


# ------------------------------------------------------------------ checkpoint
def make_checkpoint(block: Block) -> dict:
    """Checkpoint = signed header (without the transactions)."""
    if not block.signature:
        raise ValidationError("a block without a signature is not a checkpoint")
    return {"header": block.header(), "signature": block.signature}


def _block_from_checkpoint(cp) -> Block:
    cp = _keys(cp, {"header", "signature"})
    h = _keys(cp["header"], {"height", "prev_hash", "timestamp", "merkle_root", "producer", "nonce",
                             "meta", "state_root"})
    if not (isinstance(h["meta"], str) and len(h["meta"]) <= 128):
        raise ValidationError("invalid header")
    return Block(_int(h["height"]), _hex(h["prev_hash"], 64), _int(h["timestamp"]),
                 _hex(h["merkle_root"], 64), _hex(h["producer"], 64), _int(h["nonce"]), h["meta"], (),
                 _hex(cp["signature"], 128), _hex(h["state_root"], 64))


def verify_checkpoint(cp, params, consensus) -> Block:
    """Verifies the authority and the signature (without the transactions). Returns the header block."""
    block = _block_from_checkpoint(cp)
    consensus.verify_block(block, None, params)
    return block


# ------------------------------------------------------------------ proof construction (payer's side, online)
def build_vault_proof(chain, vault_id: str, slot_index: int) -> dict:
    """Slot proof against the state of the chain TIP (the tip is the checkpoint)."""
    vault = chain.get_vault(vault_id)
    if vault is None:
        raise ValidationError("nonexistent vault")
    if not 0 <= slot_index < len(vault.slots):
        raise ValidationError("nonexistent slot")
    tip = chain.tip
    if not tip.signature:
        raise ValidationError("there is no signed block yet to serve as a checkpoint")
    chash = chain_id_hash(chain.params.chain_id)
    vaults = chain.vaults.values_sorted()
    vidx = [v.vault_id for v in vaults].index(vault_id)
    vpath = SR.merkle_path([SR.vault_leaf(chash, v) for v in vaults], vidx)
    records = [SR.slot_record(i, s) for i, s in enumerate(vault.slots)]
    spath = SR.merkle_path([SR.slot_leaf(i, r) for i, r in enumerate(records)], slot_index)
    return {
        "v": PROOF_VERSION,
        "checkpoint": make_checkpoint(tip),
        "vault": {"id": vault_id, "static": SR.static_fields(vault), "state": vault.state,
                  "fraud": vault.fraud, "index": vidx, "count": len(vaults),
                  "path": [x.hex() for x in vpath]},
        "slot": {"index": slot_index, "count": len(vault.slots), "record": records[slot_index],
                 "path": [x.hex() for x in spath]},
    }


# ------------------------------------------------------------------ verification (receiver's side, offline)
@dataclass(frozen=True)
class VerifiedSlot:
    vault_id: str
    slot: int
    cap: int
    collateral_left: int
    paid: int
    claimed: bool            # the slot was already occupied AT the checkpoint
    compensated: int
    slot_key: str            # slot's own key ("" for a voucher slot)
    device_key: str
    key_type: str
    refund_address: str
    opened_height: int
    expires_height: int
    state: str               # OPEN | CLOSED
    fraud: bool
    checkpoint_height: int
    checkpoint_hash: str
    checkpoint_timestamp: int


def verify_vault_proof(proof, params, consensus, *, min_checkpoint_height: int = 0) -> VerifiedSlot:
    """Cryptographically verifies the proof. It does NOT decide the policy (state, fraud, value, deadline): that belongs to the
    receiver's verifier, which uses the returned `VerifiedSlot`."""
    p = _keys(proof, {"v", "checkpoint", "vault", "slot"})
    if p["v"] != PROOF_VERSION:
        raise ValidationError("unsupported proof version")
    block = verify_checkpoint(p["checkpoint"], params, consensus)
    if block.height < min_checkpoint_height:
        raise ValidationError("checkpoint older than the one already known to the receiver")

    v = _keys(p["vault"], {"id", "static", "state", "fraud", "index", "count", "path"})
    vid = _hex(v["id"], 64)
    st = _keys(v["static"], {"refund_address", "device_key", "key_type", "opened_height", "expires_height"})
    if not (isinstance(st["key_type"], str) and st["key_type"] in KEY_TYPES):
        raise ValidationError("invalid key type in the proof")
    _hex(st["device_key"], 2 * KEY_TYPES[st["key_type"]])
    if not is_valid_address(st["refund_address"]):
        raise ValidationError("invalid address in the proof")
    _int(st["opened_height"]); _int(st["expires_height"])
    if not (isinstance(v["state"], str) and v["state"] in SR.STATE_CODES and isinstance(v["fraud"], bool)):
        raise ValidationError("invalid vault state in the proof")
    v_index, v_count = _int(v["index"]), _int(v["count"], 1)

    s = _keys(p["slot"], {"index", "count", "record", "path"})
    s_index, s_count = _int(s["index"]), _int(s["count"], 1, 65535)
    r = _keys(s["record"], {"cap", "collateral_left", "paid", "claimed_by", "compensated", "comp_digest", "key"})
    for k in ("cap", "collateral_left", "paid", "compensated"):
        _int(r[k])
    _hex(r["claimed_by"], 64, allow_empty=True)
    _hex(r["comp_digest"], 64)
    _hex(r["key"], 2 * KEY_TYPES[st["key_type"]], allow_empty=True)

    slots_top = SR.top_from_path(SR.slot_leaf(s_index, r), s_index, s_count, _path(s["path"]))
    if slots_top is None:
        raise ValidationError("inconsistent slot path")
    leaf = SR.vault_leaf_from_parts(chain_id_hash(params.chain_id), vid, st, v["state"], v["fraud"],
                                    SR.bind_slots(s_count, slots_top))
    vault_top = SR.top_from_path(leaf, v_index, v_count, _path(v["path"]))
    if vault_top is None or SR.bind_vaults(v_count, vault_top).hex() != block.state_root:
        raise ValidationError("the proof does not match the checkpoint's state_root")
    return VerifiedSlot(vid, s_index, r["cap"], r["collateral_left"], r["paid"], r["claimed_by"] != "",
                        r["compensated"], r["key"], st["device_key"], st["key_type"], st["refund_address"],
                        st["opened_height"], st["expires_height"], v["state"], v["fraud"],
                        block.height, block.hash, block.timestamp)


# ------------------------------------------------------------------ clock and deadlines (without trusting the payer)
def estimated_height(checkpoint_height: int, checkpoint_timestamp: int, now: int, target_block_time: int) -> int:
    """Height estimated by the receiver's OWN clock; never uses time declared by the payer."""
    return checkpoint_height + max(0, (now - checkpoint_timestamp) // target_block_time)


def blocks_until_claim_deadline(vs: VerifiedSlot, now: int, params) -> int:
    est = estimated_height(vs.checkpoint_height, vs.checkpoint_timestamp, now, params.target_block_time)
    return vs.expires_height + params.claim_window_blocks - est


class CheckpointStore:
    """Receiver's local memory: the newest checkpoint seen. Prevents accepting older proofs (a
    payer showing a state in which the slot was still free) and detects conflicting checkpoints."""

    def __init__(self):
        self.height = 0
        self.hash = ""

    def observe(self, height: int, block_hash: str) -> None:
        if height == self.height and self.hash and block_hash != self.hash:
            raise ValidationError("conflicting checkpoints at the same height (possible fork or fraud)")
        if height > self.height:
            self.height, self.hash = height, block_hash

    def min_height(self) -> int:
        return self.height
