"""Offline vaults: consensus state, opening, claim and refund rules.

See docs/offline-payments.md (Revision 2). Summary:
- `vault_open` locks value + collateral in N slots and registers the device key `D`.
- `voucher_claim` redeems a voucher signed by `D`: the slot pays at most once; a second
  distinct voucher for the same slot is paid by the collateral and marks the vault as fraudulent.
- `note_claim` (A3) settles ONE address leaf of an offline note chain in a slot with its own key.
  The slot records which offline transactions have already spent each note; a branch that contradicts the record is a
  conflict (double spend) and is compensated by the collateral under R1-R9, never by the deposited value.
- `vault_refund` returns what is left after `expires_height + claim_window` (collateral burned
  if there was fraud). There is NO early close.
"""
import copy
import re
from struct import error as struct_error
from dataclasses import dataclass, field

from ..crypto.address import address_from_hash, is_valid_address
from ..crypto.hashing import canonical_json, sha256
from ..crypto.keys import verify_device_signature  # noqa: F401  (re-export for validation)
from ..errors import ValidationError
from ..offline import note as N
from ..offline.voucher import Voucher, chain_id_hash
from .exposure import plan_compensation
from .params import ChainParams

KEY_TYPES = {"ed25519": 32, "p256": 33}
_HEX = re.compile(r"^[0-9a-f]+$")
POP_DOMAIN = b"WFLX-VAULT-POP-V1"
MAX_SETTLED_PER_SLOT = 64   # settled leaves per slot (bounds state); consensus constant
NOTE_STATE_TAG = b"WFLX-NOTESTATE-V1"


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


@dataclass
class Slot:
    cap: int
    collateral_left: int
    paid: int = 0
    claimed_by: str | None = None   # hash of the voucher that occupied the slot
    key: str = ""                   # slot's own key (hex); "" = voucher slot (vault key D)
    compensated: int = 0            # sum already compensated by the collateral (R2)
    comp_leaves: list = field(default_factory=list)  # vouchers already compensated (R3, at most R9)
    spends: dict = field(default_factory=dict)       # notes: spent note (hex) -> offline txid that spent it on the chain
    settled: list = field(default_factory=list)      # note leaves already settled (hex)

    def note_state_digest(self) -> str:
        """Commitment to `spends` + `settled`; goes in the state root via `claimed_by` (format unchanged)."""
        return sha256(NOTE_STATE_TAG + canonical_json([sorted(self.spends.items()), sorted(self.settled)])).hex()

    def locked(self) -> int:
        return (self.cap - self.paid) + self.collateral_left


@dataclass
class Vault:
    vault_id: str
    refund_address: str
    device_key: str
    key_type: str
    opened_height: int
    expires_height: int
    slots: list = field(default_factory=list)
    state: str = "OPEN"             # OPEN | CLOSED (refunded)
    fraud: bool = False

    def locked(self) -> int:
        return 0 if self.state == "CLOSED" else sum(s.locked() for s in self.slots)

    def to_dict(self) -> dict:
        return {"vault_id": self.vault_id, "refund_address": self.refund_address,
                "device_key": self.device_key, "key_type": self.key_type,
                "opened_height": self.opened_height, "expires_height": self.expires_height,
                "state": self.state, "fraud": self.fraud,
                "slots": [[s.cap, s.collateral_left, s.paid, s.claimed_by, s.compensated,
                           list(s.comp_leaves), s.key, sorted(s.spends.items()), list(s.settled)]
                          for s in self.slots]}


    @classmethod
    def from_dict(cls, d) -> "Vault":
        """Inverse of `to_dict` (client/CLI reading the node API). Strict parsing; not used by consensus."""
        keys = {"vault_id", "refund_address", "device_key", "key_type", "opened_height", "expires_height",
                "state", "fraud", "slots"}
        if not isinstance(d, dict) or not keys <= set(d):
            raise ValidationError("malformed vault")
        slots = []
        for r in d["slots"]:
            if not isinstance(r, list) or len(r) != 9:
                raise ValidationError("malformed slot")
            cap, col, paid, cb, comp, leaves, key, spends, settled = r
            if not all(_is_int(x) and x >= 0 for x in (cap, col, paid, comp)):
                raise ValidationError("malformed slot")
            if not (isinstance(leaves, list) and isinstance(settled, list) and isinstance(spends, list)
                    and all(isinstance(p, (list, tuple)) and len(p) == 2 for p in spends)):
                raise ValidationError("malformed slot")
            slots.append(Slot(cap=cap, collateral_left=col, paid=paid, claimed_by=cb, key=key, compensated=comp,
                              comp_leaves=list(leaves), spends={a: b for a, b in spends}, settled=list(settled)))
        if d["state"] not in ("OPEN", "CLOSED") or not isinstance(d["fraud"], bool):
            raise ValidationError("malformed vault")
        return cls(d["vault_id"], d["refund_address"], d["device_key"], d["key_type"], d["opened_height"],
                   d["expires_height"], slots, d["state"], d["fraud"])


@dataclass
class VaultUndo:
    vault_id: str
    prev: Vault | None


class VaultRegistry:
    """Registry derived from the chain (rebuilt on load), with undo for reorganizations."""

    def __init__(self):
        self._v: dict[str, Vault] = {}
        self.total_locked = 0

    def __len__(self):
        return len(self._v)

    def get(self, vault_id: str) -> Vault | None:
        return self._v.get(vault_id)

    def for_refund_address(self, address: str, limit: int = 100) -> list:
        """Vaults whose refund goes to `address` (linear scan; enough for the testnet)."""
        return [v for v in self._v.values() if v.refund_address == address][:limit]

    def put(self, vault: Vault) -> VaultUndo:
        prev = self._v.get(vault.vault_id)
        self.total_locked += vault.locked() - (prev.locked() if prev else 0)
        self._v[vault.vault_id] = vault
        return VaultUndo(vault.vault_id, prev)

    def revert(self, undo: VaultUndo) -> None:
        cur = self._v[undo.vault_id]
        self.total_locked -= cur.locked()
        if undo.prev is None:
            del self._v[undo.vault_id]
        else:
            self._v[undo.vault_id] = undo.prev
            self.total_locked += undo.prev.locked()

    def values_sorted(self) -> list:
        return [self._v[k] for k in sorted(self._v)]

    def snapshot(self) -> dict:
        return {k: self._v[k].to_dict() for k in sorted(self._v)}


# ---------------------------------------------------------------- opening
@dataclass(frozen=True)
class VaultOpenSpec:
    device_key: str
    key_type: str
    caps: tuple
    collateral_pct: int
    ttl_blocks: int
    refund_address: str
    pop: str
    slot_keys: tuple = ()


def build_slots(caps, collateral_pct: int, slot_keys=()) -> list:
    return [Slot(cap, (cap * collateral_pct + 99) // 100, key=(slot_keys[i] if slot_keys else ""))
            for i, cap in enumerate(caps)]  # collateral rounds up


def parse_vault_open(payload, params: ChainParams) -> VaultOpenSpec:
    keys = {"device_key", "key_type", "slots", "collateral_pct", "ttl_blocks", "refund_address", "pop"}
    if not isinstance(payload, dict) or set(payload) not in (keys, keys | {"slot_keys"}):
        raise ValidationError("invalid vault_open payload")
    kt = payload["key_type"]
    if not (isinstance(kt, str) and kt in KEY_TYPES):
        raise ValidationError("unsupported device key type")
    dk = payload["device_key"]
    if not (isinstance(dk, str) and len(dk) == 2 * KEY_TYPES[kt] and _HEX.match(dk)):
        raise ValidationError("invalid device key")
    caps = payload["slots"]
    if not isinstance(caps, list) or not 1 <= len(caps) <= params.vault_max_slots:
        raise ValidationError("number of slots out of range")
    if not all(_is_int(c) and c >= params.min_voucher_value for c in caps):
        raise ValidationError("slot cap below the minimum voucher")
    pct = payload["collateral_pct"]
    if not (_is_int(pct) and params.vault_collateral_min_pct <= pct <= 1000):
        raise ValidationError("collateral below the network minimum")
    ttl = payload["ttl_blocks"]
    if not (_is_int(ttl) and params.vault_ttl_min_blocks <= ttl <= params.vault_ttl_max_blocks):
        raise ValidationError("vault TTL outside the allowed range")
    if not is_valid_address(payload["refund_address"]):
        raise ValidationError("invalid refund address")
    pop = payload["pop"]
    if not (isinstance(pop, str) and len(pop) == 128 and _HEX.match(pop)):
        raise ValidationError("malformed proof of possession")
    slot_keys = ()
    if "slot_keys" in payload:
        sk = payload["slot_keys"]
        if not isinstance(sk, list) or len(sk) != len(caps):
            raise ValidationError("slot_keys must have one key per slot")
        for k in sk:
            if not (isinstance(k, str) and len(k) == 2 * KEY_TYPES[kt] and _HEX.match(k)):
                raise ValidationError("invalid slot key")
            if kt == "p256" and k[:2] not in ("02", "03"):
                raise ValidationError("slot P-256 key must be in compressed form")
        if len(set(sk)) != len(sk):
            raise ValidationError("repeated slot keys")
        slot_keys = tuple(sk)
    spec = VaultOpenSpec(dk, kt, tuple(caps), pct, ttl, payload["refund_address"], pop, slot_keys)
    locked = sum(s.cap + s.collateral_left for s in build_slots(spec.caps, pct))
    if locked > params.vault_max_value:
        raise ValidationError("vault value above the maximum allowed")
    return spec


def pop_message(tx) -> bytes:
    """Message that key `D` signs to prove possession: the tx body WITHOUT the `pop` field."""
    body = tx.body()
    payload = dict(body["payload"])
    payload.pop("pop", None)
    body["payload"] = payload
    return POP_DOMAIN + sha256(canonical_json(body))


# ---------------------------------------------------------------- claim
@dataclass(frozen=True)
class ClaimPlan:
    slot: int
    payout: int
    from_collateral: bool
    voucher_hash: str


def claim_deadline(vault: Vault, params: ChainParams) -> int:
    return vault.expires_height + params.claim_window_blocks


def parse_claim_payload(payload) -> Voucher:
    if not isinstance(payload, dict) or set(payload) != {"voucher"}:
        raise ValidationError("invalid voucher_claim payload")
    h = payload["voucher"]
    if not (isinstance(h, str) and len(h) == 350 and _HEX.match(h)):
        raise ValidationError("malformed voucher")
    return Voucher.from_bytes(bytes.fromhex(h))


def plan_claim(vault: Vault, v: Voucher, params: ChainParams, height: int | None) -> ClaimPlan:
    """Applies all voucher rules. `height=None` skips only the deadline (used by the tx builder)."""
    if v.chain_id_hash != chain_id_hash(params.chain_id):
        raise ValidationError("voucher from another network")
    if vault.state != "OPEN":
        raise ValidationError("vault already closed")
    if height is not None and height > claim_deadline(vault, params):
        raise ValidationError("claim deadline passed")
    if v.slot >= len(vault.slots):
        raise ValidationError("nonexistent slot")
    slot = vault.slots[v.slot]
    if slot.key:
        raise ValidationError("a slot with its own key can only be settled by note (note_claim)")
    if not params.min_voucher_value <= v.amount <= slot.cap:
        raise ValidationError("voucher value outside the slot's limits")
    if not verify_device_signature(vault.key_type, bytes.fromhex(vault.device_key),
                                   v.signature, v.signing_message()):
        raise ValidationError("invalid voucher signature")
    vh = v.hash
    if slot.claimed_by is None:
        return ClaimPlan(v.slot, v.amount, False, vh)
    if slot.claimed_by == vh:
        raise ValidationError("voucher already settled")
    # Conflict: compensation by the collateral, under the deterministic limits of exposure.py.
    payout = plan_compensation(
        collateral_left=slot.collateral_left, compensated_total=slot.compensated,
        contested_value=slot.cap, paid_leaves=slot.comp_leaves,
        max_events=params.max_compensations_per_slot, leaf_id=vh, leaf_value=v.amount,
        min_payout=max(params.min_voucher_value, params.min_fee + 1))
    return ClaimPlan(v.slot, payout, True, vh)


def apply_claim(vault: Vault, plan: ClaimPlan) -> Vault:
    new = copy.deepcopy(vault)
    slot = new.slots[plan.slot]
    if plan.from_collateral:
        slot.collateral_left -= plan.payout
        slot.compensated += plan.payout
        slot.comp_leaves.append(plan.voucher_hash)
        new.fraud = True
    else:
        slot.paid = plan.payout
        slot.claimed_by = plan.voucher_hash
    return new


# ---------------------------------------------------------------- note_claim (A3)
@dataclass(frozen=True)
class NoteClaimSpec:
    vault_id: str
    slot: int
    leaf: int
    hops: tuple


@dataclass(frozen=True)
class NoteClaimPlan:
    vault_id: str
    slot: int
    leaf_id: str            # hex
    leaf_value: int
    payout: int             # comes out of the deposit (no conflict) or out of the collateral (conflict)
    address: str
    from_collateral: bool
    new_spends: tuple       # ((note_hex, txid_hex), ...) to record (empty on conflict)


def parse_note_claim(payload) -> NoteClaimSpec:
    """Strict parsing: extra fields, wrong types, malformed hex => ValidationError."""
    if not isinstance(payload, dict) or set(payload) != {"vault_id", "slot", "leaf", "hops"}:
        raise ValidationError("invalid note_claim payload")
    vid = payload["vault_id"]
    if not (isinstance(vid, str) and len(vid) == 64 and _HEX.match(vid)):
        raise ValidationError("invalid vault_id")
    for k, hi in (("slot", 65536), ("leaf", N.MAX_OUTPUTS)):
        if not _is_int(payload[k]) or not 0 <= payload[k] < hi:
            raise ValidationError(f"invalid {k}")
    raw = payload["hops"]
    if not isinstance(raw, list) or not 1 <= len(raw) <= N.MAX_HOPS:
        raise ValidationError("invalid chain of hops")
    hops = []
    for h in raw:
        if not isinstance(h, dict) or set(h) != {"tx", "key_type", "pubkey", "sig"}:
            raise ValidationError("malformed hop")
        try:
            hops.append(N.Hop.from_dict({**h, "att": None}))   # attestation is not consensus: always None
        except ValidationError:
            raise
        except (ValueError, TypeError, struct_error):
            raise ValidationError("malformed hop") from None
    return NoteClaimSpec(vid, payload["slot"], payload["leaf"], tuple(hops))


def plan_note_claim(vault: Vault, spec: NoteClaimSpec, params: ChainParams, height: int | None) -> NoteClaimPlan:
    """All the rules of `note_claim`. `height=None` skips only the deadline (used by the tx builder)."""
    if vault.state != "OPEN":
        raise ValidationError("vault already closed")
    if height is not None and height > claim_deadline(vault, params):
        raise ValidationError("claim deadline passed")
    if spec.slot >= len(vault.slots):
        raise ValidationError("nonexistent slot")
    slot = vault.slots[spec.slot]
    if not slot.key:
        raise ValidationError("slot without its own key: use voucher_claim")
    chk = N.verify_hop_chain(spec.hops, chain_hash=chain_id_hash(params.chain_id), vault_id=vault.vault_id,
                             slot=spec.slot, cap=slot.cap, root_key_type=vault.key_type,
                             root_key_hex=slot.key, leaf=spec.leaf)
    if chk.leaf.kind != N.KIND_ADDRESS:
        raise ValidationError("only an address-type leaf can be settled")
    floor = max(params.min_voucher_value, params.min_fee + 1)
    if chk.leaf.value < floor:
        raise ValidationError("leaf value below the minimum settleable amount")
    lid = chk.leaf_id.hex()
    if lid in slot.settled or lid in slot.comp_leaves:
        raise ValidationError("leaf already settled")                                          # R3
    address = address_from_hash(chk.leaf.owner[:20])
    conflict = any(slot.spends.get(note, txid) != txid for note, txid in chk.links)
    if not conflict:
        if len(slot.settled) >= MAX_SETTLED_PER_SLOT:
            raise ValidationError("slot limit of settled leaves reached")
        if slot.paid + chk.leaf.value > slot.cap:       # unreachable given conservation; consensus defense
            raise ValidationError("settlement exceeds the slot's value")
        new = tuple((n, t) for n, t in chk.links if n not in slot.spends)
        return NoteClaimPlan(vault.vault_id, spec.slot, lid, chk.leaf.value, chk.leaf.value, address, False, new)
    # Conflict: some hop spends a note already spent differently on the chain. The losing branch is compensated
    # by the collateral under R1-R9 and is NOT recorded (its descendants keep conflicting).
    payout = plan_compensation(
        collateral_left=slot.collateral_left, compensated_total=slot.compensated, contested_value=slot.cap,
        paid_leaves=slot.comp_leaves, max_events=params.max_compensations_per_slot, leaf_id=lid,
        leaf_value=chk.leaf.value, min_payout=floor)
    return NoteClaimPlan(vault.vault_id, spec.slot, lid, chk.leaf.value, payout, address, True, ())


def apply_note_claim(vault: Vault, plan: NoteClaimPlan) -> Vault:
    new = copy.deepcopy(vault)
    slot = new.slots[plan.slot]
    if plan.from_collateral:
        slot.collateral_left -= plan.payout
        slot.compensated += plan.payout
        slot.comp_leaves.append(plan.leaf_id)
        new.fraud = True
    else:
        slot.paid += plan.payout
        slot.settled.append(plan.leaf_id)
        for note, txid in plan.new_spends:
            slot.spends[note] = txid
        slot.claimed_by = slot.note_state_digest()
    return new


# ---------------------------------------------------------------- refund
@dataclass(frozen=True)
class RefundPlan:
    total: int     # returned to the owner before the fee
    fee: int
    payout: int
    burn: int      # collateral burned (fraud)


def plan_refund(vault: Vault, params: ChainParams, height: int | None) -> RefundPlan:
    if vault.state != "OPEN":
        raise ValidationError("vault already closed")
    if height is not None and height <= claim_deadline(vault, params):
        raise ValidationError("claims window still open")
    cap_left = sum(s.cap - s.paid for s in vault.slots)
    col = sum(s.collateral_left for s in vault.slots)
    burn = col if vault.fraud else 0
    total = cap_left + (0 if vault.fraud else col)
    fee = min(total, params.min_fee)
    return RefundPlan(total, fee, total - fee, burn)


def parse_refund_payload(payload) -> str:
    if not isinstance(payload, dict) or set(payload) != {"vault_id"}:
        raise ValidationError("invalid vault_refund payload")
    vid = payload["vault_id"]
    if not (isinstance(vid, str) and len(vid) == 64 and _HEX.match(vid)):
        raise ValidationError("invalid vault_id")
    return vid
