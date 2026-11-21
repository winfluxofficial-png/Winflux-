"""A4 — Reconciliation: the vault owner compares what they ISSUED offline with what the chain shows.

There is no new consensus transaction: closing a slot before the end of the claims window would harm whoever already received offline
notes (the owner could "undo" payments). The only way out is `vault_refund` after
`expires_height + claim_window_blocks`. This layer says, with the SAME arithmetic as consensus (`plan_refund`), what each slot
is, what will be refunded, who may have lost money and what looks wrong (a spend the owner does not recognize, double
spend, collateral consumed). Pure layer: no network I/O; the journal is a simple JSON file.
"""
import json
import os
import re
from dataclasses import dataclass, field

from ..blockchain import vaults as V
from ..errors import ValidationError
from ..offline.note import root_note_id
from ..units import format_units

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# primary states of a slot
UNUSED, OUTSTANDING, PARTIAL, SETTLED, LAPSED = "UNUSED", "OUTSTANDING", "PARTIAL", "SETTLED", "LAPSED"
# flags (can coexist with any state)
DIVERGENT, CONFLICT, DOUBLE_ISSUED = "DIVERGENT", "CONFLICT", "DOUBLE_ISSUED"


# ---------------------------------------------------------------- owner's issuance journal
class Journal:
    """Record, on the owner's device, of the root notes they signed (one per slot, if they behave)."""

    def __init__(self, entries=()):
        self._e: dict[tuple, None] = {}
        for vid, slot, txid in entries:
            self.add(vid, slot, txid)

    def add(self, vault_id: str, slot: int, root_txid: str) -> bool:
        if not (isinstance(vault_id, str) and _HEX64.match(vault_id) and isinstance(root_txid, str)
                and _HEX64.match(root_txid)):
            raise ValidationError("invalid journal entry")
        if not (isinstance(slot, int) and not isinstance(slot, bool) and 0 <= slot < 65536):
            raise ValidationError("invalid slot")
        new = (vault_id, slot, root_txid) not in self._e
        self._e[(vault_id, slot, root_txid)] = None
        return new

    def record_hop(self, hop, slot: int) -> bool:
        """Records the 1st hop (root) the owner has just signed. Refuses hops that do not spend the slot's root."""
        tx = hop.tx
        if tx.input_note != root_note_id(tx.vault_id, slot):
            raise ValidationError("this hop does not spend the root note of the given slot")
        return self.add(tx.vault_id, slot, tx.txid.hex())

    def roots(self, vault_id: str, slot: int) -> set:
        return {t for v, s, t in self._e if v == vault_id and s == slot}

    def __len__(self):
        return len(self._e)

    def to_dict(self) -> dict:
        return {"v": 1, "entries": [{"vault_id": v, "slot": s, "root_txid": t} for v, s, t in sorted(self._e)]}

    @classmethod
    def from_dict(cls, d) -> "Journal":
        if not isinstance(d, dict) or set(d) != {"v", "entries"} or d["v"] != 1 or not isinstance(d["entries"], list):
            raise ValidationError("invalid journal")
        j = cls()
        for e in d["entries"]:
            if not isinstance(e, dict) or set(e) != {"vault_id", "slot", "root_txid"}:
                raise ValidationError("invalid journal")
            j.add(e["vault_id"], e["slot"], e["root_txid"])
        return j

    def save(self, path: str) -> None:
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.to_dict(), f, indent=1)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> "Journal":
        if not os.path.exists(path):
            return cls()
        try:
            with open(path) as f:
                return cls.from_dict(json.load(f))
        except json.JSONDecodeError:
            raise ValidationError("corrupted journal") from None


# ---------------------------------------------------------------- report
@dataclass
class SlotReport:
    slot: int
    status: str
    flags: list
    cap: int
    paid: int
    compensated: int
    collateral_left: int
    issued: bool                 # the journal has this slot's root note
    unsettled_issued: int        # value issued offline and not yet settled on-chain (at risk for the recipient)


@dataclass
class Report:
    vault_id: str
    height: int
    state: str
    fraud: bool
    claim_deadline: int
    claims_open: bool
    can_refund_now: bool
    blocks_until_refund: int
    slots: list
    refund_total: int            # what `plan_refund` would return today (0 if already closed)
    refund_fee: int
    refund_net: int
    burned: int
    warnings: list = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not any(s.flags for s in self.slots)


def reconcile(vault: "V.Vault", journal: Journal, params, height: int) -> Report:
    """Compares the owner's journal with the vault state at height `height` (current chain height)."""
    deadline = V.claim_deadline(vault, params)
    claims_open = height + 1 <= deadline            # a block included now would still accept claims
    closed = vault.state != "OPEN"
    reports, warn = [], []
    for i, s in enumerate(vault.slots):
        roots = journal.roots(vault.vault_id, i)
        onchain = s.spends.get(root_note_id(vault.vault_id, i).hex())
        flags = []
        if len(roots) > 1:
            flags.append(DOUBLE_ISSUED)
        if s.compensated or s.comp_leaves:
            flags.append(CONFLICT)
        if onchain is not None and onchain not in roots:
            flags.append(DIVERGENT)
        if onchain is None and not s.paid:
            status = (OUTSTANDING if claims_open else LAPSED) if roots else UNUSED
        elif s.paid >= s.cap:
            status = SETTLED
        else:
            status = PARTIAL if claims_open else LAPSED
        unsettled = (s.cap - s.paid) if roots and not s.compensated else 0
        reports.append(SlotReport(i, status, flags, s.cap, s.paid, s.compensated, s.collateral_left, bool(roots), unsettled))

    if closed:
        total = fee = net = burn = 0
    else:
        plan = V.plan_refund(vault, params, None)    # the SAME arithmetic as consensus
        total, fee, net, burn = plan.total, plan.fee, plan.payout, plan.burn
    can_refund = (not closed) and not claims_open
    sym = "WFLX"
    if closed:
        warn.append("Vault already closed: the refund has been made.")
    open_with_issue = [r.slot for r in reports if r.issued and r.status in (OUTSTANDING, PARTIAL)]
    if open_with_issue:
        warn.append(f"Slots {open_with_issue} have issued payments that recipients can still settle until block "
                    f"{deadline}. The refund is only possible after that.")
    lost = [(r.slot, r.unsettled_issued) for r in reports if r.status == LAPSED and r.unsettled_issued > 0]
    if lost and not closed:
        warn.append("Payments issued in slots " + ", ".join(f"{a} ({format_units(b)} {sym})" for a, b in lost)
                    + " were not settled in time: whoever received them lost the right; the value comes back to you on the refund.")
    bad = [r.slot for r in reports if DIVERGENT in r.flags]
    if bad:
        warn.append(f"Slots {bad}: the chain shows a spend that your journal does NOT record. The slot key may have been "
                    "exposed/cloned, or the journal is incomplete. Treat it as a possible compromise.")
    dbl = [r.slot for r in reports if DOUBLE_ISSUED in r.flags]
    if dbl:
        warn.append(f"Slots {dbl}: your journal has more than one root note (you issued the same slot twice).")
    conf = [r.slot for r in reports if CONFLICT in r.flags]
    if conf:
        used = sum(r.compensated for r in reports)
        warn.append(f"Double spend detected in slots {conf}: {format_units(used)} {sym} of the collateral already compensated "
                    "recipients; the vault is marked as fraudulent"
                    + (f" and the remaining collateral ({format_units(burn)} {sym}) will be BURNED on refund." if burn and not closed else "."))
    return Report(vault.vault_id, height, vault.state, vault.fraud, deadline, claims_open, can_refund,
                  max(0, deadline - height), reports, total, fee, net, burn, warn)


def render(r: Report, symbol: str = "WFLX") -> str:
    f = lambda v: f"{format_units(v)} {symbol}"
    L = [f"Vault {r.vault_id[:16]}…  state={r.state}{'  FRAUD' if r.fraud else ''}  height={r.height}",
         f"Claim deadline: block {r.claim_deadline} "
         + ("(still open; refund in ~%d blocks)" % r.blocks_until_refund if r.claims_open else "(closed)")]
    for s in r.slots:
        L.append(f"  slot {s.slot}: {s.status:<11} paid {f(s.paid)} of {f(s.cap)}"
                 + (f" | compensated {f(s.compensated)}" if s.compensated else "")
                 + (f" | flags: {','.join(s.flags)}" if s.flags else ""))
    if r.state == "OPEN":
        L.append(f"Refund {'available now' if r.can_refund_now else 'not yet available'}: "
                 f"{f(r.refund_net)} net (fee {f(r.refund_fee)}" + (f", burned {f(r.burned)}" if r.burned else "") + ")")
    L += ["WARNING: " + w for w in r.warnings]
    return "\n".join(L)
