"""Recipient's OFFLINE verifier (A2): decides whether to accept a note payment, without consulting the network.

What the verification PROVES: the vault exists with these parameters in a signed checkpoint; each hop was signed by the
key owning the spent note; value is conserved; the chain is contiguous; the recipient owns the leaf; and the security
level (hardware/software) of each hop, on which the accepted depth and cap depend.
What it does NOT prove: that the note was not spent in another way elsewhere (impossible offline). That risk is bounded by the
level, the caps and the collateral (R1-R9) and resolved at settlement (A3). The result is always PENDING, never confirmed.
"""
from dataclasses import dataclass

from ..crypto.keys import verify_device_signature
from ..errors import ValidationError
from . import note as N
from .attestation import verify_attestation
from .proofs import CheckpointStore, blocks_until_claim_deadline, verify_vault_proof
from .voucher import chain_id_hash

STATUS_PENDING = "RECEIVED_OFFLINE"


@dataclass(frozen=True)
class ReceiverPolicy:
    """Receiver limits (testnet, to be calibrated). Approved: depth 1 without hardware, 3 with attested hardware."""
    max_hops_software: int = 1
    max_hops_hardware: int = 3
    max_value_software: int = 5        # in whole coins (× 10**decimals)
    max_value_hardware: int = 100
    margin_hours: int = 48
    min_margin_blocks: int | None = None   # if given, replaces margin_hours
    reject_fraud_vault: bool = True

    def margin_blocks(self, params) -> int:
        if self.min_margin_blocks is not None:
            return self.min_margin_blocks
        return -(-self.margin_hours * 3600 // params.target_block_time)


class SeenNotes:
    """Receiver's local memory: which offline transaction it has already seen spend each note (detects local double spend)."""

    def __init__(self):
        self._spent: dict[bytes, bytes] = {}

    def check(self, hops) -> None:
        for h in hops:
            prev = self._spent.get(h.tx.input_note)
            if prev is not None and prev != h.tx.txid:
                raise ValidationError("this note has already been seen spent in another way (possible double spend)")

    def record(self, hops) -> None:
        for h in hops:
            self._spent.setdefault(h.tx.input_note, h.tx.txid)


@dataclass(frozen=True)
class VerifiedPayment:
    status: str
    vault_id: str
    slot: int
    depth: int
    level: str                 # "hardware" | "software" (the worst hop)
    hop_levels: tuple
    value: int                 # leaf value, in units
    leaf_kind: int
    request_id: str
    txids: tuple
    deadline_blocks: int
    checkpoint_height: int
    checkpoint_hash: str
    hops: tuple


class OfflineVerifier:
    def __init__(self, params, consensus, *, roots, revoked=frozenset(), policy: ReceiverPolicy | None = None,
                 seen: SeenNotes | None = None, checkpoints: CheckpointStore | None = None):
        self.params, self.consensus = params, consensus
        self.roots, self.revoked = list(roots), frozenset(revoked)
        self.policy = policy or ReceiverPolicy()
        self.seen = seen or SeenNotes()
        self.checkpoints = checkpoints or CheckpointStore()

    # ------------------------------------------------------------------ security level of a hop
    def _hop_level(self, hop: N.Hop, expected_challenge: bytes | None, now: int) -> str:
        """"hardware" only with a valid attestation of THIS key, single use and TEE/StrongBox; any problem downgrades to software
        (the software depth and cap are the most restrictive, so downgrading never helps the attacker)."""
        if hop.attestation is None:
            return "software"
        try:
            res = verify_attestation(hop.attestation, roots=self.roots, now=now, revoked=self.revoked,
                                     expect_pubkey=hop.pubkey.hex(), expect_key_type=hop.key_type,
                                     expect_challenge=None if expected_challenge is None else expected_challenge.hex())
        except ValidationError:
            return "software"
        return "hardware" if res.is_hardware else "software"

    # ------------------------------------------------------------------ verification
    def verify(self, payment, *, now: int, my_key: tuple | None = None, my_address: str | None = None,
               request_id: bytes | None = None) -> VerifiedPayment:
        """`my_key`=(key_type, pubkey_bytes) if the leaf is a NOTE for me; `my_address` if it is a final output.
        One of the two is required: without it there is no proof that the payment is INTENDED for this receiver."""
        if (my_key is None) == (my_address is None):
            raise ValidationError("provide exactly one: note key or the recipient's address")
        pay = payment if isinstance(payment, N.OfflinePayment) else N.OfflinePayment.from_dict(payment)
        p, pol = self.params, self.policy

        # 1. vault and slot (proof + policy)
        vs = verify_vault_proof(pay.proof, p, self.consensus, min_checkpoint_height=self.checkpoints.min_height())
        if vs.state != "OPEN":
            raise ValidationError("vault closed")
        if vs.fraud and pol.reject_fraud_vault:
            raise ValidationError("vault marked as fraudulent")
        if vs.slot != pay.slot:
            raise ValidationError("the proof is for another slot")
        if vs.claimed or vs.paid or vs.compensated:
            raise ValidationError("the slot was already occupied at the checkpoint")
        if not vs.slot_key:
            raise ValidationError("slot without its own key: notes require a vault with slot_keys (use voucher)")
        deadline = blocks_until_claim_deadline(vs, now, p)
        if deadline < pol.margin_blocks(p):
            raise ValidationError("little time left to settle (insufficient margin)")

        # 2. chain of hops
        chash = chain_id_hash(p.chain_id)
        expected_note, expected_value = N.root_note_id(vs.vault_id, vs.slot), vs.cap
        owner_commit = None          # commitment of the next hop's owner (None on the 1st: the slot's key applies)
        levels, prev_hop = [], None
        for i, hop in enumerate(pay.hops):
            tx = hop.tx
            if tx.chain_hash != chash or tx.vault_id != vs.vault_id:
                raise ValidationError("hop from another network or another vault")
            if tx.input_note != expected_note or tx.input_value != expected_value:
                raise ValidationError("hop does not spend the expected note (broken chain or different value)")
            if sum(o.value for o in tx.outputs) != tx.input_value:
                raise ValidationError("value is not conserved in the hop")
            if i == 0:
                owner_ok = hop.key_type == vs.key_type and hop.pubkey.hex() == vs.slot_key
            else:
                owner_ok = N.owner_commitment(hop.key_type, hop.pubkey) == owner_commit
            if not owner_ok:
                raise ValidationError("the key that signed is not the owner of the spent note")
            if not verify_device_signature(hop.key_type, hop.pubkey, hop.signature, tx.signing_message()):
                raise ValidationError("invalid hop signature")
            levels.append(self._hop_level(hop, None if prev_hop is None else prev_hop.tx.request_id, now))
            if i + 1 < len(pay.hops):
                nxt = pay.hops[i + 1].tx
                j = next((j for j in range(len(tx.outputs)) if N.child_note_id(tx.txid, j) == nxt.input_note), None)
                if j is None or tx.outputs[j].kind != N.KIND_NOTE or tx.outputs[j].value != nxt.input_value:
                    raise ValidationError("the next hop does not spend a note output of the previous hop")
                expected_note, expected_value, owner_commit = nxt.input_note, nxt.input_value, tx.outputs[j].owner
            prev_hop = hop

        # 3. the leaf is MINE
        last = pay.hops[-1].tx
        if not 0 <= pay.leaf < len(last.outputs):
            raise ValidationError("leaf index outside the last hop")
        leaf = last.outputs[pay.leaf]
        if my_key is not None:
            if leaf.kind != N.KIND_NOTE or leaf.owner != N.owner_commitment(*my_key):
                raise ValidationError("the leaf is not a note of my key")
        elif leaf.kind != N.KIND_ADDRESS or leaf.owner != N.address_owner(my_address):
            raise ValidationError("the leaf is not an output to my address")
        if request_id is not None and last.request_id != request_id:
            raise ValidationError("request_id does not match my request")

        # 4. effective level, depth and cap
        level = "hardware" if all(l == "hardware" for l in levels) else "software"
        depth = len(pay.hops)
        max_hops = pol.max_hops_hardware if level == "hardware" else pol.max_hops_software
        if depth > max_hops:
            raise ValidationError(f"depth {depth} above the maximum of {max_hops} for {level} level")
        scale = 10 ** p.decimals
        max_value = (pol.max_value_hardware if level == "hardware" else pol.max_value_software) * scale
        if leaf.value > max_value:
            raise ValidationError(f"value above the {level} level cap")

        # 5. local memory (double spend seen by this receiver)
        self.seen.check(pay.hops)
        return VerifiedPayment(STATUS_PENDING, vs.vault_id, vs.slot, depth, level, tuple(levels), leaf.value,
                               leaf.kind, last.request_id.hex(), tuple(h.tx.txid.hex() for h in pay.hops), deadline,
                               vs.checkpoint_height, vs.checkpoint_hash, pay.hops)

    def accept(self, verified: VerifiedPayment) -> None:
        """Writes to local memory (write-ahead) BEFORE confirming receipt to the payer."""
        self.seen.record(verified.hops)
        self.checkpoints.observe(verified.checkpoint_height, verified.checkpoint_hash)
