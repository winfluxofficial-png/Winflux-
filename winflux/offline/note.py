"""Transferable note and offline transaction (A2) — binary format and provenance chain.

Model (docs/offline-chained-payments.md): the root slot is a note of value `cap`, owner = the slot's key. An OFFLINE
TRANSACTION spends a note and creates up to 4 outputs: NOTE (owner = commitment to someone's new key, re-transferable) or ADDRESS
(final, not re-transferable). EXACT conservation: Σ outputs = value of the spent note. Each payment carries the chain
`[t1 (spends the root), t2 (spends an output of t1), ...]` + the vault proof.

    tx body = version(1) ‖ chain_hash(32) ‖ vault_id(32) ‖ spent_note(32) ‖ value(u64) ‖ n(u8)
                  ‖ n × [ value(u64) ‖ type(u8) ‖ owner(32) ] ‖ request_id(16)
    txid = H("WFLX-OTX-ID-V1" ‖ body);  signature = key owning the spent note, over "WFLX-OTX-SIG-V1" ‖ body
The signature and the public key do NOT enter the txid; the public key is revealed only when spending (the note's owner is a
hash commitment) — which limits the key's exposure (relevant against quantum attack).
"""
import re
import struct
from dataclasses import dataclass

from ..crypto.address import address_to_hash, is_valid_address
from ..crypto.hashing import sha256
from ..crypto.keys import verify_device_signature
from ..errors import ValidationError

VERSION = 1
KIND_NOTE, KIND_ADDRESS = 1, 2
MAX_OUTPUTS = 4
MAX_HOPS = 8
KEY_CODES = {"ed25519": 1, "p256": 2}
KEY_LENGTHS = {"ed25519": 32, "p256": 33}
_HEAD = ">B32s32s32sQB"
_HEAD_LEN = struct.calcsize(_HEAD)
_OUT = ">QB32s"
_OUT_LEN = struct.calcsize(_OUT)
_HEX = re.compile(r"^[0-9a-f]*$")
MAX_VALUE = 2**63 - 1


def root_note_id(vault_id: str, slot: int) -> bytes:
    return sha256(b"WFLX-NOTE-ROOT-V1" + bytes.fromhex(vault_id) + struct.pack(">H", slot))


def child_note_id(txid: bytes, index: int) -> bytes:
    return sha256(b"WFLX-NOTE-V1" + txid + bytes([index]))


def owner_commitment(key_type: str, pubkey: bytes) -> bytes:
    """Owner of a NOTE: hash of (type, key). The key is only revealed when spending."""
    if key_type not in KEY_CODES or len(pubkey) != KEY_LENGTHS[key_type]:
        raise ValidationError("invalid key for an owner commitment")
    return sha256(b"WFLX-NOTE-OWNER-V1" + bytes([KEY_CODES[key_type]]) + pubkey)


def address_owner(address: str) -> bytes:
    if not is_valid_address(address):
        raise ValidationError("invalid address")
    return address_to_hash(address) + bytes(12)


@dataclass(frozen=True)
class NoteOutput:
    value: int
    kind: int
    owner: bytes


@dataclass(frozen=True)
class OfflineTx:
    chain_hash: bytes
    vault_id: str
    input_note: bytes
    input_value: int
    outputs: tuple
    request_id: bytes
    version: int = VERSION

    def body(self) -> bytes:
        try:
            head = struct.pack(_HEAD, self.version, self.chain_hash, bytes.fromhex(self.vault_id), self.input_note,
                               self.input_value, len(self.outputs))
            outs = b"".join(struct.pack(_OUT, o.value, o.kind, o.owner) for o in self.outputs)
            return head + outs + struct.pack(">16s", self.request_id)
        except (struct.error, ValueError, TypeError) as e:
            raise ValidationError(f"offline transaction with invalid fields: {e}") from None

    @property
    def txid(self) -> bytes:
        return sha256(b"WFLX-OTX-ID-V1" + self.body())

    def signing_message(self) -> bytes:
        return b"WFLX-OTX-SIG-V1" + self.body()

    def to_bytes(self) -> bytes:
        return self.body()

    @classmethod
    def from_bytes(cls, raw) -> "OfflineTx":
        if not isinstance(raw, (bytes, bytearray)) or len(raw) < _HEAD_LEN + _OUT_LEN + 16:
            raise ValidationError("offline transaction too short")
        raw = bytes(raw)
        ver, ch, vid, note, value, n = struct.unpack(_HEAD, raw[:_HEAD_LEN])
        if ver != VERSION:
            raise ValidationError("unsupported offline transaction version")
        if not 1 <= n <= MAX_OUTPUTS or len(raw) != _HEAD_LEN + n * _OUT_LEN + 16:
            raise ValidationError("offline transaction with invalid size/outputs")
        outs = []
        for i in range(n):
            v, kind, owner = struct.unpack(_OUT, raw[_HEAD_LEN + i * _OUT_LEN: _HEAD_LEN + (i + 1) * _OUT_LEN])
            if v <= 0 or v > MAX_VALUE or kind not in (KIND_NOTE, KIND_ADDRESS):
                raise ValidationError("invalid offline output")
            if kind == KIND_ADDRESS and owner[20:] != bytes(12):
                raise ValidationError("malformed address-type owner")
            outs.append(NoteOutput(v, kind, owner))
        tx = cls(ch, vid.hex(), note, value, tuple(outs), raw[-16:], ver)
        if tx.input_value <= 0 or tx.input_value > MAX_VALUE:
            raise ValidationError("invalid input value")
        return tx


@dataclass(frozen=True)
class Hop:
    """A hop: offline transaction + the key that signed it (revealed here) + signature + attestation (optional)."""
    tx: OfflineTx
    key_type: str
    pubkey: bytes
    signature: bytes
    attestation: dict | None = None

    def to_dict(self) -> dict:
        return {"tx": self.tx.to_bytes().hex(), "key_type": self.key_type, "pubkey": self.pubkey.hex(),
                "sig": self.signature.hex(), "att": self.attestation}

    @classmethod
    def from_dict(cls, d) -> "Hop":
        if not isinstance(d, dict) or set(d) != {"tx", "key_type", "pubkey", "sig", "att"}:
            raise ValidationError("malformed hop")
        if not (isinstance(d["key_type"], str) and d["key_type"] in KEY_CODES):
            raise ValidationError("invalid key type in the hop")
        for k, n in (("tx", None), ("pubkey", 2 * KEY_LENGTHS[d["key_type"]]), ("sig", 128)):
            if not (isinstance(d[k], str) and _HEX.match(d[k]) and (n is None or len(d[k]) == n)):
                raise ValidationError("invalid hexadecimal field in the hop")
        if len(d["tx"]) > 2 * (_HEAD_LEN + MAX_OUTPUTS * _OUT_LEN + 16):
            raise ValidationError("offline transaction too large")
        if d["att"] is not None and not isinstance(d["att"], dict):
            raise ValidationError("malformed attestation")
        return cls(OfflineTx.from_bytes(bytes.fromhex(d["tx"])), d["key_type"], bytes.fromhex(d["pubkey"]),
                   bytes.fromhex(d["sig"]), d["att"])


@dataclass(frozen=True)
class OfflinePayment:
    """What Bob hands to Carlos: vault proof + chain of hops + which output is his."""
    proof: dict
    slot: int
    hops: tuple
    leaf: int

    def to_dict(self) -> dict:
        return {"v": 1, "proof": self.proof, "slot": self.slot, "hops": [h.to_dict() for h in self.hops],
                "leaf": self.leaf}

    @classmethod
    def from_dict(cls, d) -> "OfflinePayment":
        if not isinstance(d, dict) or set(d) != {"v", "proof", "slot", "hops", "leaf"} or d["v"] != 1:
            raise ValidationError("malformed offline payment")
        for k in ("slot", "leaf"):
            if not isinstance(d[k], int) or isinstance(d[k], bool) or not 0 <= d[k] < 65536:
                raise ValidationError("invalid index in the payment")
        if not isinstance(d["hops"], list) or not 1 <= len(d["hops"]) <= MAX_HOPS or not isinstance(d["proof"], dict):
            raise ValidationError("invalid chain of hops")
        return cls(d["proof"], d["slot"], tuple(Hop.from_dict(h) for h in d["hops"]), d["leaf"])


# ---------------------------------------------------------------- construction (payer's side)
class SoftwareSigner:
    """Software key (no attestation): software level."""

    def __init__(self, keypair):
        self._kp = keypair
        self.key_type = keypair.key_type
        self.public_key = keypair.public_key
        self.attestation = None

    @property
    def public_hex(self) -> str:
        return self.public_key.hex()

    def sign(self, message: bytes) -> bytes:
        return self._kp.sign(message)


def make_hop(*, chain_hash: bytes, vault_id: str, input_note: bytes, input_value: int, outputs, request_id: bytes,
             signer) -> Hop:
    """Builds and signs a hop. `signer`: hardware KeyHandle or SoftwareSigner (key_type, public_key, attestation, sign)."""
    tx = OfflineTx(chain_hash, vault_id, input_note, input_value, tuple(outputs), request_id)
    return Hop(tx, signer.key_type, signer.public_key, signer.sign(tx.signing_message()), signer.attestation)


def spend_root(*, chain_hash: bytes, vault_id: str, slot: int, cap: int, outputs, request_id: bytes, signer) -> Hop:
    return make_hop(chain_hash=chain_hash, vault_id=vault_id, input_note=root_note_id(vault_id, slot),
                    input_value=cap, outputs=outputs, request_id=request_id, signer=signer)


def spend_output(prev: Hop, index: int, *, outputs, request_id: bytes, signer) -> Hop:
    out = prev.tx.outputs[index]
    return make_hop(chain_hash=prev.tx.chain_hash, vault_id=prev.tx.vault_id,
                    input_note=child_note_id(prev.tx.txid, index), input_value=out.value, outputs=outputs,
                    request_id=request_id, signer=signer)


# ---------------------------------------------------------------- chain verification (consensus: note_claim)
@dataclass(frozen=True)
class ChainCheck:
    """Result of verifying a chain of hops up to a leaf."""
    leaf: NoteOutput
    leaf_id: bytes              # leaf identifier: child_note_id(txid of the last hop, index)
    links: tuple                # ((spent_note_hex, txid_hex), ...) in hop order


def verify_hop_chain(hops, *, chain_hash: bytes, vault_id: str, slot: int, cap: int, root_key_type: str,
                     root_key_hex: str, leaf: int) -> ChainCheck:
    """Verifies, in a PURE and deterministic way, the root -> leaf chain. Used by consensus in `note_claim`.

    Requires: 1..MAX_HOPS hops; hops from the right network/vault; the first hop spends the slot's root note (value `cap`);
    each following hop spends a NOTE output of the previous one; exact conservation; owner = the slot's key (1st) or the hash
    commitment of the previous note output; valid signature; leaf = output of the last hop. It does not decide the leaf's TYPE.
    """
    if not isinstance(hops, (tuple, list)) or not 1 <= len(hops) <= MAX_HOPS:
        raise ValidationError("number of hops out of range")
    expected_note, expected_value, owner_commit = root_note_id(vault_id, slot), cap, None
    links = []
    for i, hop in enumerate(hops):
        tx = hop.tx
        if tx.chain_hash != chain_hash or tx.vault_id != vault_id:
            raise ValidationError("hop from another network or another vault")
        if tx.input_note != expected_note or tx.input_value != expected_value:
            raise ValidationError("hop does not spend the expected note (broken chain or different value)")
        if sum(o.value for o in tx.outputs) != tx.input_value:
            raise ValidationError("value is not conserved in the hop")
        if i == 0:
            owner_ok = hop.key_type == root_key_type and hop.pubkey.hex() == root_key_hex
        else:
            owner_ok = owner_commitment(hop.key_type, hop.pubkey) == owner_commit
        if not owner_ok:
            raise ValidationError("the key that signed is not the owner of the spent note")
        if not verify_device_signature(hop.key_type, hop.pubkey, hop.signature, tx.signing_message()):
            raise ValidationError("invalid hop signature")
        links.append((tx.input_note.hex(), tx.txid.hex()))
        if i + 1 < len(hops):
            nxt = hops[i + 1].tx
            j = next((j for j in range(len(tx.outputs)) if child_note_id(tx.txid, j) == nxt.input_note), None)
            if j is None or tx.outputs[j].kind != KIND_NOTE or tx.outputs[j].value != nxt.input_value:
                raise ValidationError("the next hop does not spend a note output of the previous hop")
            expected_note, expected_value, owner_commit = nxt.input_note, nxt.input_value, tx.outputs[j].owner
    last = hops[-1].tx
    if not isinstance(leaf, int) or isinstance(leaf, bool) or not 0 <= leaf < len(last.outputs):
        raise ValidationError("leaf index outside the last hop")
    return ChainCheck(last.outputs[leaf], child_note_id(last.txid, leaf), tuple(links))
