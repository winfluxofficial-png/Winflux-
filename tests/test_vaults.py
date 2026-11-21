"""Phase 1 (3b-1): offline vaults — opening, claim, duplicates, refund, supply, undo."""
import json
from dataclasses import replace

import pytest

from winflux.blockchain.block import Block
from winflux.blockchain.chain import Chain
from winflux.blockchain.transaction import Transaction, TxInput, TxOutput
from winflux.blockchain import vaults as V
from winflux.crypto.keys import KeyPair, P256KeyPair, _P256_N
from winflux.errors import ValidationError
from winflux.node.storage import BlockStorage
from winflux.offline.voucher import TOTAL_LEN, Voucher
from winflux.wallet.vault_builder import build_vault_open, build_vault_refund, build_voucher_claim

from .conftest import WFLX, make_chain, mine

FEE = 1000
VP = dict(vault_ttl_min_blocks=2, vault_ttl_max_blocks=20, claim_window_blocks=4)
CAPS = (10 * WFLX, 10 * WFLX)


def vchain(keys, **over):
    return make_chain(keys, **{**VP, **over})


def devs():
    return {"ed25519": KeyPair(bytes([9]) * 32), "p256": P256KeyPair(private_value=123456789)}


@pytest.fixture(params=["ed25519", "p256"])
def dev(request):
    return devs()[request.param]


def open_vault(chain, keys, dev, caps=CAPS, pct=100, ttl=5):
    tx = build_vault_open(keys["alice"], chain.utxo.utxos_for(keys["alice"].address), dev, caps, pct,
                          ttl, keys["alice"].address, chain.params)
    mine(chain, keys, [tx])
    return tx.txid


def issue(chain, dev, vid, slot, amount, receiver, req=b"\x01" * 16):
    return Voucher.issue(dev, chain.params.chain_id, vid, slot, amount, receiver.address, req)


def claim(chain, keys, voucher):
    tx = build_voucher_claim(voucher, chain.get_vault(voucher.vault_id), chain.params)
    mine(chain, keys, [tx])
    return tx


def advance(chain, keys, n):
    for _ in range(n):
        mine(chain, keys)


def to_deadline(chain, keys, vid):
    """Mines up to the height = final claim deadline (the last block in which it is still valid)."""
    advance(chain, keys, V.claim_deadline(chain.get_vault(vid), chain.params) - chain.height)


def balances(chain, keys):
    return sum(chain.balance(k.address) for k in keys.values())


# ------------------------------------------------------------ opening
def test_open_locks_funds_and_preserves_supply(keys, dev):
    chain = vchain(keys)
    before = chain.total_supply()
    vid = open_vault(chain, keys, dev)
    v = chain.get_vault(vid)
    assert v.state == "OPEN" and len(v.slots) == 2 and not v.fraud
    assert v.expires_height == v.opened_height + 5 and v.opened_height == 1
    assert chain.vaults.total_locked == 40 * WFLX                  # 2 x (10 cap + 10 collateral)
    assert chain.total_supply() == before + 50 * WFLX              # only the block reward
    assert balances(chain, keys) + chain.vaults.total_locked == chain.total_supply()
    assert chain.balance(keys["alice"].address) < 5_000_000 * WFLX - 40 * WFLX   # locked + fee


def forge_open(chain, keys, dev, over=None, pop_signer=None, fee=200_000, sign_inputs=True):
    payload = {"device_key": dev.public_hex, "key_type": dev.key_type, "slots": list(CAPS),
               "collateral_pct": 100, "ttl_blocks": 5, "refund_address": keys["alice"].address}
    payload.update(over or {})
    caps, pct = payload["slots"], payload["collateral_pct"]
    try:
        locked = sum(s.cap + s.collateral_left for s in V.build_slots(caps, pct))
    except TypeError:
        locked = 0
    (op, out), = chain.utxo.utxos_for(keys["alice"].address)[:1]
    outs = (TxOutput(out.value - locked - fee, keys["alice"].address),)
    draft = Transaction(chain.params.chain_id, (TxInput(op[0], op[1], keys["alice"].public_hex),), outs,
                        kind="vault_open", payload=payload)
    pop = (pop_signer or dev).sign(V.pop_message(draft)).hex()
    tx = replace(draft, payload={**payload, "pop": pop})
    if sign_inputs:
        tx = replace(tx, inputs=(replace(tx.inputs[0], signature=keys["alice"].sign(tx.signing_message()).hex()),))
    return tx


def test_forge_helper_accepts_baseline(keys, dev):
    chain = vchain(keys)
    assert chain.check_transaction(forge_open(chain, keys, dev)) > 0


@pytest.mark.parametrize("over,msg", [
    ({"collateral_pct": 50}, "collateral"),
    ({"ttl_blocks": 1}, "TTL"),
    ({"ttl_blocks": 21}, "TTL"),
    ({"slots": []}, "slots"),
    ({"slots": [10 * WFLX] * 65}, "slots"),
    ({"slots": [9_999, 10 * WFLX]}, "minimum voucher"),
    ({"slots": [4000 * WFLX, 4000 * WFLX]}, "maximum allowed"),
    ({"slots": [True, 10 * WFLX]}, "minimum voucher"),
    ({"refund_address": "wflx1invalid"}, "refund"),
    ({"key_type": "rsa"}, "key type"),
    ({"device_key": "ab" * 10}, "device key"),
    ({"extra": 1}, "payload"),
])
def test_open_rejects_bad_parameters(keys, dev, over, msg):
    chain = vchain(keys)
    with pytest.raises(ValidationError, match=msg):
        chain.check_transaction(forge_open(chain, keys, dev, over))


def test_open_rejects_pop_signed_by_other_key(keys, dev):
    chain = vchain(keys)
    other = P256KeyPair(private_value=5) if dev.key_type == "p256" else KeyPair(bytes([8]) * 32)
    with pytest.raises(ValidationError, match="possession"):
        chain.check_transaction(forge_open(chain, keys, dev, pop_signer=other))


def test_open_rejects_underfunded_and_low_fee(keys, dev):
    small = vchain(keys, alloc=((keys["alice"].address, 30 * WFLX),))      # < 40 WFLX of vault
    with pytest.raises(Exception, match="insufficient funds"):
        build_vault_open(keys["alice"], small.utxo.utxos_for(keys["alice"].address), dev, CAPS, 100, 5,
                         keys["alice"].address, small.params)
    chain = vchain(keys)
    with pytest.raises(ValidationError, match="fee"):
        chain.check_transaction(forge_open(chain, keys, dev, fee=FEE - 1))   # below the fixed fee
    big = {"slots": [10 * WFLX] * 64}                                         # large tx: fee per byte
    tx = forge_open(chain, keys, dev, big, fee=FEE)
    assert tx.size() > FEE
    with pytest.raises(ValidationError, match="fee"):
        chain.check_transaction(tx)
    assert chain.check_transaction(forge_open(chain, keys, dev, big, fee=tx.size() + 1000)) >= tx.size()
    with pytest.raises(ValidationError, match="do not cover"):
        chain.check_transaction(forge_open(chain, keys, dev, fee=-1))


def test_open_cannot_be_replayed(keys, dev):
    chain = vchain(keys)
    tx = build_vault_open(keys["alice"], chain.utxo.utxos_for(keys["alice"].address), dev, CAPS, 100, 5,
                          keys["alice"].address, chain.params)
    mine(chain, keys, [tx])
    with pytest.raises(ValidationError, match="nonexistent or already spent"):
        chain.check_transaction(tx)


def test_open_max_slots_boundary(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev, caps=(10 * WFLX,) * 64)
    assert len(chain.get_vault(vid).slots) == 64


# ------------------------------------------------------------ claim
def test_claim_pays_receiver_and_marks_slot(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    v = issue(chain, dev, vid, 0, 6 * WFLX, keys["bob"])
    tx = claim(chain, keys, v)
    assert chain.balance(keys["bob"].address) == 6 * WFLX - chain.params.min_fee
    s = chain.get_vault(vid).slots[0]
    assert s.claimed_by == v.hash and s.paid == 6 * WFLX and not chain.get_vault(vid).fraud
    assert chain.vaults.total_locked == 40 * WFLX - 6 * WFLX
    assert chain.confirmations(tx.txid) == 1
    assert balances(chain, keys) + chain.vaults.total_locked == chain.total_supply()


def test_anyone_can_relay_a_claim_but_cannot_redirect_it(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    v = issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"])
    tx = build_voucher_claim(v, chain.get_vault(vid), chain.params)
    stolen = replace(tx, outputs=(TxOutput(tx.outputs[0].value, keys["mallory"].address),))
    with pytest.raises(ValidationError, match="does not match"):
        chain.check_transaction(stolen)
    mine(chain, keys, [tx])  # the honest relay (anyone) is accepted
    assert chain.balance(keys["bob"].address) > 0 and chain.balance(keys["mallory"].address) == 0


def test_same_voucher_cannot_be_claimed_twice(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    tx = claim(chain, keys, issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"]))
    with pytest.raises(ValidationError, match="already settled"):
        chain.check_transaction(tx)


@pytest.mark.parametrize("offset", [0, 1, 20, 33, 50, 65, 66, 67, 74, 75, 90, 95, 110])
def test_any_tampered_body_byte_is_rejected(keys, dev, offset):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    raw = bytearray(issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"]).to_bytes())
    raw[offset] ^= 0x01
    tx = Transaction(chain.params.chain_id, (), (TxOutput(5 * WFLX - FEE, keys["bob"].address),),
                     kind="voucher_claim", payload={"voucher": bytes(raw).hex()})
    with pytest.raises(ValidationError):
        chain.check_transaction(tx)


def test_tampered_signature_rejected(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    raw = bytearray(issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"]).to_bytes())
    raw[-1] ^= 0x01
    tx = Transaction(chain.params.chain_id, (), (TxOutput(5 * WFLX - FEE, keys["bob"].address),),
                     kind="voucher_claim", payload={"voucher": bytes(raw).hex()})
    with pytest.raises(ValidationError, match="signature"):
        chain.check_transaction(tx)


def test_voucher_for_other_network_or_unknown_vault_rejected(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    other = Voucher.issue(dev, "other-network", vid, 0, 5 * WFLX, keys["bob"].address, b"\x02" * 16)
    with pytest.raises(ValidationError, match="another network"):
        build_voucher_claim(other, chain.get_vault(vid), chain.params)
    ghost = issue(chain, dev, "ab" * 32, 0, 5 * WFLX, keys["bob"])
    tx = Transaction(chain.params.chain_id, (), (TxOutput(5 * WFLX - FEE, keys["bob"].address),),
                     kind="voucher_claim", payload={"voucher": ghost.to_bytes().hex()})
    with pytest.raises(ValidationError, match="nonexistent"):
        chain.check_transaction(tx)


@pytest.mark.parametrize("slot,amount,msg", [(2, 5 * WFLX, "nonexistent slot"),
                                              (0, 10 * WFLX + 1, "limits"), (0, 9_999, "limits")])
def test_voucher_limits(keys, dev, slot, amount, msg):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    with pytest.raises(ValidationError, match=msg):
        build_voucher_claim(issue(chain, dev, vid, slot, amount, keys["bob"]), chain.get_vault(vid), chain.params)


def test_claim_deadline_boundaries(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    v = chain.get_vault(vid)
    deadline = V.claim_deadline(v, chain.params)                    # = opening + ttl + window
    assert deadline == v.opened_height + 5 + 4
    advance(chain, keys, deadline - 1 - chain.height)               # next block = deadline
    claim(chain, keys, issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"]))  # included WITHIN the deadline: ok
    assert chain.height == deadline
    late = build_voucher_claim(issue(chain, dev, vid, 1, 5 * WFLX, keys["bob"], b"\x03" * 16),
                               chain.get_vault(vid), chain.params)
    with pytest.raises(ValidationError, match="deadline"):
        chain.check_transaction(late)                               # block deadline+1: too late


def test_claim_tx_shape_rules(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    tx = build_voucher_claim(issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"]), chain.get_vault(vid), chain.params)
    for bad in (replace(tx, outputs=tx.outputs + tx.outputs),
                replace(tx, outputs=(TxOutput(tx.outputs[0].value + 1, keys["bob"].address),)),
                replace(tx, outputs=(TxOutput(tx.outputs[0].value, keys["alice"].address),)),
                replace(tx, inputs=(TxInput("11" * 32, 0, "", ""),)),
                replace(tx, payload={"voucher": tx.payload["voucher"], "x": 1}),
                replace(tx, payload={"voucher": "00" * 10})):
        with pytest.raises(ValidationError):
            chain.check_transaction(bad)


# ------------------------------------------------------------ duplicates (offline double spend)
def test_equivocation_second_receiver_paid_from_collateral(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    v1 = issue(chain, dev, vid, 0, 10 * WFLX, keys["bob"], b"\x01" * 16)
    v2 = issue(chain, dev, vid, 0, 10 * WFLX, keys["carol"], b"\x02" * 16)   # same slot!
    tx2 = build_voucher_claim(v2, chain.get_vault(vid), chain.params)       # carol, slot still free
    claim(chain, keys, v1)                                                  # bob arrives first
    assert chain.check_transaction(tx2) == chain.params.min_fee             # same value: still valid
    mine(chain, keys, [tx2])
    assert chain.balance(keys["bob"].address) == 10 * WFLX - FEE
    assert chain.balance(keys["carol"].address) == 10 * WFLX - FEE           # compensated by the collateral
    vault = chain.get_vault(vid)
    assert vault.fraud and vault.slots[0].collateral_left == 0
    v3 = issue(chain, dev, vid, 0, 10 * WFLX, keys["mallory"], b"\x03" * 16)
    with pytest.raises(ValidationError, match="exhausted"):
        build_voucher_claim(v3, vault, chain.params)                        # 3rd victim: no collateral


def test_partial_collateral_is_shared_in_claim_order(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev, caps=(10 * WFLX,))
    claim(chain, keys, issue(chain, dev, vid, 0, 6 * WFLX, keys["bob"], b"\x01" * 16))     # cap: 6
    stale = build_voucher_claim(issue(chain, dev, vid, 0, 5 * WFLX, keys["mallory"], b"\x03" * 16),
                                chain.get_vault(vid), chain.params)         # built seeing 10 of collateral
    claim(chain, keys, issue(chain, dev, vid, 0, 8 * WFLX, keys["carol"], b"\x02" * 16))   # collateral: 8
    with pytest.raises(ValidationError, match="does not match"):               # only 2 remain: the old claim fell through
        chain.check_transaction(stale)
    claim(chain, keys, issue(chain, dev, vid, 0, 5 * WFLX, keys["mallory"], b"\x03" * 16)) # redone: pays 2
    assert chain.balance(keys["carol"].address) == 8 * WFLX - FEE
    assert chain.balance(keys["mallory"].address) == 2 * WFLX - FEE
    assert chain.get_vault(vid).slots[0].collateral_left == 0


def test_free_slots_remain_claimable_after_fraud(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    claim(chain, keys, issue(chain, dev, vid, 0, 4 * WFLX, keys["bob"], b"\x01" * 16))
    claim(chain, keys, issue(chain, dev, vid, 0, 4 * WFLX, keys["carol"], b"\x02" * 16))
    assert chain.get_vault(vid).fraud
    claim(chain, keys, issue(chain, dev, vid, 1, 4 * WFLX, keys["mallory"], b"\x03" * 16))
    assert chain.balance(keys["mallory"].address) == 4 * WFLX - FEE


# ------------------------------------------------------------ refund
def test_refund_only_after_window_and_returns_leftover(keys, dev):
    chain = vchain(keys)
    alice0 = chain.balance(keys["alice"].address)
    vid = open_vault(chain, keys, dev)
    open_fee = alice0 - 40 * WFLX - chain.balance(keys["alice"].address)
    claim(chain, keys, issue(chain, dev, vid, 0, 6 * WFLX, keys["bob"]))
    early = build_vault_refund(chain.get_vault(vid), chain.params)
    with pytest.raises(ValidationError, match="window"):
        chain.check_transaction(early)
    advance(chain, keys, V.claim_deadline(chain.get_vault(vid), chain.params) - 1 - chain.height)
    with pytest.raises(ValidationError, match="window"):
        chain.check_transaction(early)                               # next block = last claim block
    advance(chain, keys, 1)
    assert chain.check_transaction(early) == chain.params.min_fee    # next block = deadline+1: ok
    mine(chain, keys, [build_vault_refund(chain.get_vault(vid), chain.params)])
    # alice: -opening fee, -6 WFLX paid, -refund fee (collateral comes back in full: no fraud)
    assert chain.balance(keys["alice"].address) == alice0 - open_fee - 6 * WFLX - chain.params.min_fee
    assert chain.get_vault(vid).state == "CLOSED" and chain.vaults.total_locked == 0
    assert balances(chain, keys) == chain.total_supply()


def test_refund_burns_collateral_after_fraud(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev, caps=(10 * WFLX,))
    claim(chain, keys, issue(chain, dev, vid, 0, 6 * WFLX, keys["bob"], b"\x01" * 16))
    claim(chain, keys, issue(chain, dev, vid, 0, 6 * WFLX, keys["carol"], b"\x02" * 16))
    assert chain.get_vault(vid).fraud
    to_deadline(chain, keys, vid)
    advance(chain, keys, 1)
    supply_before = chain.total_supply()
    rf = build_vault_refund(chain.get_vault(vid), chain.params)
    plan = V.plan_refund(chain.get_vault(vid), chain.params, None)
    assert plan.burn == 4 * WFLX and plan.total == 4 * WFLX            # cap left 4; collateral 4 burned
    mine(chain, keys, [rf])
    expected_burn = 4 * WFLX
    assert chain.total_supply() == supply_before + 50 * WFLX - expected_burn   # reward - burn
    assert balances(chain, keys) == chain.total_supply()


def test_refund_twice_and_claim_after_refund_rejected(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    to_deadline(chain, keys, vid)
    advance(chain, keys, 1)
    rf = build_vault_refund(chain.get_vault(vid), chain.params)
    mine(chain, keys, [rf])
    with pytest.raises(ValidationError, match="closed"):
        chain.check_transaction(rf)
    with pytest.raises(ValidationError):
        build_voucher_claim(issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"]), chain.get_vault(vid), chain.params)


def test_refund_shape_rules(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    to_deadline(chain, keys, vid)
    advance(chain, keys, 1)
    rf = build_vault_refund(chain.get_vault(vid), chain.params)
    for bad in (replace(rf, outputs=(TxOutput(rf.outputs[0].value + 1, keys["alice"].address),)),
                replace(rf, outputs=(TxOutput(rf.outputs[0].value, keys["mallory"].address),)),
                replace(rf, outputs=()),
                replace(rf, payload={"vault_id": "cd" * 32}),
                replace(rf, payload={"vault_id": vid, "x": 1})):
        with pytest.raises(ValidationError):
            chain.check_transaction(bad)


def test_no_early_close_exists():
    from winflux.blockchain.transaction import KINDS
    assert "vault_close" not in KINDS  # Review 2: no early close


# ------------------------------------------------------------ supply, atomicity, undo, determinism
def test_vault_value_counts_toward_supply_cap(keys, dev):
    chain = vchain(keys, alloc=((keys["alice"].address, 1000 * WFLX),), max_supply=1100 * WFLX)
    open_vault(chain, keys, dev, caps=(20 * WFLX,))                 # locks 40 WFLX
    advance(chain, keys, 5)
    assert chain.total_supply() == 1100 * WFLX                       # rewards stopped at the cap
    assert balances(chain, keys) + chain.vaults.total_locked == chain.total_supply()


def test_block_with_bad_claim_is_atomic(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    snap, utxos, supply = chain.vaults.snapshot(), len(chain.utxo), chain.total_supply()
    good = issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"])
    ok = build_voucher_claim(good, chain.get_vault(vid), chain.params)
    bad = replace(ok, outputs=(TxOutput(1, keys["bob"].address),))
    tmpl = chain.create_block(keys["producer"].public_hex, keys["producer"].address, [])
    forged = Block.build(tmpl.height, tmpl.prev_hash, tmpl.timestamp, tmpl.producer,
                         [tmpl.transactions[0], ok, bad])
    chain.consensus.seal(forged, keys["producer"])
    with pytest.raises(ValidationError):
        chain.add_block(forged)
    assert (chain.vaults.snapshot(), len(chain.utxo), chain.total_supply()) == (snap, utxos, supply)


def test_ledger_undo_restores_exact_state(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    snap, utxos, supply = chain.vaults.snapshot(), len(chain.utxo), chain.total_supply()
    h = chain.height + 1
    claim_tx = build_voucher_claim(issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"]), chain.get_vault(vid), chain.params)
    undo = chain.ledger.apply(claim_tx, chain.ledger.check(claim_tx, h))
    assert chain.vaults.snapshot() != snap
    chain.ledger.revert(undo)
    assert (chain.vaults.snapshot(), len(chain.utxo), chain.total_supply()) == (snap, utxos, supply)


def _replay(src: Chain, keys):
    dst = vchain(keys)
    for b in src.blocks[1:]:
        dst.add_block(Block.from_dict(json.loads(json.dumps(b.to_dict()))))
    return dst


def test_two_nodes_reach_identical_vault_state(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    claim(chain, keys, issue(chain, dev, vid, 0, 6 * WFLX, keys["bob"], b"\x01" * 16))
    claim(chain, keys, issue(chain, dev, vid, 0, 6 * WFLX, keys["carol"], b"\x02" * 16))
    to_deadline(chain, keys, vid)
    advance(chain, keys, 1)
    mine(chain, keys, [build_vault_refund(chain.get_vault(vid), chain.params)])
    other = _replay(chain, keys)
    assert other.vaults.snapshot() == chain.vaults.snapshot()
    assert other.total_supply() == chain.total_supply() and other.tip.hash == chain.tip.hash


def test_vault_state_survives_restart(keys, dev, tmp_path):
    path = str(tmp_path / "c.db")
    chain = vchain(keys, storage=BlockStorage(path))
    vid = open_vault(chain, keys, dev)
    claim(chain, keys, issue(chain, dev, vid, 0, 6 * WFLX, keys["bob"]))
    snap, supply = chain.vaults.snapshot(), chain.total_supply()
    chain.storage.close()
    again = vchain(keys, storage=BlockStorage(path))
    assert again.vaults.snapshot() == snap and again.total_supply() == supply


# ------------------------------------------------------------ P-256, voucher, transaction types
def test_p256_high_s_rejected_and_hash_independent_of_signature(keys):
    chain = vchain(keys)
    dev = devs()["p256"]
    vid = open_vault(chain, keys, dev)
    v = issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"])
    r, s = v.signature[:32], int.from_bytes(v.signature[32:], "big")
    assert s <= _P256_N // 2
    malleated = replace(v, signature=r + (_P256_N - s).to_bytes(32, "big"))   # (r, n-s) is also valid ECDSA
    assert malleated.hash == v.hash and malleated.signature != v.signature   # identity = body only
    with pytest.raises(ValidationError, match="signature"):
        build_voucher_claim(malleated, chain.get_vault(vid), chain.params)   # high S: rejected
    claim(chain, keys, v)
    with pytest.raises(ValidationError, match="signature"):                 # the variant never becomes "another voucher"
        build_voucher_claim(malleated, chain.get_vault(vid), chain.params)
    assert chain.get_vault(vid).fraud is False                               # collateral untouched


def test_voucher_codec_roundtrip_and_strictness(keys):
    dev = devs()["ed25519"]
    v = Voucher.issue(dev, "net", "ab" * 32, 7, 123456789, keys["bob"].address, b"\x09" * 16)
    raw = v.to_bytes()
    assert len(raw) == TOTAL_LEN == 175 and Voucher.from_bytes(raw) == v
    assert v.receiver_address == keys["bob"].address
    for bad in (raw[:-1], raw + b"\x00", b"", bytes([2]) + raw[1:]):
        with pytest.raises(ValidationError):
            Voucher.from_bytes(bad)
    with pytest.raises(ValidationError):
        Voucher.issue(dev, "net", "ab" * 32, 70_000, 1, keys["bob"].address, b"\x09" * 16)   # slot > u16
    with pytest.raises(ValidationError):
        Voucher.issue(dev, "net", "ab" * 32, 1, 2**64, keys["bob"].address, b"\x09" * 16)    # value > u64


def test_transaction_kind_rules_at_parse(keys):
    base = Transaction("c", (), (), kind="voucher_claim", payload={"voucher": "00"}).to_dict()
    assert Transaction.from_dict(base).kind == "voucher_claim"
    for mutate in (lambda d: d.update(kind="vault_close"),            # removed
                   lambda d: d.update(kind="nothing"),
                   lambda d: d.update(payload=None),                  # vault requires a payload
                   lambda d: d.update(coinbase_height=3),             # vault is not a coinbase
                   lambda d: d.update(kind="transfer", payload={"a": 1})):
        d = json.loads(json.dumps(base))
        mutate(d)
        with pytest.raises(ValidationError):
            Transaction.from_dict(d)
