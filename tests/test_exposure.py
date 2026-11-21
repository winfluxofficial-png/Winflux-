"""Deterministic collateral exposure limits (R1-R9) — adversarial tests."""
import random
from dataclasses import replace

import pytest

from winflux.blockchain import vaults as V
from winflux.blockchain.exposure import plan_compensation
from winflux.blockchain.transaction import Transaction, TxOutput
from winflux.errors import ValidationError
from winflux.offline.voucher import Voucher
from winflux.wallet.vault_builder import build_vault_refund, build_voucher_claim

from .conftest import WFLX, mine
from .test_vaults import FEE, advance, balances, claim, devs, issue, open_vault, to_deadline, vchain

BASE = dict(collateral_left=10, compensated_total=0, contested_value=10, paid_leaves=(), max_events=16,
            leaf_id="a", leaf_value=6, min_payout=2)


# ---------------------------------------------------------------- pure function
def test_pure_basic_payout_and_each_rule():
    assert plan_compensation(**BASE) == 6                                           # R4: leaf value
    assert plan_compensation(**{**BASE, "leaf_value": 50}) == 10                    # R1/R2: cap
    assert plan_compensation(**{**BASE, "collateral_left": 3}) == 3                 # R1
    assert plan_compensation(**{**BASE, "compensated_total": 7}) == 3               # R2: 3 of the contested value remain
    with pytest.raises(ValidationError, match="already compensated"):                     # R3
        plan_compensation(**{**BASE, "paid_leaves": ("a",)})
    with pytest.raises(ValidationError, match="compensation limit"):            # R9
        plan_compensation(**{**BASE, "paid_leaves": ("x", "y"), "max_events": 2})
    with pytest.raises(ValidationError, match="exhausted"):                          # R1
        plan_compensation(**{**BASE, "collateral_left": 0})
    with pytest.raises(ValidationError, match="contested value"):                  # R2
        plan_compensation(**{**BASE, "compensated_total": 10})
    with pytest.raises(ValidationError, match="below the minimum"):                  # R8
        plan_compensation(**{**BASE, "collateral_left": 1})


@pytest.mark.parametrize("bad", [dict(leaf_value=0), dict(leaf_value=-5), dict(contested_value=0)])
def test_pure_rejects_nonpositive_values(bad):
    with pytest.raises(ValidationError):
        plan_compensation(**{**BASE, **bad})


def test_pure_is_deterministic_and_total_never_exceeds_caps():
    """Any sequence of losing claims: Σ ≤ collateral and Σ ≤ contested value; each leaf once."""
    rnd = random.Random(42)
    for _ in range(300):
        K, contested = rnd.randint(1, 100), rnd.randint(1, 100)
        coll, comp, leaves, total = K, 0, [], 0
        for n in range(rnd.randint(1, 40)):
            leaf = rnd.choice([f"l{rnd.randint(0, 12)}", f"l{n}"])       # includes resubmissions
            try:
                p = plan_compensation(collateral_left=coll, compensated_total=comp, contested_value=contested,
                                      paid_leaves=leaves, max_events=8, leaf_id=leaf,
                                      leaf_value=rnd.randint(1, 60), min_payout=1)
            except ValidationError:
                continue
            assert p > 0
            coll -= p; comp += p; total += p; leaves.append(leaf)
        assert total <= K and total <= contested and len(leaves) == len(set(leaves)) <= 8 and coll >= 0


# ---------------------------------------------------------------- resubmission (bug found in review)
def test_compensated_voucher_cannot_be_replayed_same_payout(keys):
    dev = devs()["ed25519"]
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev, caps=(10 * WFLX,))
    claim(chain, keys, issue(chain, dev, vid, 0, 4 * WFLX, keys["bob"], b"\x01" * 16))
    v2 = issue(chain, dev, vid, 0, 3 * WFLX, keys["carol"], b"\x02" * 16)
    tx = claim(chain, keys, v2)
    left = chain.get_vault(vid).slots[0].collateral_left
    with pytest.raises(ValidationError, match="already compensated"):
        chain.check_transaction(tx)                         # the SAME tx, resent
    with pytest.raises(ValidationError, match="already compensated"):
        build_voucher_claim(v2, chain.get_vault(vid), chain.params)
    assert chain.get_vault(vid).slots[0].collateral_left == left


def test_compensated_voucher_cannot_be_replayed_with_changed_payout(keys):
    dev = devs()["p256"]
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev, caps=(10 * WFLX,))
    claim(chain, keys, issue(chain, dev, vid, 0, 4 * WFLX, keys["bob"], b"\x01" * 16))
    v3 = issue(chain, dev, vid, 0, 8 * WFLX, keys["carol"], b"\x03" * 16)
    claim(chain, keys, v3)
    carol = chain.balance(keys["carol"].address)
    assert carol == 8 * WFLX - FEE
    with pytest.raises(ValidationError, match="already compensated"):
        build_voucher_claim(v3, chain.get_vault(vid), chain.params)   # before: it paid 2 more (total 10 > 8)
    assert chain.balance(keys["carol"].address) == carol


def test_block_production_survives_replayed_and_poisoned_claims(keys):
    """Invalid/resubmitted candidates are discarded; they never bring down block production."""
    dev = devs()["ed25519"]
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev, caps=(10 * WFLX,))
    claim(chain, keys, issue(chain, dev, vid, 0, 4 * WFLX, keys["bob"], b"\x01" * 16))
    v2 = issue(chain, dev, vid, 0, 3 * WFLX, keys["carol"], b"\x02" * 16)
    tx2 = claim(chain, keys, v2)
    blk = mine(chain, keys, [tx2, tx2, tx2])                # resubmissions as candidates
    assert len(blk.transactions) == 1                       # only the coinbase
    assert chain.get_vault(vid).slots[0].comp_leaves == [v2.hash]


def test_duplicate_outpoint_guard_is_a_validation_error(keys):
    dev = devs()["ed25519"]
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev, caps=(10 * WFLX,))
    tx = build_voucher_claim(issue(chain, dev, vid, 0, 4 * WFLX, keys["bob"]), chain.get_vault(vid), chain.params)
    chain.utxo._add((tx.txid, 0), tx.outputs[0])            # simulates an outpoint collision
    with pytest.raises(ValidationError, match="repeated"):
        chain.check_transaction(tx)


# ---------------------------------------------------------------- R2 / R9 / R8 on the chain
def test_r2_value_cap_even_with_big_collateral(keys):
    """ρ = 300%: the collateral is 3x the cap, but compensations for a contested note never exceed its value."""
    dev = devs()["ed25519"]
    chain = vchain(keys, vault_collateral_min_pct=100)
    vid = open_vault(chain, keys, dev, caps=(10 * WFLX,), pct=300)
    assert chain.get_vault(vid).slots[0].collateral_left == 30 * WFLX
    claim(chain, keys, issue(chain, dev, vid, 0, 10 * WFLX, keys["bob"], b"\x01" * 16))     # cap: 10
    claim(chain, keys, issue(chain, dev, vid, 0, 7 * WFLX, keys["carol"], b"\x02" * 16))    # compensates 7
    claim(chain, keys, issue(chain, dev, vid, 0, 7 * WFLX, keys["mallory"], b"\x03" * 16))  # only 3 of the value remain
    assert chain.balance(keys["mallory"].address) == 3 * WFLX - FEE
    with pytest.raises(ValidationError, match="contested value"):
        build_voucher_claim(issue(chain, dev, vid, 0, 5 * WFLX, keys["alice"], b"\x04" * 16),
                            chain.get_vault(vid), chain.params)                             # 10 already compensated
    s = chain.get_vault(vid).slots[0]
    assert s.compensated == 10 * WFLX <= s.cap and s.collateral_left == 20 * WFLX              # the remainder is burned on fraud


def test_r9_max_compensations_per_slot(keys):
    dev = devs()["ed25519"]
    chain = vchain(keys, max_compensations_per_slot=2)
    vid = open_vault(chain, keys, dev, caps=(100 * WFLX,), pct=100)
    claim(chain, keys, issue(chain, dev, vid, 0, 1 * WFLX, keys["bob"], b"\x01" * 16))
    claim(chain, keys, issue(chain, dev, vid, 0, 1 * WFLX, keys["carol"], b"\x02" * 16))
    claim(chain, keys, issue(chain, dev, vid, 0, 1 * WFLX, keys["mallory"], b"\x03" * 16))
    with pytest.raises(ValidationError, match="compensation limit"):
        build_voucher_claim(issue(chain, dev, vid, 0, 1 * WFLX, keys["alice"], b"\x04" * 16),
                            chain.get_vault(vid), chain.params)
    assert len(chain.get_vault(vid).slots[0].comp_leaves) == 2


def test_r8_dust_remainder_is_not_compensated(keys):
    dev = devs()["ed25519"]
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev, caps=(10 * WFLX,), pct=100)
    claim(chain, keys, issue(chain, dev, vid, 0, 1 * WFLX, keys["bob"], b"\x01" * 16))
    claim(chain, keys, issue(chain, dev, vid, 0, 10 * WFLX - 5_000, keys["carol"], b"\x02" * 16))  # 5,000 u remain
    with pytest.raises(ValidationError, match="below the minimum"):
        build_voucher_claim(issue(chain, dev, vid, 0, 1 * WFLX, keys["mallory"], b"\x03" * 16),
                            chain.get_vault(vid), chain.params)


def test_refund_after_exposure_burns_only_the_remainder(keys):
    dev = devs()["ed25519"]
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev, caps=(10 * WFLX,), pct=300)
    claim(chain, keys, issue(chain, dev, vid, 0, 10 * WFLX, keys["bob"], b"\x01" * 16))
    claim(chain, keys, issue(chain, dev, vid, 0, 6 * WFLX, keys["carol"], b"\x02" * 16))
    to_deadline(chain, keys, vid)
    advance(chain, keys, 1)
    before = chain.total_supply()
    plan = V.plan_refund(chain.get_vault(vid), chain.params, None)
    assert plan.burn == 30 * WFLX - 6 * WFLX and plan.total == 0                  # cap paid; remaining collateral burned
    mine(chain, keys, [build_vault_refund(chain.get_vault(vid), chain.params)])
    assert chain.total_supply() == before + 50 * WFLX - plan.burn
    assert balances(chain, keys) == chain.total_supply() and chain.vaults.total_locked == 0


# ---------------------------------------------------------------- adversarial properties
def test_property_random_claims_never_exceed_guaranteed_value(keys):
    rnd = random.Random(11)
    dev = devs()["p256"]
    chain = vchain(keys, max_compensations_per_slot=5)
    cap, pct = 20 * WFLX, 150
    vid = open_vault(chain, keys, dev, caps=(cap, cap), pct=pct, ttl=15)
    pool = [issue(chain, dev, vid, rnd.randint(0, 1), rnd.randint(11_000, cap),
                  keys[rnd.choice(["bob", "carol", "mallory", "alice"])],
                  bytes([n]) * 16) for n in range(1, 40)]
    locked0 = chain.vaults.total_locked
    for step in range(120):
        v = rnd.choice(pool)                                    # includes resubmissions and invalid vouchers, in order
        try:
            tx = build_voucher_claim(v, chain.get_vault(vid), chain.params)
            mine(chain, keys, [tx])
        except ValidationError:
            mine(chain, keys)
        vault = chain.get_vault(vid)
        for s in vault.slots:
            assert 0 <= s.paid <= s.cap and 0 <= s.collateral_left
            assert s.compensated <= s.cap                                    # R2
            assert s.compensated <= (s.cap * pct + 99) // 100                # R1
            assert len(s.comp_leaves) == len(set(s.comp_leaves)) <= 5        # R3, R9
            assert s.paid + s.compensated <= s.cap + min(s.cap, (s.cap * pct + 99) // 100)
        assert vault.locked() == sum(s.cap - s.paid + s.collateral_left for s in vault.slots)
        assert balances(chain, keys) + chain.vaults.total_locked == chain.total_supply()
    assert chain.vaults.total_locked <= locked0


def test_fuzz_ledger_never_raises_non_validation_errors(keys):
    """Randomly mutated claims: only ValidationError is acceptable (never ValueError/KeyError...)."""
    rnd = random.Random(5)
    dev = devs()["ed25519"]
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    base = build_voucher_claim(issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"]), chain.get_vault(vid), chain.params)
    for _ in range(1500):
        raw = bytearray(bytes.fromhex(base.payload["voucher"]))
        for _ in range(rnd.randint(1, 3)):
            raw[rnd.randrange(len(raw))] = rnd.randrange(256)
        out = TxOutput(rnd.choice([base.outputs[0].value, 1, 0, -1, 2**70]), rnd.choice([keys["bob"].address, keys["alice"].address]))
        tx = replace(base, payload={"voucher": bytes(raw).hex()}, outputs=rnd.choice([(out,), (), (out, out)]))
        try:
            chain.check_transaction(tx)
        except ValidationError:
            pass
