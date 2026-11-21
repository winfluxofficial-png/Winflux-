"""A4: vault owner reconciliation (journal × chain), vault API and CLI. The projection matches consensus."""
import asyncio
import json
import random
from dataclasses import replace
from types import SimpleNamespace

import pytest

from winflux.api.server import ApiServer
from winflux.blockchain import vaults as V
from winflux.cli import main as cli_main
from winflux.errors import ValidationError
from winflux.wallet import reconcile as RC
from winflux.wallet.reconcile import Journal, reconcile, render
from winflux.wallet.vault_builder import build_note_claim, build_vault_refund

from .conftest import WFLX, mine
from .test_note_claim import CAP, FEE, claim, direct, slot_of
from .test_notes import R, World, addr_out, note_out, soft
from .test_vaults import advance, to_deadline
from .test_network import run


@pytest.fixture(params=["p256", "ed25519"])
def w(keys, request):
    return World(keys, key_type=request.param, cap=CAP, software_slots=True)


def rep(w, journal):
    return reconcile(w.chain.get_vault(w.vid), journal, w.chain.params, w.chain.height)


def issue(w, journal, slot, to, req, value=None):
    pay = direct(w, to, value=value, req=req, slot=slot)
    journal.record_hop(pay.hops[0], slot)
    return pay


def real_refund(w, keys):
    """Performs the refund for real and returns (net amount received by the owner, supply before/after)."""
    before = w.chain.balance(keys["alice"].address)
    mine(w.chain, keys, [build_vault_refund(w.chain.get_vault(w.vid), w.chain.params)])
    return w.chain.balance(keys["alice"].address) - before


# ================================================================== journal
def test_journal_roundtrip_dedup_and_strictness(w, tmp_path):
    j = Journal()
    pay = direct(w, w.keys["bob"].address)
    assert j.record_hop(pay.hops[0], 0) is True and j.record_hop(pay.hops[0], 0) is False and len(j) == 1
    path = str(tmp_path / "j.json")
    j.save(path)
    assert Journal.load(path).to_dict() == j.to_dict()
    assert oct(__import__("os").stat(path).st_mode & 0o777) == "0o600"
    assert Journal.load(str(tmp_path / "does-not-exist.json")).to_dict() == Journal().to_dict()
    with pytest.raises(ValidationError, match="root"):
        j.record_hop(pay.hops[0], 1)                               # hop of slot 0 recorded as slot 1
    good = j.to_dict()
    for bad in (None, [], {}, {"v": 2, "entries": []}, {**good, "x": 1}, {"v": 1, "entries": [{}]},
                {"v": 1, "entries": [{"vault_id": "zz", "slot": 0, "root_txid": "00" * 32}]},
                {"v": 1, "entries": [{"vault_id": "00" * 32, "slot": -1, "root_txid": "00" * 32}]},
                {"v": 1, "entries": [{"vault_id": "00" * 32, "slot": True, "root_txid": "00" * 32}]}):
        with pytest.raises(ValidationError):
            Journal.from_dict(bad)
    (tmp_path / "bad.json").write_text("{not json")
    with pytest.raises(ValidationError, match="corrupted"):
        Journal.load(str(tmp_path / "bad.json"))


def test_vault_from_dict_is_the_inverse_of_to_dict(w, keys):
    claim(w, direct(w, keys["bob"].address))
    claim(w, direct(w, keys["carol"].address, req=R[1]))             # conflict: fills comp_leaves
    v = w.chain.get_vault(w.vid)
    again = V.Vault.from_dict(json.loads(json.dumps(v.to_dict())))
    assert again == v
    for bad in (None, {}, {**v.to_dict(), "state": "X"}, {**v.to_dict(), "slots": [[1]]},
                {**v.to_dict(), "slots": [[-1, 0, 0, None, 0, [], "", [], []]]}):
        with pytest.raises(ValidationError):
            V.Vault.from_dict(bad)


# ================================================================== slot states
def test_unused_vault_refund_is_projected_exactly(w, keys):
    r = rep(w, Journal())
    assert [s.status for s in r.slots] == [RC.UNUSED, RC.UNUSED] and r.clean and not r.warnings
    assert r.claims_open and not r.can_refund_now and r.refund_total == 2 * CAP + 2 * CAP  # deposit + 100% collateral
    with pytest.raises(ValidationError, match="window"):
        V.plan_refund(w.chain.get_vault(w.vid), w.chain.params, w.chain.height + 1)
    to_deadline(w.chain, keys, w.vid)
    r = rep(w, Journal())
    assert r.can_refund_now and r.blocks_until_refund == 0
    assert real_refund(w, keys) == r.refund_net
    r2 = rep(w, Journal())
    assert r2.state == "CLOSED" and r2.refund_total == 0 and not r2.can_refund_now
    assert any("closed" in x for x in r2.warnings)


def test_outstanding_then_lapsed_when_receivers_never_claim(w, keys):
    j = Journal()
    issue(w, j, 0, keys["bob"].address, R[0])
    r = rep(w, j)
    assert r.slots[0].status == RC.OUTSTANDING and r.slots[0].unsettled_issued == CAP
    assert r.slots[1].status == RC.UNUSED and any("can still settle" in x for x in r.warnings)
    assert r.blocks_until_refund > 0
    to_deadline(w.chain, keys, w.vid)
    r = rep(w, j)
    assert r.slots[0].status == RC.LAPSED and r.can_refund_now
    assert any("lost" in x for x in r.warnings)                      # warns that the receiver lost the right
    assert real_refund(w, keys) == r.refund_net == 2 * CAP + 2 * CAP - FEE


def test_settled_and_partial_slots(w, keys):
    j = Journal()
    issue(w, j, 0, keys["bob"].address, R[0])
    split = w.first(None, R[1], slot=1, outputs=[addr_out(10 * WFLX, keys["carol"].address),
                                                 addr_out(20 * WFLX, keys["mallory"].address)])
    j.record_hop(split.hops[0], 1)
    claim(w, direct(w, keys["bob"].address, req=R[0]))
    claim(w, replace(split, leaf=0))
    r = rep(w, j)
    assert [s.status for s in r.slots] == [RC.SETTLED, RC.PARTIAL] and r.clean
    assert r.slots[1].unsettled_issued == 20 * WFLX and r.slots[1].paid == 10 * WFLX
    to_deadline(w.chain, keys, w.vid)
    r = rep(w, j)
    assert [s.status for s in r.slots] == [RC.SETTLED, RC.LAPSED]
    assert real_refund(w, keys) == r.refund_net == (CAP - 10 * WFLX) + 2 * CAP - FEE


# ================================================================== problem signals
def test_chain_spend_the_journal_does_not_know_is_divergent(w, keys):
    claim(w, direct(w, keys["bob"].address))                            # "cloned" key: nothing in the journal
    r = rep(w, Journal())
    assert RC.DIVERGENT in r.slots[0].flags and r.slots[0].status == RC.SETTLED and not r.clean
    assert any("does NOT record" in x for x in r.warnings)
    j = Journal()
    j.add(w.vid, 0, "ab" * 32)                                          # journal has another root
    assert RC.DIVERGENT in rep(w, j).slots[0].flags
    j2 = Journal()
    issue(w, j2, 0, keys["bob"].address, R[0])
    assert rep(w, j2).clean                                             # with the right root, it does not diverge


def test_double_spend_is_reported_with_burned_collateral_and_matches_consensus(w, keys):
    j = Journal()
    issue(w, j, 0, keys["bob"].address, R[0])
    issue(w, j, 0, keys["carol"].address, R[1])                         # the owner issued the same slot twice
    claim(w, direct(w, keys["bob"].address, req=R[0]))
    claim(w, direct(w, keys["carol"].address, req=R[1]))
    r = rep(w, j)
    assert set(r.slots[0].flags) == {RC.DOUBLE_ISSUED, RC.CONFLICT} and r.fraud and r.slots[0].compensated == CAP
    assert any("Double spend" in x for x in r.warnings)
    to_deadline(w.chain, keys, w.vid)
    r = rep(w, j)
    assert r.burned == slot_of(w, 0).collateral_left + slot_of(w, 1).collateral_left == CAP
    assert any("BURNED" in x for x in r.warnings)
    supply = w.chain.total_supply()
    assert real_refund(w, keys) == r.refund_net == CAP - FEE            # only slot 1 (unused); collateral burned
    assert w.chain.total_supply() == supply + 50 * WFLX - r.burned


def test_render_is_readable_and_mentions_everything(w, keys):
    j = Journal()
    issue(w, j, 0, keys["bob"].address, R[0])
    out = render(rep(w, j), "WFLX")
    assert "slot 0: OUTSTANDING" in out and "slot 1: UNUSED" in out and "not yet available" in out


# ================================================================== property: the projection ALWAYS matches consensus
@pytest.mark.parametrize("seed", range(14))
def test_random_scenarios_projection_equals_real_refund(keys, seed):
    rng = random.Random(seed)
    w = World(keys, key_type=rng.choice(["p256", "ed25519"]), cap=CAP, software_slots=True)
    j = Journal()
    who = [keys["bob"].address, keys["carol"].address, keys["mallory"].address]
    for slot in range(2):
        mode = rng.choice(["none", "pay", "split", "double", "unlisted"])
        if mode == "none":
            continue
        if mode in ("pay", "double", "unlisted"):
            p = direct(w, rng.choice(who), req=R[0], slot=slot)
            if mode != "unlisted":
                j.record_hop(p.hops[0], slot)
            if rng.random() < .8:
                claim(w, p)
            if mode == "double":
                p2 = direct(w, rng.choice(who), req=R[1], slot=slot)
                j.record_hop(p2.hops[0], slot)
                if rng.random() < .8:
                    claim(w, p2)
        else:
            sp = w.first(None, R[0], slot=slot, outputs=[addr_out(10 * WFLX, who[0]), addr_out(20 * WFLX, who[1])])
            j.record_hop(sp.hops[0], slot)
            for leaf in (0, 1):
                if rng.random() < .6:
                    claim(w, replace(sp, leaf=leaf))
    to_deadline(w.chain, keys, w.vid)
    r = rep(w, j)
    plan = V.plan_refund(w.chain.get_vault(w.vid), w.chain.params, w.chain.height + 1)
    assert (r.refund_total, r.refund_fee, r.refund_net, r.burned) == (plan.total, plan.fee, plan.payout, plan.burn)
    supply = w.chain.total_supply()
    got = real_refund(w, keys)
    assert got == r.refund_net
    assert w.chain.total_supply() == supply + 50 * WFLX - r.burned           # nothing disappears or appears, apart from what was burned
    assert w.chain.get_vault(w.vid).locked() == 0


# ================================================================== vault API
def test_vault_api_routes(w, keys):
    claim(w, direct(w, keys["bob"].address))
    api = ApiServer(SimpleNamespace(chain=w.chain))
    code, d = asyncio.run(api._route("GET", f"/api/vault/{w.vid}", b""))
    assert code == 200 and d["vault_id"] == w.vid and d["height"] == w.chain.height
    assert d["claim_deadline"] == V.claim_deadline(w.chain.get_vault(w.vid), w.chain.params)
    assert V.Vault.from_dict(d) == w.chain.get_vault(w.vid)
    code, lst = asyncio.run(api._route("GET", f"/api/vaults/{keys['alice'].address}", b""))
    assert code == 200 and [v["vault_id"] for v in lst["vaults"]] == [w.vid]
    code, lst = asyncio.run(api._route("GET", f"/api/vaults/{keys['bob'].address}", b""))
    assert code == 200 and lst["vaults"] == []
    for path, want in ((f"/api/vault/{'0' * 64}", 404), ("/api/vault/xyz", 400), (f"/api/vault/{w.vid.upper()}", 400),
                       ("/api/vaults/garbage", 400)):
        assert asyncio.run(api._route("GET", path, b""))[0] == want


# ================================================================== end-to-end CLI (reconcile + vault-refund)
def test_cli_reconcile_and_refund_end_to_end(w, keys, tmp_path, capsys, monkeypatch):
    j = Journal()
    issue(w, j, 0, keys["bob"].address, R[0])
    jpath = str(tmp_path / "vault-journal.json")
    j.save(jpath)

    async def submit_tx(tx):
        w.chain.check_transaction(tx)                      # like the node's mempool: rejects before mining
        mine(w.chain, keys, [tx])
        return tx.txid

    async def go():
        api = ApiServer(SimpleNamespace(chain=w.chain, submit_tx=submit_tx))
        await api.start()
        url = f"http://127.0.0.1:{api.port}"
        loop = asyncio.get_running_loop()
        call = lambda *a: loop.run_in_executor(None, lambda: cli_main(["--node", url, *a]))
        try:
            assert await call("reconcile", w.vid, "--journal", jpath) == 0
            out = capsys.readouterr().out
            assert "OUTSTANDING" in out and "not yet available" in out
            assert await call("vault-refund", w.vid) == 1                        # window open: the node refuses
            assert "window" in capsys.readouterr().err
            to_deadline(w.chain, keys, w.vid)
            before = w.chain.balance(keys["alice"].address)
            assert await call("vault-refund", w.vid) == 0
            assert "refund sent" in capsys.readouterr().out
            assert w.chain.balance(keys["alice"].address) > before and w.chain.get_vault(w.vid).state == "CLOSED"
            assert await call("reconcile", w.vid, "--journal", jpath) == 0
            assert "closed" in capsys.readouterr().out
            assert await call("reconcile", "00" * 32) == 1
        finally:
            await api.stop()
    run(go())


def test_window_boundary_agrees_with_consensus_at_every_height(w, keys):
    """At every height near the deadline, the report agrees with what the node actually accepts (claim x refund)."""
    pay = direct(w, keys["bob"].address)
    j = Journal()
    j.record_hop(pay.hops[0], 0)
    deadline = V.claim_deadline(w.chain.get_vault(w.vid), w.chain.params)
    advance(w.chain, keys, deadline - 2 - w.chain.height)
    for _ in range(4):                                             # heights deadline-2 .. deadline+1
        r = rep(w, j)
        vault = w.chain.get_vault(w.vid)
        claim_ok = refund_ok = True
        try:
            w.chain.ledger.check(build_note_claim(pay, vault, w.chain.params), w.chain.height + 1)
        except ValidationError:
            claim_ok = False
        try:
            w.chain.ledger.check(build_vault_refund(vault, w.chain.params), w.chain.height + 1)
        except ValidationError:
            refund_ok = False
        assert r.claims_open == claim_ok and r.can_refund_now == refund_ok and claim_ok != refund_ok
        assert r.blocks_until_refund == max(0, deadline - w.chain.height)
        advance(w.chain, keys, 1)
