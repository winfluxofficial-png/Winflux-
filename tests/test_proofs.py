"""A1: state_root, checkpoints and vault proofs verifiable offline — adversarial tests."""
import copy
import json
import random
from dataclasses import replace

import pytest

from winflux.blockchain import state_root as SR
from winflux.blockchain.block import Block
from winflux.consensus.poa import ProofOfAuthority
from winflux.errors import ValidationError
from winflux.offline import proofs as P
from winflux.wallet.vault_builder import build_voucher_claim

from .conftest import WFLX, T0, make_chain, mine
from .test_vaults import advance, claim, devs, issue, open_vault, vchain

POA = ProofOfAuthority()


@pytest.fixture(params=["ed25519", "p256"])
def dev(request):
    return devs()[request.param]


def proof_for(chain, vid, slot=0):
    return P.build_vault_proof(chain, vid, slot)


def verify(chain, proof, **kw):
    return P.verify_vault_proof(proof, chain.params, POA, **kw)


# ------------------------------------------------------------------ state_root in consensus
def test_state_root_evolves_with_vault_state_and_is_committed_in_header(keys, dev):
    chain = vchain(keys)
    assert chain.tip.state_root == SR.EMPTY_VAULT_ROOT
    mine(chain, keys)
    assert chain.tip.state_root == SR.EMPTY_VAULT_ROOT                     # no vaults: does not change
    vid = open_vault(chain, keys, dev)
    r1 = chain.tip.state_root
    assert r1 != SR.EMPTY_VAULT_ROOT and r1 == chain.ledger.state_root()
    claim(chain, keys, issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"]))
    r2 = chain.tip.state_root
    assert r2 != r1
    blk = chain.tip
    assert replace(blk, state_root=r1).hash != blk.hash                    # the header (and the hash) covers the root


def test_forged_state_root_is_rejected(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    tx = build_voucher_claim(issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"]), chain.get_vault(vid), chain.params)
    tmpl = chain.create_block(keys["producer"].public_hex, keys["producer"].address, [tx])
    for bad in (SR.EMPTY_VAULT_ROOT, "ab" * 32, chain.tip.state_root):    # empty, garbage, the OLD root
        forged = replace(tmpl, state_root=bad)
        chain.consensus.seal(forged, keys["producer"])
        with pytest.raises(ValidationError, match="state_root"):
            chain.add_block(forged)
    chain.consensus.seal(tmpl, keys["producer"])
    chain.add_block(tmpl)                                                  # the correct root passes


def test_state_root_identical_on_independent_replay_and_after_undo(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    claim(chain, keys, issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"]))
    other = vchain(keys)
    for b in chain.blocks[1:]:
        other.add_block(Block.from_dict(json.loads(json.dumps(b.to_dict()))))
    assert other.tip.state_root == chain.tip.state_root and other.tip.hash == chain.tip.hash
    before = chain.ledger.state_root()
    tx = build_voucher_claim(issue(chain, dev, vid, 1, 4 * WFLX, keys["carol"], b"\x07" * 16),
                             chain.get_vault(vid), chain.params)
    undo = chain.ledger.apply(tx, chain.ledger.check(tx, chain.height + 1))
    assert chain.ledger.state_root() != before
    chain.ledger.revert(undo)
    assert chain.ledger.state_root() == before


# ------------------------------------------------------------------ Merkle
@pytest.mark.parametrize("n", list(range(1, 21)))
def test_merkle_paths_for_every_index(n):
    leaves = [SR._leaf(bytes([i])) for i in range(n)]
    top = SR.merkle_top(leaves)
    for i in range(n):
        path = SR.merkle_path(leaves, i)
        assert SR.top_from_path(leaves[i], i, n, path) == top


def test_merkle_rejects_wrong_index_count_path_and_leaf():
    n = 11
    leaves = [SR._leaf(bytes([i])) for i in range(n)]
    top = SR.merkle_top(leaves)
    path = SR.merkle_path(leaves, 4)
    assert SR.top_from_path(leaves[4], 5, n, path) != top
    assert SR.top_from_path(leaves[4], 4, n, path[:-1]) is None            # short path
    assert SR.top_from_path(leaves[4], 4, n, path + [path[0]]) is None     # long path
    assert SR.top_from_path(leaves[4], 4, n + 6, path) is None             # another depth
    assert SR.top_from_path(leaves[4], 11, n, path) is None                # index out of range
    assert SR.top_from_path(leaves[5], 4, n, path) != top                  # wrong leaf
    assert SR.top_from_path(leaves[4], 4, n, [bytes(32)] + path[1:]) != top
    # the count enters the commitment: the same tree with another n produces another root
    assert SR.bind_vaults(n, top) != SR.bind_vaults(n + 1, top) and SR.bind_vaults(0, top) != SR.bind_vaults(1, top)


def test_leaf_and_node_domains_are_separated():
    a, b = SR._leaf(b"a"), SR._leaf(b"b")
    assert SR._node(a, b) != SR._leaf(a + b)                               # internal node ≠ leaf with the same content


# ------------------------------------------------------------------ proof: happy path
def test_proof_roundtrip_and_fields(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev, caps=(10 * WFLX, 12 * WFLX), ttl=7)
    proof = json.loads(json.dumps(proof_for(chain, vid, 1)))               # survives QR/JSON
    vs = verify(chain, proof)
    assert (vs.vault_id, vs.slot, vs.cap, vs.collateral_left, vs.paid) == (vid, 1, 12 * WFLX, 12 * WFLX, 0)
    assert not vs.claimed and not vs.fraud and vs.state == "OPEN" and vs.key_type == dev.key_type
    assert vs.device_key == dev.public_hex and vs.refund_address == keys["alice"].address
    assert vs.expires_height == vs.opened_height + 7 and vs.checkpoint_height == chain.height
    assert vs.checkpoint_hash == chain.tip.hash


def test_proof_reflects_claims_fraud_and_close(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev, caps=(10 * WFLX,))
    claim(chain, keys, issue(chain, dev, vid, 0, 4 * WFLX, keys["bob"], b"\x01" * 16))
    vs = verify(chain, proof_for(chain, vid))
    assert vs.claimed and vs.paid == 4 * WFLX and not vs.fraud
    claim(chain, keys, issue(chain, dev, vid, 0, 4 * WFLX, keys["carol"], b"\x02" * 16))
    vs = verify(chain, proof_for(chain, vid))
    assert vs.fraud and vs.compensated == 4 * WFLX and vs.collateral_left == 6 * WFLX


def test_proof_among_many_vaults_is_small(keys):
    chain = vchain(keys)
    dev = devs()["p256"]
    ids = [open_vault(chain, keys, dev, caps=(10 * WFLX,) * 64, ttl=15) for _ in range(12)]
    proof = proof_for(chain, ids[7], 63)
    size = len(canonical_size(proof))
    vs = verify(chain, proof)
    assert vs.slot == 63 and vs.vault_id == ids[7]
    assert size < 3000, f"proof too large: {size} bytes"


def canonical_size(proof):
    return json.dumps(proof, separators=(",", ":")).encode()


# ------------------------------------------------------------------ proof: tampering
def _paths(o, pre=()):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _paths(v, pre + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _paths(v, pre + (i,))
    else:
        yield pre


def _set(o, path, val):
    for k in path[:-1]:
        o = o[k]
    o[path[-1]] = val


def _get(o, path):
    for k in path:
        o = o[k]
    return o


def _altered(v):
    if isinstance(v, bool):
        return not v
    if isinstance(v, int):
        return v + 1
    if isinstance(v, str):
        if v == "":
            return "00"
        c = "1" if v[-1] != "1" else "2"
        return v[:-1] + c if all(ch in "0123456789abcdef" for ch in v) else v + "x"
    return None


def test_every_single_field_of_the_proof_is_bound(keys, dev):
    chain = vchain(keys)
    for _ in range(4):                                                     # non-empty vault path
        open_vault(chain, keys, dev, caps=(10 * WFLX,), ttl=15)
    vid = open_vault(chain, keys, dev, caps=(10 * WFLX, 10 * WFLX, 10 * WFLX), ttl=15)
    claim(chain, keys, issue(chain, dev, vid, 2, 3 * WFLX, keys["bob"]))
    base = proof_for(chain, vid, 2)
    verify(chain, base)
    assert len(base["vault"]["path"]) >= 2 and len(base["slot"]["path"]) == 2
    n = 0
    for path in _paths(base):
        mutated = copy.deepcopy(base)
        _set(mutated, path, _altered(_get(base, path)))
        with pytest.raises(ValidationError):
            verify(chain, mutated)
        n += 1
    assert n == len(list(_paths(base))) >= 33                              # ALL fields were tampered with


def test_proof_fuzz_only_validation_errors(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    base = proof_for(chain, vid)
    rnd = random.Random(9)
    junk = [None, -1, 0, 2**70, "", "x", [], {}, True, 1.5, "00" * 32, [1, 2], {"a": 1}, "g" * 64]
    for _ in range(2500):
        m = copy.deepcopy(base)
        for _ in range(rnd.choice([1, 2, 3])):
            _set(m, rnd.choice([p for p in _paths(m) if p]), copy.deepcopy(rnd.choice(junk)))
        try:
            verify(chain, m)
        except ValidationError:
            continue
        assert m == base                                                   # only the original proof passes


def test_structural_attacks(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    base = proof_for(chain, vid)
    for bad in (None, [], "x", {}, {**base, "extra": 1}, {k: v for k, v in base.items() if k != "slot"}):
        with pytest.raises(ValidationError):
            verify(chain, bad)
    long_path = copy.deepcopy(base)
    long_path["vault"]["path"] = ["00" * 32] * 200
    with pytest.raises(ValidationError):
        verify(chain, long_path)


# ------------------------------------------------------------------ checkpoint and authority
def test_checkpoint_must_come_from_the_authority_of_that_height(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    proof = proof_for(chain, vid)
    hdr = dict(proof["checkpoint"]["header"])
    # (a) forged by someone who is not an authority, with the SAME state_root
    fake = Block(hdr["height"], hdr["prev_hash"], hdr["timestamp"], hdr["merkle_root"], keys["mallory"].public_hex,
                 hdr["nonce"], hdr["meta"], (), "", hdr["state_root"])
    POA.seal(fake, keys["mallory"])
    forged = copy.deepcopy(proof)
    forged["checkpoint"] = P.make_checkpoint(fake)
    with pytest.raises(ValidationError, match="whose turn"):
        verify(chain, forged)
    # (b) header signed by a key other than the declared producer's
    forged2 = copy.deepcopy(proof)
    forged2["checkpoint"]["signature"] = keys["mallory"].sign(b"x").hex()
    with pytest.raises(ValidationError, match="signature"):
        verify(chain, forged2)
    # (c) valid signature reused with a changed state_root
    forged3 = copy.deepcopy(proof)
    forged3["checkpoint"]["header"]["state_root"] = SR.EMPTY_VAULT_ROOT
    with pytest.raises(ValidationError, match="signature"):
        verify(chain, forged3)


def test_two_authorities_round_robin_checkpoints(keys, dev):
    chain = vchain(keys, authorities=(keys["producer"].public_hex, keys["carol"].public_hex))
    blk = mine(chain, keys)                                                # height 1: producer
    assert P.verify_checkpoint(P.make_checkpoint(blk), chain.params, POA).height == 1
    b2 = chain.create_block(keys["carol"].public_hex, keys["carol"].address, [])
    chain.consensus.seal(b2, keys["carol"])
    chain.add_block(b2)                                                    # height 2: carol
    cp = P.make_checkpoint(b2)
    assert P.verify_checkpoint(cp, chain.params, POA).height == 2
    wrong = copy.deepcopy(cp)
    wrong["header"]["height"] = 3                                          # height 3 would be the producer's
    with pytest.raises(ValidationError):
        P.verify_checkpoint(wrong, chain.params, POA)


def test_genesis_is_not_a_checkpoint(keys):
    chain = vchain(keys)
    with pytest.raises(ValidationError):
        P.make_checkpoint(chain.genesis_block)


def test_proof_from_another_network_is_rejected(keys, dev):
    a = vchain(keys)
    vid = open_vault(a, keys, dev)
    proof = proof_for(a, vid)
    b = vchain(keys, chain_id="other-network")                                 # same authorities, another network
    with pytest.raises(ValidationError):
        P.verify_vault_proof(proof, b.params, POA)
    verify(a, proof)


# ------------------------------------------------------------------ freshness and clock
def test_stale_proof_rejected_by_receiver_memory(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev)
    old = proof_for(chain, vid)                                            # slot FREE at this checkpoint
    claim(chain, keys, issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"]))
    new = proof_for(chain, vid)
    store = P.CheckpointStore()
    vs_new = verify(chain, new, min_checkpoint_height=store.min_height())
    store.observe(vs_new.checkpoint_height, vs_new.checkpoint_hash)
    assert vs_new.claimed
    with pytest.raises(ValidationError, match="older"):
        verify(chain, old, min_checkpoint_height=store.min_height())       # showing the old state fails
    verify(chain, old)                                                     # without memory, the proof is still "valid"


def test_checkpoint_store_monotonic_and_conflict_detection():
    s = P.CheckpointStore()
    s.observe(10, "aa"); s.observe(5, "bb"); s.observe(10, "aa")
    assert s.min_height() == 10 and s.hash == "aa"
    s.observe(11, "cc")
    assert s.min_height() == 11
    with pytest.raises(ValidationError, match="conflicting"):
        s.observe(11, "dd")


def test_deadline_estimation_uses_receivers_clock_only(keys, dev):
    chain = vchain(keys)
    vid = open_vault(chain, keys, dev, ttl=5)
    vs = verify(chain, proof_for(chain, vid))
    p = chain.params
    deadline = vs.expires_height + p.claim_window_blocks
    t0 = vs.checkpoint_timestamp
    assert P.estimated_height(vs.checkpoint_height, t0, t0 - 9999, p.target_block_time) == vs.checkpoint_height
    assert P.blocks_until_claim_deadline(vs, t0, p) == deadline - vs.checkpoint_height
    later = P.blocks_until_claim_deadline(vs, t0 + 3 * p.target_block_time, p)
    assert later == deadline - vs.checkpoint_height - 3


# ------------------------------------------------------------------ construction
def test_build_proof_errors(keys, dev):
    chain = vchain(keys)
    with pytest.raises(ValidationError):
        proof_for(chain, "ab" * 32)                                        # nonexistent vault
    vid = open_vault(chain, keys, dev)
    with pytest.raises(ValidationError):
        proof_for(chain, vid, 9)                                           # nonexistent slot
