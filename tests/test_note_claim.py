"""A3: `note_claim` — liquidação on-chain de cadeias de notas offline (sucesso, conflito, R1-R9, adulteração, fuzz)."""
import copy
import json
import random
from dataclasses import replace

import pytest

from winflux.blockchain import vaults as V
from winflux.blockchain.block import Block
from winflux.blockchain.transaction import Transaction, TxOutput
from winflux.errors import ValidationError
from winflux.offline import note as N
from winflux.wallet.vault_builder import build_note_claim, build_vault_refund, build_voucher_claim

from .conftest import WFLX, mine
from .test_notes import R, World, addr_out, note_out, soft
from .test_vaults import advance, issue, to_deadline, vchain

FEE = 1000
CAP = 30 * WFLX


@pytest.fixture(params=["p256", "ed25519"])
def kt(request):
    return request.param


@pytest.fixture
def w(keys, kt):
    return World(keys, key_type=kt, cap=CAP, software_slots=True)


def claim(w, pay, *, mine_it=True):
    tx = build_note_claim(pay, w.chain.get_vault(w.vid), w.chain.params)
    if mine_it:
        mine(w.chain, w.keys, [tx])
    return tx


def slot_of(w, i=0):
    return w.chain.get_vault(w.vid).slots[i]


def direct(w, to_address, value=None, req=R[0], slot=0):
    return w.first(None, req, slot=slot, outputs=[addr_out(value or w.cap, to_address)])


def rejects(w, tx, match=None):
    with pytest.raises(ValidationError, match=match):
        w.chain.ledger.check(tx, w.chain.height + 1)


# ================================================================== sucesso
def test_direct_claim_pays_the_address_and_updates_slot_and_supply(w, keys):
    supply = w.chain.total_supply()
    before = w.chain.balance(keys["bob"].address)
    root = w.chain.ledger.state_root()
    claim(w, direct(w, keys["bob"].address))
    assert w.chain.balance(keys["bob"].address) == before + CAP - FEE
    s = slot_of(w)
    assert s.paid == CAP and len(s.settled) == 1 and len(s.spends) == 1 and s.claimed_by == s.note_state_digest()
    assert not w.chain.get_vault(w.vid).fraud
    assert w.chain.total_supply() == supply + 50 * WFLX            # só a recompensa do bloco (a taxa vai ao minerador)
    assert w.chain.ledger.state_root() != root


def test_chain_alice_bob_carlos_dave_settles_the_final_leaf(w, keys):
    bob, carlos, dave = soft(11, w.key_type), soft(12, w.key_type), soft(13, w.key_type)
    p1 = w.first(bob, R[0])
    p2 = w.forward(p1, bob, [note_out(CAP, carlos)], R[1])
    p3 = w.forward(p2, carlos, [note_out(CAP, dave)], R[2])
    p4 = w.forward(p3, dave, [addr_out(20 * WFLX, keys["carol"].address), addr_out(10 * WFLX, keys["bob"].address)],
                   R[3], leaf=0)
    claim(w, p4)
    assert w.chain.balance(keys["carol"].address) == 20 * WFLX - FEE
    assert len(slot_of(w).spends) == 4 and slot_of(w).paid == 20 * WFLX
    claim(w, replace(p4, leaf=1))                                  # a outra folha da mesma cadeia: sem conflito
    assert w.chain.balance(keys["bob"].address) >= 10 * WFLX - FEE
    s = slot_of(w)
    assert s.paid == CAP and len(s.settled) == 2 and not w.chain.get_vault(w.vid).fraud and s.compensated == 0


def test_max_hops_is_accepted_and_one_more_is_rejected(w, keys):
    signers = [soft(20 + i, w.key_type) for i in range(N.MAX_HOPS)]
    pay = w.first(signers[0], R[0])
    for i in range(1, N.MAX_HOPS - 1):
        pay = w.forward(pay, signers[i - 1], [note_out(CAP, signers[i])], bytes([i + 1]) * 16)
    pay = w.forward(pay, signers[N.MAX_HOPS - 2], [addr_out(CAP, keys["bob"].address)], b"\x77" * 16)
    assert len(pay.hops) == N.MAX_HOPS
    tx = claim(w, pay)
    assert slot_of(w).paid == CAP
    payload = copy.deepcopy(tx.payload)
    payload["hops"] = payload["hops"] + payload["hops"][-1:]
    with pytest.raises(ValidationError):
        V.parse_note_claim(payload)


def test_two_independent_slots_do_not_interfere(w, keys):
    claim(w, direct(w, keys["bob"].address, slot=0))
    claim(w, direct(w, keys["carol"].address, slot=1, req=R[1]))
    assert [s.paid for s in w.chain.get_vault(w.vid).slots] == [CAP, CAP]


def test_claim_can_be_submitted_by_anyone_and_output_is_fixed(w, keys):
    tx = claim(w, direct(w, keys["bob"].address), mine_it=False)
    rejects(w, replace(tx, outputs=(TxOutput(tx.outputs[0].value, keys["mallory"].address),)), "não confere")
    rejects(w, replace(tx, outputs=(TxOutput(tx.outputs[0].value + 1, keys["bob"].address),)), "não confere")
    assert w.chain.check_transaction(tx) == FEE


# ================================================================== reapresentação / tipo de folha / prazo / tipo de vaga
def test_replay_of_a_settled_leaf_is_rejected_and_not_compensated(w, keys):
    pay = direct(w, keys["bob"].address)
    claim(w, pay)
    with pytest.raises(ValidationError, match="já liquidada"):
        build_note_claim(pay, w.chain.get_vault(w.vid), w.chain.params)
    assert slot_of(w).compensated == 0 and slot_of(w).comp_leaves == []


def test_only_address_leaves_settle(w, keys):
    bob = soft(11, w.key_type)
    with pytest.raises(ValidationError, match="endereço"):
        build_note_claim(w.first(bob, R[0]), w.chain.get_vault(w.vid), w.chain.params)


def test_dust_leaf_is_not_claimable(w, keys):
    pay = w.first(None, R[0], outputs=[addr_out(CAP - 5, keys["bob"].address), addr_out(5, keys["carol"].address)])
    with pytest.raises(ValidationError, match="mínimo"):
        build_note_claim(replace(pay, leaf=1), w.chain.get_vault(w.vid), w.chain.params)
    claim(w, pay)                                                  # a folha grande continua liquidável


def test_deadline_closed_vault_and_unkeyed_vault(keys, kt):
    w = World(keys, key_type=kt, cap=CAP, software_slots=True)
    tx = claim(w, direct(w, keys["bob"].address), mine_it=False)
    advance(w.chain, keys, V.claim_deadline(w.chain.get_vault(w.vid), w.chain.params) - w.chain.height - 1)
    w.chain.check_transaction(tx)                                  # o bloco seguinte é o último em que ainda vale
    advance(w.chain, keys, 1)
    rejects(w, tx, "prazo")
    mine(w.chain, keys, [build_vault_refund(w.chain.get_vault(w.vid), w.chain.params)])
    rejects(w, tx, "encerrado")
    u = World(keys, key_type=kt, cap=CAP, with_slot_keys=False)    # vaga de voucher (sem chave própria)
    pay = N.OfflinePayment(u.proof(0), 0, (tx_hop(u, keys),), 0)
    with pytest.raises(ValidationError, match="sem chave própria"):
        build_note_claim(pay, u.chain.get_vault(u.vid), u.chain.params)


def tx_hop(w, keys):
    return N.spend_root(chain_hash=w.chash(), vault_id=w.vid, slot=0, cap=w.cap,
                        outputs=[addr_out(w.cap, keys["bob"].address)], request_id=R[0], signer=soft(1, w.key_type))


def test_voucher_route_stays_closed_for_keyed_slots(w, keys):
    from .test_vaults import devs
    with pytest.raises(ValidationError, match="note_claim"):
        build_voucher_claim(issue(w.chain, devs()[w.key_type], w.vid, 0, 5 * WFLX, keys["bob"]),
                            w.chain.get_vault(w.vid), w.chain.params)


# ================================================================== conflito (gasto duplo) e R1-R9
def test_double_spend_of_root_first_is_paid_loser_by_collateral(w, keys):
    claim(w, direct(w, keys["bob"].address, req=R[0]))
    s = slot_of(w)
    spends, supply = dict(s.spends), w.chain.total_supply()
    loser = direct(w, keys["carol"].address, req=R[1])             # Alice gastou a raiz de novo
    claim(w, loser)
    s = slot_of(w)
    assert w.chain.get_vault(w.vid).fraud and s.compensated == CAP and s.collateral_left == 0
    assert s.paid == CAP and s.spends == spends and len(s.comp_leaves) == 1   # ramo perdedor NÃO é registrado
    assert w.chain.balance(keys["carol"].address) == CAP - FEE
    assert w.chain.total_supply() == supply + 50 * WFLX
    with pytest.raises(ValidationError):                            # R3 (já indenizada) / R1 (colateral esgotado)
        build_note_claim(loser, w.chain.get_vault(w.vid), w.chain.params)


def test_r1_r2_total_compensation_never_exceeds_the_contested_value(w, keys):
    claim(w, direct(w, keys["bob"].address, req=R[0]))              # vencedor: 30
    split = w.first(None, R[1], outputs=[addr_out(10 * WFLX, keys["carol"].address),
                                         addr_out(20 * WFLX, keys["mallory"].address)])
    claim(w, split)                                                 # 10 do colateral
    claim(w, replace(split, leaf=1))                                # 20 do colateral
    assert slot_of(w).compensated == CAP and slot_of(w).collateral_left == 0
    third = direct(w, keys["alice"].address, req=R[2])
    with pytest.raises(ValidationError):
        build_note_claim(third, w.chain.get_vault(w.vid), w.chain.params)
    rejects(w, replace(claim(w, direct(w, keys["bob"].address, req=R[0], slot=1), mine_it=False),
                       outputs=(TxOutput(1, keys["bob"].address),)))


def test_r9_limit_on_compensation_events(keys, kt):
    w = World(keys, key_type=kt, cap=CAP, software_slots=True, max_compensations_per_slot=2, vault_collateral_min_pct=100)
    claim(w, direct(w, keys["bob"].address, req=R[0]))
    outs = [addr_out(5 * WFLX, keys["carol"].address)] * 3 + [addr_out(15 * WFLX, keys["mallory"].address)]
    split = w.first(None, R[1], outputs=outs)
    claim(w, replace(split, leaf=0))
    claim(w, replace(split, leaf=1))
    with pytest.raises(ValidationError, match="limite de indenizações"):
        build_note_claim(replace(split, leaf=2), w.chain.get_vault(w.vid), w.chain.params)
    assert len(slot_of(w).comp_leaves) == 2


def test_double_spend_by_an_intermediate_holder_is_a_conflict_at_that_hop(w, keys):
    bob, carlos, dave = soft(11, w.key_type), soft(12, w.key_type), soft(13, w.key_type)
    p1 = w.first(bob, R[0])
    to_carlos = w.forward(p1, bob, [addr_out(CAP, keys["carol"].address)], R[1])
    to_dave = w.forward(p1, bob, [addr_out(CAP, keys["mallory"].address)], R[2])   # Bob gasta a mesma nota 2x
    claim(w, to_carlos)
    s = slot_of(w)
    assert s.paid == CAP and not w.chain.get_vault(w.vid).fraud and len(s.spends) == 2
    claim(w, to_dave)                                               # compartilha T1, conflita em T2
    s = slot_of(w)
    assert w.chain.get_vault(w.vid).fraud and s.compensated == CAP and len(s.spends) == 2
    assert w.chain.balance(keys["mallory"].address) == CAP - FEE


def test_descendants_of_a_losing_branch_keep_conflicting(w, keys):
    claim(w, direct(w, keys["bob"].address, req=R[0]))
    eve = soft(15, w.key_type)
    p1 = w.first(eve, R[1])                                         # ramo perdedor (outra gasto da raiz)
    deep = w.forward(p1, eve, [addr_out(10 * WFLX, keys["carol"].address), addr_out(20 * WFLX, keys["mallory"].address)],
                     R[2])
    claim(w, deep)
    assert slot_of(w).paid == CAP and slot_of(w).compensated == 10 * WFLX
    claim(w, replace(deep, leaf=1))
    assert slot_of(w).compensated == CAP and slot_of(w).paid == CAP
    assert sum(1 for k in slot_of(w).spends) == 1                   # só a raiz do vencedor


def test_losing_branch_first_then_winner_is_paid_by_collateral_in_chain_order(w, keys):
    """Ordem de pagamento = ordem na cadeia (R5): quem entra primeiro vence, independentemente de quem é 'honesto'."""
    claim(w, direct(w, keys["mallory"].address, req=R[1]))
    claim(w, direct(w, keys["bob"].address, req=R[0]))
    assert w.chain.balance(keys["mallory"].address) >= CAP - FEE and w.chain.balance(keys["bob"].address) == CAP - FEE


def test_settled_leaf_cap_per_slot_is_enforced(keys, kt):
    w = World(keys, key_type=kt, cap=100 * WFLX, software_slots=True)
    chain_signers = [soft(30 + i, kt) for i in range(5)]
    pay = w.first(chain_signers[0], R[0])
    leaves = 0
    for i in range(4):                                              # cada salto: 3 folhas-endereço + 1 nota
        outs = [addr_out(2 * WFLX, keys["bob"].address)] * 3
        rest = pay.hops[-1].tx.outputs[pay.leaf].value - 6 * WFLX
        pay = w.forward(pay, chain_signers[i], outs + [note_out(rest, chain_signers[i + 1])], bytes([i + 1]) * 16, leaf=3)
        for j in range(3):
            tx = build_note_claim(replace(pay, leaf=j), w.chain.get_vault(w.vid), w.chain.params)
            mine(w.chain, keys, [tx])
            leaves += 1
    assert len(slot_of(w).settled) == leaves == 12 <= V.MAX_SETTLED_PER_SLOT


# ================================================================== adulteração (cada defeito => ValidationError)
def _base(w, keys):
    bob, carlos = soft(11, w.key_type), soft(12, w.key_type)
    p1 = w.first(bob, R[0])
    p2 = w.forward(p1, bob, [addr_out(CAP, keys["carol"].address)], R[1])
    return p2, build_note_claim(p2, w.chain.get_vault(w.vid), w.chain.params)


def _forge(tx, payload):
    return Transaction(tx.chain_id, tx.inputs, tx.outputs, kind="note_claim", payload=payload)


def _flip(hexstr, pos=0):
    return hexstr[:pos] + ("0" if hexstr[pos] != "0" else "1") + hexstr[pos + 1:]


def test_every_field_mutation_is_rejected(w, keys):
    _, tx = _base(w, keys)
    w.chain.check_transaction(tx)
    n_hops = len(tx.payload["hops"])
    muts = []
    for hi in range(n_hops):
        for field, positions in (("tx", (0, 3, 70, 150, -3)), ("pubkey", (0, 5, -2)), ("sig", (0, 40, 120))):
            for pos in positions:
                muts.append((hi, field, pos))
    for hi, field, pos in muts:
        p = copy.deepcopy(tx.payload)
        v = p["hops"][hi][field]
        p["hops"][hi][field] = _flip(v, pos % len(v))
        rejects(w, _forge(tx, p))
    for mutate in (lambda p: p.update(slot=1), lambda p: p.update(leaf=1), lambda p: p.update(leaf=7),
                   lambda p: p.update(vault_id="00" * 32), lambda p: p.update(extra=1),
                   lambda p: p.pop("leaf"), lambda p: p.update(hops=p["hops"][:1]),
                   lambda p: p.update(hops=p["hops"][::-1]), lambda p: p.update(hops=p["hops"] * 2),
                   lambda p: p.update(hops=[]), lambda p: p.update(slot=True), lambda p: p.update(slot=-1),
                   lambda p: p["hops"][0].update(key_type="p256" if p["hops"][0]["key_type"] != "p256" else "ed25519"),
                   lambda p: p["hops"][0].update(att={"x": 1}), lambda p: p["hops"][0].pop("sig"),
                   lambda p: p["hops"][1].update(tx="zz"), lambda p: p["hops"][1].update(tx="abc")):
        p = copy.deepcopy(tx.payload)
        mutate(p)
        rejects(w, _forge(tx, p))
    for bad in (None, [], "x", 3, {"hops": []}):
        rejects(w, _forge(tx, bad))


def _payload(pay, vid):
    return {"vault_id": vid, "slot": pay.slot, "leaf": pay.leaf,
            "hops": [{"tx": h.tx.to_bytes().hex(), "key_type": h.key_type, "pubkey": h.pubkey.hex(),
                      "sig": h.signature.hex()} for h in pay.hops]}


def test_wrong_signers_and_wrong_owners(w, keys, kt):
    bob, mallory = soft(11, kt), soft(14, kt)
    p1 = w.first(bob, R[0])
    forged_first = w.first(bob, R[0], signer=mallory)                     # não é a chave da vaga
    with pytest.raises(ValidationError, match="dona"):
        V.plan_note_claim(w.chain.get_vault(w.vid), V.parse_note_claim(_payload(forged_first, w.vid)),
                          w.chain.params, None)
    stolen = w.forward(p1, mallory, [addr_out(CAP, keys["mallory"].address)], R[1])  # Mallory gasta nota do Bob
    with pytest.raises(ValidationError, match="dona"):
        build_note_claim(stolen, w.chain.get_vault(w.vid), w.chain.params)


def test_value_conservation_and_foreign_network(w, keys):
    pay = direct(w, keys["bob"].address)
    hop = pay.hops[0]
    inflated = N.make_hop(chain_hash=w.chash(), vault_id=w.vid, input_note=N.root_note_id(w.vid, 0), input_value=CAP,
                          outputs=[addr_out(CAP + 1, keys["bob"].address)], request_id=R[0], signer=w.slot_signers[0])
    with pytest.raises(ValidationError, match="conserva"):
        build_note_claim(replace(pay, hops=(inflated,)), w.chain.get_vault(w.vid), w.chain.params)
    other_net = N.make_hop(chain_hash=b"\x09" * 32, vault_id=w.vid, input_note=N.root_note_id(w.vid, 0), input_value=CAP,
                           outputs=[addr_out(CAP, keys["bob"].address)], request_id=R[0], signer=w.slot_signers[0])
    with pytest.raises(ValidationError, match="outra rede"):
        build_note_claim(replace(pay, hops=(other_net,)), w.chain.get_vault(w.vid), w.chain.params)
    wrong_value = N.make_hop(chain_hash=w.chash(), vault_id=w.vid, input_note=N.root_note_id(w.vid, 0), input_value=CAP - 1,
                             outputs=[addr_out(CAP - 1, keys["bob"].address)], request_id=R[0], signer=w.slot_signers[0])
    with pytest.raises(ValidationError, match="esperada"):
        build_note_claim(replace(pay, hops=(wrong_value,)), w.chain.get_vault(w.vid), w.chain.params)
    assert hop.tx.outputs[0].value == CAP


def test_chain_must_follow_a_note_output(w, keys):
    bob = soft(11, w.key_type)
    p1 = w.first(None, R[0], outputs=[addr_out(10 * WFLX, keys["carol"].address), note_out(20 * WFLX, bob)])
    p_bad = w.forward(p1, bob, [addr_out(10 * WFLX, keys["bob"].address)], R[1], spend=0)   # gasta saída-endereço
    with pytest.raises(ValidationError):
        build_note_claim(p_bad, w.chain.get_vault(w.vid), w.chain.params)
    ok = w.forward(p1, bob, [addr_out(20 * WFLX, keys["bob"].address)], R[1], spend=1)
    claim(w, ok)
    claim(w, replace(p1, hops=p1.hops, leaf=0))                      # a folha-endereço do 1º salto também é liquidável
    assert slot_of(w).paid == CAP and not w.chain.get_vault(w.vid).fraud


# ================================================================== fuzz estrutural
def test_fuzz_payload_mutations_only_raise_validation_error(w, keys):
    _, tx = _base(w, keys)
    rng = random.Random(7)
    base = json.loads(json.dumps(tx.payload))

    def mutate(o):
        if isinstance(o, dict):
            k = rng.choice(list(o)) if o else None
            if k is None:
                return o
            r = rng.random()
            if r < .2:
                del o[k]
            elif r < .4:
                o[k] = rng.choice([None, True, -1, 2**70, "", "g" * 7, [], {}, 1.5, "ab" * rng.randrange(0, 400)])
            elif r < .5:
                o["zz"] = 1
            else:
                o[k] = mutate(o[k])
        elif isinstance(o, list):
            if o and rng.random() < .3:
                o.pop(rng.randrange(len(o)))
            elif o and rng.random() < .3:
                o.append(copy.deepcopy(rng.choice(o)))
            elif o:
                i = rng.randrange(len(o))
                o[i] = mutate(o[i])
        elif isinstance(o, str) and o:
            i = rng.randrange(len(o))
            return o[:i] + rng.choice("0123456789abcdefxyz") + o[i + 1:]
        elif isinstance(o, int):
            return o + rng.choice([-1, 1, 255, 2**40])
        return o

    for _ in range(600):
        p = mutate(copy.deepcopy(base))
        try:
            t = Transaction.from_dict(json.loads(json.dumps(_forge(tx, p).to_dict())))
            w.chain.ledger.check(t, w.chain.height + 1)
        except ValidationError:
            pass


# ================================================================== atomicidade, undo, determinismo
def test_ledger_undo_restores_exact_state_for_win_and_conflict(w, keys):
    for pay in (direct(w, keys["bob"].address, req=R[0]), direct(w, keys["carol"].address, req=R[1])):
        snap, utxos, supply, root = (w.chain.vaults.snapshot(), len(w.chain.utxo), w.chain.total_supply(),
                                     w.chain.ledger.state_root())
        tx = build_note_claim(pay, w.chain.get_vault(w.vid), w.chain.params)
        h = w.chain.height + 1
        undo = w.chain.ledger.apply(tx, w.chain.ledger.check(tx, h))
        assert w.chain.vaults.snapshot() != snap
        w.chain.ledger.revert(undo)
        assert (w.chain.vaults.snapshot(), len(w.chain.utxo), w.chain.total_supply(), w.chain.ledger.state_root()) == \
               (snap, utxos, supply, root)
        mine(w.chain, w.keys, [tx])


def test_two_nodes_replay_to_identical_state_and_root(w, keys):
    bob = soft(11, w.key_type)
    p1 = w.first(bob, R[0])
    pay = w.forward(p1, bob, [addr_out(10 * WFLX, keys["carol"].address), addr_out(20 * WFLX, keys["bob"].address)], R[1])
    claim(w, pay)
    claim(w, direct(w, keys["mallory"].address, req=R[2]))          # conflito
    claim(w, replace(pay, leaf=1))
    to_deadline(w.chain, keys, w.vid)
    advance(w.chain, keys, 1)
    mine(w.chain, keys, [build_vault_refund(w.chain.get_vault(w.vid), w.chain.params)])
    other = vchain(keys)
    for b in w.chain.blocks[1:]:
        other.add_block(Block.from_dict(json.loads(json.dumps(b.to_dict()))))
    assert other.vaults.snapshot() == w.chain.vaults.snapshot()
    assert other.ledger.state_root() == w.chain.ledger.state_root()
    assert other.total_supply() == w.chain.total_supply()


def test_tampered_claim_inside_a_block_leaves_state_untouched(w, keys):
    good = claim(w, direct(w, keys["bob"].address), mine_it=False)
    bad = replace(good, outputs=(TxOutput(1, keys["bob"].address),))
    snap, utxos, supply = w.chain.vaults.snapshot(), len(w.chain.utxo), w.chain.total_supply()
    tmpl = w.chain.create_block(keys["producer"].public_hex, keys["producer"].address, [])
    forged = Block.build(tmpl.height, tmpl.prev_hash, tmpl.timestamp, tmpl.producer, [tmpl.transactions[0], good, bad])
    w.chain.consensus.seal(forged, keys["producer"])
    with pytest.raises(ValidationError):
        w.chain.add_block(forged)
    assert (w.chain.vaults.snapshot(), len(w.chain.utxo), w.chain.total_supply()) == (snap, utxos, supply)


def test_proof_after_claim_shows_slot_as_occupied_to_new_receivers(w, keys):
    from winflux.consensus.poa import ProofOfAuthority
    from winflux.offline import proofs as P
    claim(w, direct(w, keys["bob"].address))
    vs = P.verify_vault_proof(P.build_vault_proof(w.chain, w.vid, 0), w.chain.params, ProofOfAuthority())
    assert vs.paid == CAP and vs.claimed
    vs1 = P.verify_vault_proof(P.build_vault_proof(w.chain, w.vid, 1), w.chain.params, ProofOfAuthority())
    assert not vs1.claimed and vs1.paid == 0


def test_transaction_survives_json_and_parse_roundtrip(w, keys):
    _, tx = _base(w, keys)
    again = Transaction.from_dict(json.loads(json.dumps(tx.to_dict())))
    assert again.txid == tx.txid and again.kind == "note_claim"
    assert w.chain.check_transaction(again) == FEE
    mine(w.chain, keys, [again])
    assert w.chain.balance(keys["carol"].address) == CAP - FEE


def test_r2_caps_compensation_at_the_contested_value_even_with_surplus_collateral(keys, kt):
    w = World(keys, key_type=kt, cap=CAP, software_slots=True, pct=200)        # colateral = 2 x cap
    claim(w, direct(w, keys["bob"].address, req=R[0]))
    claim(w, direct(w, keys["carol"].address, req=R[1]))                        # 30 do colateral (sobram 30)
    s = slot_of(w)
    assert s.compensated == CAP and s.collateral_left == CAP
    with pytest.raises(ValidationError, match="valor contestado"):
        build_note_claim(direct(w, keys["mallory"].address, req=R[2]), w.chain.get_vault(w.vid), w.chain.params)


def test_settled_leaves_per_slot_are_capped(keys, kt, monkeypatch):
    monkeypatch.setattr(V, "MAX_SETTLED_PER_SLOT", 2)
    w = World(keys, key_type=kt, cap=CAP, software_slots=True)
    pay = w.first(None, R[0], outputs=[addr_out(10 * WFLX, keys["bob"].address)] * 3)
    claim(w, replace(pay, leaf=0))
    claim(w, replace(pay, leaf=1))
    with pytest.raises(ValidationError, match="limite de folhas"):
        build_note_claim(replace(pay, leaf=2), w.chain.get_vault(w.vid), w.chain.params)


def test_next_hop_must_spend_a_note_output_not_an_address_output(w, keys):
    bob = soft(11, w.key_type)
    p1 = w.first(None, R[0], outputs=[addr_out(10 * WFLX, keys["carol"].address), note_out(20 * WFLX, bob)])
    hop2 = N.spend_output(p1.hops[0], 0, outputs=[addr_out(10 * WFLX, keys["bob"].address)], request_id=R[1], signer=bob)
    with pytest.raises(ValidationError):
        N.verify_hop_chain((p1.hops[0], hop2), chain_hash=w.chash(), vault_id=w.vid, slot=0, cap=CAP,
                           root_key_type=w.key_type, root_key_hex=w.slot_signers[0].public_hex, leaf=0)
