"""A2: chave própria por vaga (base das notas transferíveis) — consenso, prova e adulteração."""
import copy
from dataclasses import replace

import pytest

from winflux.blockchain import state_root as SR
from winflux.consensus.poa import ProofOfAuthority
from winflux.crypto.keys import KeyPair, P256KeyPair
from winflux.errors import ValidationError
from winflux.offline import proofs as P
from winflux.wallet.vault_builder import build_vault_open, build_vault_refund, build_voucher_claim

from .conftest import WFLX, mine
from .test_vaults import advance, devs, forge_open, issue, to_deadline, vchain

POA = ProofOfAuthority()


def slot_key(kind, n):
    return (KeyPair(bytes([n]) * 32) if kind == "ed25519" else P256KeyPair(private_value=1000 + n)).public_hex


def open_keyed(chain, keys, dev, n=2, cap=10 * WFLX, ttl=6):
    sk = [slot_key(dev.key_type, 50 + i) for i in range(n)]
    tx = build_vault_open(keys["alice"], chain.utxo.utxos_for(keys["alice"].address), dev, (cap,) * n, 100, ttl,
                          keys["alice"].address, chain.params, slot_keys=sk)
    mine(chain, keys, [tx])
    return tx.txid, sk


@pytest.fixture(params=["ed25519", "p256"])
def dev(request):
    return devs()[request.param]


def test_keys_are_registered_and_proven(keys, dev):
    chain = vchain(keys)
    vid, sk = open_keyed(chain, keys, dev)
    assert [s.key for s in chain.get_vault(vid).slots] == sk
    for i in range(2):
        vs = P.verify_vault_proof(P.build_vault_proof(chain, vid, i), chain.params, POA)
        assert vs.slot_key == sk[i] and vs.key_type == dev.key_type


def test_voucher_route_is_closed_for_keyed_slots(keys, dev):
    chain = vchain(keys)
    vid, _ = open_keyed(chain, keys, dev)
    with pytest.raises(ValidationError, match="note_claim"):
        build_voucher_claim(issue(chain, dev, vid, 0, 5 * WFLX, keys["bob"]), chain.get_vault(vid), chain.params)


def test_unkeyed_vaults_are_unchanged(keys, dev):
    chain = vchain(keys)
    tx = build_vault_open(keys["alice"], chain.utxo.utxos_for(keys["alice"].address), dev, (10 * WFLX,), 100, 6,
                          keys["alice"].address, chain.params)
    mine(chain, keys, [tx])
    assert chain.get_vault(tx.txid).slots[0].key == ""
    mine(chain, keys, [build_voucher_claim(issue(chain, dev, tx.txid, 0, 5 * WFLX, keys["bob"]),
                                          chain.get_vault(tx.txid), chain.params)])
    assert chain.balance(keys["bob"].address) > 0


def test_keyed_vault_can_be_refunded(keys, dev):
    chain = vchain(keys)
    vid, _ = open_keyed(chain, keys, dev)
    to_deadline(chain, keys, vid)
    advance(chain, keys, 1)
    before = chain.total_supply()
    mine(chain, keys, [build_vault_refund(chain.get_vault(vid), chain.params)])
    assert chain.vaults.total_locked == 0 and chain.total_supply() == before + 50 * WFLX


def test_slot_keys_change_the_state_root(keys, dev):
    a, b = vchain(keys), vchain(keys)
    va, _ = open_keyed(a, keys, dev)
    tx = build_vault_open(keys["alice"], b.utxo.utxos_for(keys["alice"].address), dev, (10 * WFLX,) * 2, 100, 6,
                          keys["alice"].address, b.params,
                          slot_keys=[slot_key(dev.key_type, 90), slot_key(dev.key_type, 91)])
    mine(b, keys, [tx])
    assert a.tip.state_root != b.tip.state_root


@pytest.mark.parametrize("make,msg", [
    (lambda k: k[:1], "uma chave por vaga"),                              # contagem errada
    (lambda k: k + k[:1], "uma chave por vaga"),
    (lambda k: [k[0], k[0]], "repetidas"),
    (lambda k: [k[0], "zz" * (len(k[0]) // 2)], "chave de vaga inválida"),
    (lambda k: [k[0], k[1][:-2]], "chave de vaga inválida"),               # comprimento errado
    (lambda k: [k[0], 7], "chave de vaga inválida"),
    (lambda k: "texto", "uma chave por vaga"),
])
def test_slot_key_validation(keys, dev, make, msg):
    chain = vchain(keys)
    good = [slot_key(dev.key_type, 60), slot_key(dev.key_type, 61)]
    with pytest.raises(ValidationError, match=msg):
        chain.check_transaction(forge_open(chain, keys, dev, {"slot_keys": make(good)}))


def test_p256_slot_key_must_be_compressed(keys):
    dev = devs()["p256"]
    chain = vchain(keys)
    k = slot_key("p256", 70)
    bad = ["04" + k[2:], k]
    with pytest.raises(ValidationError, match="comprimida"):
        chain.check_transaction(forge_open(chain, keys, dev, {"slot_keys": bad}))


def test_slot_keys_are_covered_by_the_proof_of_possession(keys, dev):
    chain = vchain(keys)
    sk = [slot_key(dev.key_type, 80), slot_key(dev.key_type, 81)]
    tx = forge_open(chain, keys, dev, {"slot_keys": sk})
    swapped = replace(tx, payload={**tx.payload, "slot_keys": [sk[0], slot_key(dev.key_type, 99)]})
    with pytest.raises(ValidationError):                                   # pop/assinaturas deixam de bater
        chain.check_transaction(swapped)


def test_tampering_the_slot_key_in_a_proof_is_rejected(keys, dev):
    chain = vchain(keys)
    vid, sk = open_keyed(chain, keys, dev)
    proof = P.build_vault_proof(chain, vid, 0)
    bad = copy.deepcopy(proof)
    bad["slot"]["record"]["key"] = sk[1]
    with pytest.raises(ValidationError):
        P.verify_vault_proof(bad, chain.params, POA)
    bad2 = copy.deepcopy(proof)
    bad2["slot"]["record"]["key"] = ""
    with pytest.raises(ValidationError):
        P.verify_vault_proof(bad2, chain.params, POA)


# ------------------------------------------------------------------ robustez: só ValidationError no consenso
def _junk():
    return [None, -1, 0, 2**70, "", "x", [], {}, True, False, 1.5, [1], {"a": 1}, "00" * 32, "g" * 64, [[]], [{}]]


def test_fuzz_vault_open_payload_only_validation_errors(keys, dev):
    """Regressão: `key_type` não hasheável levantava TypeError dentro da validação de consenso."""
    import random
    rnd = random.Random(21)
    chain = vchain(keys)
    base = forge_open(chain, keys, dev, {"slot_keys": [slot_key(dev.key_type, 1), slot_key(dev.key_type, 2)]})
    fields = list(base.payload)
    for _ in range(3000):
        payload = dict(base.payload)
        for _ in range(rnd.choice([1, 1, 2])):
            payload[rnd.choice(fields)] = copy.deepcopy(rnd.choice(_junk()))
        try:
            chain.check_transaction(replace(base, payload=payload))
        except ValidationError:
            pass


@pytest.mark.parametrize("kind", ["voucher_claim", "vault_refund"])
def test_fuzz_other_vault_payloads_only_validation_errors(keys, dev, kind):
    import random
    rnd = random.Random(22)
    chain = vchain(keys)
    vid, _ = open_keyed(chain, keys, dev)
    from winflux.blockchain.transaction import Transaction
    payload0 = {"voucher": "00" * 175} if kind == "voucher_claim" else {"vault_id": vid}
    for _ in range(1500):
        payload = {k: copy.deepcopy(rnd.choice(_junk())) if rnd.random() < 0.7 else v for k, v in payload0.items()}
        if rnd.random() < 0.3:
            payload[rnd.choice(["x", "voucher", "vault_id"])] = copy.deepcopy(rnd.choice(_junk()))
        tx = Transaction(chain.params.chain_id, (), (), kind=kind, payload=payload)
        try:
            chain.check_transaction(tx)
        except ValidationError:
            pass
