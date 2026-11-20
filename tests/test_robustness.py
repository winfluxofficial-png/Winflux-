"""Fase 0: sondas adversariais da auditoria, agora permanentes (determinísticas)."""
import copy
import random

import pytest

from winflux.blockchain.block import Block
from winflux.blockchain.transaction import Transaction
from winflux.crypto.keys import KeyPair, verify_signature
from winflux.errors import ValidationError
from winflux.wallet.transaction_builder import build_transfer

from .conftest import WFLX, make_chain, mine

JUNK = [None, -1, 0, 1, 2**70, -2**70, "x", "", [], {}, True, False, 1.5, "0" * 64, "g" * 64,
        "00" * 32, "A" * 200, [1], {"a": 1}]


def _paths(o, pre=()):
    yield pre
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _paths(v, pre + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _paths(v, pre + (i,))


def _set(o, path, val):
    for k in path[:-1]:
        o = o[k]
    o[path[-1]] = val


def test_ed25519_rejects_non_canonical_s():
    k = KeyPair.generate()
    sig = k.sign(b"m")
    L = 2**252 + 27742317777372353535851937790883648493
    forged = sig[:32] + (int.from_bytes(sig[32:], "little") + L).to_bytes(32, "little")
    assert verify_signature(k.public_key, sig, b"m") and not verify_signature(k.public_key, forged, b"m")


def test_fuzz_block_parsing_never_crashes(chain, keys):
    tx = build_transfer(keys["alice"], chain.utxo.utxos_for(keys["alice"].address),
                        keys["bob"].address, 10 * WFLX, 1000, chain.params.chain_id)
    base = mine(chain, keys, [tx]).to_dict()
    rnd = random.Random(7)
    for _ in range(4000):
        d = copy.deepcopy(base)
        for _ in range(rnd.choice([1, 1, 2, 3])):
            _set(d, rnd.choice([p for p in _paths(d) if p]), copy.deepcopy(rnd.choice(JUNK)))
        try:
            Block.from_dict(d)
        except ValidationError:
            pass  # qualquer outra exceção derruba o teste


def test_fuzz_validation_accepts_only_identical_tx(chain, keys):
    base = build_transfer(keys["alice"], chain.utxo.utxos_for(keys["alice"].address),
                          keys["bob"].address, 10 * WFLX, 1000, chain.params.chain_id).to_dict()
    rnd = random.Random(11)
    for _ in range(2000):
        d = copy.deepcopy(base)
        _set(d, rnd.choice([p for p in _paths(d) if p]), copy.deepcopy(rnd.choice(JUNK)))
        try:
            chain.check_transaction(Transaction.from_dict(d))
        except ValidationError:
            continue
        assert d == base, "uma transação ALTERADA foi aceita (maleabilidade)"


def test_property_supply_and_balances_under_random_operations(keys):
    chain = make_chain(keys)
    rnd = random.Random(3)
    names, pending = ["alice", "bob", "carol"], []
    for step in range(200):
        s, r = keys[rnd.choice(names)], keys[rnd.choice(names)]
        bal = chain.balance(s.address)
        if bal > 5000:
            amt = rnd.randint(1, min(bal // 2, 50 * WFLX))
            pending.append(build_transfer(s, chain.utxo.utxos_for(s.address), r.address, amt,
                                          rnd.choice([1000, 5000]), chain.params.chain_id))
            if rnd.random() < 0.3:  # tentativa de gasto duplo: mesma moeda, outro destino
                pending.append(build_transfer(s, chain.utxo.utxos_for(s.address), keys["mallory"].address,
                                              amt, 1000, chain.params.chain_id))
        if step % 5 == 4:
            mine(chain, keys, pending)
            pending = []
        total = sum(chain.balance(k.address) for k in keys.values())
        assert total == chain.total_supply() <= chain.params.max_supply
    assert chain.balance(keys["mallory"].address) == 0       # nenhum gasto duplo passou
    assert all(o.value > 0 for o in chain.utxo._utxos.values())
