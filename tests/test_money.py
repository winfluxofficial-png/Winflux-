"""Etapas 2-3: UTXO, transferências, taxas, anti gasto duplo, oferta máxima."""
from dataclasses import replace

import pytest

from winflux.blockchain.block import Block
from winflux.blockchain.transaction import Transaction, TxInput, TxOutput
from winflux.errors import InsufficientFunds, ValidationError, WalletError
from winflux.wallet.transaction_builder import build_transfer

from .conftest import WFLX, T0, make_chain, mine

FEE = 1000


def pay(chain, sender, to, amount, fee=FEE, chain_id=None):
    return build_transfer(sender, chain.utxo.utxos_for(sender.address), to.address,
                          amount, fee, chain_id or chain.params.chain_id)


def total_of_all(chain, keys):
    return sum(chain.balance(k.address) for k in keys.values())


def test_simple_transfer_with_change_and_fee(chain, keys):
    tx = pay(chain, keys["alice"], keys["bob"], 1250 * WFLX + 50_000_000)  # 1250,5 WFLX
    mine(chain, keys, [tx])
    assert chain.balance(keys["bob"].address) == 1250 * WFLX + 50_000_000
    assert chain.balance(keys["alice"].address) == 5_000_000 * WFLX - (1250 * WFLX + 50_000_000) - FEE
    assert chain.balance(keys["producer"].address) == 50 * WFLX + FEE  # recompensa + taxa
    assert total_of_all(chain, keys) == chain.total_supply() == 5_000_000 * WFLX + 50 * WFLX


def test_confirmations_and_lookup(chain, keys):
    tx = pay(chain, keys["alice"], keys["bob"], 5 * WFLX)
    assert chain.confirmations(tx.txid) == 0
    mine(chain, keys, [tx])
    assert chain.confirmations(tx.txid) == 1
    mine(chain, keys)
    mine(chain, keys)
    assert chain.confirmations(tx.txid) == 3
    found, height = chain.get_transaction(tx.txid)
    assert found == tx and height == 1


def test_chained_spend_in_same_block(chain, keys):
    t1 = pay(chain, keys["alice"], keys["bob"], 100 * WFLX)
    out_idx = 0  # saída para bob
    t2 = build_transfer(keys["bob"], [((t1.txid, out_idx), t1.outputs[out_idx])],
                        keys["carol"].address, 40 * WFLX, FEE, chain.params.chain_id)
    mine(chain, keys, [t1, t2])
    assert chain.balance(keys["carol"].address) == 40 * WFLX
    assert chain.balance(keys["bob"].address) == 100 * WFLX - 40 * WFLX - FEE


def test_double_spend_in_same_block_rejected(chain, keys):
    t1 = pay(chain, keys["alice"], keys["bob"], 10 * WFLX)
    t2 = pay(chain, keys["alice"], keys["carol"], 10 * WFLX)  # mesma entrada
    blk = chain.create_block(keys["producer"].public_hex, keys["producer"].address, [])
    forged = Block.build(blk.height, blk.prev_hash, blk.timestamp, blk.producer,
                         [blk.transactions[0], t1, t2])
    chain.consensus.seal(forged, keys["producer"])
    before = (chain.total_supply(), chain.balance(keys["alice"].address), len(chain.utxo))
    with pytest.raises(ValidationError, match="inexistente ou já gasta"):
        chain.add_block(forged)
    assert (chain.total_supply(), chain.balance(keys["alice"].address), len(chain.utxo)) == before  # atômico
    assert chain.height == 0


def test_template_skips_conflicting_transactions(chain, keys):
    t1 = pay(chain, keys["alice"], keys["bob"], 10 * WFLX)
    t2 = pay(chain, keys["alice"], keys["carol"], 10 * WFLX)
    blk = mine(chain, keys, [t1, t2])
    assert len(blk.transactions) == 2  # coinbase + só uma das duas
    assert chain.balance(keys["carol"].address) == 0


def test_double_spend_across_blocks_rejected(chain, keys):
    t1 = pay(chain, keys["alice"], keys["bob"], 10 * WFLX)
    mine(chain, keys, [t1])
    with pytest.raises(ValidationError, match="inexistente ou já gasta"):
        chain.check_transaction(t1)  # reenvio da mesma tx


def test_overspend_creates_money_rejected(chain, keys):
    utxo = chain.utxo.utxos_for(keys["alice"].address)[0]
    tx = Transaction(chain.params.chain_id,
                     (TxInput(utxo[0][0], utxo[0][1], keys["alice"].public_hex),),
                     (TxOutput(utxo[1].value + 1, keys["bob"].address),))
    tx = replace(tx, inputs=(replace(tx.inputs[0], signature=keys["alice"].sign(tx.signing_message()).hex()),))
    with pytest.raises(ValidationError, match="criação de moeda"):
        chain.check_transaction(tx)


def test_fee_below_minimum_rejected(chain, keys):
    with pytest.raises(ValidationError, match="taxa"):
        chain.check_transaction(pay(chain, keys["alice"], keys["bob"], WFLX, fee=FEE - 1))


def test_zero_and_negative_outputs_rejected(chain, keys):
    good = pay(chain, keys["alice"], keys["bob"], WFLX)
    for value in (0, -5):
        bad = replace(good, outputs=(TxOutput(value, keys["bob"].address),) + good.outputs[1:])
        with pytest.raises(ValidationError):
            chain.check_transaction(bad)


def test_invalid_output_address_rejected(chain, keys):
    good = pay(chain, keys["alice"], keys["bob"], WFLX)
    bad = replace(good, outputs=(TxOutput(WFLX, "wflx1invalido"),) + good.outputs[1:])
    with pytest.raises(ValidationError, match="endereço"):
        chain.check_transaction(bad)


def test_stealing_someones_utxo_rejected(chain, keys):
    # Mallory tenta gastar a moeda de Alice assinando com a própria chave
    (op, out), = chain.utxo.utxos_for(keys["alice"].address)
    tx = Transaction(chain.params.chain_id, (TxInput(op[0], op[1], keys["mallory"].public_hex),),
                     (TxOutput(out.value - FEE, keys["mallory"].address),))
    tx = replace(tx, inputs=(replace(tx.inputs[0], signature=keys["mallory"].sign(tx.signing_message()).hex()),))
    with pytest.raises(ValidationError, match="dono"):
        chain.check_transaction(tx)


def test_forged_signature_rejected(chain, keys):
    tx = pay(chain, keys["alice"], keys["bob"], WFLX)
    bad = replace(tx, inputs=(replace(tx.inputs[0], signature=keys["mallory"].sign(b"x").hex()),))
    with pytest.raises(ValidationError, match="assinatura"):
        chain.check_transaction(bad)


def test_tampered_output_invalidates_signature(chain, keys):
    tx = pay(chain, keys["alice"], keys["bob"], 10 * WFLX)
    bad = replace(tx, outputs=(TxOutput(10 * WFLX, keys["mallory"].address),) + tx.outputs[1:])
    with pytest.raises(ValidationError, match="assinatura"):
        chain.check_transaction(bad)


def test_replay_between_networks_rejected(keys):
    a = make_chain(keys)
    b = make_chain(keys, chain_id="winflux-test-2")  # mesmo gênese lógico, outra rede
    tx_a = pay(a, keys["alice"], keys["bob"], WFLX)
    with pytest.raises(ValidationError, match="chain_id"):
        b.check_transaction(tx_a)
    # reescrever o chain_id quebra a assinatura
    reused = replace(tx_a, chain_id=b.params.chain_id)
    # as entradas de b têm outro txid de gênese; ainda assim nunca valida
    with pytest.raises(ValidationError):
        b.check_transaction(reused)


def test_input_listed_twice_in_one_tx_rejected(chain, keys):
    (op, out), = chain.utxo.utxos_for(keys["alice"].address)
    i = TxInput(op[0], op[1], keys["alice"].public_hex)
    tx = Transaction(chain.params.chain_id, (i, i), (TxOutput(out.value * 2 - FEE, keys["alice"].address),))
    sig = keys["alice"].sign(tx.signing_message()).hex()
    tx = replace(tx, inputs=tuple(replace(x, signature=sig) for x in tx.inputs))
    with pytest.raises(ValidationError, match="duas vezes"):
        chain.check_transaction(tx)


def test_coinbase_cannot_be_submitted_as_tx(chain, keys):
    cb = Transaction(chain.params.chain_id, (), (TxOutput(WFLX, keys["mallory"].address),), coinbase_height=7)
    with pytest.raises(ValidationError, match="coinbase"):
        chain.check_transaction(cb)


def test_coinbase_overclaim_rejected(chain, keys):
    blk = chain.create_block(keys["producer"].public_hex, keys["producer"].address, [])
    cb = Transaction(chain.params.chain_id, (), (TxOutput(51 * WFLX, keys["producer"].address),), coinbase_height=1, payload={"prev_hash": blk.prev_hash})
    forged = Block.build(1, blk.prev_hash, blk.timestamp, blk.producer, [cb])
    chain.consensus.seal(forged, keys["producer"])
    with pytest.raises(ValidationError, match="reivindica"):
        chain.add_block(forged)
    assert chain.total_supply() == 5_000_000 * WFLX


def test_coinbase_may_claim_less(chain, keys):
    blk = chain.create_block(keys["producer"].public_hex, keys["producer"].address, [])
    cb = Transaction(chain.params.chain_id, (), (TxOutput(10 * WFLX, keys["producer"].address),), coinbase_height=1, payload={"prev_hash": blk.prev_hash})
    b = Block.build(1, blk.prev_hash, blk.timestamp, blk.producer, [cb])
    chain.consensus.seal(b, keys["producer"])
    chain.add_block(b)
    assert chain.total_supply() == 5_000_000 * WFLX + 10 * WFLX


def test_coinbase_wrong_height_rejected(chain, keys):
    blk = chain.create_block(keys["producer"].public_hex, keys["producer"].address, [])
    cb = Transaction(chain.params.chain_id, (), (TxOutput(WFLX, keys["producer"].address),), coinbase_height=9, payload={"prev_hash": blk.prev_hash})
    b = Block.build(1, blk.prev_hash, blk.timestamp, blk.producer, [cb])
    chain.consensus.seal(b, keys["producer"])
    with pytest.raises(ValidationError, match="altura"):
        chain.add_block(b)


# ---------- política monetária ----------
def test_supply_cap_enforced(keys):
    chain = make_chain(keys, alloc=((keys["alice"].address, 1000 * WFLX),), max_supply=1120 * WFLX)
    rewards = []
    for _ in range(4):
        before = chain.balance(keys["producer"].address)
        mine(chain, keys)
        rewards.append(chain.balance(keys["producer"].address) - before)
    assert rewards == [50 * WFLX, 50 * WFLX, 20 * WFLX, 0]  # 4º bloco sem emissão
    assert chain.total_supply() == 1120 * WFLX


def test_cap_cannot_be_bypassed_with_forged_coinbase(keys):
    chain = make_chain(keys, alloc=((keys["alice"].address, 1000 * WFLX),), max_supply=1010 * WFLX)
    blk = chain.create_block(keys["producer"].public_hex, keys["producer"].address, [])
    cb = Transaction(chain.params.chain_id, (), (TxOutput(50 * WFLX, keys["producer"].address),), coinbase_height=1, payload={"prev_hash": blk.prev_hash})
    forged = Block.build(1, blk.prev_hash, blk.timestamp, blk.producer, [cb])
    chain.consensus.seal(forged, keys["producer"])
    with pytest.raises(ValidationError):
        chain.add_block(forged)


def test_halving_schedule(keys):
    chain = make_chain(keys, halving_interval=2)
    got = []
    for _ in range(5):
        before = chain.balance(keys["producer"].address)
        mine(chain, keys)
        got.append(chain.balance(keys["producer"].address) - before)
    assert got == [50 * WFLX, 25 * WFLX, 25 * WFLX, 12_50000000, 12_50000000]


def test_supply_invariant_after_many_transfers(chain, keys):
    names = ["bob", "carol"]
    for i in range(6):
        sender, receiver = keys["alice"], keys[names[i % 2]]
        mine(chain, keys, [pay(chain, sender, receiver, (i + 1) * WFLX)])
    assert total_of_all(chain, keys) == chain.total_supply() == 5_000_000 * WFLX + 6 * 50 * WFLX


def test_max_supply_default_is_100_million(keys):
    chain = make_chain(keys)
    assert chain.params.max_supply == 100_000_000 * WFLX == 10**16


# ---------- carteira ----------
def test_builder_insufficient_funds(chain, keys):
    with pytest.raises(InsufficientFunds):
        pay(chain, keys["bob"], keys["alice"], WFLX)  # bob não tem nada


def test_builder_rejects_bad_inputs(chain, keys):
    utxos = chain.utxo.utxos_for(keys["alice"].address)
    cid = chain.params.chain_id
    with pytest.raises(WalletError):
        build_transfer(keys["alice"], utxos, "wflx1ruim", WFLX, FEE, cid)
    with pytest.raises(WalletError):
        build_transfer(keys["alice"], utxos, keys["bob"].address, 0, FEE, cid)


def test_builder_exact_amount_has_no_change_output(keys):
    chain = make_chain(keys, alloc=((keys["alice"].address, 10 * WFLX + FEE),))
    tx = pay(chain, keys["alice"], keys["bob"], 10 * WFLX)
    assert len(tx.outputs) == 1
    mine(chain, keys, [tx])
    assert chain.balance(keys["alice"].address) == 0


def test_cannot_spend_same_wallet_utxos_in_two_pending_txs_after_confirmation(chain, keys):
    t1 = pay(chain, keys["alice"], keys["bob"], 10 * WFLX)
    mine(chain, keys, [t1])
    t2 = pay(chain, keys["alice"], keys["bob"], 10 * WFLX)  # usa o troco já confirmado
    mine(chain, keys, [t2])
    assert chain.balance(keys["bob"].address) == 20 * WFLX


def test_coinbase_must_commit_to_previous_block(chain, keys):
    blk = chain.create_block(keys["producer"].public_hex, keys["producer"].address, [])
    outs = (TxOutput(WFLX, keys["producer"].address),)
    for bad in ({"prev_hash": "11" * 32}, {"prev_hash": blk.prev_hash, "x": 1}):
        cb = Transaction(chain.params.chain_id, (), outs, coinbase_height=1, payload=bad)
        forged = Block.build(1, blk.prev_hash, blk.timestamp, blk.producer, [cb])
        chain.consensus.seal(forged, keys["producer"])
        with pytest.raises(ValidationError, match="bloco anterior"):
            chain.add_block(forged)
    assert chain.height == 0
