"""Fase 0: taxa por byte, limite de bytes por bloco, índice de endereços vistos."""
import pytest

from winflux.blockchain.block import Block
from winflux.blockchain.validation import required_fee
from winflux.errors import ValidationError
from winflux.wallet.transaction_builder import build_transfer

from .conftest import WFLX, T0, make_chain, mine


def many_utxo_chain(keys, n=40, **over):
    return make_chain(keys, alloc=tuple((keys["alice"].address, 100 * WFLX) for _ in range(n)), **over)


def big_tx(chain, keys, fee, n_inputs=36):
    # valor alto o bastante para obrigar o uso de ~n_inputs entradas
    return build_transfer(keys["alice"], chain.utxo.utxos_for(keys["alice"].address),
                          keys["bob"].address, (n_inputs - 1) * 100 * WFLX + 50 * WFLX, fee,
                          chain.params.chain_id)


def test_small_tx_still_pays_flat_minimum(chain, keys):
    tx = build_transfer(keys["alice"], chain.utxo.utxos_for(keys["alice"].address),
                        keys["bob"].address, WFLX, 1000, chain.params.chain_id)
    assert required_fee(tx, chain.params) == chain.params.min_fee  # 550 B < 1000
    assert chain.check_transaction(tx) == 1000


def test_big_tx_must_pay_per_byte(keys):
    chain = many_utxo_chain(keys)
    tx = big_tx(chain, keys, fee=1000)
    need = required_fee(tx, chain.params)
    assert need > 10_000 and tx.size() > 10_000
    with pytest.raises(ValidationError, match="taxa"):
        chain.check_transaction(tx)


def test_big_tx_accepted_with_enough_fee(keys):
    chain = many_utxo_chain(keys)
    need = required_fee(big_tx(chain, keys, fee=1000), chain.params)
    tx = big_tx(chain, keys, fee=need + 5000)  # taxa maior não altera o tamanho de forma relevante
    assert chain.check_transaction(tx) >= required_fee(tx, chain.params)


def test_fee_per_byte_can_be_disabled_by_params(keys):
    chain = many_utxo_chain(keys, min_fee_per_byte=0)
    assert chain.check_transaction(big_tx(chain, keys, fee=1000)) == 1000


def test_block_over_byte_limit_rejected(keys):
    chain = many_utxo_chain(keys, max_block_bytes=6000, min_fee_per_byte=0)
    txs = []
    # cada tx gasta uma entrada distinta (~550 B): 20 delas passam de 6000 B
    for u in chain.utxo.utxos_for(keys["alice"].address)[:20]:
        txs.append(build_transfer(keys["alice"], [u], keys["bob"].address, WFLX, 1000, chain.params.chain_id))
    blk = chain.create_block(keys["producer"].public_hex, keys["producer"].address, [])
    forged = Block.build(1, blk.prev_hash, blk.timestamp, blk.producer, [blk.transactions[0], *txs])
    chain.consensus.seal(forged, keys["producer"])
    with pytest.raises(ValidationError, match="tamanho máximo"):
        chain.add_block(forged)
    assert chain.height == 0


def test_template_respects_byte_budget(keys):
    chain = many_utxo_chain(keys, max_block_bytes=6000, min_fee_per_byte=0)
    txs = [build_transfer(keys["alice"], [u], keys["bob"].address, WFLX, 1000, chain.params.chain_id)
           for u in chain.utxo.utxos_for(keys["alice"].address)[:20]]
    blk = mine(chain, keys, txs)  # não pode estourar: o gerador corta
    assert 1 < len(blk.transactions) < 21
    assert sum(t.size() for t in blk.transactions) <= 6000


def test_params_reject_tiny_block_limit(keys):
    with pytest.raises(ValidationError):
        make_chain(keys, max_block_bytes=100)


def test_address_seen_index(chain, keys):
    assert chain.address_seen(keys["alice"].address)       # alocação do gênese
    assert not chain.address_seen(keys["bob"].address)
    tx = build_transfer(keys["alice"], chain.utxo.utxos_for(keys["alice"].address),
                        keys["bob"].address, WFLX, 1000, chain.params.chain_id)
    mine(chain, keys, [tx])
    assert chain.address_seen(keys["bob"].address)
    assert chain.address_seen(keys["producer"].address)    # recompensa
