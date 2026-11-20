import pytest

from winflux.errors import ValidationError
from winflux.node.mempool import Mempool, MempoolError
from winflux.wallet.transaction_builder import build_transfer

from .conftest import WFLX, T0, kp
from .test_pow_reorg import make_pow_chain, mine_on


def _tx(chain, to, amount, fee=2000, who=2):
    return build_transfer(kp(who), chain.utxo.utxos_for(kp(who).address), kp(to).address, amount, fee,
                          chain.params.chain_id)


def _chain():
    return make_pow_chain(alloc=((kp(2).address, 1000 * WFLX),))


def test_accepts_valid_rejects_duplicate_and_conflict():
    c = _chain(); m = Mempool(c)
    t1 = _tx(c, 3, 5 * WFLX)
    assert m.add(t1) == 2000 and t1.txid in m
    with pytest.raises(MempoolError, match="já está"):
        m.add(t1)
    with pytest.raises(MempoolError, match="conflito"):
        m.add(_tx(c, 4, 7 * WFLX, fee=9000))        # gasta a mesma saída (sem RBF)
    assert len(m) == 1


def test_rejects_invalid_and_low_fee():
    c = _chain(); m = Mempool(c)
    with pytest.raises(ValidationError):
        m.add(_tx(c, 3, 5 * WFLX, fee=1))
    assert len(m) == 0


def test_block_inclusion_clears_and_candidates_by_feerate():
    c = _chain(); m = Mempool(c)
    c.add_block(mine_on(c, kp(9).address))
    # duas saídas distintas para poder enviar duas transações independentes
    split = build_transfer(kp(2), c.utxo.utxos_for(kp(2).address), kp(5).address, 100 * WFLX, 2000, c.params.chain_id)
    c.add_block(mine_on(c, kp(9).address, [split]))
    a = _tx(c, 3, WFLX, fee=2000, who=2)
    b = _tx(c, 3, WFLX, fee=50_000, who=5)
    m.add(a); m.add(b)
    assert m.candidates()[0].txid == b.txid
    blk = mine_on(c, kp(9).address, m.candidates())
    r = c.add_block(blk)
    m.on_chain_update(r)
    assert len(m) == 0


def test_reorg_returns_transactions_and_drops_double_spends():
    alloc = ((kp(2).address, 1000 * WFLX),)
    a, b = make_pow_chain(alloc=alloc), make_pow_chain(alloc=alloc)
    m = Mempool(a)
    tx = _tx(a, 3, 5 * WFLX)
    a.add_block(mine_on(a, kp(4).address, [tx]))
    # ramo B gasta a MESMA saída para outro destino e é mais pesado
    rival = _tx(b, 6, 9 * WFLX, fee=3000)
    b.add_block(mine_on(b, kp(5).address, [rival], ts=T0 + 50))
    b.add_block(mine_on(b, kp(5).address, ts=T0 + 60))
    a.add_block(b.blocks[1])
    res = a.add_block(b.blocks[2])
    m.on_chain_update(res)
    assert tx.txid not in m                      # virou gasto duplo: descartada
    assert a.balance(kp(6).address) == 9 * WFLX


def test_eviction_of_lowest_rate_when_full():
    c = _chain(); m = Mempool(c, max_txs=1)
    low = _tx(c, 3, WFLX, fee=2000)
    m.add(low)
    # outra saída para um segundo remetente
    c.add_block(mine_on(c, kp(9).address))
    split = build_transfer(kp(2), c.utxo.utxos_for(kp(2).address), kp(5).address, 100 * WFLX, 2000, c.params.chain_id)
    m2 = Mempool(c, max_txs=1)
    c.add_block(mine_on(c, kp(9).address, [split]))
    lo = _tx(c, 3, WFLX, fee=2000, who=2); hi = _tx(c, 3, WFLX, fee=90_000, who=5)
    m2.add(lo); m2.add(hi)
    assert hi.txid in m2 and lo.txid not in m2
    with pytest.raises(MempoolError, match="cheio"):
        m2.add(_tx(c, 4, WFLX, fee=2001, who=2))
