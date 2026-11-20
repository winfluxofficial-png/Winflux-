"""PoW sem autoridades, ajuste de dificuldade, maturidade e reorganizações."""
from dataclasses import replace

import pytest

from winflux.blockchain.block import Block
from winflux.blockchain.chain import Chain, KnownBlock, OrphanBlock
from winflux.blockchain.genesis import GenesisConfig
from winflux.blockchain.params import ChainParams
from winflux.consensus.pow import ProofOfWork, hash_to_int, work_for_target
from winflux.errors import ValidationError
from winflux.node.storage import BlockStorage
from winflux.wallet.transaction_builder import build_transfer

from .conftest import NOW, T0, WFLX, kp

EASY = "00ff" + "f" * 60          # ~1/256 de chance por tentativa


def pow_params(**over) -> ChainParams:
    base = dict(chain_id="winflux-pow-test", name="Winflux", symbol="WFLX", decimals=8,
                max_supply=100_000_000 * WFLX, block_reward=50 * WFLX, halving_interval=210_000,
                min_fee=1000, authorities=(), consensus="pow", pow_limit=EASY,
                pow_retarget_interval=8, target_block_time=10, coinbase_maturity=3)
    base.update(over)
    return ChainParams(**base)


class Clock:
    def __init__(self, t): self.t = t
    def __call__(self): return self.t


def make_pow_chain(storage=None, alloc=(), clock=None, **over):
    cfg = GenesisConfig(pow_params(**over), T0, tuple(alloc))
    return Chain(cfg, ProofOfWork(), storage=storage, clock=clock or (lambda: NOW + 10**6))


def mine_on(chain, reward_to, txs=(), ts=None, parent=None):
    """Minera um bloco sobre o topo (ou sobre `parent`, criando ramo lateral)."""
    if parent is None:
        blk = chain.create_block("", reward_to, list(txs), timestamp=ts)
    else:
        from winflux.blockchain.transaction import Transaction, TxOutput
        cb = Transaction(chain.params.chain_id, (), (TxOutput(chain.max_reward(parent.height + 1), reward_to),),
                         coinbase_height=parent.height + 1, payload={"prev_hash": parent.hash})
        blk = Block.build(parent.height + 1, parent.hash, ts or parent.timestamp + 10, "", [cb],
                          state_root=chain.tip.state_root)
    target = chain.consensus.next_target(chain.get_any_block(blk.prev_hash), chain.params, chain)
    assert ProofOfWork.mine(blk, target) is not None
    return blk


def test_pow_chain_has_no_authority_and_anyone_can_mine():
    chain = make_pow_chain()
    for n in (2, 3, 4):                         # três mineradores desconhecidos entre si
        r = chain.add_block(mine_on(chain, kp(n).address))
        assert r.status == "extended"
    assert chain.height == 3 and chain.params.authorities == ()
    assert chain.total_supply() == 150 * WFLX


def test_pow_rejects_insufficient_work_and_signed_blocks():
    chain = make_pow_chain(pow_limit="0000" + "f" * 60)
    blk = chain.create_block("", kp(2).address, [])
    blk.nonce = 0
    assert hash_to_int(blk.hash) > chain.next_target()   # nonce arbitrário (quase certo) não basta
    with pytest.raises(ValidationError, match="trabalho"):
        chain.add_block(blk)
    good = mine_on(chain, kp(2).address)
    with pytest.raises(ValidationError, match="produtor"):
        chain.add_block(replace(good, producer="ab" * 32))


def test_pow_params_reject_authorities():
    with pytest.raises(ValidationError):
        pow_params(authorities=("ab" * 32,))


def test_fast_search_matches_block_hash():
    chain = make_pow_chain()
    blk = chain.create_block("", kp(2).address, [])
    n = ProofOfWork.search(blk, int(EASY, 16), 0, 100000)
    blk.nonce = n
    assert hash_to_int(blk.hash) <= int(EASY, 16)


def test_difficulty_rises_when_blocks_are_too_fast_and_falls_when_slow():
    chain = make_pow_chain()                    # intervalo 8, alvo 10 s => esperado 70 s
    t = T0
    for _ in range(7):                          # blocos a cada 1 s (muito rápido)
        t += 1
        chain.add_block(mine_on(chain, kp(2).address, ts=t))
    new = chain.next_target()                   # altura 8: reajuste
    assert new < int(EASY, 16) and new >= int(EASY, 16) // 5
    for _ in range(8):                          # agora lento: 100 s por bloco
        t += 100
        chain.add_block(mine_on(chain, kp(2).address, ts=t))
    assert chain.next_target() > new            # alivia, limitado a 4x e ao pow_limit
    assert chain.next_target() <= int(EASY, 16)


def test_wrong_difficulty_is_rejected_even_if_hash_meets_declared_one():
    chain = make_pow_chain(pow_limit="0000" + "f" * 60)   # 1/65536
    blk = chain.create_block("", kp(2).address, [])
    # um bloco com hash que só satisfaz um alvo mais fraco não passa
    weak = int("00ff" + "f" * 60, 16)
    ProofOfWork.mine(blk, weak)
    if hash_to_int(blk.hash) > chain.next_target():
        with pytest.raises(ValidationError):
            chain.add_block(blk)


def test_coinbase_maturity():
    chain = make_pow_chain(alloc=((kp(2).address, 1000 * WFLX),))
    miner = kp(6)
    chain.add_block(mine_on(chain, miner.address))
    utxos = chain.utxo.utxos_for(miner.address)
    tx = build_transfer(miner, utxos, kp(3).address, 10 * WFLX, 1000, chain.params.chain_id)
    assert len(chain.create_block("", kp(7).address, [tx]).transactions) == 1   # o minerador honesto a omite
    from winflux.blockchain.transaction import Transaction, TxOutput
    cb = Transaction(chain.params.chain_id, (), (TxOutput(50 * WFLX + 1000, kp(7).address),),
                     coinbase_height=2, payload={"prev_hash": chain.tip.hash})
    forced = Block.build(2, chain.tip.hash, chain.tip.timestamp + 10, "", [cb, tx], state_root=chain.tip.state_root)
    ProofOfWork.mine(forced, chain.next_target())
    with pytest.raises(ValidationError, match="amadureceu"):
        chain.add_block(forced)
    chain.add_block(mine_on(chain, kp(7).address))
    chain.add_block(mine_on(chain, kp(7).address))       # altura 3: maturidade 3 atingida no bloco 4
    r = chain.add_block(mine_on(chain, kp(7).address, [tx]))
    assert r.status == "extended" and chain.balance(kp(3).address) == 10 * WFLX
    # o gênese não está sujeito à maturidade
    spend = build_transfer(kp(2), chain.utxo.utxos_for(kp(2).address), kp(3).address, WFLX, 1000,
                           chain.params.chain_id)
    chain.add_block(mine_on(chain, kp(7).address, [spend]))


def _fork(chain, n_main, n_side):
    """Cria dois ramos a partir do topo atual. Retorna (blocos_do_principal, blocos_do_lateral)."""
    base = chain.tip
    side_chain = make_pow_chain(alloc=((kp(2).address, 1000 * WFLX),))
    return base, side_chain


def test_reorg_to_heavier_branch_and_back_state_is_consistent():
    alloc = ((kp(2).address, 1000 * WFLX),)
    a = make_pow_chain(alloc=alloc)             # nó A
    b = make_pow_chain(alloc=alloc)             # nó B (mesmo gênese)
    assert a.genesis_block.hash == b.genesis_block.hash
    # A minera 2 blocos para o minerador 4; B minera 3 blocos para o minerador 5
    for _ in range(2):
        a.add_block(mine_on(a, kp(4).address))
    for t in range(3):
        b.add_block(mine_on(b, kp(5).address, ts=T0 + 100 + t * 10))
    assert a.balance(kp(4).address) == 100 * WFLX and a.balance(kp(5).address) == 0
    old_a_tip = a.tip.hash
    results = []
    for blk in b.blocks[1:]:
        results.append(a.add_block(blk).status)
    assert results == ["side", "side", "reorg"]
    assert a.tip.hash == b.tip.hash and a.height == 3
    assert a.balance(kp(4).address) == 0 and a.balance(kp(5).address) == 150 * WFLX
    assert a.total_supply() == b.total_supply()
    assert a.ledger.state_root() == b.ledger.state_root()
    assert a.get_block_by_hash(old_a_tip) is None and a.has_block(old_a_tip)


def test_reorg_returns_disconnected_blocks_for_mempool():
    alloc = ((kp(2).address, 1000 * WFLX),)
    a, b = make_pow_chain(alloc=alloc), make_pow_chain(alloc=alloc)
    tx = build_transfer(kp(2), a.utxo.utxos_for(kp(2).address), kp(3).address, 5 * WFLX, 1000, a.params.chain_id)
    a.add_block(mine_on(a, kp(4).address, [tx]))
    for t in range(2):
        b.add_block(mine_on(b, kp(5).address, ts=T0 + 50 + t * 10))
    a.add_block(b.blocks[1])
    r = a.add_block(b.blocks[2])
    assert r.status == "reorg" and [x.height for x in r.disconnected] == [1]
    assert any(t.txid == tx.txid for t in r.disconnected[0].transactions)
    assert a.balance(kp(3).address) == 0 and a.confirmations(tx.txid) == 0
    a.check_transaction(tx)                      # a transação voltou a ser válida


def test_invalid_heavier_branch_is_rejected_and_old_chain_restored():
    alloc = ((kp(2).address, 1000 * WFLX),)
    a, b = make_pow_chain(alloc=alloc), make_pow_chain(alloc=alloc)
    a.add_block(mine_on(a, kp(4).address))
    b.add_block(mine_on(b, kp(5).address, ts=T0 + 50))
    # bloco 2 do ramo B cria moeda do nada (coinbase inflada) mas tem PoW válido
    from winflux.blockchain.transaction import Transaction, TxOutput
    b1 = b.tip
    cb = Transaction(b.params.chain_id, (), (TxOutput(10_000 * WFLX, kp(5).address),),
                     coinbase_height=2, payload={"prev_hash": b1.hash})
    bad = Block.build(2, b1.hash, b1.timestamp + 10, "", [cb], state_root=b1.state_root)
    ProofOfWork.mine(bad, b.next_target())
    tip_before, supply = a.tip.hash, a.total_supply()
    assert a.add_block(b1).status == "side"
    with pytest.raises(ValidationError, match="coinbase"):
        a.add_block(bad)
    assert a.tip.hash == tip_before and a.total_supply() == supply
    assert a.is_invalid(bad.hash)
    with pytest.raises(ValidationError):
        a.add_block(bad)


def test_orphan_and_duplicate_signalled():
    a = make_pow_chain()
    b = make_pow_chain()
    b.add_block(mine_on(b, kp(5).address))
    b.add_block(mine_on(b, kp(5).address))
    with pytest.raises(OrphanBlock):
        a.add_block(b.blocks[2])
    a.add_block(b.blocks[1])
    with pytest.raises(KnownBlock):
        a.add_block(b.blocks[1])


def test_equal_work_does_not_reorg_first_seen_wins():
    a, b = make_pow_chain(), make_pow_chain()
    a.add_block(mine_on(a, kp(4).address))
    b.add_block(mine_on(b, kp(5).address, ts=T0 + 77))
    tip = a.tip.hash
    # trabalho por bloco é igual só se o alvo é igual; com pow_limit fixo é o caso
    assert a.add_block(b.blocks[1]).status == "side" and a.tip.hash == tip


def test_reorg_persists_atomically_and_reloads(tmp_path):
    alloc = ((kp(2).address, 1000 * WFLX),)
    path = str(tmp_path / "c.db")
    a = make_pow_chain(storage=BlockStorage(path), alloc=alloc)
    b = make_pow_chain(alloc=alloc)
    a.add_block(mine_on(a, kp(4).address))
    for t in range(2):
        b.add_block(mine_on(b, kp(5).address, ts=T0 + 50 + t * 10))
    a.add_block(b.blocks[1]); a.add_block(b.blocks[2])
    a.storage.close()
    again = make_pow_chain(storage=BlockStorage(path), alloc=alloc)
    assert again.tip.hash == b.tip.hash and again.balance(kp(5).address) == 100 * WFLX
    assert again.total_work == b.total_work


def test_locator_and_blocks_after():
    a, b = make_pow_chain(), make_pow_chain()
    for _ in range(25):
        a.add_block(mine_on(a, kp(4).address))
    for blk in a.blocks[1:11]:
        b.add_block(blk)
    got = a.blocks_after(b.locator(), limit=500)
    assert [x.height for x in got] == list(range(11, 26))
    assert a.blocks_after(["zz"], 3)[0].height == 1
