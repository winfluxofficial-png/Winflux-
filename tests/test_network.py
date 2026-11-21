"""Real network on localhost: several nodes, propagation, sync, reorg and defenses."""
import asyncio
import json
import time

import pytest

from winflux.blockchain.genesis import GenesisConfig
from winflux.node.node import Node
from winflux.wallet.transaction_builder import build_transfer

from .conftest import T0, WFLX, kp
from .test_pow_reorg import pow_params


def genesis(**over):
    over.setdefault("pow_retarget_interval", 1000)
    over.setdefault("coinbase_maturity", 2)
    return GenesisConfig(pow_params(**over), T0, ((kp(2).address, 1000 * WFLX),))


async def wait_for(cond, timeout=15):
    t = time.time() + timeout
    while time.time() < t:
        if cond():
            return True
        await asyncio.sleep(0.05)
    return False


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 90))


async def start(cfg, seeds=(), **kw):
    n = Node(cfg, seeds=seeds, **kw)
    await n.start()
    return n


def same_tip(*nodes):
    return len({n.chain.tip.hash for n in nodes}) == 1


def test_three_nodes_propagate_blocks_and_transactions():
    async def go():
        cfg = genesis()
        a = await start(cfg)
        b = await start(cfg, seeds=[f"127.0.0.1:{a.port}"])
        c = await start(cfg, seeds=[f"127.0.0.1:{a.port}"])
        try:
            assert await wait_for(lambda: len(a.p2p.ready_peers()) == 2)
            for _ in range(4):
                await a.mine_one(kp(4).address)
            assert await wait_for(lambda: b.chain.height == 4 and c.chain.height == 4)
            assert same_tip(a, b, c)
            # a transaction sent to node C reaches everyone and is mined by B
            tx = build_transfer(kp(2), c.chain.utxo.utxos_for(kp(2).address), kp(3).address, 7 * WFLX,
                                2000, cfg.params.chain_id)
            await c.submit_tx(tx)
            assert await wait_for(lambda: tx.txid in a.mempool and tx.txid in b.mempool)
            await b.mine_one(kp(5).address)
            assert await wait_for(lambda: a.chain.balance(kp(3).address) == 7 * WFLX
                                  and c.chain.balance(kp(3).address) == 7 * WFLX)
            assert await wait_for(lambda: len(a.mempool) == 0 and len(c.mempool) == 0)
            assert same_tip(a, b, c)
            assert a.chain.total_supply() == b.chain.total_supply() == c.chain.total_supply()
        finally:
            for n in (a, b, c):
                await n.stop()
    run(go())


def test_late_joiner_syncs_whole_chain():
    async def go():
        cfg = genesis()
        a = await start(cfg)
        for _ in range(30):
            await a.mine_one(kp(4).address)
        late = await start(cfg, seeds=[f"127.0.0.1:{a.port}"])
        try:
            assert await wait_for(lambda: late.chain.height == 30)
            assert same_tip(a, late)
            assert late.chain.ledger.state_root() == a.chain.ledger.state_root()
        finally:
            await a.stop(); await late.stop()
    run(go())


def test_partition_then_heal_converges_to_heaviest_chain():
    async def go():
        cfg = genesis()
        x, y = await start(cfg), await start(cfg)
        try:
            for _ in range(2):
                await x.mine_one(kp(4).address)
            for _ in range(4):
                await y.mine_one(kp(5).address)
            assert not same_tip(x, y)
            x.p2p.known_addrs[("127.0.0.1", y.port)] = 0     # the partition ends
            assert await wait_for(lambda: same_tip(x, y) and x.chain.height == 4)
            assert x.chain.balance(kp(4).address) == 0 and x.chain.balance(kp(5).address) == 200 * WFLX
        finally:
            await x.stop(); await y.stop()
    run(go())


def test_different_network_is_refused():
    async def go():
        a = await start(genesis())
        b = await start(genesis(chain_id="other-network"), seeds=[f"127.0.0.1:{a.port}"])
        try:
            await asyncio.sleep(2.5)
            assert not a.p2p.ready_peers() and not b.p2p.ready_peers()
        finally:
            await a.stop(); await b.stop()
    run(go())


def test_garbage_and_invalid_blocks_get_peer_banned():
    async def go():
        cfg = genesis()
        a = await start(cfg)
        try:
            r, w = await asyncio.open_connection("127.0.0.1", a.port)
            for _ in range(6):                       # 6 malformed messages (+20 each) => banned
                w.write((5).to_bytes(4, "big") + b"nojson")
            await w.drain()
            data = await asyncio.wait_for(r.read(), 5)  # the node closes the connection
            assert a.p2p.is_banned("127.0.0.1")
        finally:
            await a.stop()
    run(go())


def test_peer_sending_invalid_block_is_banned_and_chain_unaffected():
    async def go():
        cfg = genesis()
        a = await start(cfg)
        miner = await start(cfg)
        try:
            blk = await miner.mine_one(kp(4).address)
            d = blk.to_dict()
            d["transactions"][0]["outputs"][0]["value"] += 1     # inflated coinbase => broken Merkle
            r, w = await asyncio.open_connection("127.0.0.1", a.port)

            async def send(t, data):
                raw = json.dumps({"t": t, "d": data}).encode()
                w.write(len(raw).to_bytes(4, "big") + raw)
                await w.drain()
            await send("version", a.version_payload() | {"nonce": "evil"})
            await send("verack", None)
            await asyncio.sleep(0.3)
            await send("block", d)
            await asyncio.wait_for(r.read(), 5)
            assert a.chain.height == 0 and a.p2p.is_banned("127.0.0.1")
        finally:
            await a.stop(); await miner.stop()
    run(go())


def test_background_miner_finds_blocks_and_persists(tmp_path):
    async def go():
        cfg = genesis()
        a = Node(cfg, datadir=str(tmp_path / "a"), mine_to=kp(4).address)
        await a.start()
        try:
            assert await wait_for(lambda: a.chain.height >= 3, 30)
        finally:
            await a.stop()
        h = a.chain.height
        again = Node(cfg, datadir=str(tmp_path / "a"))
        assert again.chain.height == h and again.chain.balance(kp(4).address) == h * 50 * WFLX
        again.chain.storage.close()
    run(go())
