"""Nó Winflux: cadeia + mempool + P2P + mineração + API, num único laço asyncio.

Toda mutação do estado acontece no laço de eventos (uma thread), então não há corridas.
A busca de nonces roda em threads de trabalho e só lê um cabeçalho imutável.
"""
import asyncio
import os
import threading
import time

from ..blockchain.block import Block
from ..blockchain.chain import Chain, KnownBlock, OrphanBlock
from ..blockchain.genesis import GenesisConfig
from ..blockchain.transaction import Transaction
from ..consensus.poa import ProofOfAuthority
from ..consensus.pow import ProofOfWork
from .. import __version__
from ..errors import StorageError, ValidationError
from ..logs import exc_label, noop_log
from ..network.p2p import P2P, PROTOCOL_VERSION
from .mempool import Mempool
from .storage import BlockStorage

MAX_ORPHANS = 100
MINE_CHUNK = 150_000
TEMPLATE_REFRESH = 20      # s: reconstrói o modelo para incluir novas transações


def make_consensus(params):
    return ProofOfWork() if params.consensus == "pow" else ProofOfAuthority()


class Node:
    def __init__(self, genesis: GenesisConfig, datadir: str | None = None, host="127.0.0.1", port=0,
                 seeds=(), mine_to: str | None = None, max_outbound=8, max_inbound=32,
                 clock=time.time, log=noop_log, max_inbound_per_ip=8):
        self.log = log
        self.clock = clock
        storage = None
        peers_file = None
        if datadir:
            os.makedirs(datadir, exist_ok=True)
            storage = BlockStorage(os.path.join(datadir, "chain.db"))
            peers_file = os.path.join(datadir, "peers.json")
        self.chain = Chain(genesis, make_consensus(genesis.params), storage=storage, clock=clock)
        self.mempool = Mempool(self.chain)
        self.p2p = P2P(self, host, port, seeds, max_outbound, max_inbound, peers_file, log,
                       max_per_ip=max_inbound_per_ip)
        self.mine_to = mine_to
        self.mining = False
        self._orphans: dict[str, Block] = {}
        self._mine_task = None
        self._new_tip = None
        self.started = None

    # ---------- ciclo de vida ----------
    async def start(self):
        self._new_tip = asyncio.Event()
        await self.p2p.start()
        self.started = time.time()
        self.log(f"nó iniciado: rede {self.chain.params.chain_id}, altura {self.chain.height}, P2P porta {self.p2p.port}")
        if self.mine_to:
            self.start_mining()

    async def stop(self):
        self.mining = False
        if self._mine_task:
            self._mine_task.cancel()
            await asyncio.gather(self._mine_task, return_exceptions=True)
        await self.p2p.stop()
        if self.chain.storage:
            self.chain.storage.close()
        self.log("nó parado")

    @property
    def port(self):
        return self.p2p.port

    # ---------- informações ----------
    def version_payload(self) -> dict:
        c = self.chain
        return {"proto": PROTOCOL_VERSION, "chain_id": c.params.chain_id, "genesis": c.genesis_block.hash,
                "nonce": self.p2p.node_id, "height": c.height, "work": format(c.total_work, "x"),
                "port": self.p2p.port, "agent": "winflux-py/0.1"}

    def knows_block(self, h: str) -> bool:
        return self.chain.has_block(h) or h in self._orphans or self.chain.is_invalid(h)

    def knows_tx(self, txid: str) -> bool:
        return txid in self.mempool or self.chain.get_transaction(txid) is not None

    def status(self) -> dict:
        c = self.chain
        return {"version": __version__, "chain_id": c.params.chain_id, "symbol": c.params.symbol, "consensus": c.params.consensus,
                "height": c.height, "tip": c.tip.hash, "total_work": format(c.total_work, "x"),
                "next_target": format(c.next_target(), "064x") if c.params.consensus == "pow" else None,
                "supply": c.total_supply(), "max_supply": c.params.max_supply,
                "mempool": len(self.mempool), "peers": len(self.p2p.ready_peers()),
                "mining": self.mining, "orphans": len(self._orphans)}

    # ---------- blocos ----------
    async def on_block_message(self, peer, d):
        try:
            block = Block.from_dict(d)
        except ValidationError as e:
            return peer.misbehave(50, f"bloco malformado: {e}")
        peer.known.add(block.hash)
        await self.accept_block(block, peer)

    async def on_blocks_message(self, peer, d):
        if not isinstance(d, dict) or not isinstance(d.get("blocks"), list):
            return peer.misbehave(20, "blocks inválido")
        peer.sync_inflight = False
        before = self.chain.tip.hash
        for raw in d["blocks"][:500]:
            try:
                block = Block.from_dict(raw)
            except ValidationError as e:
                return peer.misbehave(50, f"bloco malformado: {e}")
            peer.known.add(block.hash)
            if not await self.accept_block(block, peer, batch=True) and peer.closed:
                return
            await asyncio.sleep(0)               # cede o laço entre blocos
        if self.chain.tip.hash != before:
            await self.p2p.broadcast_inv(blocks=[self.chain.tip.hash], exclude=peer)
            if d.get("more"):
                await self.request_blocks(peer)

    async def accept_block(self, block: Block, peer=None, batch=False) -> bool:
        """Retorna True se o bloco entrou (ativo ou lateral)."""
        try:
            result = self.chain.add_block(block)
        except KnownBlock:
            return False
        except OrphanBlock:
            if len(self._orphans) >= MAX_ORPHANS:
                self._orphans.pop(next(iter(self._orphans)))
            self._orphans[block.hash] = block
            if peer is not None and not batch:
                await self.request_blocks(peer)
            return False
        except ValidationError as e:
            if peer is not None and "futuro" not in str(e):
                peer.misbehave(20 if "já foi rejeitado" in str(e) else 100, f"bloco inválido: {e}")
            self.log(f"bloco {block.height} rejeitado: {e}", "warning")
            return False
        except StorageError as e:                         # disco cheio/corrompido: grave e deixe subir ao chamador
            self.log(f"FALHA DE ARMAZENAMENTO ao aceitar bloco {block.height}: {e}", "error")
            raise
        if result.status in ("extended", "reorg"):
            self.mempool.on_chain_update(result)
            if result.status == "reorg":
                self.log(f"REORG: {len(result.disconnected)} bloco(s) desfeito(s), {len(result.connected)} novo(s)", "warning")
            self.log(f"novo topo {self.chain.height} {self.chain.tip.hash[:12]}")
            if not batch:
                await self.p2p.broadcast_inv(blocks=[self.chain.tip.hash], exclude=peer)
            if self._new_tip is not None:
                self._new_tip.set()
        await self._resolve_orphans(block.hash, peer)
        return True

    async def _resolve_orphans(self, parent_hash: str, peer):
        queue = [parent_hash]
        while queue:
            ph = queue.pop()
            for h, b in [(h, b) for h, b in self._orphans.items() if b.prev_hash == ph]:
                del self._orphans[h]
                if await self.accept_block(b, peer, batch=True):
                    queue.append(h)

    # ---------- transações ----------
    async def on_tx_message(self, peer, d):
        try:
            tx = Transaction.from_dict(d)
        except ValidationError as e:
            return peer.misbehave(20, f"tx malformada: {e}")
        peer.known.add(tx.txid)
        try:
            await self.submit_tx(tx, peer)
        except ValidationError as e:
            if "já está" not in str(e) and "já confirmada" not in str(e):
                peer.misbehave(10, f"tx inválida: {e}")

    async def submit_tx(self, tx: Transaction, source=None) -> str:
        """Valida, põe no mempool e difunde. Levanta ValidationError se rejeitada."""
        self.mempool.add(tx)
        await self.p2p.broadcast_inv(txs=[tx.txid], exclude=source)
        return tx.txid

    # ---------- sincronização ----------
    async def maybe_sync(self, peer):
        if peer.work > self.chain.total_work:
            await self.request_blocks(peer)

    async def request_blocks(self, peer):
        if peer.sync_inflight or peer.closed:
            return
        peer.sync_inflight = True
        await peer.send("getblocks", {"locator": self.chain.locator()})

    # ---------- mineração ----------
    def start_mining(self, address: str | None = None):
        if address:
            self.mine_to = address
        if not self.mine_to:
            raise ValueError("endereço de recompensa não definido")
        if self.chain.params.consensus != "pow":
            raise ValueError("mineração só existe em redes PoW")
        self.mining = True
        if self._mine_task is None or self._mine_task.done():
            self._mine_task = asyncio.create_task(self._mine_loop())

    def stop_mining(self):
        self.mining = False

    def build_template(self):
        c = self.chain
        blk = c.create_block("", self.mine_to, self.mempool.candidates(),
                             timestamp=max(int(self.clock()), c.tip.timestamp + 1))
        return blk, c.next_target()

    async def mine_one(self, address: str | None = None) -> Block:
        """Minera exatamente um bloco agora (útil em testes e regtest) e o propaga."""
        if address:
            self.mine_to = address
        blk, target = self.build_template()
        loop = asyncio.get_running_loop()
        nonce = 0
        while True:
            found = await loop.run_in_executor(None, ProofOfWork.search, blk, target, nonce, MINE_CHUNK, None)
            if found is not None:
                blk.nonce = found
                break
            nonce += MINE_CHUNK
        if not await self.accept_block(blk, None):
            raise ValidationError("bloco minerado foi rejeitado")
        return blk

    async def _mine_loop(self):
        loop = asyncio.get_running_loop()
        while True:
            try:
                if not self.mining:
                    await asyncio.sleep(0.5)
                    continue
                tip = self.chain.tip.hash
                blk, target = self.build_template()
                deadline = time.time() + TEMPLATE_REFRESH
                nonce, found = 0, None
                while self.mining and self.chain.tip.hash == tip and time.time() < deadline:
                    found = await loop.run_in_executor(None, ProofOfWork.search, blk, target, nonce, MINE_CHUNK, None)
                    if found is not None:
                        break
                    nonce += MINE_CHUNK
                if found is not None and self.chain.tip.hash == tip:
                    blk.nonce = found
                    if await self.accept_block(blk, None):
                        self.log(f"bloco minerado: altura {blk.height} {blk.hash[:12]}")
                await asyncio.sleep(0)
            except asyncio.CancelledError:
                return
            except Exception as e:                       # um erro isolado não pode matar a mineração em silêncio
                self.log(f"erro na mineração (tentando de novo em 2 s): {exc_label(e)}", "error")
                await asyncio.sleep(2)
