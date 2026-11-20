"""Rede P2P sobre TCP (asyncio). Sem servidor central: cada nó fala com quem conhecer.

Formato: 4 bytes (big-endian) com o tamanho + JSON UTF-8 `{"t": tipo, "d": dados}`.
Mensagens: version, verack, ping, pong, getaddr, addr, inv, getdata, block, tx,
getblocks, blocks, getmempool.

Defesas: tamanho máximo de mensagem (menor antes do handshake e por tipo), limite de taxa por peer
(mensagens/s no total, por tipo e bytes/s), pontuação de mau comportamento com banimento temporário,
limites de conexões (total e por IP), recuo exponencial ao reconectar, timeout de handshake e de
inatividade, detecção de autoconexão e de conexão duplicada, verificação de chain_id/gênese.

Política de excesso: dicas (inv/addr/ping/pong) são descartadas; o resto é processado COM atraso e rende
pontos de mau comportamento (descartar pedidos travaria a sincronização do par honesto, que não reenvia).
`blocks` que NÓS pedimos (sync em andamento) não contam para o limite de bytes.
"""
import asyncio
import json
import os
import random
import re
import time

from ..logs import exc_label, noop_log
from .limits import TokenBucket

PROTOCOL_VERSION = 1
MAX_MESSAGE = 4 * 1024 * 1024
MAX_INV = 1000
MAX_GETDATA = 200
MAX_ADDR = 100
BATCH_BYTES = 2 * 1024 * 1024
BAN_SCORE = 100
HANDSHAKE_TIMEOUT = 10
IDLE_TIMEOUT = 120
PING_EVERY = 30
MAX_PREHANDSHAKE_MESSAGE = 16 * 1024     # antes do handshake só cabe um `version`
MAX_BY_TYPE = {                          # teto por tipo (bytes do JSON); tipos ausentes: MAX_MESSAGE
    "version": 4 * 1024, "verack": 256, "ping": 256, "pong": 256, "getaddr": 256, "getmempool": 256,
    "addr": 64 * 1024, "inv": 256 * 1024, "getdata": 64 * 1024, "getblocks": 64 * 1024, "tx": 512 * 1024,
}
PER_TYPE = {                             # (mensagens/s sustentadas, rajada) por tipo
    "getblocks": (4, 20), "getdata": (20, 100), "getmempool": (0.5, 3), "getaddr": (0.2, 3), "addr": (1, 5),
    "inv": (30, 150), "block": (20, 200), "tx": (60, 300), "ping": (2, 10), "pong": (2, 10),
}
HINTS = frozenset({"inv", "addr", "ping", "pong"})
MSGS_PER_SEC, MSGS_BURST = 100, 300
BYTES_PER_SEC, BYTES_BURST = 4 * 1024 * 1024, 16 * 1024 * 1024
MAX_PER_IP = 8                           # conexões de entrada por IP (loopback isento por padrão)
RECONNECT_BASE, RECONNECT_MAX, MAX_FAILS = 5, 300, 12
_TYPE_RX = re.compile(rb'^\{"t":"([a-z]{1,16})"')


def _peek_type(raw: bytes):
    m = _TYPE_RX.match(raw[:32])
    return m.group(1).decode() if m else None


class Peer:
    def __init__(self, p2p, reader, writer, outbound: bool, addr):
        self.p2p, self.reader, self.writer = p2p, reader, writer
        self.outbound = outbound
        self.addr = addr                    # (host, port) como visto por nós
        self.listen_port = 0                # porta anunciada pelo peer
        self.node_id = None
        self.ready = False
        self.score = 0.0
        self._score_at = time.time()
        self.height = 0
        self.work = 0
        self.last_recv = time.time()
        self._msgs = TokenBucket(MSGS_PER_SEC, MSGS_BURST)
        self._bytes = TokenBucket(BYTES_PER_SEC, BYTES_BURST)
        self._typed: dict = {}
        self.known: set = set()             # hashes/txids que o peer já conhece
        self.requested: set = set()
        self.closed = False
        self.sync_inflight = False

    def __repr__(self):
        return f"<Peer {self.addr[0]}:{self.addr[1]} {'out' if self.outbound else 'in'}>"

    async def send(self, t: str, d=None):
        if self.closed:
            return
        raw = json.dumps({"t": t, "d": d}, separators=(",", ":")).encode()
        if len(raw) > MAX_MESSAGE:
            return
        try:
            self.writer.write(len(raw).to_bytes(4, "big") + raw)
            await asyncio.wait_for(self.writer.drain(), 10)
        except Exception as e:
            self.p2p.log(f"{self}: falha ao enviar '{t}': {type(e).__name__}", "debug")
            self.close()

    def misbehave(self, points: int, why: str):
        now = time.time()                                   # a pontuação decai: 1 ponto a cada 5 s
        self.score = max(0.0, self.score - (now - self._score_at) / 5) + points
        self._score_at = now
        self.p2p.log(f"{self}: mau comportamento +{points} ({why}) => {self.score:.0f}", "debug")
        if self.score >= BAN_SCORE:
            self.p2p.ban(self.addr[0])
            self.close()

    def allow(self) -> bool:
        return self._msgs.allow()

    def rate_check(self, t: str, n: int, solicited: bool = False) -> str:
        """"ok" | "drop" (dica em excesso: descarta) | "slow" (processa com atraso e pontua)."""
        ok = self._msgs.allow()
        spec = PER_TYPE.get(t)
        if spec:
            b = self._typed.get(t)
            if b is None:
                b = self._typed[t] = TokenBucket(*spec)
            ok = b.allow() and ok
        if not solicited:
            ok = self._bytes.allow(n) and ok
        if ok:
            return "ok"
        return "drop" if t in HINTS else "slow"

    def close(self):
        if not self.closed:
            self.closed = True
            try:
                self.writer.close()
            except Exception:
                pass


class P2P:
    def __init__(self, node, host="127.0.0.1", port=0, seeds=(), max_outbound=8, max_inbound=32,
                 peers_file=None, log=noop_log, max_per_ip=MAX_PER_IP, exempt_loopback=True):
        self.node = node
        self.host, self.port = host, port
        self.max_outbound, self.max_inbound = max_outbound, max_inbound
        self.max_per_ip, self.exempt_loopback = max_per_ip, exempt_loopback
        self._fails: dict[tuple, int] = {}                # falhas seguidas de conexão por endereço (recuo)
        self.peers: list[Peer] = []
        self.node_id = os.urandom(8).hex()
        self.known_addrs: dict[tuple, float] = {}      # (host, port) -> última tentativa
        self.seeds = [self._parse(s) for s in seeds]
        self.bans: dict[str, float] = {}
        self.peers_file = peers_file
        self.log = log
        self._server = None
        self._tasks: list = []
        for s in self.seeds:
            self.known_addrs.setdefault(s, 0)
        self._load_peers()

    # ---------- util ----------
    @staticmethod
    def _parse(s):
        if isinstance(s, tuple):
            return s
        host, _, port = s.rpartition(":")
        return (host, int(port))

    def _load_peers(self):
        if self.peers_file and os.path.exists(self.peers_file):
            try:
                for a in json.load(open(self.peers_file)):
                    self.known_addrs.setdefault(self._parse(a), 0)
            except Exception as e:
                self.log(f"peers.json ilegível, ignorado ({type(e).__name__})", "warning")

    def _save_peers(self):
        if self.peers_file:
            try:
                tmp = self.peers_file + ".tmp"
                json.dump([f"{h}:{p}" for h, p in list(self.known_addrs)[:1000]], open(tmp, "w"))
                os.replace(tmp, self.peers_file)
            except Exception as e:
                self.log(f"não foi possível gravar peers.json ({type(e).__name__})", "warning")

    def ban(self, host: str, seconds: int = 3600):
        self.bans[host] = time.time() + seconds
        self.log(f"banido {host} por {seconds}s", "warning")

    def is_banned(self, host: str) -> bool:
        t = self.bans.get(host)
        if t is None:
            return False
        if t < time.time():
            del self.bans[host]
            return False
        return True

    def ready_peers(self):
        return [p for p in self.peers if p.ready and not p.closed]

    # ---------- ciclo de vida ----------
    async def start(self):
        self._server = await asyncio.start_server(self._on_inbound, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        self._tasks.append(asyncio.create_task(self._connect_loop()))
        self._tasks.append(asyncio.create_task(self._ping_loop()))

    async def stop(self):
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        for p in list(self.peers):
            p.close()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._save_peers()

    def _retry_delay(self, addr) -> float:
        """Recuo exponencial: 5 s, 10 s, 20 s... até 5 min, por endereço que falha seguidamente."""
        f = self._fails.get(addr, 0)
        return RECONNECT_BASE * 2 ** max(0, f - 1) if f else RECONNECT_BASE
    _retry_delay_max = RECONNECT_MAX

    async def _connect_loop(self):
        while True:
            try:
                outs = [p for p in self.peers if p.outbound]
                if len(outs) < self.max_outbound:
                    connected = {p.addr for p in self.peers} | {(self.host, self.port)}
                    now = time.time()
                    cands = [a for a, t in self.known_addrs.items()
                             if a not in connected and now - t > min(self._retry_delay(a), RECONNECT_MAX)
                             and not self.is_banned(a[0])]
                    random.shuffle(cands)
                    for a in cands[: self.max_outbound - len(outs)]:
                        self.known_addrs[a] = now
                        asyncio.create_task(self.connect(a))
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                return
            except Exception as e:                       # um erro aqui não pode matar a descoberta de peers
                self.log(f"erro no laço de conexões: {exc_label(e)}", "error")
                await asyncio.sleep(5)

    async def _ping_loop(self):
        while True:
            try:
                await asyncio.sleep(PING_EVERY)
                now = time.time()
                for p in list(self.peers):
                    if now - p.last_recv > IDLE_TIMEOUT:
                        p.close()
                    elif p.ready:
                        await p.send("ping", {"n": random.getrandbits(32)})
            except asyncio.CancelledError:
                return
            except Exception as e:
                self.log(f"erro no laço de ping: {exc_label(e)}", "error")

    def _note_failure(self, addr) -> None:
        f = self._fails[addr] = self._fails.get(addr, 0) + 1
        if f >= MAX_FAILS and addr not in self.seeds:     # endereço morto: esquece (seeds nunca)
            self.known_addrs.pop(addr, None)
            self._fails.pop(addr, None)
            self.log(f"esquecendo {addr[0]}:{addr[1]} após {f} falhas", "debug")

    async def connect(self, addr):
        if self.is_banned(addr[0]):
            return None
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(*addr), 5)
        except Exception as e:
            self._note_failure(addr)
            self.log(f"falha ao conectar em {addr[0]}:{addr[1]}: {type(e).__name__}", "debug")
            return None
        peer = Peer(self, r, w, True, addr)
        await self._run_peer(peer)

    async def _on_inbound(self, reader, writer):
        pn = writer.get_extra_info("peername")
        if not pn:
            writer.close()
            return
        host, port = pn[:2]
        inbound = [p for p in self.peers if not p.outbound]
        loopback = host in ("127.0.0.1", "::1") or host.startswith("127.")
        same_ip = sum(1 for p in inbound if p.addr[0] == host)
        if (self.is_banned(host) or len(inbound) >= self.max_inbound
                or (same_ip >= self.max_per_ip and not (loopback and self.exempt_loopback))):
            self.log(f"conexão de entrada recusada de {host} (banido/lotado/limite por IP)", "debug")
            writer.close()
            return
        await self._run_peer(Peer(self, reader, writer, False, (host, port)))

    # ---------- laço do peer ----------
    async def _run_peer(self, peer: Peer):
        self.peers.append(peer)
        try:
            await peer.send("version", self.node.version_payload())
            while not peer.closed:
                timeout = IDLE_TIMEOUT if peer.ready else HANDSHAKE_TIMEOUT
                hdr = await asyncio.wait_for(peer.reader.readexactly(4), timeout)
                n = int.from_bytes(hdr, "big")
                if n == 0 or n > (MAX_MESSAGE if peer.ready else MAX_PREHANDSHAKE_MESSAGE):
                    peer.misbehave(100, "tamanho de mensagem inválido")
                    break
                raw = await asyncio.wait_for(peer.reader.readexactly(n), 30)
                peer.last_recv = time.time()
                hint = _peek_type(raw)
                if hint is not None and n > MAX_BY_TYPE.get(hint, MAX_MESSAGE):   # barra antes de analisar o JSON
                    peer.misbehave(50, f"mensagem grande demais para o tipo ({n} bytes)")
                    continue
                try:
                    msg = json.loads(raw)
                    t, d = msg["t"], msg.get("d")
                    if not isinstance(t, str):
                        raise ValueError
                except Exception:
                    peer.misbehave(20, "mensagem malformada")
                    continue
                if n > MAX_BY_TYPE.get(t, MAX_MESSAGE):
                    peer.misbehave(50, f"mensagem grande demais para o tipo ({n} bytes)")
                    continue
                verdict = peer.rate_check(t, n, solicited=(t == "blocks" and peer.sync_inflight))
                if verdict == "drop":
                    continue                                  # dicas: descartar rajadas é seguro
                if verdict == "slow":
                    peer.misbehave(1, "excesso de mensagens/bytes")
                    await asyncio.sleep(0.25)                 # contrapressão: processa, mas devagar
                await self._dispatch(peer, t, d)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception as e:                      # nunca derrubar o nó por um peer
            self.log(f"{peer}: erro interno {exc_label(e)}", "error")
        finally:
            peer.close()
            if peer in self.peers:
                self.peers.remove(peer)
                if peer.ready:
                    self.log(f"peer desconectado {peer.addr[0]}:{peer.addr[1]}", "info")

    async def _dispatch(self, peer: Peer, t: str, d):
        node = self.node
        if t == "version":
            return await self._on_version(peer, d)
        if not peer.ready:
            if t == "verack":
                peer.ready = True
                await self._after_handshake(peer)
                return
            peer.misbehave(50, "mensagem antes do handshake")
            return
        if t == "ping":
            await peer.send("pong", d)
        elif t == "pong" or t == "verack":
            pass
        elif t == "getaddr":
            addrs = [f"{h}:{p}" for (h, p) in random.sample(list(self.known_addrs), min(MAX_ADDR, len(self.known_addrs)))]
            await peer.send("addr", addrs)
        elif t == "addr":
            if isinstance(d, list):
                for a in d[:MAX_ADDR]:
                    try:
                        pa = self._parse(a)
                        if 0 < pa[1] < 65536 and len(self.known_addrs) < 2000:
                            self.known_addrs.setdefault(pa, 0)
                    except Exception:
                        peer.misbehave(5, "addr inválido")
                self._save_peers()
        elif t == "inv":
            await self._on_inv(peer, d)
        elif t == "getdata":
            await self._on_getdata(peer, d)
        elif t == "block":
            await node.on_block_message(peer, d)
        elif t == "tx":
            await node.on_tx_message(peer, d)
        elif t == "getblocks":
            await self._on_getblocks(peer, d)
        elif t == "blocks":
            await node.on_blocks_message(peer, d)
        elif t == "getmempool":
            ids = node.mempool.txids()[:MAX_INV]
            if ids:
                await peer.send("inv", {"blocks": [], "txs": ids})
        else:
            peer.misbehave(10, f"mensagem desconhecida {t[:20]}")

    async def _on_version(self, peer: Peer, d):
        node = self.node
        try:
            ok = (isinstance(d, dict) and d["proto"] == PROTOCOL_VERSION
                  and d["chain_id"] == node.chain.params.chain_id
                  and d["genesis"] == node.chain.genesis_block.hash)
        except Exception:
            ok = False
        if not ok:
            peer.misbehave(100, "versão/rede incompatível")
            return
        if d["nonce"] == self.node_id:
            peer.close()                      # conectou em si mesmo
            self.known_addrs.pop(peer.addr, None)
            return
        if any(p is not peer and p.node_id == d["nonce"] and not p.closed for p in self.peers):
            peer.close()                      # já conectado a este nó
            return
        peer.node_id = d["nonce"]
        peer.height = int(d.get("height", 0)) if isinstance(d.get("height", 0), int) else 0
        try:
            peer.work = int(d.get("work", "0"), 16)
        except Exception:
            peer.work = 0
        lp = d.get("port", 0)
        peer.listen_port = lp if isinstance(lp, int) and 0 < lp < 65536 else 0
        if not peer.outbound and peer.listen_port:
            self.known_addrs.setdefault((peer.addr[0], peer.listen_port), 0)
        await peer.send("verack")

    async def _after_handshake(self, peer: Peer):
        self._fails.pop(peer.addr, None)
        self.log(f"peer pronto {peer.addr[0]}:{peer.addr[1]} ({'saída' if peer.outbound else 'entrada'}), "
                 f"altura {peer.height}", "info")
        await peer.send("getaddr")
        await peer.send("getmempool")
        await self.node.maybe_sync(peer)

    async def _on_inv(self, peer: Peer, d):
        node = self.node
        if not isinstance(d, dict):
            return peer.misbehave(10, "inv inválido")
        blocks, txs = d.get("blocks", []), d.get("txs", [])
        if not isinstance(blocks, list) or not isinstance(txs, list) or len(blocks) + len(txs) > MAX_INV:
            return peer.misbehave(20, "inv grande demais")
        want_b = [h for h in blocks if isinstance(h, str) and len(h) == 64 and not node.knows_block(h)]
        want_t = [h for h in txs if isinstance(h, str) and len(h) == 64 and not node.knows_tx(h)]
        for h in blocks + txs:
            if isinstance(h, str):
                peer.known.add(h)
        if want_b or want_t:
            await peer.send("getdata", {"blocks": want_b[:MAX_GETDATA], "txs": want_t[:MAX_GETDATA]})

    async def _on_getdata(self, peer: Peer, d):
        node = self.node
        if not isinstance(d, dict):
            return peer.misbehave(10, "getdata inválido")
        for h in list(d.get("blocks", []))[:MAX_GETDATA]:
            b = node.chain.get_any_block(h) if isinstance(h, str) else None
            if b is not None:
                await peer.send("block", b.to_dict())
        for h in list(d.get("txs", []))[:MAX_GETDATA]:
            tx = node.mempool.get(h) if isinstance(h, str) else None
            if tx is not None:
                await peer.send("tx", tx.to_dict())

    async def _on_getblocks(self, peer: Peer, d):
        if not isinstance(d, dict) or not isinstance(d.get("locator"), list):
            return peer.misbehave(10, "getblocks inválido")
        chain = self.node.chain
        blocks, size = [], 0
        more = False
        for b in chain.blocks_after(d["locator"], 500):
            sz = sum(t.size() for t in b.transactions) + 400
            if blocks and size + sz > BATCH_BYTES:
                more = True
                break
            blocks.append(b)
            size += sz
        else:
            more = bool(blocks) and blocks[-1].height < chain.height
        await peer.send("blocks", {"blocks": [b.to_dict() for b in blocks], "more": more})

    # ---------- difusão ----------
    async def broadcast_inv(self, blocks=(), txs=(), exclude=None):
        for p in self.ready_peers():
            if p is exclude:
                continue
            nb = [h for h in blocks if h not in p.known]
            nt = [h for h in txs if h not in p.known]
            if nb or nt:
                p.known.update(nb); p.known.update(nt)
                if len(p.known) > 50_000:
                    p.known.clear()
                await p.send("inv", {"blocks": nb, "txs": nt})
