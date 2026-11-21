"""Local testnet: N connected nodes + 1 miner, each in its own process, from a genesis generated with `netgen`.

    python scripts/run_local_testnet.py --dir local-testnet

Also used by `scripts/smoke_test.py`. For LOCAL tests ONLY: the miner's wallet uses a default devnet password
(or WINFLUX_DEVNET_PASSWORD) and the ports listen on 127.0.0.1. It does not change consensus rules or
monetary parameters: the genesis comes from `netgen.make_genesis`; only the initial difficulty (calibrated for the requested
`block_time`) and the maturity (2 blocks) are adjusted, both exposed by netgen itself.
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field

from ..blockchain.chain import Chain
from ..blockchain.genesis import load_genesis_config, save_genesis_config
from ..consensus.pow import ProofOfWork
from ..wallet.hd import HDWallet
from ..wallet.wallet import Wallet
from .netgen import make_genesis

DEFAULT_PASSWORD = "devnet-only-password"           # LOCAL tests ONLY
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def measure_hashrate(seconds_of_work: int = 150_000) -> float:
    """Hashes/s of ONE mining thread (what the node uses), measured on a real block."""
    cfg = make_genesis("calibration", block_time=60, initial_hashes=2**40)
    chain = Chain(cfg, ProofOfWork())
    blk = chain.create_block("", _dummy_address(), [], timestamp=cfg.timestamp + 1)
    t = time.perf_counter()
    ProofOfWork.search(blk, 0, 0, seconds_of_work)            # target 0: never finds one, sweeps everything
    return seconds_of_work / (time.perf_counter() - t)


def _dummy_address() -> str:
    from ..crypto.keys import KeyPair
    return KeyPair(b"\x01" * 32).address


def http_json(url: str, timeout: float = 3.0):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


@dataclass
class NodeProc:
    name: str
    p2p_port: int
    api_port: int
    datadir: str
    log_path: str
    mine: bool = False
    proc: subprocess.Popen | None = field(default=None, repr=False)

    @property
    def api(self) -> str:
        return f"http://127.0.0.1:{self.api_port}"

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def status(self):
        return http_json(self.api + "/api/status")


class LocalTestnet:
    def __init__(self, directory: str, *, nodes: int = 3, base_p2p: int = 18333, base_api: int = 18080,
                 block_time: int = 4, maturity: int = 2, log_level: str = "info", password: str | None = None):
        self.dir, self.n_nodes = os.path.abspath(directory), nodes
        self.base_p2p, self.base_api = base_p2p, base_api
        self.block_time, self.maturity, self.log_level = block_time, maturity, log_level
        self.password = password or os.environ.get("WINFLUX_DEVNET_PASSWORD") or DEFAULT_PASSWORD
        self.nodes: list[NodeProc] = []
        self.genesis_path = os.path.join(self.dir, "genesis.json")
        self.wallet_path = os.path.join(self.dir, "miner.wallet.json")
        self.miner_address = ""

    # ---------- setup ----------
    def prepare(self, fresh: bool = True) -> None:
        if fresh and os.path.isdir(self.dir):
            shutil.rmtree(self.dir)
        os.makedirs(os.path.join(self.dir, "logs"), exist_ok=True)
        if os.path.exists(self.wallet_path):
            wallet = Wallet.load(self.wallet_path, self.password)
        else:
            wallet = Wallet.create()
            wallet.save(self.wallet_path, self.password)
        self.miner_address = HDWallet.from_wallet(wallet).address(0)   # the same one `cli balance` sees
        if not os.path.exists(self.genesis_path):
            hashes = max(16, int(measure_hashrate() * self.block_time))   # ~block_time s per block with 1 miner
            cfg = make_genesis("local", block_time=self.block_time, initial_hashes=hashes, maturity=self.maturity)
            save_genesis_config(cfg, self.genesis_path)
        self.config = load_genesis_config(self.genesis_path)

    @property
    def chain_id(self) -> str:
        return self.config.params.chain_id

    # ---------- processes ----------
    def _spawn(self, node: NodeProc, seeds: list[str]) -> None:
        cmd = [sys.executable, "-u", "-m", "winflux.node.main", "--genesis", self.genesis_path,
               "--datadir", node.datadir, "--listen", f"127.0.0.1:{node.p2p_port}",
               "--api", f"127.0.0.1:{node.api_port}", "--log-level", self.log_level]
        for s in seeds:
            cmd += ["--seed", s]
        if node.mine:
            cmd += ["--mine", self.miner_address]
        env = dict(os.environ, PYTHONPATH=REPO_ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
        log = open(node.log_path, "ab")
        node.proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=REPO_ROOT, env=env)

    def add_node(self, name: str, *, mine: bool = False, seeds: list[str] | None = None) -> NodeProc:
        i = len(self.nodes)
        n = NodeProc(name, self.base_p2p + i, self.base_api + i, os.path.join(self.dir, name),
                     os.path.join(self.dir, "logs", f"{name}.log"), mine)
        self.nodes.append(n)
        self._spawn(n, seeds if seeds is not None else [f"127.0.0.1:{self.nodes[0].p2p_port}"] if i else [])
        return n

    def start(self, timeout: float = 60) -> None:
        for i in range(self.n_nodes):
            self.add_node(f"node{i}")
        self.add_node("miner", mine=True)            # the miner is also a full node, connected to the others
        self.wait_ready(timeout)

    def wait_ready(self, timeout: float = 60) -> None:
        deadline = time.time() + timeout
        pending = list(self.nodes)
        while pending and time.time() < deadline:
            for n in list(pending):
                if not n.alive():
                    raise RuntimeError(f"{n.name} exited on startup (see {n.log_path}):\n{self.tail(n)}")
                try:
                    n.status()
                    pending.remove(n)
                except OSError:
                    pass
            time.sleep(0.3)
        if pending:
            raise RuntimeError("nodes did not respond in time: " + ", ".join(n.name for n in pending))

    def tail(self, node: NodeProc, lines: int = 15) -> str:
        try:
            with open(node.log_path, "rb") as f:
                return b"".join(f.readlines()[-lines:]).decode("utf-8", "replace")
        except OSError:
            return ""

    def stop(self, grace: float = 10) -> None:
        for n in self.nodes:
            if n.alive():
                n.proc.terminate()
        end = time.time() + grace
        for n in self.nodes:
            if n.proc is None:
                continue
            try:
                n.proc.wait(max(0.1, end - time.time()))
            except subprocess.TimeoutExpired:
                n.proc.kill()
                n.proc.wait()
