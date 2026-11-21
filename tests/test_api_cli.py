"""HTTP API and command-line wallet against a real node; fair genesis."""
import asyncio
import json
import urllib.request

from winflux.api.server import ApiServer
from winflux.blockchain.genesis import GenesisConfig, load_genesis_config
from winflux.cli import main as cli_main
from winflux.consensus.pow import ProofOfWork
from winflux.node.node import Node
from winflux.tools.netgen import make_genesis, main as netgen_main
from winflux.wallet.hd import HDWallet

from .conftest import T0, WFLX, kp
from .test_network import run, wait_for
from .test_pow_reorg import pow_params


def http(port, path, data=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 data=None if data is None else json.dumps(data).encode())
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def test_fair_launch_genesis_has_no_premine_no_authority(tmp_path):
    out = str(tmp_path / "g.json")
    netgen_main(["--name", "t", "--out", out, "--initial-hashes", "256"])
    cfg = load_genesis_config(out)
    assert cfg.allocations == () and cfg.total == 0
    assert cfg.params.authorities == () and cfg.params.consensus == "pow"
    # total issuance never exceeds the cap
    p, total, r, h = cfg.params, 0, cfg.params.block_reward, cfg.params.halving_interval
    while r > 0:
        total += r * h
        r >>= 1
    assert 0.999 * p.max_supply <= total <= p.max_supply


def test_api_and_cli_end_to_end(tmp_path, monkeypatch, capsys):
    async def go():
        cfg = make_genesis("e2e", initial_hashes=64, maturity=2)
        node = Node(cfg)
        await node.start()
        api = ApiServer(node)
        await api.start()
        url = f"http://127.0.0.1:{api.port}"
        loop = asyncio.get_running_loop()
        call = lambda *a: loop.run_in_executor(None, lambda: cli_main(["--node", url, "--wallet", w, *a]))
        w = str(tmp_path / "w.json")
        monkeypatch.setenv("WINFLUX_WALLET_PASSWORD", "strong-password-123")
        try:
            assert await call("create") == 0
            addr = capsys.readouterr().out.split("address: ")[1].split()[0]
            for _ in range(4):
                await node.mine_one(addr)
            code, st = await loop.run_in_executor(None, http, api.port, "/api/status")
            assert code == 200 and st["height"] == 4 and st["supply"] == 4 * cfg.params.block_reward
            assert await call("balance") == 0
            # only 2 rewards matured (maturity 2): 4 blocks => full balance visible, partially spendable
            assert "WFLX" in capsys.readouterr().out
            dest = kp(3).address
            amount = str(cfg.params.block_reward // 10**8 // 2)
            capsys.readouterr()
            assert await call("send", dest, amount) == 0
            txid = capsys.readouterr().out.split("sent: ")[1].strip()
            assert await wait_for(lambda: txid in node.mempool)
            code, r = await loop.run_in_executor(None, http, api.port, f"/api/tx/{txid}")
            assert code == 200 and r["confirmations"] == 0
            await node.mine_one(kp(9).address)
            code, r = await loop.run_in_executor(None, http, api.port, f"/api/tx/{txid}")
            assert r["confirmations"] == 1
            code, a = await loop.run_in_executor(None, http, api.port, f"/api/address/{dest}")
            assert a["balance"] == int(amount) * 10**8
            # invalid inputs on the API
            assert (await loop.run_in_executor(None, http, api.port, "/api/address/garbage"))[0] == 400
            assert (await loop.run_in_executor(None, http, api.port, "/api/tx", {"x": 1}))[0] == 400
            assert (await loop.run_in_executor(None, http, api.port, "/api/block/999"))[0] == 404
        finally:
            await api.stop(); await node.stop()
    run(go())
