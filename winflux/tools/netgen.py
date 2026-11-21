"""Generates the genesis of a PUBLIC PoW network with a fair launch.

    python -m winflux.tools.netgen --name testnet --out genesis-testnet.json

Fair launch: ZERO premine, ZERO allocations, ZERO authorities, no administrative
key. Every coin is born from open mining. The `chain_id` is derived from the genesis.
Parameters (block time, initial difficulty, maturity) are design decisions:
review them (docs/decentralization.md) before publishing. Whoever publishes the file gains no
power at all: the genesis is just data, and every node verifies it.
"""
import argparse
import dataclasses
import sys
import time

from ..blockchain.genesis import GenesisConfig, genesis_fingerprint, save_genesis_config
from ..blockchain.params import ChainParams
from ..units import to_units

DAY = 86400


def public_pow_params(name: str, block_time: int = 60, initial_hashes: int = 2**20, halving_years: float = 2.0,
                      maturity: int = 100) -> ChainParams:
    max_supply = to_units("100000000")
    halving = max(1, int(halving_years * 365 * DAY // block_time))
    reward = max_supply // (2 * halving)                 # sum of issuance <= max_supply
    limit = (1 << 256) // initial_hashes - 1             # initial difficulty ~ `initial_hashes` attempts
    return ChainParams(
        chain_id="provisional", name="Winflux", symbol="WFLX", decimals=8, max_supply=max_supply,
        block_reward=reward, halving_interval=halving, min_fee=1000, authorities=(),
        target_block_time=block_time, consensus="pow", pow_limit=format(limit, "064x"),
        pow_retarget_interval=max(2, min(2016, DAY // block_time)),
        coinbase_maturity=maturity,
        vault_ttl_min_blocks=max(1, DAY // block_time),
        vault_ttl_max_blocks=30 * DAY // block_time,
        claim_window_blocks=max(1, 7 * DAY // block_time))


def make_genesis(name: str, **kw) -> GenesisConfig:
    params = public_pow_params(name, **kw)
    ts = int(time.time())
    cid = f"winflux-{name}-" + genesis_fingerprint(params, ts, ())
    return GenesisConfig(dataclasses.replace(params, chain_id=cid), ts, ())


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", default="testnet")
    ap.add_argument("--out", required=True)
    ap.add_argument("--block-time", type=int, default=60)
    ap.add_argument("--initial-hashes", type=int, default=2**20, help="initial difficulty (attempts per block)")
    ap.add_argument("--maturity", type=int, default=100)
    a = ap.parse_args(argv)
    cfg = make_genesis(a.name, block_time=a.block_time, initial_hashes=a.initial_hashes, maturity=a.maturity)
    save_genesis_config(cfg, a.out)
    p = cfg.params
    print(f"genesis written to {a.out}\n  chain_id: {p.chain_id}\n  premine: 0 | authorities: 0")
    print(f"  initial reward: {p.block_reward / 1e8:.8f} WFLX | halving every {p.halving_interval} blocks")


if __name__ == "__main__":
    sys.exit(main())
