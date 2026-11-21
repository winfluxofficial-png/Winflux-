"""Creates the files of a local test network (devnet).

    python -m winflux.tools.devnet init --dir devnet

Generates: genesis.json, producer.key.json (PoA authority) and faucet.key.json
(wallet that receives the initial allocation). The keys are encrypted.
The password comes from the WINFLUX_DEVNET_PASSWORD variable or from a prompt; never from the command line.
"""
import argparse
import dataclasses
import getpass
import os
import sys
import time

from ..blockchain.genesis import GenesisConfig, genesis_fingerprint, save_genesis_config
from ..blockchain.params import ChainParams
from ..units import DECIMALS, to_units
from ..wallet.wallet import Wallet

DEFAULT_PASSWORD = "devnet-only-password"  # LOCAL tests ONLY


def init_devnet(directory: str, genesis_wflx: str, password: str, chain_id: str | None = None,
                kdf_n: int | None = None) -> dict:
    os.makedirs(directory, exist_ok=True)
    gpath = os.path.join(directory, "genesis.json")
    if os.path.exists(gpath):
        raise SystemExit(f"{gpath} already exists; delete the folder to recreate the network")
    producer, faucet = Wallet.create(), Wallet.create()
    kw = {} if kdf_n is None else {"kdf_n": kdf_n}
    producer.save(os.path.join(directory, "producer.key.json"), password, **kw)
    faucet.save(os.path.join(directory, "faucet.key.json"), password, **kw)
    params = ChainParams(
        chain_id=chain_id or "provisional", name="Winflux", symbol="WFLX", decimals=DECIMALS,
        max_supply=to_units("100000000"), block_reward=to_units("50"),
        halving_interval=210_000, min_fee=1000,
        authorities=(producer.keypair.public_hex,))
    ts, allocs = int(time.time()), ((faucet.address, to_units(genesis_wflx)),)
    if chain_id is None:  # unique per genesis: avoids replay between recreated devnets
        chain_id = "winflux-devnet-" + genesis_fingerprint(params, ts, allocs)
        params = dataclasses.replace(params, chain_id=chain_id)
    cfg = GenesisConfig(params, ts, allocs)
    save_genesis_config(cfg, gpath)
    return {"genesis": gpath, "chain_id": params.chain_id, "producer": producer.address, "faucet": faucet.address,
            "genesis_wflx": genesis_wflx}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="creates genesis.json and the devnet keys")
    p.add_argument("--dir", default="devnet")
    p.add_argument("--genesis-wflx", default="5000000", help="WFLX created in the genesis (default 5,000,000)")
    p.add_argument("--chain-id", default=None, help="default: derived from the genesis (recommended)")
    a = ap.parse_args(argv)
    # The password is NOT accepted on the command line (it would show up in `ps` and in the shell history).
    password = os.environ.get("WINFLUX_DEVNET_PASSWORD")
    if password is None and sys.stdin.isatty():
        password = getpass.getpass("Password to encrypt the devnet keys: ")
    if not password:
        password = DEFAULT_PASSWORD
    info = init_devnet(a.dir, a.genesis_wflx, password, a.chain_id)
    print(f"Devnet criada em {a.dir}/  (chain_id: {info['chain_id']})")
    print(f"  authority (producer): {info['producer']}")
    print(f"  faucet wallet       : {info['faucet']}  ({info['genesis_wflx']} WFLX)")
    if password == DEFAULT_PASSWORD:
        print("  WARNING: default devnet password; use only for local tests.")


if __name__ == "__main__":
    sys.exit(main())
