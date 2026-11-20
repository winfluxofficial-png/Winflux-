"""Cria os arquivos de uma rede de testes local (devnet).

    python -m winflux.tools.devnet init --dir devnet

Gera: genesis.json, producer.key.json (autoridade PoA) e faucet.key.json
(carteira que recebe a alocação inicial). As chaves ficam cifradas.
A senha vem da variável WINFLUX_DEVNET_PASSWORD ou de um prompt; nunca da linha de comando.
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

DEFAULT_PASSWORD = "devnet-only-password"  # SOMENTE testes locais


def init_devnet(directory: str, genesis_wflx: str, password: str, chain_id: str | None = None,
                kdf_n: int | None = None) -> dict:
    os.makedirs(directory, exist_ok=True)
    gpath = os.path.join(directory, "genesis.json")
    if os.path.exists(gpath):
        raise SystemExit(f"{gpath} já existe; apague a pasta para recriar a rede")
    producer, faucet = Wallet.create(), Wallet.create()
    kw = {} if kdf_n is None else {"kdf_n": kdf_n}
    producer.save(os.path.join(directory, "producer.key.json"), password, **kw)
    faucet.save(os.path.join(directory, "faucet.key.json"), password, **kw)
    params = ChainParams(
        chain_id=chain_id or "provisorio", name="Winflux", symbol="WFLX", decimals=DECIMALS,
        max_supply=to_units("100000000"), block_reward=to_units("50"),
        halving_interval=210_000, min_fee=1000,
        authorities=(producer.keypair.public_hex,))
    ts, allocs = int(time.time()), ((faucet.address, to_units(genesis_wflx)),)
    if chain_id is None:  # único por gênese: evita replay entre devnets recriadas
        chain_id = "winflux-devnet-" + genesis_fingerprint(params, ts, allocs)
        params = dataclasses.replace(params, chain_id=chain_id)
    cfg = GenesisConfig(params, ts, allocs)
    save_genesis_config(cfg, gpath)
    return {"genesis": gpath, "chain_id": params.chain_id, "producer": producer.address, "faucet": faucet.address,
            "genesis_wflx": genesis_wflx}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="cria genesis.json e chaves da devnet")
    p.add_argument("--dir", default="devnet")
    p.add_argument("--genesis-wflx", default="5000000", help="WFLX criados no gênese (padrão 5.000.000)")
    p.add_argument("--chain-id", default=None, help="padrão: derivado do gênese (recomendado)")
    a = ap.parse_args(argv)
    # A senha NÃO é aceita na linha de comando (apareceria em `ps` e no histórico do shell).
    password = os.environ.get("WINFLUX_DEVNET_PASSWORD")
    if password is None and sys.stdin.isatty():
        password = getpass.getpass("Senha para cifrar as chaves da devnet: ")
    if not password:
        password = DEFAULT_PASSWORD
    info = init_devnet(a.dir, a.genesis_wflx, password, a.chain_id)
    print(f"Devnet criada em {a.dir}/  (chain_id: {info['chain_id']})")
    print(f"  autoridade (produtor): {info['producer']}")
    print(f"  carteira faucet      : {info['faucet']}  ({info['genesis_wflx']} WFLX)")
    if password == DEFAULT_PASSWORD:
        print("  AVISO: senha padrão de devnet; use apenas em testes locais.")


if __name__ == "__main__":
    sys.exit(main())
