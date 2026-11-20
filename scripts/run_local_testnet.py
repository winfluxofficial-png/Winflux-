"""Sobe uma testnet local: 3 nós conectados + 1 minerador (4 processos), com gênese gerado pelo `netgen`.

    PYTHONPATH=. python scripts/run_local_testnet.py --dir local-testnet [--block-time 4] [--base-p2p 18333]

Cria em --dir: genesis.json, miner.wallet.json (carteira do minerador; senha padrão de devnet ou a variável
WINFLUX_DEVNET_PASSWORD), <nó>/ (dados) e logs/<nó>.log. Portas: P2P base..base+3 e API base..base+3, em 127.0.0.1.
Ctrl+C encerra tudo. Use `--keep` para reaproveitar o diretório (retoma a cadeia).
SOMENTE testes locais: não use as chaves/senha daqui com dinheiro real.
"""
import argparse
import os
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from winflux.tools.localnet import DEFAULT_PASSWORD, LocalTestnet  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default="local-testnet")
    ap.add_argument("--nodes", type=int, default=3, help="nós sem mineração (padrão 3); o minerador é um nó a mais")
    ap.add_argument("--block-time", type=int, default=4, help="segundos por bloco desejados (calibra a dificuldade)")
    ap.add_argument("--base-p2p", type=int, default=18333)
    ap.add_argument("--base-api", type=int, default=18080)
    ap.add_argument("--keep", action="store_true", help="não apaga o diretório: retoma a rede anterior")
    ap.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])
    ap.add_argument("--duration", type=int, default=0, help="encerra sozinho após N segundos (0 = até Ctrl+C)")
    a = ap.parse_args(argv)

    net = LocalTestnet(a.dir, nodes=a.nodes, base_p2p=a.base_p2p, base_api=a.base_api,
                       block_time=a.block_time, log_level=a.log_level)
    print("calibrando dificuldade e gerando o gênese...", flush=True)
    net.prepare(fresh=not a.keep)
    stop = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.append(1))
    try:
        net.start()
        print(f"\nTestnet local no ar (rede {net.chain_id})")
        for n in net.nodes:
            print(f"  {n.name:<7} P2P 127.0.0.1:{n.p2p_port}  API {n.api}" + ("  [minerando]" if n.mine else "")
                  + f"  log {os.path.relpath(n.log_path)}")
        print(f"\n  gênese : {os.path.relpath(net.genesis_path)}")
        print(f"  carteira do minerador: {os.path.relpath(net.wallet_path)}  (endereço {net.miner_address})")
        if net.password == DEFAULT_PASSWORD:
            print("  AVISO: senha padrão de devnet; use apenas em testes locais.")
        print("\nExemplos:")
        print(f"  curl -s {net.nodes[0].api}/api/status")
        print(f"  WINFLUX_WALLET_PASSWORD='{DEFAULT_PASSWORD}' PYTHONPATH=. python -m winflux.cli "
              f"--node {net.nodes[1].api} --wallet {os.path.relpath(net.wallet_path)} balance")
        print("\nCtrl+C para encerrar.", flush=True)
        end = time.time() + a.duration if a.duration else None
        while not stop and (end is None or time.time() < end):
            dead = [n for n in net.nodes if not n.alive()]
            if dead:
                print(f"ERRO: {dead[0].name} parou:\n{net.tail(dead[0])}", file=sys.stderr)
                return 1
            time.sleep(0.5)
    except RuntimeError as e:
        print(f"ERRO: {e}", file=sys.stderr)
        return 1
    finally:
        print("\nencerrando nós...", flush=True)
        net.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
