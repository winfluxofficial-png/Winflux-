"""Executa um nó Winflux.

    python -m winflux.node.main --genesis genesis.json --datadir ~/.winflux \
        --listen 0.0.0.0:8333 --api 127.0.0.1:8080 --seed host:8333 [--mine wflx1...] \\
        [--log-level info] [--log-file node.log]

Qualquer pessoa pode rodar isto sem pedir permissão. O gênese é verificado por você mesmo:
o `chain_id` e o hash do gênese precisam ser os mesmos dos seus pares.
"""
import argparse
import asyncio
import signal
import sys

from ..api.server import ApiServer
from ..blockchain.genesis import load_genesis_config
from ..crypto.address import is_valid_address
from ..errors import StorageError, ValidationError
from ..logs import LEVELS, make_log, setup_logging
from .node import Node


def _hostport(s: str, default_host="127.0.0.1"):
    host, _, port = s.rpartition(":")
    return (host or default_host, int(port))


async def run(args) -> None:
    cfg = load_genesis_config(args.genesis)
    lh, lp = _hostport(args.listen, "0.0.0.0")
    node = Node(cfg, datadir=args.datadir, host=lh, port=lp, seeds=args.seed, mine_to=args.mine,
                max_outbound=args.max_outbound, max_inbound=args.max_inbound,
                max_inbound_per_ip=args.max_inbound_per_ip, log=make_log("node"))
    await node.start()
    api = None
    if args.api:
        ah, ap = _hostport(args.api)
        api = ApiServer(node, ah, ap, rate_per_min=args.api_rate, tx_rate_per_min=args.api_tx_rate,
                        trust_proxy=args.api_trust_proxy, log=make_log("api"))
        await api.start()
    make_log("node")(f"Winflux {cfg.params.chain_id}: altura {node.chain.height}, P2P :{node.port}"
                     + (f", API {api.host}:{api.port}" if api else "") + (", minerando" if node.mining else ""))
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    await stop.wait()
    if api:
        await api.stop()
    await node.stop()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--genesis", required=True)
    ap.add_argument("--datadir", default="winflux-data")
    ap.add_argument("--listen", default="0.0.0.0:8333")
    ap.add_argument("--api", default="127.0.0.1:8080", help="vazio para desativar")
    ap.add_argument("--seed", action="append", default=[], help="host:porta de um nó conhecido (repetível)")
    ap.add_argument("--mine", default=None, help="endereço que recebe as recompensas; liga a mineração")
    ap.add_argument("--log-level", default="info", choices=list(LEVELS))
    ap.add_argument("--log-file", default=None, help="também grava em arquivo (rotação 5 MB x 3)")
    ap.add_argument("--max-outbound", type=int, default=8)
    ap.add_argument("--max-inbound", type=int, default=32)
    ap.add_argument("--max-inbound-per-ip", type=int, default=8, help="conexões de entrada por IP (loopback isento)")
    ap.add_argument("--api-rate", type=int, default=600, help="requisições/min por IP na API (padrão 600)")
    ap.add_argument("--api-tx-rate", type=int, default=60, help="POST /api/tx por min por IP (padrão 60)")
    ap.add_argument("--api-trust-proxy", action="store_true",
                    help="usa o último X-Forwarded-For como IP do cliente (SÓ atrás de proxy seu, nunca exposto)")
    a = ap.parse_args(argv)
    if a.mine and not is_valid_address(a.mine):
        ap.error("endereço de mineração inválido")
    setup_logging(a.log_level, a.log_file)
    try:
        asyncio.run(run(a))
    except FileNotFoundError as e:
        print(f"erro: arquivo não encontrado: {e.filename}", file=sys.stderr)
        return 2
    except (ValidationError, StorageError) as e:
        print(f"erro: {e}", file=sys.stderr)
        return 2
    except OSError as e:                      # porta em uso, sem permissão, disco...
        print(f"erro de sistema ao iniciar o nó: {e.strerror or type(e).__name__}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
