"""Smoke test de ponta a ponta da testnet Winflux. Verifica, em ordem:

  1. os nós sobem, estão na mesma rede e se enxergam;
  2. a mineração produz blocos e a recompensa chega ao minerador;
  3. uma transação enviada a um nó se propaga, é minerada e chega a todos;
  4. todos os nós convergem (mesmo topo/oferta) e um nó que entra TARDE sincroniza a cadeia toda;
  5. fluxo offline: abre cofre com chave por vaga, paga Bob -> Carol OFFLINE, liquida com `note_claim` num nó
     diferente, confere saldo, estado do cofre, relatório de reconciliação (A4) e rejeição de reapresentação.

    PYTHONPATH=. python scripts/smoke_test.py                    # sobe uma testnet local temporária e derruba no fim
    PYTHONPATH=. python scripts/smoke_test.py --nodes http://127.0.0.1:18080,http://127.0.0.1:18081 \\
        --wallet local-testnet/miner.wallet.json                 # contra uma rede já rodando (pula o passo do nó tardio)

Código de saída 0 = tudo passou. Usa chaves/senha de devnet: SOMENTE testes locais.
"""
import argparse
import os
import secrets
import shutil
import sys
import tempfile
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from winflux.blockchain.params import ChainParams  # noqa: E402
from winflux.blockchain.transaction import TxOutput  # noqa: E402
from winflux.blockchain.vaults import Vault  # noqa: E402
from winflux.cli import RemoteChain, api  # noqa: E402
from winflux.crypto.keys import KeyPair  # noqa: E402
from winflux.errors import WinfluxError  # noqa: E402
from winflux.offline import note as N  # noqa: E402
from winflux.offline.voucher import chain_id_hash  # noqa: E402
from winflux.tools.localnet import DEFAULT_PASSWORD, LocalTestnet  # noqa: E402
from winflux.units import format_units, to_units  # noqa: E402
from winflux.wallet.hd import HDWallet  # noqa: E402
from winflux.wallet.reconcile import SETTLED, Journal, reconcile  # noqa: E402
from winflux.wallet.vault_builder import build_note_claim, build_vault_open  # noqa: E402
from winflux.wallet.wallet import Wallet  # noqa: E402

RESULTS: list = []


def wait(cond, timeout, what, every=0.5):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            last = cond()
            if last:
                return last
        except (WinfluxError, OSError, KeyError):
            pass
        time.sleep(every)
    raise AssertionError(f"tempo esgotado esperando: {what}")


def step(title):
    def deco(fn):
        def run(*a, **k):
            t = time.time()
            try:
                out = fn(*a, **k)
                RESULTS.append((title, True, ""))
                print(f"[ OK ] {title}  ({time.time() - t:.1f}s)", flush=True)
                return out
            except Exception as e:
                RESULTS.append((title, False, str(e) or type(e).__name__))
                print(f"[FALHOU] {title}: {e or type(e).__name__}", flush=True)
                if os.environ.get("SMOKE_TRACE"):
                    traceback.print_exc()
                return None
        return run
    return deco


class Smoke:
    def __init__(self, urls, wallet_path, password, net=None, timeout=240):
        self.urls, self.net, self.timeout = urls, net, timeout
        self.hd = HDWallet.from_wallet(Wallet.load(wallet_path, password))
        self.params = ChainParams.from_dict(api(urls[0], "/api/params"))
        self.fee = self.params.min_fee

    # ---------- utilidades ----------
    def status(self, url):
        return api(url, "/api/status")

    def height(self, url=None):
        return self.status(url or self.urls[0])["height"]

    def balance(self, url, address):
        return api(url, f"/api/address/{address}")["balance"]

    def converged(self):
        sts = [self.status(u) for u in self.urls]
        return len({s["tip"] for s in sts}) == 1 and len({s["supply"] for s in sts}) == 1

    def submit(self, url, tx):
        return api(url, "/api/tx", tx.to_dict())["txid"]

    def confirmed(self, txid, url=None):
        try:
            return api(url or self.urls[0], f"/api/tx/{txid}")["confirmations"] >= 1
        except WinfluxError:
            return False

    def fund(self, to_address, amount, via):
        """Paga `amount` a `to_address` a partir da carteira do minerador, enviando ao nó `via`."""
        def spendable():                          # recompensas só amadurecem após `coinbase_maturity` blocos
            chain = RemoteChain(self.urls[0])
            self.hd.discover(chain)
            return sum(o.value for _, o in self.hd.utxos(chain)) >= amount + 20 * self.fee
        wait(spendable, 150, f"minerador ter {format_units(amount)} WFLX gastáveis", every=2)
        chain = RemoteChain(self.urls[0])
        self.hd.discover(chain)
        tx = self.hd.pay(chain, to_address, amount)
        txid = self.submit(via, tx)
        wait(lambda: self.confirmed(txid), 90, f"tx {txid[:12]} minerada")
        return txid

    # ---------- passos ----------
    @step("1. nós sobem, mesma rede e conectados entre si")
    def nodes_up(self):
        ids = set()
        for u in self.urls:
            st = wait(lambda u=u: self.status(u), 30, f"nó {u} responder")
            ids.add(st["chain_id"])
        assert len(ids) == 1, f"redes diferentes: {ids}"
        for u in self.urls:
            wait(lambda u=u: self.status(u)["peers"] >= 1, 40, f"{u} ter peers")
        return ids.pop()

    @step("2. mineração produz blocos e paga o minerador")
    def mining(self):
        mature = self.params.coinbase_maturity
        h0 = self.height()
        wait(lambda: self.height() >= max(h0 + 2, mature + 4), 120, "altura subir")
        addr = self.hd.address(0)
        wait(lambda: self.balance(self.urls[0], addr) > 0, 30, "saldo do minerador > 0")
        return self.balance(self.urls[0], addr)

    @step("3. transação propaga, é minerada e chega a todos os nós")
    def transfer(self):
        dest = KeyPair.generate().address
        amount = to_units("7.5")
        via = self.urls[-2] if len(self.urls) > 2 else self.urls[-1]     # um nó que NÃO é o minerador
        txid = self.fund(dest, amount, via)
        for u in self.urls:
            wait(lambda u=u: self.balance(u, dest) == amount, 60, f"{u} ver o saldo de {format_units(amount)}")
        return txid

    @step("4. nós convergem (topo e oferta) e um nó tardio sincroniza a cadeia")
    def sync(self):
        wait(self.converged, 90, "todos no mesmo topo")
        if self.net is None:
            return
        late = self.net.add_node("late", seeds=[f"127.0.0.1:{self.net.nodes[0].p2p_port}"])
        self.net.wait_ready(40)
        tip = self.status(self.urls[0])["height"]
        wait(lambda: self.status(late.api)["height"] >= tip, 90, "nó tardio alcançar a cadeia")
        self.urls.append(late.api)
        wait(self.converged, 60, "nó tardio no mesmo topo")

    @step("5. fluxo offline: cofre + notas offline + note_claim + reconciliação")
    def offline(self):
        a, b = self.urls[0], self.urls[-1]
        # 5.1 dono do cofre recebe fundos
        owner, device, carol = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
        self.fund(owner.address, to_units("3"), b)
        wait(lambda: self.balance(a, owner.address) >= to_units("3"), 60, "dono financiado")
        # 5.2 abre o cofre com chave por vaga (2 vagas de 0,5 WFLX; colateral de 100%)
        cap = to_units("0.5")
        slot_signers = [N.SoftwareSigner(KeyPair.generate()) for _ in range(2)]
        info = api(a, f"/api/address/{owner.address}")
        utxos = [((u["txid"], u["index"]), TxOutput(u["value"], owner.address)) for u in info["utxos"]]
        tx = build_vault_open(owner, utxos, device, (cap, cap), 100, self.params.vault_ttl_min_blocks,
                              owner.address, self.params, slot_keys=[s.public_hex for s in slot_signers])
        vid = self.submit(b, tx)
        vault = wait(lambda: api(a, f"/api/vault/{vid}"), 90, "cofre aparecer on-chain")
        assert vault["state"] == "OPEN" and len(vault["slots"]) == 2, vault
        # 5.3 pagamento OFFLINE encadeado: vaga 0 -> Bob (nota) -> Carol (endereço). Nada disto toca a rede.
        bob = N.SoftwareSigner(KeyPair.generate())
        chash = chain_id_hash(self.params.chain_id)
        t1 = N.spend_root(chain_hash=chash, vault_id=vid, slot=0, cap=cap, request_id=secrets.token_bytes(16),
                          signer=slot_signers[0],
                          outputs=[N.NoteOutput(cap, N.KIND_NOTE, N.owner_commitment(bob.key_type, bob.public_key))])
        t2 = N.spend_output(t1, 0, request_id=secrets.token_bytes(16), signer=bob,
                            outputs=[N.NoteOutput(cap, N.KIND_ADDRESS, N.address_owner(carol.address))])
        pay = N.OfflinePayment({}, 0, (t1, t2), 0)
        journal = Journal()
        journal.record_hop(t1, 0)
        # 5.4 Carol liquida num nó DIFERENTE do que viu o cofre ser aberto
        v = Vault.from_dict(api(b, f"/api/vault/{vid}"))
        claim = build_note_claim(pay, v, self.params)
        assert claim.kind == "note_claim"
        txid = self.submit(self.urls[len(self.urls) // 2], claim)
        wait(lambda: self.confirmed(txid, b), 90, "note_claim minerado")
        want = cap - self.fee
        for u in self.urls:
            wait(lambda u=u: self.balance(u, carol.address) == want, 60, f"{u} ver {format_units(want)} de Carol")
        # 5.5 estado do cofre e reconciliação (A4)
        d = api(a, f"/api/vault/{vid}")
        slot = Vault.from_dict(d).slots[0]
        assert slot.paid == cap and len(slot.settled) == 1 and not d["fraud"], d
        rep = reconcile(Vault.from_dict(d), journal, self.params, d["height"])
        assert rep.slots[0].status == SETTLED and rep.clean, rep
        # 5.6 reapresentar a mesma cadeia é recusado
        try:
            build_note_claim(pay, Vault.from_dict(d), self.params)
            raise AssertionError("reapresentação deveria ser recusada")
        except WinfluxError:
            pass
        wait(self.converged, 60, "convergência final")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nodes", default="", help="URLs de API separadas por vírgula (padrão: sobe uma testnet local)")
    ap.add_argument("--wallet", default="", help="keystore do minerador (obrigatório com --nodes)")
    ap.add_argument("--block-time", type=int, default=2)
    ap.add_argument("--keep", action="store_true", help="mantém o diretório temporário e os logs")
    a = ap.parse_args(argv)
    password = os.environ.get("WINFLUX_DEVNET_PASSWORD", DEFAULT_PASSWORD)
    net, tmp = None, None
    try:
        if a.nodes:
            if not a.wallet:
                ap.error("--wallet é obrigatório com --nodes")
            urls, wallet = [u.strip() for u in a.nodes.split(",") if u.strip()], a.wallet
        else:
            tmp = tempfile.mkdtemp(prefix="winflux-smoke-")
            net = LocalTestnet(tmp, block_time=a.block_time, password=password)
            print(f"subindo testnet local em {tmp} ...", flush=True)
            net.prepare()
            net.start()
            urls, wallet = [n.api for n in net.nodes], net.wallet_path
        s = Smoke(urls, wallet, password, net)
        s.nodes_up()
        s.mining()
        s.transfer()
        s.sync()
        s.offline()
    except Exception as e:                                   # falha de infraestrutura (não de um passo)
        print(f"[FALHOU] infraestrutura: {e}", file=sys.stderr)
        RESULTS.append(("infraestrutura", False, str(e)))
    finally:
        if net:
            net.stop()
        if tmp and not a.keep:
            shutil.rmtree(tmp, ignore_errors=True)
        elif tmp:
            print(f"(logs mantidos em {tmp}/logs)")
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passos OK" + ("" if not failed else "  — FALHAS: "
          + "; ".join(f"{t}" for t, _, _ in failed)))
    return 1 if failed or not RESULTS else 0


if __name__ == "__main__":
    sys.exit(main())
