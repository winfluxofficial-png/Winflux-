"""Command-line wallet. Talks to ANY node through the API; the keys never leave here.

    python -m winflux.cli --node http://127.0.0.1:8080 --wallet mine.json create
    python -m winflux.cli ... address | balance | send <address> <amount> | status | recover <key>
    python -m winflux.cli ... vaults | reconcile <vault_id> [--journal vault-journal.json] | vault-refund <vault_id>

Password: WINFLUX_WALLET_PASSWORD variable or prompt (never on the command line).
"""
import argparse
import getpass
import json
import os
import sys
import urllib.request

from .blockchain.params import ChainParams
from .blockchain.transaction import TxOutput
from .errors import WinfluxError
from .units import format_units, to_units
from .wallet.hd import HDWallet
from .wallet.reconcile import Journal, reconcile, render
from .wallet.wallet import Wallet


def api(node: str, path: str, data=None):
    req = urllib.request.Request(node.rstrip("/") + path,
                                 data=None if data is None else json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise WinfluxError(json.load(e).get("error", str(e))) from None
    except OSError as e:
        raise WinfluxError(f"could not reach node {node}: {e}") from None


class _Utxo:
    def __init__(self, remote): self.r = remote

    def utxos_for(self, address):
        info = self.r._addr(address)
        spend_h = info["height"] + 1
        return [((u["txid"], u["index"]), TxOutput(u["value"], address)) for u in info["utxos"]
                if u["spendable_at_height"] <= spend_h]


class RemoteChain:
    """Adapter with the minimal interface HDWallet expects, backed by the node API."""

    def __init__(self, node: str):
        self.node = node
        self.params = ChainParams.from_dict(api(node, "/api/params"))
        self.utxo = _Utxo(self)
        self._cache: dict = {}

    def _addr(self, a):
        if a not in self._cache:
            self._cache[a] = api(self.node, f"/api/address/{a}")
        return self._cache[a]

    def address_seen(self, a): return self._addr(a)["seen"]
    def balance(self, a): return self._addr(a)["balance"]


def _password(confirm=False) -> str:
    pw = os.environ.get("WINFLUX_WALLET_PASSWORD")
    if pw:
        return pw
    pw = getpass.getpass("Wallet password: ")
    if confirm and getpass.getpass("Repeat the password: ") != pw:
        raise WinfluxError("passwords do not match")
    if len(pw) < 8:
        raise WinfluxError("use a password with 8 or more characters")
    return pw


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--node", default="http://127.0.0.1:8080")
    ap.add_argument("--wallet", default="wallet.json")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("create"); sub.add_parser("address"); sub.add_parser("balance"); sub.add_parser("status")
    r = sub.add_parser("recover"); r.add_argument("key")
    s = sub.add_parser("send"); s.add_argument("to"); s.add_argument("amount"); s.add_argument("--fee", default=None)
    sub.add_parser("vaults")
    rc = sub.add_parser("reconcile"); rc.add_argument("vault_id"); rc.add_argument("--journal", default="vault-journal.json")
    vr = sub.add_parser("vault-refund"); vr.add_argument("vault_id")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "status":
            print(json.dumps(api(a.node, "/api/status"), indent=2)); return 0
        if a.cmd in ("create", "recover"):
            hd = HDWallet.generate() if a.cmd == "create" else HDWallet.from_recovery_key(a.key)
            from .crypto.keys import KeyPair
            Wallet(KeyPair(hd._master)).save(a.wallet, _password(confirm=True))
            print(f"wallet saved to {a.wallet}\naddress: {hd.address(0)}")
            if a.cmd == "create":
                print(f"RECOVERY KEY (write it on paper; whoever has it controls the funds):\n  {hd.recovery_key()}")
            return 0
        if a.cmd in ("reconcile", "vault-refund"):            # no wallet: the refund goes to the address registered in the vault
            from .blockchain.vaults import Vault
            from .wallet.vault_builder import build_vault_refund
            params = ChainParams.from_dict(api(a.node, "/api/params"))
            d = api(a.node, f"/api/vault/{a.vault_id}")
            vault = Vault.from_dict(d)
            if a.cmd == "reconcile":
                print(render(reconcile(vault, Journal.load(a.journal), params, d["height"]), params.symbol))
            else:
                res = api(a.node, "/api/tx", build_vault_refund(vault, params).to_dict())
                print(f"refund sent: {res['txid']}")
            return 0
        hd = HDWallet.from_wallet(Wallet.load(a.wallet, _password()))
        chain = RemoteChain(a.node)
        hd.discover(chain)
        if a.cmd == "vaults":
            seen = set()
            for i in range(hd.next_index + 20):
                for v in api(a.node, f"/api/vaults/{hd.address(i)}")["vaults"]:
                    if v["vault_id"] not in seen:
                        seen.add(v["vault_id"])
                        print(f"{v['vault_id']}  {v['state']}{'  FRAUD' if v['fraud'] else ''}  "
                              f"deadline={v['claim_deadline']}  locked={format_units(v['locked'])} {chain.params.symbol}")
            if not seen:
                print("no vault found for this wallet")
        elif a.cmd == "address":
            print(hd.address(max(0, hd.next_index - 1)) if hd.next_index else hd.address(0))
        elif a.cmd == "balance":
            print(f"{format_units(hd.balance(chain))} {chain.params.symbol}")
        elif a.cmd == "send":
            fee = None if a.fee is None else to_units(a.fee)
            tx = hd.pay(chain, a.to, to_units(a.amount), fee)
            res = api(a.node, "/api/tx", tx.to_dict())
            print(f"sent: {res['txid']}")
        return 0
    except (WinfluxError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
