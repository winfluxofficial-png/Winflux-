from dataclasses import replace

import pytest

from winflux.blockchain.transaction import Transaction
from winflux.errors import ValidationError
from winflux.wallet.transaction_builder import build_transfer

from .conftest import WFLX


def _tx(chain, keys, amount=10 * WFLX):
    utxos = chain.utxo.utxos_for(keys["alice"].address)
    return build_transfer(keys["alice"], utxos, keys["bob"].address, amount, 1000, chain.params.chain_id)


def test_txid_ignores_signature(chain, keys):
    tx = _tx(chain, keys)
    changed = replace(tx, inputs=tuple(replace(i, signature="00" * 64) for i in tx.inputs))
    assert changed.txid == tx.txid


def test_txid_changes_with_content(chain, keys):
    a, b = _tx(chain, keys, 10 * WFLX), _tx(chain, keys, 11 * WFLX)
    assert a.txid != b.txid


def test_roundtrip(chain, keys):
    tx = _tx(chain, keys)
    again = Transaction.from_dict(tx.to_dict())
    assert again == tx and again.txid == tx.txid


def _mut(f):
    def run(d):
        f(d)
        return d
    return run


MALFORMED = [
    "text", None, [], {},
    _mut(lambda d: d.update(extra=1)),
    _mut(lambda d: d.pop("outputs")),
    _mut(lambda d: d.update(version="1")),
    _mut(lambda d: d.update(version=True)),
    _mut(lambda d: d.update(chain_id="")),
    _mut(lambda d: d.update(chain_id="x" * 65)),
    _mut(lambda d: d.update(coinbase_height=-1)),
    _mut(lambda d: d["inputs"][0].update(txid="zz")),
    _mut(lambda d: d["inputs"][0].update(index=-1)),
    _mut(lambda d: d["inputs"][0].update(index=1.5)),
    _mut(lambda d: d["inputs"][0].update(signature="abc")),
    _mut(lambda d: d["inputs"][0].update(pubkey="AA" * 32)),
    _mut(lambda d: d["outputs"][0].update(value="10")),
    _mut(lambda d: d["outputs"][0].update(value=1.5)),
    _mut(lambda d: d["outputs"][0].update(address=5)),
    _mut(lambda d: d["outputs"][0].update(extra=1)),
    _mut(lambda d: d.update(inputs=d["inputs"] * 2000)),
]


@pytest.mark.parametrize("m", MALFORMED)
def test_malformed_rejected(chain, keys, m):
    d = _tx(chain, keys).to_dict()
    payload = m(d) if callable(m) else m
    with pytest.raises(ValidationError):
        Transaction.from_dict(payload)
