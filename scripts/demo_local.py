"""Demonstração local de ponta a ponta (1 processo): gênese -> transferência -> blocos."""
import os
import tempfile

from winflux.blockchain.chain import Chain
from winflux.blockchain.genesis import GenesisConfig
from winflux.blockchain.params import ChainParams
from winflux.consensus.poa import ProofOfAuthority
from winflux.crypto.keys import KeyPair
from winflux.node.storage import BlockStorage
from winflux.units import format_units, to_units
from winflux.wallet.transaction_builder import build_transfer

producer, alice, bob = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
params = ChainParams("winflux-demo", "Winflux", "WFLX", 8, to_units("100000000"), to_units("50"),
                     210_000, 1000, (producer.public_hex,))
cfg = GenesisConfig(params, 1_700_000_000, ((alice.address, to_units("5000000")),))
db = os.path.join(tempfile.mkdtemp(), "chain.db")
chain = Chain(cfg, ProofOfAuthority(), BlockStorage(db))


def show(title):
    print(f"\n== {title} (altura {chain.height}) ==")
    for name, k in (("alice", alice), ("bob", bob), ("produtor", producer)):
        print(f"  {name:9s} {k.address}  {format_units(chain.balance(k.address))} WFLX")
    print(f"  oferta total: {format_units(chain.total_supply())} WFLX (máx {format_units(params.max_supply)})")


def mine(txs=()):
    b = chain.create_block(producer.public_hex, producer.address, list(txs))
    chain.consensus.seal(b, producer)
    chain.add_block(b)
    return b


show("gênese")
tx = build_transfer(alice, chain.utxo.utxos_for(alice.address), bob.address,
                    to_units("1250.5"), 1000, params.chain_id)
print(f"\ntransação {tx.txid}\n  entradas={len(tx.inputs)} saídas={len(tx.outputs)} "
      f"taxa={format_units(chain.check_transaction(tx))} WFLX (validada contra o UTXO)")
blk = mine([tx])
show("após bloco 1")
print(f"\nbloco 1 hash={blk.hash[:16]}... confirmações da tx: {chain.confirmations(tx.txid)}")
mine(); mine()
print(f"após mais 2 blocos, confirmações: {chain.confirmations(tx.txid)}")
