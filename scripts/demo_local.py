"""End-to-end local demo (1 process): genesis -> transfer -> blocks."""
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
    print(f"\n== {title} (height {chain.height}) ==")
    for name, k in (("alice", alice), ("bob", bob), ("producer", producer)):
        print(f"  {name:9s} {k.address}  {format_units(chain.balance(k.address))} WFLX")
    print(f"  total supply: {format_units(chain.total_supply())} WFLX (max {format_units(params.max_supply)})")


def mine(txs=()):
    b = chain.create_block(producer.public_hex, producer.address, list(txs))
    chain.consensus.seal(b, producer)
    chain.add_block(b)
    return b


show("genesis")
tx = build_transfer(alice, chain.utxo.utxos_for(alice.address), bob.address,
                    to_units("1250.5"), 1000, params.chain_id)
print(f"\ntransaction {tx.txid}\n  inputs={len(tx.inputs)} outputs={len(tx.outputs)} "
      f"fee={format_units(chain.check_transaction(tx))} WFLX (validated against the UTXO set)")
blk = mine([tx])
show("after block 1")
print(f"\nblock 1 hash={blk.hash[:16]}... tx confirmations: {chain.confirmations(tx.txid)}")
mine(); mine()
print(f"after 2 more blocks, confirmations: {chain.confirmations(tx.txid)}")
