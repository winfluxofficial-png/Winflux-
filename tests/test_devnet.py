import json

from winflux.blockchain.chain import Chain
from winflux.blockchain.genesis import load_genesis_config
from winflux.consensus.poa import ProofOfAuthority
from winflux.node.storage import BlockStorage
from winflux.tools.devnet import init_devnet
from winflux.units import to_units
from winflux.wallet.wallet import Wallet

from .conftest import KDF_N


def test_devnet_init_creates_funded_network(tmp_path):
    d = str(tmp_path / "dn")
    info = init_devnet(d, "5000000", "test-password-123", "winflux-devnet-t", kdf_n=KDF_N)
    cfg = load_genesis_config(f"{d}/genesis.json")
    assert cfg.total == to_units("5000000")
    assert cfg.params.max_supply == to_units("100000000")
    chain = Chain(cfg, ProofOfAuthority(), BlockStorage(f"{d}/chain.db"))
    assert chain.balance(info["faucet"]) == to_units("5000000")
    # encrypted keys: the seed never appears in plain text
    w = Wallet.load(f"{d}/faucet.key.json", "test-password-123")
    assert w.address == info["faucet"]
    assert w.keypair.seed.hex() not in open(f"{d}/faucet.key.json").read()
    assert json.load(open(f"{d}/genesis.json"))["params"]["authorities"]


def test_devnet_chain_id_is_unique_per_genesis(tmp_path):
    a = init_devnet(str(tmp_path / "a"), "5000000", "test-password-123", kdf_n=KDF_N)
    b = init_devnet(str(tmp_path / "b"), "5000000", "test-password-123", kdf_n=KDF_N)
    assert a["chain_id"] != b["chain_id"] and a["chain_id"].startswith("winflux-devnet-")
    cfg = load_genesis_config(f"{a['genesis']}")
    assert cfg.params.chain_id == a["chain_id"]


def test_same_chain_id_no_longer_allows_cross_network_replay(keys):
    """The coinbase commits to the previous block hash: different geneses => different coins,
    even with an identical chain_id (fixes finding 4 of the audit)."""
    import pytest

    from winflux.errors import ValidationError
    from winflux.wallet.transaction_builder import build_transfer

    from .conftest import WFLX, make_chain, mine

    a = make_chain(keys)
    b = make_chain(keys, alloc=((keys["bob"].address, 1 * WFLX),))  # another genesis, SAME chain_id
    mine(a, keys)
    mine(b, keys)
    assert a.get_block(1).transactions[0].txid != b.get_block(1).transactions[0].txid
    tx = build_transfer(keys["producer"], a.utxo.utxos_for(keys["producer"].address),
                        keys["carol"].address, 10 * WFLX, 1000, a.params.chain_id)
    with pytest.raises(ValidationError, match="nonexistent or already spent"):
        b.check_transaction(tx)
