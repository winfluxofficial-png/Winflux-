"""Etapa 1: gênese, encadeamento, validação estrutural, persistência."""
import json
import sqlite3
from dataclasses import replace

import pytest

from winflux.blockchain.block import Block
from winflux.blockchain.chain import Chain
from winflux.blockchain.genesis import GenesisConfig, build_genesis_block
from winflux.errors import StorageError, ValidationError
from winflux.node.storage import BlockStorage

from .conftest import WFLX, NOW, T0, make_chain, make_params, mine


def test_genesis_is_deterministic(keys):
    a, b = make_chain(keys), make_chain(keys)
    assert a.genesis_block.hash == b.genesis_block.hash
    assert a.height == 0 and a.total_supply() == 5_000_000 * WFLX


def test_genesis_hash_depends_on_params(keys):
    a = make_chain(keys)
    b = make_chain(keys, block_reward=49 * WFLX)
    assert a.genesis_block.hash != b.genesis_block.hash


def test_genesis_over_max_supply_rejected(keys):
    with pytest.raises(ValidationError):
        GenesisConfig(make_params(keys["producer"], max_supply=10 * WFLX), T0,
                      ((keys["alice"].address, 11 * WFLX),))


def test_chain_links_blocks(chain, keys):
    b1 = mine(chain, keys)
    b2 = mine(chain, keys)
    assert chain.height == 2
    assert b1.prev_hash == chain.genesis_block.hash and b2.prev_hash == b1.hash
    assert chain.get_block_by_hash(b2.hash) is b2 and chain.get_block(1) is b1


def _sealed(chain, keys, **changes):
    blk = chain.create_block(keys["producer"].public_hex, keys["producer"].address, [])
    blk = replace(blk, **changes)
    return chain.consensus.seal(blk, keys["producer"])


def test_wrong_prev_hash(chain, keys):
    with pytest.raises(ValidationError, match="prev_hash"):
        chain.add_block(_sealed(chain, keys, prev_hash="11" * 32))


def test_wrong_height(chain, keys):
    with pytest.raises(ValidationError, match="altura"):
        chain.add_block(_sealed(chain, keys, height=5))


def test_bad_merkle(chain, keys):
    with pytest.raises(ValidationError, match="Merkle"):
        chain.add_block(_sealed(chain, keys, merkle_root="22" * 32))


def test_timestamp_rules(chain, keys):
    with pytest.raises(ValidationError, match="posterior"):
        chain.add_block(_sealed(chain, keys, timestamp=T0))
    with pytest.raises(ValidationError, match="futuro"):
        chain.add_block(_sealed(chain, keys, timestamp=NOW + 100_000))


def test_empty_block_rejected(chain, keys):
    blk = Block.build(1, chain.tip.hash, T0 + 1, keys["producer"].public_hex, [])
    chain.consensus.seal(blk, keys["producer"])
    with pytest.raises(ValidationError):
        chain.add_block(blk)


def test_missing_or_extra_coinbase(chain, keys):
    good = chain.create_block(keys["producer"].public_hex, keys["producer"].address, [])
    cb = good.transactions[0]
    two = Block.build(1, chain.tip.hash, T0 + 1, keys["producer"].public_hex, [cb, replace(cb, coinbase_height=2)])
    chain.consensus.seal(two, keys["producer"])
    with pytest.raises(ValidationError, match="coinbase"):
        chain.add_block(two)


def test_block_serialization_roundtrip(chain, keys):
    b = mine(chain, keys)
    again = Block.from_dict(json.loads(json.dumps(b.to_dict())))
    assert again.hash == b.hash and again.signature == b.signature


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(extra=1), lambda d: d.update(height=-1), lambda d: d.update(height="1"),
    lambda d: d.update(prev_hash="zz"), lambda d: d.update(transactions="x"),
    lambda d: d.update(signature="abc"), lambda d: d.pop("meta"),
])
def test_malformed_block_rejected(chain, keys, mutate):
    d = mine(chain, keys).to_dict()
    mutate(d)
    with pytest.raises(ValidationError):
        Block.from_dict(d)


# ---------- persistência ----------
def test_persistence_roundtrip(keys, tmp_path):
    path = str(tmp_path / "chain.db")
    c1 = make_chain(keys, storage=BlockStorage(path))
    mine(c1, keys)
    mine(c1, keys)
    tip, supply = c1.tip.hash, c1.total_supply()
    c1.storage.close()
    c2 = make_chain(keys, storage=BlockStorage(path))  # "reinicialização"
    assert c2.height == 2 and c2.tip.hash == tip and c2.total_supply() == supply
    assert c2.balance(keys["producer"].address) == 100 * WFLX
    mine(c2, keys)
    assert c2.height == 3


def test_storage_tampering_detected(keys, tmp_path):
    path = str(tmp_path / "chain.db")
    c1 = make_chain(keys, storage=BlockStorage(path))
    mine(c1, keys)
    c1.storage.close()
    db = sqlite3.connect(path)
    (data,) = db.execute("SELECT data FROM blocks WHERE height=1").fetchone()
    d = json.loads(data)
    d["transactions"][0]["outputs"][0]["value"] += 1  # inflar a coinbase no disco
    db.execute("UPDATE blocks SET data=? WHERE height=1", (json.dumps(d),))
    db.commit()
    db.close()
    with pytest.raises(StorageError):
        make_chain(keys, storage=BlockStorage(path))


def test_storage_garbage_detected(keys, tmp_path):
    path = str(tmp_path / "chain.db")
    c1 = make_chain(keys, storage=BlockStorage(path))
    mine(c1, keys)
    c1.storage.close()
    db = sqlite3.connect(path)
    db.execute("UPDATE blocks SET data='{lixo' WHERE height=1")
    db.commit()
    db.close()
    with pytest.raises(StorageError):
        make_chain(keys, storage=BlockStorage(path))


def test_storage_from_other_network_rejected(keys, tmp_path):
    path = str(tmp_path / "chain.db")
    make_chain(keys, storage=BlockStorage(path)).storage.close()
    with pytest.raises(StorageError, match="gênese"):
        make_chain(keys, storage=BlockStorage(path), alloc=((keys["bob"].address, 1 * WFLX),))
