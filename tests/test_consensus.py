"""PoA: only the authority whose turn it is, with a valid signature."""
from dataclasses import replace

import pytest

from winflux.consensus.poa import ProofOfAuthority
from winflux.errors import ValidationError

from .conftest import make_chain, mine


def _template(chain, keys, producer=None):
    p = producer or keys["producer"]
    return chain.create_block(p.public_hex, p.address, [])


def test_unsigned_block_rejected(chain, keys):
    with pytest.raises(ValidationError, match="without a signature"):
        chain.add_block(_template(chain, keys))


def test_non_authority_rejected(chain, keys):
    blk = _template(chain, keys, producer=keys["mallory"])
    chain.consensus.seal(blk, keys["mallory"])
    with pytest.raises(ValidationError, match="whose turn"):
        chain.add_block(blk)


def test_forged_signature_rejected(chain, keys):
    blk = _template(chain, keys)
    blk.signature = keys["mallory"].sign(b"x").hex()
    with pytest.raises(ValidationError, match="signature"):
        chain.add_block(blk)


def test_signature_does_not_cover_other_block(chain, keys):
    blk = _template(chain, keys)
    chain.consensus.seal(blk, keys["producer"])
    forged = replace(blk, timestamp=blk.timestamp + 1)  # reuses the signature
    with pytest.raises(ValidationError, match="signature"):
        chain.add_block(forged)


def test_seal_requires_matching_key(chain, keys):
    with pytest.raises(ValidationError):
        chain.consensus.seal(_template(chain, keys), keys["mallory"])


def test_round_robin_with_two_authorities(keys):
    chain = make_chain(keys, authorities=(keys["producer"].public_hex, keys["carol"].public_hex))
    assert ProofOfAuthority.expected_producer(1, chain.params) == keys["producer"].public_hex
    assert ProofOfAuthority.expected_producer(2, chain.params) == keys["carol"].public_hex
    mine(chain, keys)
    blk = chain.create_block(keys["producer"].public_hex, keys["producer"].address, [])
    chain.consensus.seal(blk, keys["producer"])  # out of turn at block 2
    with pytest.raises(ValidationError, match="whose turn"):
        chain.add_block(blk)
    blk2 = chain.create_block(keys["carol"].public_hex, keys["carol"].address, [])
    chain.consensus.seal(blk2, keys["carol"])
    chain.add_block(blk2)
    assert chain.height == 2
