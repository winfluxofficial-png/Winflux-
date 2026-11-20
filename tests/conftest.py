import pytest

from winflux.blockchain.chain import Chain
from winflux.blockchain.genesis import GenesisConfig
from winflux.blockchain.params import ChainParams
from winflux.consensus.poa import ProofOfAuthority
from winflux.crypto.keys import KeyPair

WFLX = 10**8
T0 = 1_700_000_000
NOW = T0 + 10_000
KDF_N = 2**10  # barato para testes


def kp(n: int) -> KeyPair:
    return KeyPair(bytes([n]) * 32)


@pytest.fixture
def keys():
    return {"producer": kp(1), "alice": kp(2), "bob": kp(3), "carol": kp(4), "mallory": kp(5)}


def make_params(producer, **over) -> ChainParams:
    base = dict(chain_id="winflux-test-1", name="Winflux", symbol="WFLX", decimals=8,
                max_supply=100_000_000 * WFLX, block_reward=50 * WFLX,
                halving_interval=210_000, min_fee=1000,
                authorities=(producer.public_hex,))
    base.update(over)
    return ChainParams(**base)


def make_chain(keys, storage=None, alloc=None, **over) -> Chain:
    alloc = alloc if alloc is not None else ((keys["alice"].address, 5_000_000 * WFLX),)
    cfg = GenesisConfig(make_params(keys["producer"], **over), T0, tuple(alloc))
    return Chain(cfg, ProofOfAuthority(), storage=storage, clock=lambda: NOW)


def mine(chain: Chain, keys, txs=(), reward_to=None):
    reward_to = reward_to or keys["producer"].address
    block = chain.create_block(keys["producer"].public_hex, reward_to, list(txs))
    chain.consensus.seal(block, keys["producer"])
    chain.add_block(block)
    return block


@pytest.fixture
def chain(keys):
    return make_chain(keys)
