"""Consensus interface: allows swapping PoA (tests) for PoW (public network)."""
from abc import ABC, abstractmethod

from ..blockchain.block import Block
from ..blockchain.params import ChainParams
from ..crypto.keys import KeyPair


class Consensus(ABC):
    name: str

    @abstractmethod
    def verify_block(self, block: Block, prev: Block, params: ChainParams, view=None) -> None:
        """Raises ValidationError if the block does not satisfy consensus.

        `view` gives access to the chain context (ancestors and target of each block) for rules
        that depend on history, such as difficulty adjustment.
        """

    @abstractmethod
    def seal(self, block: Block, keypair: KeyPair) -> Block:
        """Produces the proof (signature/nonce) and writes it into the block."""

    def next_target(self, prev: Block, params: ChainParams, view) -> int:
        """Target required of `prev`'s child (0 when consensus does not use a target)."""
        return 0

    def block_work(self, target: int) -> int:
        """Work accumulated by a block with this target (PoA: 1 per block)."""
        return 1
