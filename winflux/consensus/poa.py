"""Round-robin Proof of Authority — ONLY for the local testnet.

It is not decentralized: the authority list is fixed in the genesis. It serves to
validate P2P, UTXO and synchronization before PoW (Stage 5).
"""
from ..blockchain.block import Block
from ..blockchain.params import ChainParams
from ..crypto.keys import KeyPair, verify_signature
from ..errors import ValidationError
from .interface import Consensus

BLOCK_SIG_DOMAIN = b"WFLX-BLOCK-SIG-V1"


class ProofOfAuthority(Consensus):
    name = "poa"

    @staticmethod
    def expected_producer(height: int, params: ChainParams) -> str:
        auths = params.authorities
        if not auths:
            raise ValidationError("network without configured authorities")
        return auths[(height - 1) % len(auths)]

    def verify_block(self, block: Block, prev: Block, params: ChainParams, view=None) -> None:
        if block.producer != self.expected_producer(block.height, params):
            raise ValidationError("producer is not the one whose turn it is")
        if not block.signature:
            raise ValidationError("block without a signature")
        if not verify_signature(bytes.fromhex(block.producer),
                                bytes.fromhex(block.signature),
                                BLOCK_SIG_DOMAIN + bytes.fromhex(block.hash)):
            raise ValidationError("invalid block signature")

    def seal(self, block: Block, keypair: KeyPair) -> Block:
        if keypair.public_hex != block.producer:
            raise ValidationError("key is not the block producer's")
        block.signature = keypair.sign(BLOCK_SIG_DOMAIN + bytes.fromhex(block.hash)).hex()
        return block
