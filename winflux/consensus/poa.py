"""Proof of Authority em rodízio — SOMENTE para a testnet local.

Não é descentralizado: a lista de autoridades é fixa no gênese. Serve para
validar P2P, UTXO e sincronização antes do PoW (Etapa 5).
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
            raise ValidationError("rede sem autoridades configuradas")
        return auths[(height - 1) % len(auths)]

    def verify_block(self, block: Block, prev: Block, params: ChainParams, view=None) -> None:
        if block.producer != self.expected_producer(block.height, params):
            raise ValidationError("produtor não é o da vez")
        if not block.signature:
            raise ValidationError("bloco sem assinatura")
        if not verify_signature(bytes.fromhex(block.producer),
                                bytes.fromhex(block.signature),
                                BLOCK_SIG_DOMAIN + bytes.fromhex(block.hash)):
            raise ValidationError("assinatura do bloco inválida")

    def seal(self, block: Block, keypair: KeyPair) -> Block:
        if keypair.public_hex != block.producer:
            raise ValidationError("chave não é a do produtor do bloco")
        block.signature = keypair.sign(BLOCK_SIG_DOMAIN + bytes.fromhex(block.hash)).hex()
        return block
