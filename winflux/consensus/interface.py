"""Interface de consenso: permite trocar PoA (testes) por PoW (rede pública)."""
from abc import ABC, abstractmethod

from ..blockchain.block import Block
from ..blockchain.params import ChainParams
from ..crypto.keys import KeyPair


class Consensus(ABC):
    name: str

    @abstractmethod
    def verify_block(self, block: Block, prev: Block, params: ChainParams, view=None) -> None:
        """Levanta ValidationError se o bloco não satisfaz o consenso.

        `view` dá acesso ao contexto da cadeia (ancestrais e alvo de cada bloco) para regras
        que dependem do histórico, como o ajuste de dificuldade.
        """

    @abstractmethod
    def seal(self, block: Block, keypair: KeyPair) -> Block:
        """Produz a prova (assinatura/nonce) e a grava no bloco."""

    def next_target(self, prev: Block, params: ChainParams, view) -> int:
        """Alvo exigido do filho de `prev` (0 quando o consenso não usa alvo)."""
        return 0

    def block_work(self, target: int) -> int:
        """Trabalho acumulado por um bloco com esse alvo (PoA: 1 por bloco)."""
        return 1
