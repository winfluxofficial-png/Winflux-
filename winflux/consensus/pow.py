"""Proof of Work: qualquer pessoa pode minerar; ninguém tem autoridade especial.

Regras
------
* O bloco é válido se `int(hash_do_bloco, 16) <= alvo`. O hash é o do cabeçalho (SHA-256 com
  separação de domínio), que já inclui o nonce. Produtor e assinatura ficam vazios: quem recebe a
  recompensa é só o endereço da coinbase.
* O alvo NÃO vai no cabeçalho: é derivado do histórico (como no Ethereum), então ninguém pode
  declarar a própria dificuldade. A cada `pow_retarget_interval` blocos o alvo é recalculado pelo
  tempo real gasto nos últimos intervalos, com ajuste limitado a 4x para cima ou para baixo.
* A cadeia vencedora é a de MAIOR TRABALHO ACUMULADO (não a mais longa).

Limitação conhecida: SHA-256 favorece hardware dedicado (ASIC). A escolha do algoritmo é uma
decisão de governança a tomar antes de uma rede com valor real (ver docs/decentralization.md).
"""
import hashlib
import threading

from ..blockchain.block import Block
from ..blockchain.params import ChainParams
from ..crypto.hashing import canonical_json
from ..errors import ValidationError
from .interface import Consensus

MAX_ADJUST = 4
MAX_NONCE = 2**63 - 1
_SENTINEL = 999_999_999_999_999_999
_DOMAIN = b"WFLX-BLOCK-HEADER-V1"


def hash_to_int(block_hash_hex: str) -> int:
    return int(block_hash_hex, 16)


def work_for_target(target: int) -> int:
    """Trabalho esperado (nº médio de tentativas) para achar um hash <= alvo."""
    return (1 << 256) // (target + 1)


class ProofOfWork(Consensus):
    name = "pow"

    # ---- dificuldade ----
    def next_target(self, prev: Block, params: ChainParams, view) -> int:
        limit = int(params.pow_limit, 16)
        interval = params.pow_retarget_interval
        height = prev.height + 1
        prev_target = view.target_of(prev.hash) if prev.height > 0 else limit
        if height % interval != 0:
            return prev_target
        first = view.ancestor(prev, interval - 1)           # bloco de altura `height - interval`
        if first is None:
            return prev_target
        expected = (interval - 1) * params.target_block_time
        actual = max(1, prev.timestamp - first.timestamp)
        actual = min(max(actual, expected // MAX_ADJUST), expected * MAX_ADJUST)
        return max(1, min(limit, prev_target * actual // expected))

    def block_work(self, target: int) -> int:
        return work_for_target(target)

    # ---- verificação ----
    def verify_block(self, block: Block, prev: Block, params: ChainParams, view=None) -> None:
        if prev is None or view is None:
            raise ValidationError("PoW exige o contexto da cadeia (alvo derivado do histórico)")
        if block.producer != "" or block.signature != "":
            raise ValidationError("bloco PoW não tem produtor nem assinatura")
        if block.nonce > MAX_NONCE:
            raise ValidationError("nonce fora do intervalo")
        target = self.next_target(prev, params, view)
        if hash_to_int(block.hash) > target:
            raise ValidationError("prova de trabalho insuficiente")

    def seal(self, block: Block, keypair=None) -> Block:
        raise ValidationError("em PoW use mine(); não há selo por chave")

    # ---- mineração ----
    @staticmethod
    def _split_header(block: Block):
        """Pré-calcula prefixo e sufixo do JSON canônico: só o nonce muda a cada tentativa."""
        h = block.header()
        h["nonce"] = _SENTINEL
        blob = _DOMAIN + canonical_json(h)
        marker = b'"nonce":%d' % _SENTINEL
        i = blob.index(marker)
        return blob[:i + len(b'"nonce":')], blob[i + len(marker):]

    @classmethod
    def search(cls, block: Block, target: int, start: int, count: int, stop: threading.Event | None = None):
        """Procura um nonce em [start, start+count). Retorna o nonce ou None. Não toca no estado."""
        prefix, suffix = cls._split_header(block)
        base = hashlib.sha256(prefix)
        end = min(start + count, MAX_NONCE + 1)
        for n in range(start, end):
            if stop is not None and (n & 0x3FFF) == 0 and stop.is_set():
                return None
            h = base.copy()
            h.update(b"%d" % n + suffix)
            if int.from_bytes(h.digest(), "big") <= target:
                return n
        return None

    @classmethod
    def mine(cls, block: Block, target: int, max_tries: int = 50_000_000,
             stop: threading.Event | None = None) -> Block | None:
        """Bloqueia até achar um nonce (ou desistir). Retorna o bloco com o nonce, ou None."""
        n = cls.search(block, target, 0, max_tries, stop)
        if n is None:
            return None
        block.nonce = n
        return block
