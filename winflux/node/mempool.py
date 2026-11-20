"""Mempool: transações válidas ainda não confirmadas.

Política (local, não faz parte do consenso):
* só aceita transações válidas contra o estado ATUAL da cadeia (sem encadear gastos não confirmados);
* primeira a chegar vence: não substitui transação que gaste a mesma saída;
* limite de contagem e de bytes; ao encher, expulsa as de menor taxa por byte;
* após cada bloco/reorg, revalida tudo e descarta o que ficou inválido.
"""
from dataclasses import dataclass

from ..errors import ValidationError


@dataclass
class _Item:
    tx: object
    fee: int
    size: int

    @property
    def rate(self) -> float:
        return self.fee / self.size


class MempoolError(ValidationError):
    pass


class Mempool:
    def __init__(self, chain, max_txs: int = 5000, max_bytes: int = 20_000_000):
        self.chain = chain
        self.max_txs = max_txs
        self.max_bytes = max_bytes
        self._items: dict[str, _Item] = {}
        self._spent: dict[tuple, str] = {}     # outpoint -> txid na pool
        self._bytes = 0

    def __len__(self):
        return len(self._items)

    def __contains__(self, txid):
        return txid in self._items

    def get(self, txid):
        it = self._items.get(txid)
        return it.tx if it else None

    @property
    def total_bytes(self) -> int:
        return self._bytes

    def txids(self) -> list:
        return list(self._items)

    def _outpoints(self, tx):
        return [(i.txid, i.index) for i in tx.inputs]

    def add(self, tx) -> int:
        """Valida e adiciona. Retorna a taxa. Levanta MempoolError/ValidationError se rejeitada."""
        if tx.is_coinbase:
            raise MempoolError("coinbase não entra no mempool")
        if tx.txid in self._items:
            raise MempoolError("transação já está no mempool")
        if self.chain.get_transaction(tx.txid) is not None:
            raise MempoolError("transação já confirmada")
        for op in self._outpoints(tx):
            if op in self._spent:
                raise MempoolError("conflito: outra transação do mempool gasta a mesma saída")
        fee = self.chain.check_transaction(tx)       # ValidationError se inválida
        item = _Item(tx, fee, tx.size())
        if len(self._items) >= self.max_txs or self._bytes + item.size > self.max_bytes:
            worst = min(self._items.values(), key=lambda i: i.rate, default=None)
            if worst is None or worst.rate >= item.rate:
                raise MempoolError("mempool cheio e a taxa é baixa demais")
            self._remove(worst.tx.txid)
            if len(self._items) >= self.max_txs or self._bytes + item.size > self.max_bytes:
                raise MempoolError("mempool cheio")
        self._items[tx.txid] = item
        self._bytes += item.size
        for op in self._outpoints(tx):
            self._spent[op] = tx.txid
        return fee

    def _remove(self, txid):
        it = self._items.pop(txid, None)
        if it is None:
            return
        self._bytes -= it.size
        for op in self._outpoints(it.tx):
            if self._spent.get(op) == txid:
                del self._spent[op]

    def candidates(self) -> list:
        """Transações em ordem decrescente de taxa por byte (para montar blocos)."""
        return [i.tx for i in sorted(self._items.values(), key=lambda i: (-i.rate, i.tx.txid))]

    def on_chain_update(self, result) -> None:
        """Chamar após cada bloco aceito: remove confirmadas, devolve as de blocos desfeitos."""
        confirmed = {t.txid for b in result.connected for t in b.transactions}
        for txid in confirmed:
            self._remove(txid)
        for b in result.disconnected:              # reorg: o que saiu da cadeia pode voltar
            for t in b.transactions:
                if not t.is_coinbase and t.txid not in confirmed:
                    try:
                        self.add(t)
                    except ValidationError:
                        pass
        self.revalidate()

    def revalidate(self) -> None:
        for txid in list(self._items):
            tx = self._items[txid].tx
            try:
                self.chain.check_transaction(tx)
            except ValidationError:
                self._remove(txid)
