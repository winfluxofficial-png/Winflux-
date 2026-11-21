"""Mempool: valid transactions not yet confirmed.

Policy (local, not part of consensus):
* only accepts transactions valid against the CURRENT chain state (no chaining of unconfirmed spends);
* first to arrive wins: it does not replace a transaction that spends the same output;
* count and byte limits; when full, evicts the ones with the lowest fee per byte;
* after each block/reorg, revalidates everything and drops what became invalid.
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
        """Validates and adds. Returns the fee. Raises MempoolError/ValidationError if rejected."""
        if tx.is_coinbase:
            raise MempoolError("coinbase does not enter the mempool")
        if tx.txid in self._items:
            raise MempoolError("transaction already in the mempool")
        if self.chain.get_transaction(tx.txid) is not None:
            raise MempoolError("transaction already confirmed")
        for op in self._outpoints(tx):
            if op in self._spent:
                raise MempoolError("conflict: another mempool transaction spends the same output")
        fee = self.chain.check_transaction(tx)       # ValidationError if invalid
        item = _Item(tx, fee, tx.size())
        if len(self._items) >= self.max_txs or self._bytes + item.size > self.max_bytes:
            worst = min(self._items.values(), key=lambda i: i.rate, default=None)
            if worst is None or worst.rate >= item.rate:
                raise MempoolError("mempool full and the fee is too low")
            self._remove(worst.tx.txid)
            if len(self._items) >= self.max_txs or self._bytes + item.size > self.max_bytes:
                raise MempoolError("mempool full")
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
        """Transactions in descending order of fee per byte (for building blocks)."""
        return [i.tx for i in sorted(self._items.values(), key=lambda i: (-i.rate, i.tx.txid))]

    def on_chain_update(self, result) -> None:
        """Call after each accepted block: removes confirmed ones, returns those from undone blocks."""
        confirmed = {t.txid for b in result.connected for t in b.transactions}
        for txid in confirmed:
            self._remove(txid)
        for b in result.disconnected:              # reorg: what left the chain may come back
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
