"""Conjunto de saídas não gastas (UTXO set) com desfazimento (undo)."""
from dataclasses import dataclass, field

from .transaction import Transaction, TxOutput

Outpoint = tuple  # (txid, index)


@dataclass
class Undo:
    spent: list = field(default_factory=list)    # [(outpoint, TxOutput)]
    created: list = field(default_factory=list)  # [outpoint]


class UTXOSet:
    """Estado derivado da cadeia: pode ser sempre reconstruído a partir dos blocos."""

    def __init__(self):
        self._utxos: dict[Outpoint, TxOutput] = {}
        self._by_addr: dict[str, set] = {}
        self.total_value = 0

    def __len__(self):
        return len(self._utxos)

    def get(self, op: Outpoint) -> TxOutput | None:
        return self._utxos.get(op)

    def _add(self, op, out):
        if op in self._utxos:
            raise ValueError("outpoint duplicado")
        self._utxos[op] = out
        self._by_addr.setdefault(out.address, set()).add(op)
        self.total_value += out.value

    def _remove(self, op) -> TxOutput:
        out = self._utxos.pop(op)
        s = self._by_addr[out.address]
        s.discard(op)
        if not s:
            del self._by_addr[out.address]
        self.total_value -= out.value
        return out

    def apply_transaction(self, tx: Transaction) -> Undo:
        undo = Undo()
        try:
            for i in tx.inputs:
                op = (i.txid, i.index)
                undo.spent.append((op, self._remove(op)))
            for idx, out in enumerate(tx.outputs):
                op = (tx.txid, idx)
                self._add(op, out)
                undo.created.append(op)
        except Exception:
            self.revert(undo)
            raise
        return undo

    def revert(self, undo: Undo) -> None:
        for op in reversed(undo.created):
            self._remove(op)
        for op, out in reversed(undo.spent):
            self._add(op, out)

    def balance(self, address: str) -> int:
        return sum(self._utxos[op].value for op in self._by_addr.get(address, ()))

    def utxos_for(self, address: str) -> list:
        """[(outpoint, TxOutput)] ordenado de forma determinística."""
        return sorted(((op, self._utxos[op]) for op in self._by_addr.get(address, ())),
                      key=lambda x: x[0])
