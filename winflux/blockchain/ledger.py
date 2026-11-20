"""Livro-razão: UTXO set + registro de cofres, com validação e aplicação por tipo de transação."""
import copy
from dataclasses import dataclass

from . import vaults as V
from .params import ChainParams
from .transaction import Transaction
from .state_root import registry_root
from .utxo import UTXOSet, Undo
from .validation import (validate_note_claim, validate_transaction, validate_vault_open,
                         validate_vault_refund, validate_voucher_claim)
from ..errors import ValidationError


@dataclass
class Checked:
    fee: int
    kind: str
    vault: V.Vault | None = None      # vault_open: o cofre a registrar
    plan: object = None               # claim/refund: plano calculado na validação


@dataclass
class LedgerUndo:
    utxo: Undo | None = None
    vault: V.VaultUndo | None = None
    coinbase: list | None = None      # outpoints de coinbase registrados (para a maturidade)


class Ledger:
    def __init__(self, params: ChainParams):
        self.params = params
        self.utxo = UTXOSet()
        self.vaults = V.VaultRegistry()
        self._coinbase_height: dict = {}   # outpoint -> altura da coinbase (exceto o gênese)

    def total_supply(self) -> int:
        """Oferta = UTXOs + valor travado em cofres (colateral queimado já saiu da conta)."""
        return self.utxo.total_value + self.vaults.total_locked

    def state_root(self) -> str:
        """Raiz Merkle do registro de cofres (vai no cabeçalho de cada bloco)."""
        return registry_root(self.params.chain_id, self.vaults)

    def check(self, tx: Transaction, height: int) -> Checked:
        """Valida contra o estado atual, sem alterá-lo. `height` = altura do bloco de inclusão."""
        self._check_maturity(tx, height)
        checked = self._check(tx, height)
        for i in range(len(tx.outputs)):  # defesa: nunca deixar a aplicação falhar com erro não-ValidationError
            if self.utxo.get((tx.txid, i)) is not None:
                raise ValidationError("transação repetida (saída já existe)")
        return checked

    def _check_maturity(self, tx: Transaction, height: int) -> None:
        """Recompensas de mineração só podem ser gastas após `coinbase_maturity` blocos.

        Protege contra reorganizações: se o bloco que criou a recompensa sair da cadeia,
        nada que dependa dela já foi gasto.
        """
        m = self.params.coinbase_maturity
        if m == 0 or tx.is_coinbase:
            return
        for inp in tx.inputs:
            h = self._coinbase_height.get((inp.txid, inp.index))
            if h is not None and height - h < m:
                raise ValidationError("recompensa de mineração ainda não amadureceu")

    def _check(self, tx: Transaction, height: int) -> Checked:
        p = self.params
        if tx.is_coinbase or tx.kind == "transfer":
            return Checked(validate_transaction(tx, self.utxo, p), "transfer")
        if tx.kind == "vault_open":
            fee, vault = validate_vault_open(tx, self.utxo, self.vaults, p, height)
            return Checked(fee, tx.kind, vault=vault)
        if tx.kind == "voucher_claim":
            fee, plan = validate_voucher_claim(tx, self.vaults, p, height)
            return Checked(fee, tx.kind, plan=plan)
        if tx.kind == "note_claim":
            fee, plan = validate_note_claim(tx, self.vaults, p, height)
            return Checked(fee, tx.kind, plan=plan)
        if tx.kind == "vault_refund":
            fee, plan, vault = validate_vault_refund(tx, self.vaults, p, height)
            return Checked(fee, tx.kind, vault=vault, plan=plan)
        raise ValidationError("tipo de transação desconhecido")

    def apply(self, tx: Transaction, checked: Checked | None) -> LedgerUndo:
        """Aplica uma transação já validada (ou a coinbase, com checked=None)."""
        undo = LedgerUndo()
        undo.utxo = self.utxo.apply_transaction(tx)
        try:
            if tx.is_coinbase and tx.coinbase_height > 0:
                undo.coinbase = [(tx.txid, i) for i in range(len(tx.outputs))]
                for op in undo.coinbase:
                    self._coinbase_height[op] = tx.coinbase_height
            if checked is None or checked.kind == "transfer":
                return undo
            if checked.kind == "vault_open":
                undo.vault = self.vaults.put(checked.vault)
            elif checked.kind == "voucher_claim":
                vault = self.vaults.get(_claim_vault_id(tx))
                undo.vault = self.vaults.put(V.apply_claim(vault, checked.plan))
            elif checked.kind == "note_claim":
                vault = self.vaults.get(checked.plan.vault_id)
                undo.vault = self.vaults.put(V.apply_note_claim(vault, checked.plan))
            elif checked.kind == "vault_refund":
                new = copy.deepcopy(checked.vault)
                new.state = "CLOSED"
                undo.vault = self.vaults.put(new)
        except Exception:
            self._forget_coinbase(undo)
            self.utxo.revert(undo.utxo)
            raise
        return undo

    def _forget_coinbase(self, undo: LedgerUndo) -> None:
        for op in undo.coinbase or ():
            self._coinbase_height.pop(op, None)

    def revert(self, undo: LedgerUndo) -> None:
        if undo.vault is not None:
            self.vaults.revert(undo.vault)
        self._forget_coinbase(undo)
        if undo.utxo is not None:
            self.utxo.revert(undo.utxo)


def _claim_vault_id(tx: Transaction) -> str:
    return V.parse_claim_payload(tx.payload).vault_id
