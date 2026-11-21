"""Ledger: UTXO set + vault registry, with validation and application per transaction type."""
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
    vault: V.Vault | None = None      # vault_open: the vault to register
    plan: object = None               # claim/refund: plan computed during validation


@dataclass
class LedgerUndo:
    utxo: Undo | None = None
    vault: V.VaultUndo | None = None
    coinbase: list | None = None      # registered coinbase outpoints (for maturity)


class Ledger:
    def __init__(self, params: ChainParams):
        self.params = params
        self.utxo = UTXOSet()
        self.vaults = V.VaultRegistry()
        self._coinbase_height: dict = {}   # outpoint -> coinbase height (except the genesis)

    def total_supply(self) -> int:
        """Supply = UTXOs + value locked in vaults (burned collateral has already left the count)."""
        return self.utxo.total_value + self.vaults.total_locked

    def state_root(self) -> str:
        """Merkle root of the vault registry (goes in each block's header)."""
        return registry_root(self.params.chain_id, self.vaults)

    def check(self, tx: Transaction, height: int) -> Checked:
        """Validates against the current state, without changing it. `height` = height of the including block."""
        self._check_maturity(tx, height)
        checked = self._check(tx, height)
        for i in range(len(tx.outputs)):  # defense: never let the application fail with a non-ValidationError error
            if self.utxo.get((tx.txid, i)) is not None:
                raise ValidationError("repeated transaction (output already exists)")
        return checked

    def _check_maturity(self, tx: Transaction, height: int) -> None:
        """Mining rewards can only be spent after `coinbase_maturity` blocks.

        Protects against reorganizations: if the block that created the reward leaves the chain,
        nothing that depends on it has been spent yet.
        """
        m = self.params.coinbase_maturity
        if m == 0 or tx.is_coinbase:
            return
        for inp in tx.inputs:
            h = self._coinbase_height.get((inp.txid, inp.index))
            if h is not None and height - h < m:
                raise ValidationError("mining reward has not matured yet")

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
        raise ValidationError("unknown transaction type")

    def apply(self, tx: Transaction, checked: Checked | None) -> LedgerUndo:
        """Applies an already validated transaction (or the coinbase, with checked=None)."""
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
