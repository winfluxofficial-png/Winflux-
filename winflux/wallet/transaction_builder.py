"""Building and signing transfers (simple coin selection)."""
from dataclasses import replace

from ..blockchain.transaction import Transaction, TxInput, TxOutput
from ..crypto.address import is_valid_address
from ..crypto.keys import KeyPair
from ..errors import InsufficientFunds, WalletError
from ..blockchain.validation import required_fee


def build_transfer(keypair: KeyPair, utxos, to_address: str, amount: int, fee: int,
                   chain_id: str, change_address: str | None = None,
                   max_inputs: int = 256) -> Transaction:
    """utxos: [(outpoint, TxOutput)] of the sender. Returns a signed Transaction."""
    if not is_valid_address(to_address):
        raise WalletError("invalid destination address")
    if amount <= 0 or fee < 0:
        raise WalletError("invalid amount or fee")
    need = amount + fee
    chosen, total = [], 0
    for op, out in sorted(utxos, key=lambda x: (-x[1].value, x[0])):  # largest first
        chosen.append((op, out))
        total += out.value
        if total >= need:
            break
    if total < need:
        raise InsufficientFunds(f"insufficient funds: have {total}, need {need}")
    if len(chosen) > max_inputs:
        raise WalletError("too many inputs: consolidate the coins first")
    outputs = [TxOutput(amount, to_address)]
    change = total - need
    if change > 0:
        outputs.append(TxOutput(change, change_address or keypair.address))
    inputs = tuple(TxInput(op[0], op[1], keypair.public_hex) for op in (c[0] for c in chosen))
    tx = Transaction(chain_id, inputs, tuple(outputs))
    sig = keypair.sign(tx.signing_message()).hex()
    signed = tuple(replace(i, signature=sig) for i in inputs)
    return replace(tx, inputs=signed)


def _assemble(signers, utxos, to_address, amount, change_address, chain_id, fee, max_inputs):
    need = amount + fee
    chosen, total = [], 0
    for op, out in sorted(utxos, key=lambda x: (-x[1].value, x[0])):  # largest first
        chosen.append((op, out))
        total += out.value
        if total >= need:
            break
    if total < need:
        raise InsufficientFunds(f"insufficient funds: have {total}, need {need}")
    if len(chosen) > max_inputs:
        raise WalletError("too many inputs: consolidate the coins first")
    outputs = [TxOutput(amount, to_address)]
    if total - need > 0:
        outputs.append(TxOutput(total - need, change_address))
    keys = []
    for op, out in chosen:
        kp = signers.get(out.address)
        if kp is None:
            raise WalletError("no key for one of the source addresses")
        keys.append(kp)
    inputs = tuple(TxInput(op[0], op[1], kp.public_hex) for (op, _), kp in zip(chosen, keys))
    tx = Transaction(chain_id, inputs, tuple(outputs))
    msg = tx.signing_message()
    signed = tuple(replace(i, signature=kp.sign(msg).hex()) for i, kp in zip(inputs, keys))
    return replace(tx, inputs=signed)


def build_payment(signers: dict, utxos, to_address: str, amount: int, change_address: str,
                  chain_id: str, fee: int | None = None, params=None, max_inputs: int = 256):
    """Payment with inputs from several addresses (each input signed by its own key).

    `signers`: {address: KeyPair}. The change goes to `change_address` (use a NEW address).
    With `fee=None`, computes the lowest fee the network accepts (requires `params`).
    """
    if not is_valid_address(to_address) or not is_valid_address(change_address):
        raise WalletError("invalid address")
    if amount <= 0 or (fee is not None and fee < 0):
        raise WalletError("invalid amount or fee")
    if fee is not None:
        return _assemble(signers, utxos, to_address, amount, change_address, chain_id, fee, max_inputs)
    if params is None:
        raise WalletError("provide the fee or the network parameters")
    trial = params.min_fee
    for _ in range(8):
        tx = _assemble(signers, utxos, to_address, amount, change_address, chain_id, trial, max_inputs)
        need = required_fee(tx, params)
        if trial >= need:
            return tx
        trial = need
    raise WalletError("could not estimate the fee")
