"""Montagem e assinatura de transferências (coin selection simples)."""
from dataclasses import replace

from ..blockchain.transaction import Transaction, TxInput, TxOutput
from ..crypto.address import is_valid_address
from ..crypto.keys import KeyPair
from ..errors import InsufficientFunds, WalletError
from ..blockchain.validation import required_fee


def build_transfer(keypair: KeyPair, utxos, to_address: str, amount: int, fee: int,
                   chain_id: str, change_address: str | None = None,
                   max_inputs: int = 256) -> Transaction:
    """utxos: [(outpoint, TxOutput)] do remetente. Retorna Transaction assinada."""
    if not is_valid_address(to_address):
        raise WalletError("endereço de destino inválido")
    if amount <= 0 or fee < 0:
        raise WalletError("valor ou taxa inválidos")
    need = amount + fee
    chosen, total = [], 0
    for op, out in sorted(utxos, key=lambda x: (-x[1].value, x[0])):  # maiores primeiro
        chosen.append((op, out))
        total += out.value
        if total >= need:
            break
    if total < need:
        raise InsufficientFunds(f"saldo insuficiente: tem {total}, precisa {need}")
    if len(chosen) > max_inputs:
        raise WalletError("muitas entradas: consolide as moedas antes")
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
    for op, out in sorted(utxos, key=lambda x: (-x[1].value, x[0])):  # maiores primeiro
        chosen.append((op, out))
        total += out.value
        if total >= need:
            break
    if total < need:
        raise InsufficientFunds(f"saldo insuficiente: tem {total}, precisa {need}")
    if len(chosen) > max_inputs:
        raise WalletError("muitas entradas: consolide as moedas antes")
    outputs = [TxOutput(amount, to_address)]
    if total - need > 0:
        outputs.append(TxOutput(total - need, change_address))
    keys = []
    for op, out in chosen:
        kp = signers.get(out.address)
        if kp is None:
            raise WalletError("sem chave para um dos endereços de origem")
        keys.append(kp)
    inputs = tuple(TxInput(op[0], op[1], kp.public_hex) for (op, _), kp in zip(chosen, keys))
    tx = Transaction(chain_id, inputs, tuple(outputs))
    msg = tx.signing_message()
    signed = tuple(replace(i, signature=kp.sign(msg).hex()) for i, kp in zip(inputs, keys))
    return replace(tx, inputs=signed)


def build_payment(signers: dict, utxos, to_address: str, amount: int, change_address: str,
                  chain_id: str, fee: int | None = None, params=None, max_inputs: int = 256):
    """Pagamento com entradas de vários endereços (cada entrada assinada pela sua chave).

    `signers`: {endereço: KeyPair}. O troco vai para `change_address` (use um endereço NOVO).
    Com `fee=None`, calcula a menor taxa aceita pela rede (exige `params`).
    """
    if not is_valid_address(to_address) or not is_valid_address(change_address):
        raise WalletError("endereço inválido")
    if amount <= 0 or (fee is not None and fee < 0):
        raise WalletError("valor ou taxa inválidos")
    if fee is not None:
        return _assemble(signers, utxos, to_address, amount, change_address, chain_id, fee, max_inputs)
    if params is None:
        raise WalletError("informe a taxa ou os parâmetros da rede")
    trial = params.min_fee
    for _ in range(8):
        tx = _assemble(signers, utxos, to_address, amount, change_address, chain_id, trial, max_inputs)
        need = required_fee(tx, params)
        if trial >= need:
            return tx
        trial = need
    raise WalletError("não foi possível estimar a taxa")
