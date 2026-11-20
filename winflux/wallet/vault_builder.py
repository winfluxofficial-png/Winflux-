"""Montagem de transações de cofre offline: abertura, claim e devolução."""
from dataclasses import replace

from ..blockchain import vaults as V
from ..blockchain.transaction import Transaction, TxInput, TxOutput
from ..blockchain.validation import required_fee
from ..crypto.address import is_valid_address
from ..crypto.keys import KeyPair
from ..errors import InsufficientFunds, WalletError
from ..offline.voucher import Voucher


def _open_once(owner: KeyPair, utxos, device_key, caps, pct, ttl, refund_address, change_address,
               chain_id, fee, max_inputs, slot_keys=()):
    locked = sum(s.cap + s.collateral_left for s in V.build_slots(caps, pct))
    need = locked + fee
    chosen, total = [], 0
    for op, out in sorted(utxos, key=lambda x: (-x[1].value, x[0])):
        chosen.append((op, out))
        total += out.value
        if total >= need:
            break
    if total < need:
        raise InsufficientFunds(f"saldo insuficiente: tem {total}, precisa {need}")
    if len(chosen) > max_inputs:
        raise WalletError("muitas entradas: consolide as moedas antes")
    outputs = (TxOutput(total - need, change_address),) if total - need > 0 else ()
    inputs = tuple(TxInput(op[0], op[1], owner.public_hex) for op, _ in chosen)
    payload = {"device_key": device_key.public_hex, "key_type": device_key.key_type,
               "slots": list(caps), "collateral_pct": pct, "ttl_blocks": ttl,
               "refund_address": refund_address}
    if slot_keys:
        payload["slot_keys"] = list(slot_keys)
    draft = Transaction(chain_id, inputs, outputs, kind="vault_open", payload=payload)
    pop = device_key.sign(V.pop_message(draft)).hex()           # prova de posse de D
    tx = replace(draft, payload={**payload, "pop": pop})
    sig = owner.sign(tx.signing_message()).hex()                 # o txid já cobre o `pop`
    return replace(tx, inputs=tuple(replace(i, signature=sig) for i in tx.inputs))


def build_vault_open(owner: KeyPair, utxos, device_key, caps, collateral_pct: int, ttl_blocks: int,
                     refund_address: str, params, fee: int | None = None,
                     change_address: str | None = None, max_inputs: int = 256,
                     slot_keys=()) -> Transaction:
    """`device_key`: KeyPair (ed25519) ou P256KeyPair. `utxos`: [(outpoint, TxOutput)] do dono.
    `slot_keys`: chaves públicas (hex) de uso único, uma por vaga, para vagas de NOTA (A2)."""
    if not is_valid_address(refund_address):
        raise WalletError("endereço de devolução inválido")
    change = change_address or owner.address
    if fee is not None:
        return _open_once(owner, utxos, device_key, caps, collateral_pct, ttl_blocks, refund_address,
                          change, params.chain_id, fee, max_inputs, slot_keys)
    trial = params.min_fee
    for _ in range(8):
        tx = _open_once(owner, utxos, device_key, caps, collateral_pct, ttl_blocks, refund_address,
                        change, params.chain_id, trial, max_inputs, slot_keys)
        need = required_fee(tx, params)
        if trial >= need:
            return tx
        trial = need
    raise WalletError("não foi possível estimar a taxa")


def build_voucher_claim(voucher: Voucher, vault: V.Vault, params) -> Transaction:
    """Claim de um voucher recebido offline. Se o estado do cofre mudar antes da inclusão
    (ex.: outra pessoa ocupou a vaga), a tx fica inválida e deve ser refeita com o estado novo."""
    plan = V.plan_claim(vault, voucher, params, None)   # prazo é checado na inclusão
    out = TxOutput(plan.payout - params.min_fee, voucher.receiver_address)
    return Transaction(params.chain_id, (), (out,), kind="voucher_claim",
                       payload={"voucher": voucher.to_bytes().hex()})


def build_note_claim(payment, vault: V.Vault, params) -> Transaction:
    """Liquida a folha de um `OfflinePayment` (recebido offline). A folha precisa ser do tipo endereço.
    Se o estado do cofre mudar antes da inclusão, a tx fica inválida e deve ser refeita."""
    payload = {"vault_id": vault.vault_id, "slot": payment.slot, "leaf": payment.leaf,
               "hops": [{"tx": h.tx.to_bytes().hex(), "key_type": h.key_type, "pubkey": h.pubkey.hex(),
                         "sig": h.signature.hex()} for h in payment.hops]}
    plan = V.plan_note_claim(vault, V.parse_note_claim(payload), params, None)
    out = TxOutput(plan.payout - params.min_fee, plan.address)
    return Transaction(params.chain_id, (), (out,), kind="note_claim", payload=payload)


def build_vault_refund(vault: V.Vault, params) -> Transaction:
    plan = V.plan_refund(vault, params, None)
    outs = (TxOutput(plan.payout, vault.refund_address),) if plan.payout > 0 else ()
    return Transaction(params.chain_id, (), outs, kind="vault_refund",
                       payload={"vault_id": vault.vault_id})
