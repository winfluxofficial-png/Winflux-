"""Transaction validation rules (independent of consensus)."""
from ..crypto.address import is_valid_address, pubkey_to_address
from ..crypto.keys import verify_device_signature, verify_signature
from ..errors import ValidationError
from . import vaults as V
from .params import ChainParams
from .transaction import Transaction, TxOutput
from .utxo import UTXOSet


def _check_outputs(outputs, params: ChainParams) -> int:
    total = 0
    for o in outputs:
        if not isinstance(o.value, int) or isinstance(o.value, bool):
            raise ValidationError("non-integer output value")
        if not 0 < o.value <= params.max_supply:
            raise ValidationError("output value out of range")
        if not is_valid_address(o.address):
            raise ValidationError("invalid output address")
        total += o.value
    if total > params.max_supply:
        raise ValidationError("outputs exceed the maximum supply")
    return total


def required_fee(tx: Transaction, params: ChainParams) -> int:
    """Minimum fee: the larger of the fixed fee and `min_fee_per_byte` x size (canonical JSON).

    Prevents huge transactions from taking up the block while paying the same as a small one.
    (Claims and refunds have a fixed fee defined by the protocol, since they only change state once.)
    """
    return max(params.min_fee, params.min_fee_per_byte * tx.size())


def _common(tx: Transaction, params: ChainParams, kind: str) -> None:
    if tx.is_coinbase:
        raise ValidationError("coinbase out of position")
    if tx.kind != kind:
        raise ValidationError("unexpected transaction type")
    if tx.version != 1:
        raise ValidationError("unsupported transaction version")
    if tx.chain_id != params.chain_id:
        raise ValidationError("different chain_id (replay between networks)")
    if len(tx.inputs) > params.max_tx_inputs or len(tx.outputs) > params.max_tx_outputs:
        raise ValidationError("transaction with too many inputs/outputs")
    if tx.size() > params.max_tx_size:
        raise ValidationError("transaction too large")


def _spend_inputs(tx: Transaction, utxo: UTXOSet) -> int:
    seen, in_total = set(), 0
    msg = tx.signing_message()
    for inp in tx.inputs:
        op = (inp.txid, inp.index)
        if op in seen:
            raise ValidationError("same input used twice in the transaction")
        seen.add(op)
        prev = utxo.get(op)
        if prev is None:
            raise ValidationError("input nonexistent or already spent")
        if not inp.pubkey or not inp.signature:
            raise ValidationError("input without key or signature")
        pub = bytes.fromhex(inp.pubkey)
        if pubkey_to_address(pub) != prev.address:
            raise ValidationError("key does not correspond to the output's owner")
        if not verify_signature(pub, bytes.fromhex(inp.signature), msg):
            raise ValidationError("invalid signature")
        in_total += prev.value
    return in_total


def validate_transaction(tx: Transaction, utxo: UTXOSet, params: ChainParams) -> int:
    """Validates a plain transfer against the UTXO set. Returns the fee (units)."""
    _common(tx, params, "transfer")
    if tx.payload is not None:
        raise ValidationError("a plain transfer has no payload")
    if not tx.inputs or not tx.outputs:
        raise ValidationError("transaction needs inputs and outputs")
    out_total = _check_outputs(tx.outputs, params)  # cheap: before the signatures
    in_total = _spend_inputs(tx, utxo)
    fee = in_total - out_total
    if fee < 0:
        raise ValidationError("outputs larger than inputs (coin creation)")
    if fee < required_fee(tx, params):
        raise ValidationError("fee below the minimum (fixed or per byte)")
    return fee


def validate_vault_open(tx, utxo: UTXOSet, vaults, params: ChainParams, height: int):
    """Returns (fee, Vault to register)."""
    _common(tx, params, "vault_open")
    if not tx.inputs:
        raise ValidationError("vault_open needs inputs")
    spec = V.parse_vault_open(tx.payload, params)
    out_total = _check_outputs(tx.outputs, params)
    if not verify_device_signature(spec.key_type, bytes.fromhex(spec.device_key),
                                   bytes.fromhex(spec.pop), V.pop_message(tx)):
        raise ValidationError("invalid proof of possession of the device key")
    in_total = _spend_inputs(tx, utxo)
    slots = V.build_slots(spec.caps, spec.collateral_pct, spec.slot_keys)
    locked = sum(s.cap + s.collateral_left for s in slots)
    fee = in_total - out_total - locked
    if fee < 0:
        raise ValidationError("inputs do not cover the vault, the outputs and the fee")
    if fee < required_fee(tx, params):
        raise ValidationError("fee below the minimum (fixed or per byte)")
    if vaults.get(tx.txid) is not None:
        raise ValidationError("vault already exists")
    vault = V.Vault(tx.txid, spec.refund_address, spec.device_key, spec.key_type,
                    height, height + spec.ttl_blocks, slots)
    return fee, vault


def validate_voucher_claim(tx, vaults, params: ChainParams, height: int):
    """Returns (fee, ClaimPlan). Anyone can relay: the output is fixed."""
    _common(tx, params, "voucher_claim")
    if tx.inputs or len(tx.outputs) != 1:
        raise ValidationError("claim: no inputs and exactly one output")
    voucher = V.parse_claim_payload(tx.payload)
    vault = vaults.get(voucher.vault_id)
    if vault is None:
        raise ValidationError("nonexistent vault")
    plan = V.plan_claim(vault, voucher, params, height)
    expected = TxOutput(plan.payout - params.min_fee, voucher.receiver_address)
    if tx.outputs[0] != expected:
        raise ValidationError("claim output does not match the voucher")
    return params.min_fee, plan


def validate_note_claim(tx, vaults, params: ChainParams, height: int):
    """Returns (fee, NoteClaimPlan). Anyone can submit: the output is fixed by the leaf."""
    _common(tx, params, "note_claim")
    if tx.inputs or len(tx.outputs) != 1:
        raise ValidationError("note_claim: no inputs and exactly one output")
    spec = V.parse_note_claim(tx.payload)
    vault = vaults.get(spec.vault_id)
    if vault is None:
        raise ValidationError("nonexistent vault")
    plan = V.plan_note_claim(vault, spec, params, height)
    if tx.outputs[0] != TxOutput(plan.payout - params.min_fee, plan.address):
        raise ValidationError("note_claim output does not match the leaf")
    return params.min_fee, plan


def validate_vault_refund(tx, vaults, params: ChainParams, height: int):
    """Returns (fee, RefundPlan, Vault)."""
    _common(tx, params, "vault_refund")
    if tx.inputs:
        raise ValidationError("vault_refund has no inputs")
    vault = vaults.get(V.parse_refund_payload(tx.payload))
    if vault is None:
        raise ValidationError("nonexistent vault")
    plan = V.plan_refund(vault, params, height)
    expected = (TxOutput(plan.payout, vault.refund_address),) if plan.payout > 0 else ()
    if tuple(tx.outputs) != expected:
        raise ValidationError("refund outputs do not match")
    return plan.fee, plan, vault


def validate_coinbase(tx: Transaction, height: int, params: ChainParams, max_value: int,
                      prev_hash: str) -> None:
    if not tx.is_coinbase or tx.coinbase_height != height:
        raise ValidationError("invalid coinbase for this height")
    if tx.kind != "transfer" or tx.version != 1 or tx.chain_id != params.chain_id:
        raise ValidationError("coinbase with invalid type/version/chain_id")
    if tx.payload != {"prev_hash": prev_hash}:
        raise ValidationError("coinbase must commit to the previous block hash")
    if tx.inputs:
        raise ValidationError("coinbase cannot have inputs")
    total = _check_outputs(tx.outputs, params)
    if total > max_value:
        raise ValidationError("coinbase claims more than reward + fees")
