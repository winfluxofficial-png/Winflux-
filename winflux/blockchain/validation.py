"""Regras de validação de transações (independentes do consenso)."""
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
            raise ValidationError("valor de saída não inteiro")
        if not 0 < o.value <= params.max_supply:
            raise ValidationError("valor de saída fora do intervalo")
        if not is_valid_address(o.address):
            raise ValidationError("endereço de saída inválido")
        total += o.value
    if total > params.max_supply:
        raise ValidationError("saídas excedem a oferta máxima")
    return total


def required_fee(tx: Transaction, params: ChainParams) -> int:
    """Taxa mínima: o maior entre a taxa fixa e `min_fee_per_byte` x tamanho (JSON canônico).

    Evita que transações enormes ocupem o bloco pagando o mesmo que uma pequena.
    (Claims e refunds têm taxa fixa definida pelo protocolo, pois só mudam estado uma vez.)
    """
    return max(params.min_fee, params.min_fee_per_byte * tx.size())


def _common(tx: Transaction, params: ChainParams, kind: str) -> None:
    if tx.is_coinbase:
        raise ValidationError("coinbase fora de posição")
    if tx.kind != kind:
        raise ValidationError("tipo de transação inesperado")
    if tx.version != 1:
        raise ValidationError("versão de transação não suportada")
    if tx.chain_id != params.chain_id:
        raise ValidationError("chain_id diferente (replay entre redes)")
    if len(tx.inputs) > params.max_tx_inputs or len(tx.outputs) > params.max_tx_outputs:
        raise ValidationError("transação com entradas/saídas demais")
    if tx.size() > params.max_tx_size:
        raise ValidationError("transação grande demais")


def _spend_inputs(tx: Transaction, utxo: UTXOSet) -> int:
    seen, in_total = set(), 0
    msg = tx.signing_message()
    for inp in tx.inputs:
        op = (inp.txid, inp.index)
        if op in seen:
            raise ValidationError("mesma entrada usada duas vezes na transação")
        seen.add(op)
        prev = utxo.get(op)
        if prev is None:
            raise ValidationError("entrada inexistente ou já gasta")
        if not inp.pubkey or not inp.signature:
            raise ValidationError("entrada sem chave ou assinatura")
        pub = bytes.fromhex(inp.pubkey)
        if pubkey_to_address(pub) != prev.address:
            raise ValidationError("chave não corresponde ao dono da saída")
        if not verify_signature(pub, bytes.fromhex(inp.signature), msg):
            raise ValidationError("assinatura inválida")
        in_total += prev.value
    return in_total


def validate_transaction(tx: Transaction, utxo: UTXOSet, params: ChainParams) -> int:
    """Valida uma transferência comum contra o UTXO set. Retorna a taxa (unidades)."""
    _common(tx, params, "transfer")
    if tx.payload is not None:
        raise ValidationError("transferência comum não tem carga útil")
    if not tx.inputs or not tx.outputs:
        raise ValidationError("transação precisa de entradas e saídas")
    out_total = _check_outputs(tx.outputs, params)  # barato: antes das assinaturas
    in_total = _spend_inputs(tx, utxo)
    fee = in_total - out_total
    if fee < 0:
        raise ValidationError("saídas maiores que entradas (criação de moeda)")
    if fee < required_fee(tx, params):
        raise ValidationError("taxa abaixo do mínimo (fixa ou por byte)")
    return fee


def validate_vault_open(tx, utxo: UTXOSet, vaults, params: ChainParams, height: int):
    """Retorna (taxa, Vault a registrar)."""
    _common(tx, params, "vault_open")
    if not tx.inputs:
        raise ValidationError("vault_open precisa de entradas")
    spec = V.parse_vault_open(tx.payload, params)
    out_total = _check_outputs(tx.outputs, params)
    if not verify_device_signature(spec.key_type, bytes.fromhex(spec.device_key),
                                   bytes.fromhex(spec.pop), V.pop_message(tx)):
        raise ValidationError("prova de posse da chave do dispositivo inválida")
    in_total = _spend_inputs(tx, utxo)
    slots = V.build_slots(spec.caps, spec.collateral_pct, spec.slot_keys)
    locked = sum(s.cap + s.collateral_left for s in slots)
    fee = in_total - out_total - locked
    if fee < 0:
        raise ValidationError("entradas não cobrem o cofre, as saídas e a taxa")
    if fee < required_fee(tx, params):
        raise ValidationError("taxa abaixo do mínimo (fixa ou por byte)")
    if vaults.get(tx.txid) is not None:
        raise ValidationError("cofre já existe")
    vault = V.Vault(tx.txid, spec.refund_address, spec.device_key, spec.key_type,
                    height, height + spec.ttl_blocks, slots)
    return fee, vault


def validate_voucher_claim(tx, vaults, params: ChainParams, height: int):
    """Retorna (taxa, ClaimPlan). Qualquer pessoa pode retransmitir: a saída é fixa."""
    _common(tx, params, "voucher_claim")
    if tx.inputs or len(tx.outputs) != 1:
        raise ValidationError("claim: sem entradas e com exatamente uma saída")
    voucher = V.parse_claim_payload(tx.payload)
    vault = vaults.get(voucher.vault_id)
    if vault is None:
        raise ValidationError("cofre inexistente")
    plan = V.plan_claim(vault, voucher, params, height)
    expected = TxOutput(plan.payout - params.min_fee, voucher.receiver_address)
    if tx.outputs[0] != expected:
        raise ValidationError("saída do claim não confere com o voucher")
    return params.min_fee, plan


def validate_note_claim(tx, vaults, params: ChainParams, height: int):
    """Retorna (taxa, NoteClaimPlan). Qualquer pessoa pode submeter: a saída é fixa pela folha."""
    _common(tx, params, "note_claim")
    if tx.inputs or len(tx.outputs) != 1:
        raise ValidationError("note_claim: sem entradas e com exatamente uma saída")
    spec = V.parse_note_claim(tx.payload)
    vault = vaults.get(spec.vault_id)
    if vault is None:
        raise ValidationError("cofre inexistente")
    plan = V.plan_note_claim(vault, spec, params, height)
    if tx.outputs[0] != TxOutput(plan.payout - params.min_fee, plan.address):
        raise ValidationError("saída do note_claim não confere com a folha")
    return params.min_fee, plan


def validate_vault_refund(tx, vaults, params: ChainParams, height: int):
    """Retorna (taxa, RefundPlan, Vault)."""
    _common(tx, params, "vault_refund")
    if tx.inputs:
        raise ValidationError("vault_refund não tem entradas")
    vault = vaults.get(V.parse_refund_payload(tx.payload))
    if vault is None:
        raise ValidationError("cofre inexistente")
    plan = V.plan_refund(vault, params, height)
    expected = (TxOutput(plan.payout, vault.refund_address),) if plan.payout > 0 else ()
    if tuple(tx.outputs) != expected:
        raise ValidationError("saídas do refund não conferem")
    return plan.fee, plan, vault


def validate_coinbase(tx: Transaction, height: int, params: ChainParams, max_value: int,
                      prev_hash: str) -> None:
    if not tx.is_coinbase or tx.coinbase_height != height:
        raise ValidationError("coinbase inválida para esta altura")
    if tx.kind != "transfer" or tx.version != 1 or tx.chain_id != params.chain_id:
        raise ValidationError("coinbase com tipo/versão/chain_id inválidos")
    if tx.payload != {"prev_hash": prev_hash}:
        raise ValidationError("coinbase deve comprometer o hash do bloco anterior")
    if tx.inputs:
        raise ValidationError("coinbase não pode ter entradas")
    total = _check_outputs(tx.outputs, params)
    if total > max_value:
        raise ValidationError("coinbase reivindica mais que recompensa + taxas")
