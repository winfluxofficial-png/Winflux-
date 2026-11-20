"""Verificador OFFLINE do destinatário (A2): decide se aceita um pagamento em nota, sem consultar a rede.

O que a verificação PROVA: o cofre existe com esses parâmetros num checkpoint assinado; cada salto foi assinado pela
chave dona da nota gasta; o valor se conserva; a cadeia é contígua; o destinatário é o dono da folha; e o nível de
segurança (hardware/software) de cada salto, do qual dependem a profundidade e o teto aceitos.
O que NÃO prova: que a nota não foi gasta de outra forma noutro lugar (impossível offline). Esse risco é limitado pelo
nível, pelos tetos e pelo colateral (R1-R9) e resolvido na liquidação (A3). O resultado é sempre PENDENTE, nunca confirmado.
"""
from dataclasses import dataclass

from ..crypto.keys import verify_device_signature
from ..errors import ValidationError
from . import note as N
from .attestation import verify_attestation
from .proofs import CheckpointStore, blocks_until_claim_deadline, verify_vault_proof
from .voucher import chain_id_hash

STATUS_PENDING = "RECEBIDA_OFFLINE"


@dataclass(frozen=True)
class ReceiverPolicy:
    """Limites do receptor (testnet, a calibrar). Aprovados: profundidade 1 sem hardware, 3 com hardware atestado."""
    max_hops_software: int = 1
    max_hops_hardware: int = 3
    max_value_software: int = 5        # em moedas inteiras (× 10**decimals)
    max_value_hardware: int = 100
    margin_hours: int = 48
    min_margin_blocks: int | None = None   # se dado, substitui margin_hours
    reject_fraud_vault: bool = True

    def margin_blocks(self, params) -> int:
        if self.min_margin_blocks is not None:
            return self.min_margin_blocks
        return -(-self.margin_hours * 3600 // params.target_block_time)


class SeenNotes:
    """Memória local do receptor: qual transação offline ele já viu gastar cada nota (detecta gasto duplo local)."""

    def __init__(self):
        self._spent: dict[bytes, bytes] = {}

    def check(self, hops) -> None:
        for h in hops:
            prev = self._spent.get(h.tx.input_note)
            if prev is not None and prev != h.tx.txid:
                raise ValidationError("esta nota já foi vista sendo gasta de outra forma (possível gasto duplo)")

    def record(self, hops) -> None:
        for h in hops:
            self._spent.setdefault(h.tx.input_note, h.tx.txid)


@dataclass(frozen=True)
class VerifiedPayment:
    status: str
    vault_id: str
    slot: int
    depth: int
    level: str                 # "hardware" | "software" (o pior salto)
    hop_levels: tuple
    value: int                 # valor da folha, em unidades
    leaf_kind: int
    request_id: str
    txids: tuple
    deadline_blocks: int
    checkpoint_height: int
    checkpoint_hash: str
    hops: tuple


class OfflineVerifier:
    def __init__(self, params, consensus, *, roots, revoked=frozenset(), policy: ReceiverPolicy | None = None,
                 seen: SeenNotes | None = None, checkpoints: CheckpointStore | None = None):
        self.params, self.consensus = params, consensus
        self.roots, self.revoked = list(roots), frozenset(revoked)
        self.policy = policy or ReceiverPolicy()
        self.seen = seen or SeenNotes()
        self.checkpoints = checkpoints or CheckpointStore()

    # ------------------------------------------------------------------ nível de segurança de um salto
    def _hop_level(self, hop: N.Hop, expected_challenge: bytes | None, now: int) -> str:
        """"hardware" só com atestação válida DESTA chave, uso único e TEE/StrongBox; qualquer problema rebaixa a software
        (a profundidade e o teto de software são os mais restritivos, então rebaixar nunca ajuda o atacante)."""
        if hop.attestation is None:
            return "software"
        try:
            res = verify_attestation(hop.attestation, roots=self.roots, now=now, revoked=self.revoked,
                                     expect_pubkey=hop.pubkey.hex(), expect_key_type=hop.key_type,
                                     expect_challenge=None if expected_challenge is None else expected_challenge.hex())
        except ValidationError:
            return "software"
        return "hardware" if res.is_hardware else "software"

    # ------------------------------------------------------------------ verificação
    def verify(self, payment, *, now: int, my_key: tuple | None = None, my_address: str | None = None,
               request_id: bytes | None = None) -> VerifiedPayment:
        """`my_key`=(key_type, pubkey_bytes) se a folha é uma NOTA para mim; `my_address` se é uma saída final.
        Informar um dos dois é obrigatório: sem isso não se prova que o pagamento é DESTINADO a este receptor."""
        if (my_key is None) == (my_address is None):
            raise ValidationError("informe exatamente um: chave de nota ou endereço do destinatário")
        pay = payment if isinstance(payment, N.OfflinePayment) else N.OfflinePayment.from_dict(payment)
        p, pol = self.params, self.policy

        # 1. cofre e vaga (prova + política)
        vs = verify_vault_proof(pay.proof, p, self.consensus, min_checkpoint_height=self.checkpoints.min_height())
        if vs.state != "OPEN":
            raise ValidationError("cofre encerrado")
        if vs.fraud and pol.reject_fraud_vault:
            raise ValidationError("cofre marcado como fraudulento")
        if vs.slot != pay.slot:
            raise ValidationError("a prova é de outra vaga")
        if vs.claimed or vs.paid or vs.compensated:
            raise ValidationError("a vaga já estava ocupada no checkpoint")
        if not vs.slot_key:
            raise ValidationError("vaga sem chave própria: notas exigem cofre com slot_keys (use voucher)")
        deadline = blocks_until_claim_deadline(vs, now, p)
        if deadline < pol.margin_blocks(p):
            raise ValidationError("pouco prazo restante para liquidar (margem insuficiente)")

        # 2. cadeia de saltos
        chash = chain_id_hash(p.chain_id)
        expected_note, expected_value = N.root_note_id(vs.vault_id, vs.slot), vs.cap
        owner_commit = None          # compromisso do dono do próximo salto (None no 1º: vale a chave da vaga)
        levels, prev_hop = [], None
        for i, hop in enumerate(pay.hops):
            tx = hop.tx
            if tx.chain_hash != chash or tx.vault_id != vs.vault_id:
                raise ValidationError("salto de outra rede ou de outro cofre")
            if tx.input_note != expected_note or tx.input_value != expected_value:
                raise ValidationError("salto não gasta a nota esperada (cadeia quebrada ou valor diferente)")
            if sum(o.value for o in tx.outputs) != tx.input_value:
                raise ValidationError("valor não se conserva no salto")
            if i == 0:
                owner_ok = hop.key_type == vs.key_type and hop.pubkey.hex() == vs.slot_key
            else:
                owner_ok = N.owner_commitment(hop.key_type, hop.pubkey) == owner_commit
            if not owner_ok:
                raise ValidationError("a chave que assinou não é a dona da nota gasta")
            if not verify_device_signature(hop.key_type, hop.pubkey, hop.signature, tx.signing_message()):
                raise ValidationError("assinatura do salto inválida")
            levels.append(self._hop_level(hop, None if prev_hop is None else prev_hop.tx.request_id, now))
            if i + 1 < len(pay.hops):
                nxt = pay.hops[i + 1].tx
                j = next((j for j in range(len(tx.outputs)) if N.child_note_id(tx.txid, j) == nxt.input_note), None)
                if j is None or tx.outputs[j].kind != N.KIND_NOTE or tx.outputs[j].value != nxt.input_value:
                    raise ValidationError("o próximo salto não gasta uma saída-nota do salto anterior")
                expected_note, expected_value, owner_commit = nxt.input_note, nxt.input_value, tx.outputs[j].owner
            prev_hop = hop

        # 3. a folha é MINHA
        last = pay.hops[-1].tx
        if not 0 <= pay.leaf < len(last.outputs):
            raise ValidationError("índice da folha fora do último salto")
        leaf = last.outputs[pay.leaf]
        if my_key is not None:
            if leaf.kind != N.KIND_NOTE or leaf.owner != N.owner_commitment(*my_key):
                raise ValidationError("a folha não é uma nota da minha chave")
        elif leaf.kind != N.KIND_ADDRESS or leaf.owner != N.address_owner(my_address):
            raise ValidationError("a folha não é uma saída para o meu endereço")
        if request_id is not None and last.request_id != request_id:
            raise ValidationError("request_id não confere com o meu pedido")

        # 4. nível efetivo, profundidade e teto
        level = "hardware" if all(l == "hardware" for l in levels) else "software"
        depth = len(pay.hops)
        max_hops = pol.max_hops_hardware if level == "hardware" else pol.max_hops_software
        if depth > max_hops:
            raise ValidationError(f"profundidade {depth} acima do máximo de {max_hops} para nível {level}")
        scale = 10 ** p.decimals
        max_value = (pol.max_value_hardware if level == "hardware" else pol.max_value_software) * scale
        if leaf.value > max_value:
            raise ValidationError(f"valor acima do teto do nível {level}")

        # 5. memória local (gasto duplo visto por este receptor)
        self.seen.check(pay.hops)
        return VerifiedPayment(STATUS_PENDING, vs.vault_id, vs.slot, depth, level, tuple(levels), leaf.value,
                               leaf.kind, last.request_id.hex(), tuple(h.tx.txid.hex() for h in pay.hops), deadline,
                               vs.checkpoint_height, vs.checkpoint_hash, pay.hops)

    def accept(self, verified: VerifiedPayment) -> None:
        """Grava na memória local (write-ahead) ANTES de confirmar o recebimento ao pagador."""
        self.seen.record(verified.hops)
        self.checkpoints.observe(verified.checkpoint_height, verified.checkpoint_hash)
