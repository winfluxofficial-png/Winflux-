"""Cofres offline: estado de consenso, regras de abertura, claim e devolução.

Ver docs/offline-payments.md (Revisão 2). Resumo:
- `vault_open` trava valor + colateral em N vagas e registra a chave `D` do dispositivo.
- `voucher_claim` resgata um voucher assinado por `D`: a vaga paga no máximo uma vez; um segundo
  voucher distinto para a mesma vaga é pago pelo colateral e marca o cofre como fraudulento.
- `note_claim` (A3) liquida UMA folha-endereço de uma cadeia de notas offline numa vaga com chave própria.
  A vaga registra quais transações offline já gastaram cada nota; um ramo que contradiz o registrado é
  conflito (gasto duplo) e é indenizado pelo colateral sob R1-R9, nunca pelo valor em depósito.
- `vault_refund` devolve o que sobrou depois de `expires_height + claim_window` (colateral queimado
  se houve fraude). NÃO existe fechamento antecipado.
"""
import copy
import re
from struct import error as struct_error
from dataclasses import dataclass, field

from ..crypto.address import address_from_hash, is_valid_address
from ..crypto.hashing import canonical_json, sha256
from ..crypto.keys import verify_device_signature  # noqa: F401  (reexport p/ validação)
from ..errors import ValidationError
from ..offline import note as N
from ..offline.voucher import Voucher, chain_id_hash
from .exposure import plan_compensation
from .params import ChainParams

KEY_TYPES = {"ed25519": 32, "p256": 33}
_HEX = re.compile(r"^[0-9a-f]+$")
POP_DOMAIN = b"WFLX-VAULT-POP-V1"
MAX_SETTLED_PER_SLOT = 64   # folhas liquidadas por vaga (limita o estado); constante de consenso
NOTE_STATE_TAG = b"WFLX-NOTESTATE-V1"


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


@dataclass
class Slot:
    cap: int
    collateral_left: int
    paid: int = 0
    claimed_by: str | None = None   # hash do voucher que ocupou a vaga
    key: str = ""                   # chave própria da vaga (hex); "" = vaga de voucher (chave D do cofre)
    compensated: int = 0            # soma já indenizada pelo colateral (R2)
    comp_leaves: list = field(default_factory=list)  # vouchers já indenizados (R3, no máx. R9)
    spends: dict = field(default_factory=dict)       # notas: nota gasta (hex) -> txid offline que a gastou na cadeia
    settled: list = field(default_factory=list)      # folhas de nota já liquidadas (hex)

    def note_state_digest(self) -> str:
        """Compromisso com `spends` + `settled`; vai na raiz de estado via `claimed_by` (formato inalterado)."""
        return sha256(NOTE_STATE_TAG + canonical_json([sorted(self.spends.items()), sorted(self.settled)])).hex()

    def locked(self) -> int:
        return (self.cap - self.paid) + self.collateral_left


@dataclass
class Vault:
    vault_id: str
    refund_address: str
    device_key: str
    key_type: str
    opened_height: int
    expires_height: int
    slots: list = field(default_factory=list)
    state: str = "OPEN"             # OPEN | CLOSED (devolvido)
    fraud: bool = False

    def locked(self) -> int:
        return 0 if self.state == "CLOSED" else sum(s.locked() for s in self.slots)

    def to_dict(self) -> dict:
        return {"vault_id": self.vault_id, "refund_address": self.refund_address,
                "device_key": self.device_key, "key_type": self.key_type,
                "opened_height": self.opened_height, "expires_height": self.expires_height,
                "state": self.state, "fraud": self.fraud,
                "slots": [[s.cap, s.collateral_left, s.paid, s.claimed_by, s.compensated,
                           list(s.comp_leaves), s.key, sorted(s.spends.items()), list(s.settled)]
                          for s in self.slots]}


    @classmethod
    def from_dict(cls, d) -> "Vault":
        """Inverso de `to_dict` (cliente/CLI lendo a API do nó). Parsing estrito; não é usado pelo consenso."""
        keys = {"vault_id", "refund_address", "device_key", "key_type", "opened_height", "expires_height",
                "state", "fraud", "slots"}
        if not isinstance(d, dict) or not keys <= set(d):
            raise ValidationError("cofre malformado")
        slots = []
        for r in d["slots"]:
            if not isinstance(r, list) or len(r) != 9:
                raise ValidationError("vaga malformada")
            cap, col, paid, cb, comp, leaves, key, spends, settled = r
            if not all(_is_int(x) and x >= 0 for x in (cap, col, paid, comp)):
                raise ValidationError("vaga malformada")
            if not (isinstance(leaves, list) and isinstance(settled, list) and isinstance(spends, list)
                    and all(isinstance(p, (list, tuple)) and len(p) == 2 for p in spends)):
                raise ValidationError("vaga malformada")
            slots.append(Slot(cap=cap, collateral_left=col, paid=paid, claimed_by=cb, key=key, compensated=comp,
                              comp_leaves=list(leaves), spends={a: b for a, b in spends}, settled=list(settled)))
        if d["state"] not in ("OPEN", "CLOSED") or not isinstance(d["fraud"], bool):
            raise ValidationError("cofre malformado")
        return cls(d["vault_id"], d["refund_address"], d["device_key"], d["key_type"], d["opened_height"],
                   d["expires_height"], slots, d["state"], d["fraud"])


@dataclass
class VaultUndo:
    vault_id: str
    prev: Vault | None


class VaultRegistry:
    """Registro derivado da cadeia (reconstruído na carga), com undo para reorganizações."""

    def __init__(self):
        self._v: dict[str, Vault] = {}
        self.total_locked = 0

    def __len__(self):
        return len(self._v)

    def get(self, vault_id: str) -> Vault | None:
        return self._v.get(vault_id)

    def for_refund_address(self, address: str, limit: int = 100) -> list:
        """Cofres cujo reembolso vai para `address` (varredura linear; suficiente para a testnet)."""
        return [v for v in self._v.values() if v.refund_address == address][:limit]

    def put(self, vault: Vault) -> VaultUndo:
        prev = self._v.get(vault.vault_id)
        self.total_locked += vault.locked() - (prev.locked() if prev else 0)
        self._v[vault.vault_id] = vault
        return VaultUndo(vault.vault_id, prev)

    def revert(self, undo: VaultUndo) -> None:
        cur = self._v[undo.vault_id]
        self.total_locked -= cur.locked()
        if undo.prev is None:
            del self._v[undo.vault_id]
        else:
            self._v[undo.vault_id] = undo.prev
            self.total_locked += undo.prev.locked()

    def values_sorted(self) -> list:
        return [self._v[k] for k in sorted(self._v)]

    def snapshot(self) -> dict:
        return {k: self._v[k].to_dict() for k in sorted(self._v)}


# ---------------------------------------------------------------- abertura
@dataclass(frozen=True)
class VaultOpenSpec:
    device_key: str
    key_type: str
    caps: tuple
    collateral_pct: int
    ttl_blocks: int
    refund_address: str
    pop: str
    slot_keys: tuple = ()


def build_slots(caps, collateral_pct: int, slot_keys=()) -> list:
    return [Slot(cap, (cap * collateral_pct + 99) // 100, key=(slot_keys[i] if slot_keys else ""))
            for i, cap in enumerate(caps)]  # colateral arredonda p/ cima


def parse_vault_open(payload, params: ChainParams) -> VaultOpenSpec:
    keys = {"device_key", "key_type", "slots", "collateral_pct", "ttl_blocks", "refund_address", "pop"}
    if not isinstance(payload, dict) or set(payload) not in (keys, keys | {"slot_keys"}):
        raise ValidationError("carga útil de vault_open inválida")
    kt = payload["key_type"]
    if not (isinstance(kt, str) and kt in KEY_TYPES):
        raise ValidationError("tipo de chave de dispositivo não suportado")
    dk = payload["device_key"]
    if not (isinstance(dk, str) and len(dk) == 2 * KEY_TYPES[kt] and _HEX.match(dk)):
        raise ValidationError("chave de dispositivo inválida")
    caps = payload["slots"]
    if not isinstance(caps, list) or not 1 <= len(caps) <= params.vault_max_slots:
        raise ValidationError("número de vagas fora do limite")
    if not all(_is_int(c) and c >= params.min_voucher_value for c in caps):
        raise ValidationError("teto de vaga abaixo do voucher mínimo")
    pct = payload["collateral_pct"]
    if not (_is_int(pct) and params.vault_collateral_min_pct <= pct <= 1000):
        raise ValidationError("colateral abaixo do mínimo da rede")
    ttl = payload["ttl_blocks"]
    if not (_is_int(ttl) and params.vault_ttl_min_blocks <= ttl <= params.vault_ttl_max_blocks):
        raise ValidationError("TTL do cofre fora do intervalo permitido")
    if not is_valid_address(payload["refund_address"]):
        raise ValidationError("endereço de devolução inválido")
    pop = payload["pop"]
    if not (isinstance(pop, str) and len(pop) == 128 and _HEX.match(pop)):
        raise ValidationError("prova de posse malformada")
    slot_keys = ()
    if "slot_keys" in payload:
        sk = payload["slot_keys"]
        if not isinstance(sk, list) or len(sk) != len(caps):
            raise ValidationError("slot_keys deve ter uma chave por vaga")
        for k in sk:
            if not (isinstance(k, str) and len(k) == 2 * KEY_TYPES[kt] and _HEX.match(k)):
                raise ValidationError("chave de vaga inválida")
            if kt == "p256" and k[:2] not in ("02", "03"):
                raise ValidationError("chave P-256 de vaga deve estar na forma comprimida")
        if len(set(sk)) != len(sk):
            raise ValidationError("chaves de vaga repetidas")
        slot_keys = tuple(sk)
    spec = VaultOpenSpec(dk, kt, tuple(caps), pct, ttl, payload["refund_address"], pop, slot_keys)
    locked = sum(s.cap + s.collateral_left for s in build_slots(spec.caps, pct))
    if locked > params.vault_max_value:
        raise ValidationError("valor do cofre acima do máximo permitido")
    return spec


def pop_message(tx) -> bytes:
    """Mensagem que a chave `D` assina para provar posse: corpo da tx SEM o campo `pop`."""
    body = tx.body()
    payload = dict(body["payload"])
    payload.pop("pop", None)
    body["payload"] = payload
    return POP_DOMAIN + sha256(canonical_json(body))


# ---------------------------------------------------------------- claim
@dataclass(frozen=True)
class ClaimPlan:
    slot: int
    payout: int
    from_collateral: bool
    voucher_hash: str


def claim_deadline(vault: Vault, params: ChainParams) -> int:
    return vault.expires_height + params.claim_window_blocks


def parse_claim_payload(payload) -> Voucher:
    if not isinstance(payload, dict) or set(payload) != {"voucher"}:
        raise ValidationError("carga útil de voucher_claim inválida")
    h = payload["voucher"]
    if not (isinstance(h, str) and len(h) == 350 and _HEX.match(h)):
        raise ValidationError("voucher malformado")
    return Voucher.from_bytes(bytes.fromhex(h))


def plan_claim(vault: Vault, v: Voucher, params: ChainParams, height: int | None) -> ClaimPlan:
    """Aplica todas as regras do voucher. `height=None` pula só o prazo (uso do construtor de tx)."""
    if v.chain_id_hash != chain_id_hash(params.chain_id):
        raise ValidationError("voucher de outra rede")
    if vault.state != "OPEN":
        raise ValidationError("cofre já encerrado")
    if height is not None and height > claim_deadline(vault, params):
        raise ValidationError("prazo de claim encerrado")
    if v.slot >= len(vault.slots):
        raise ValidationError("vaga inexistente")
    slot = vault.slots[v.slot]
    if slot.key:
        raise ValidationError("vaga com chave própria só pode ser liquidada por nota (note_claim)")
    if not params.min_voucher_value <= v.amount <= slot.cap:
        raise ValidationError("valor do voucher fora dos limites da vaga")
    if not verify_device_signature(vault.key_type, bytes.fromhex(vault.device_key),
                                   v.signature, v.signing_message()):
        raise ValidationError("assinatura do voucher inválida")
    vh = v.hash
    if slot.claimed_by is None:
        return ClaimPlan(v.slot, v.amount, False, vh)
    if slot.claimed_by == vh:
        raise ValidationError("voucher já liquidado")
    # Conflito: indenização pelo colateral, sob os limites determinísticos de exposure.py.
    payout = plan_compensation(
        collateral_left=slot.collateral_left, compensated_total=slot.compensated,
        contested_value=slot.cap, paid_leaves=slot.comp_leaves,
        max_events=params.max_compensations_per_slot, leaf_id=vh, leaf_value=v.amount,
        min_payout=max(params.min_voucher_value, params.min_fee + 1))
    return ClaimPlan(v.slot, payout, True, vh)


def apply_claim(vault: Vault, plan: ClaimPlan) -> Vault:
    new = copy.deepcopy(vault)
    slot = new.slots[plan.slot]
    if plan.from_collateral:
        slot.collateral_left -= plan.payout
        slot.compensated += plan.payout
        slot.comp_leaves.append(plan.voucher_hash)
        new.fraud = True
    else:
        slot.paid = plan.payout
        slot.claimed_by = plan.voucher_hash
    return new


# ---------------------------------------------------------------- note_claim (A3)
@dataclass(frozen=True)
class NoteClaimSpec:
    vault_id: str
    slot: int
    leaf: int
    hops: tuple


@dataclass(frozen=True)
class NoteClaimPlan:
    vault_id: str
    slot: int
    leaf_id: str            # hex
    leaf_value: int
    payout: int             # sai do depósito (sem conflito) ou do colateral (conflito)
    address: str
    from_collateral: bool
    new_spends: tuple       # ((nota_hex, txid_hex), ...) a registrar (vazio em conflito)


def parse_note_claim(payload) -> NoteClaimSpec:
    """Parsing estrito: campos extras, tipos errados, hex malformado => ValidationError."""
    if not isinstance(payload, dict) or set(payload) != {"vault_id", "slot", "leaf", "hops"}:
        raise ValidationError("carga útil de note_claim inválida")
    vid = payload["vault_id"]
    if not (isinstance(vid, str) and len(vid) == 64 and _HEX.match(vid)):
        raise ValidationError("vault_id inválido")
    for k, hi in (("slot", 65536), ("leaf", N.MAX_OUTPUTS)):
        if not _is_int(payload[k]) or not 0 <= payload[k] < hi:
            raise ValidationError(f"{k} inválido")
    raw = payload["hops"]
    if not isinstance(raw, list) or not 1 <= len(raw) <= N.MAX_HOPS:
        raise ValidationError("cadeia de saltos inválida")
    hops = []
    for h in raw:
        if not isinstance(h, dict) or set(h) != {"tx", "key_type", "pubkey", "sig"}:
            raise ValidationError("salto malformado")
        try:
            hops.append(N.Hop.from_dict({**h, "att": None}))   # atestação não é consenso: sempre None
        except ValidationError:
            raise
        except (ValueError, TypeError, struct_error):
            raise ValidationError("salto malformado") from None
    return NoteClaimSpec(vid, payload["slot"], payload["leaf"], tuple(hops))


def plan_note_claim(vault: Vault, spec: NoteClaimSpec, params: ChainParams, height: int | None) -> NoteClaimPlan:
    """Todas as regras do `note_claim`. `height=None` pula só o prazo (uso do construtor de tx)."""
    if vault.state != "OPEN":
        raise ValidationError("cofre já encerrado")
    if height is not None and height > claim_deadline(vault, params):
        raise ValidationError("prazo de claim encerrado")
    if spec.slot >= len(vault.slots):
        raise ValidationError("vaga inexistente")
    slot = vault.slots[spec.slot]
    if not slot.key:
        raise ValidationError("vaga sem chave própria: use voucher_claim")
    chk = N.verify_hop_chain(spec.hops, chain_hash=chain_id_hash(params.chain_id), vault_id=vault.vault_id,
                             slot=spec.slot, cap=slot.cap, root_key_type=vault.key_type,
                             root_key_hex=slot.key, leaf=spec.leaf)
    if chk.leaf.kind != N.KIND_ADDRESS:
        raise ValidationError("só uma folha do tipo endereço pode ser liquidada")
    floor = max(params.min_voucher_value, params.min_fee + 1)
    if chk.leaf.value < floor:
        raise ValidationError("valor da folha abaixo do mínimo liquidável")
    lid = chk.leaf_id.hex()
    if lid in slot.settled or lid in slot.comp_leaves:
        raise ValidationError("folha já liquidada")                                          # R3
    address = address_from_hash(chk.leaf.owner[:20])
    conflict = any(slot.spends.get(note, txid) != txid for note, txid in chk.links)
    if not conflict:
        if len(slot.settled) >= MAX_SETTLED_PER_SLOT:
            raise ValidationError("limite de folhas liquidadas da vaga atingido")
        if slot.paid + chk.leaf.value > slot.cap:       # inalcançável com a conservação; defesa de consenso
            raise ValidationError("liquidação excede o valor da vaga")
        new = tuple((n, t) for n, t in chk.links if n not in slot.spends)
        return NoteClaimPlan(vault.vault_id, spec.slot, lid, chk.leaf.value, chk.leaf.value, address, False, new)
    # Conflito: algum salto gasta uma nota já gasta de outra forma na cadeia. O ramo perdedor é indenizado
    # pelo colateral sob R1-R9 e NÃO é registrado (seus descendentes continuam conflitando).
    payout = plan_compensation(
        collateral_left=slot.collateral_left, compensated_total=slot.compensated, contested_value=slot.cap,
        paid_leaves=slot.comp_leaves, max_events=params.max_compensations_per_slot, leaf_id=lid,
        leaf_value=chk.leaf.value, min_payout=floor)
    return NoteClaimPlan(vault.vault_id, spec.slot, lid, chk.leaf.value, payout, address, True, ())


def apply_note_claim(vault: Vault, plan: NoteClaimPlan) -> Vault:
    new = copy.deepcopy(vault)
    slot = new.slots[plan.slot]
    if plan.from_collateral:
        slot.collateral_left -= plan.payout
        slot.compensated += plan.payout
        slot.comp_leaves.append(plan.leaf_id)
        new.fraud = True
    else:
        slot.paid += plan.payout
        slot.settled.append(plan.leaf_id)
        for note, txid in plan.new_spends:
            slot.spends[note] = txid
        slot.claimed_by = slot.note_state_digest()
    return new


# ---------------------------------------------------------------- devolução
@dataclass(frozen=True)
class RefundPlan:
    total: int     # devolvido ao dono antes da taxa
    fee: int
    payout: int
    burn: int      # colateral queimado (fraude)


def plan_refund(vault: Vault, params: ChainParams, height: int | None) -> RefundPlan:
    if vault.state != "OPEN":
        raise ValidationError("cofre já encerrado")
    if height is not None and height <= claim_deadline(vault, params):
        raise ValidationError("janela de claims ainda aberta")
    cap_left = sum(s.cap - s.paid for s in vault.slots)
    col = sum(s.collateral_left for s in vault.slots)
    burn = col if vault.fraud else 0
    total = cap_left + (0 if vault.fraud else col)
    fee = min(total, params.min_fee)
    return RefundPlan(total, fee, total - fee, burn)


def parse_refund_payload(payload) -> str:
    if not isinstance(payload, dict) or set(payload) != {"vault_id"}:
        raise ValidationError("carga útil de vault_refund inválida")
    vid = payload["vault_id"]
    if not (isinstance(vid, str) and len(vid) == 64 and _HEX.match(vid)):
        raise ValidationError("vault_id inválido")
    return vid
