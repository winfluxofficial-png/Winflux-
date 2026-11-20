"""A4 — Reconciliação: o dono do cofre compara o que EMITIU offline com o que a cadeia mostra.

Não há transação nova de consenso: fechar uma vaga antes do fim da janela de claims prejudicaria quem já recebeu notas
offline (o dono poderia "desfazer" pagamentos). O único caminho de saída é o `vault_refund` depois de
`expires_height + claim_window_blocks`. Esta camada diz, com a MESMA conta do consenso (`plan_refund`), o que cada vaga
é, o que será devolvido, quem pode ter perdido dinheiro e o que parece errado (gasto que o dono não reconhece, gasto
duplo, colateral consumido). Camada pura: sem I/O de rede; o diário é um arquivo JSON simples.
"""
import json
import os
import re
from dataclasses import dataclass, field

from ..blockchain import vaults as V
from ..errors import ValidationError
from ..offline.note import root_note_id
from ..units import format_units

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# estados primários de uma vaga
UNUSED, OUTSTANDING, PARTIAL, SETTLED, LAPSED = "UNUSED", "OUTSTANDING", "PARTIAL", "SETTLED", "LAPSED"
# sinalizadores (podem coexistir com qualquer estado)
DIVERGENT, CONFLICT, DOUBLE_ISSUED = "DIVERGENT", "CONFLICT", "DOUBLE_ISSUED"


# ---------------------------------------------------------------- diário de emissões do dono
class Journal:
    """Registro, no aparelho do dono, das notas-raiz que ele assinou (uma por vaga, se agir direito)."""

    def __init__(self, entries=()):
        self._e: dict[tuple, None] = {}
        for vid, slot, txid in entries:
            self.add(vid, slot, txid)

    def add(self, vault_id: str, slot: int, root_txid: str) -> bool:
        if not (isinstance(vault_id, str) and _HEX64.match(vault_id) and isinstance(root_txid, str)
                and _HEX64.match(root_txid)):
            raise ValidationError("entrada de diário inválida")
        if not (isinstance(slot, int) and not isinstance(slot, bool) and 0 <= slot < 65536):
            raise ValidationError("vaga inválida")
        new = (vault_id, slot, root_txid) not in self._e
        self._e[(vault_id, slot, root_txid)] = None
        return new

    def record_hop(self, hop, slot: int) -> bool:
        """Registra o 1º salto (raiz) que o dono acabou de assinar. Recusa saltos que não gastam a raiz da vaga."""
        tx = hop.tx
        if tx.input_note != root_note_id(tx.vault_id, slot):
            raise ValidationError("este salto não gasta a nota raiz da vaga informada")
        return self.add(tx.vault_id, slot, tx.txid.hex())

    def roots(self, vault_id: str, slot: int) -> set:
        return {t for v, s, t in self._e if v == vault_id and s == slot}

    def __len__(self):
        return len(self._e)

    def to_dict(self) -> dict:
        return {"v": 1, "entries": [{"vault_id": v, "slot": s, "root_txid": t} for v, s, t in sorted(self._e)]}

    @classmethod
    def from_dict(cls, d) -> "Journal":
        if not isinstance(d, dict) or set(d) != {"v", "entries"} or d["v"] != 1 or not isinstance(d["entries"], list):
            raise ValidationError("diário inválido")
        j = cls()
        for e in d["entries"]:
            if not isinstance(e, dict) or set(e) != {"vault_id", "slot", "root_txid"}:
                raise ValidationError("diário inválido")
            j.add(e["vault_id"], e["slot"], e["root_txid"])
        return j

    def save(self, path: str) -> None:
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.to_dict(), f, indent=1)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> "Journal":
        if not os.path.exists(path):
            return cls()
        try:
            with open(path) as f:
                return cls.from_dict(json.load(f))
        except json.JSONDecodeError:
            raise ValidationError("diário corrompido") from None


# ---------------------------------------------------------------- relatório
@dataclass
class SlotReport:
    slot: int
    status: str
    flags: list
    cap: int
    paid: int
    compensated: int
    collateral_left: int
    issued: bool                 # o diário tem a nota-raiz desta vaga
    unsettled_issued: int        # valor emitido offline e ainda não liquidado on-chain (em risco p/ quem recebeu)


@dataclass
class Report:
    vault_id: str
    height: int
    state: str
    fraud: bool
    claim_deadline: int
    claims_open: bool
    can_refund_now: bool
    blocks_until_refund: int
    slots: list
    refund_total: int            # o que `plan_refund` devolveria hoje (0 se já encerrado)
    refund_fee: int
    refund_net: int
    burned: int
    warnings: list = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not any(s.flags for s in self.slots)


def reconcile(vault: "V.Vault", journal: Journal, params, height: int) -> Report:
    """Compara o diário do dono com o estado do cofre na altura `height` (altura atual da cadeia)."""
    deadline = V.claim_deadline(vault, params)
    claims_open = height + 1 <= deadline            # um bloco incluído agora ainda aceitaria claims
    closed = vault.state != "OPEN"
    reports, warn = [], []
    for i, s in enumerate(vault.slots):
        roots = journal.roots(vault.vault_id, i)
        onchain = s.spends.get(root_note_id(vault.vault_id, i).hex())
        flags = []
        if len(roots) > 1:
            flags.append(DOUBLE_ISSUED)
        if s.compensated or s.comp_leaves:
            flags.append(CONFLICT)
        if onchain is not None and onchain not in roots:
            flags.append(DIVERGENT)
        if onchain is None and not s.paid:
            status = (OUTSTANDING if claims_open else LAPSED) if roots else UNUSED
        elif s.paid >= s.cap:
            status = SETTLED
        else:
            status = PARTIAL if claims_open else LAPSED
        unsettled = (s.cap - s.paid) if roots and not s.compensated else 0
        reports.append(SlotReport(i, status, flags, s.cap, s.paid, s.compensated, s.collateral_left, bool(roots), unsettled))

    if closed:
        total = fee = net = burn = 0
    else:
        plan = V.plan_refund(vault, params, None)    # a MESMA conta do consenso
        total, fee, net, burn = plan.total, plan.fee, plan.payout, plan.burn
    can_refund = (not closed) and not claims_open
    sym = "WFLX"
    if closed:
        warn.append("Cofre já encerrado: o reembolso foi feito.")
    open_with_issue = [r.slot for r in reports if r.issued and r.status in (OUTSTANDING, PARTIAL)]
    if open_with_issue:
        warn.append(f"Vagas {open_with_issue} têm pagamentos emitidos que quem recebeu ainda pode liquidar até o bloco "
                    f"{deadline}. O reembolso só é possível depois disso.")
    lost = [(r.slot, r.unsettled_issued) for r in reports if r.status == LAPSED and r.unsettled_issued > 0]
    if lost and not closed:
        warn.append("Pagamentos emitidos nas vagas " + ", ".join(f"{a} ({format_units(b)} {sym})" for a, b in lost)
                    + " não foram liquidados a tempo: quem os recebeu perdeu o direito; o valor volta a você no reembolso.")
    bad = [r.slot for r in reports if DIVERGENT in r.flags]
    if bad:
        warn.append(f"Vagas {bad}: a cadeia mostra um gasto que seu diário NÃO registra. A chave da vaga pode ter sido "
                    "exposta/clonada, ou o diário está incompleto. Trate como possível comprometimento.")
    dbl = [r.slot for r in reports if DOUBLE_ISSUED in r.flags]
    if dbl:
        warn.append(f"Vagas {dbl}: seu diário tem mais de uma nota-raiz (você emitiu a mesma vaga duas vezes).")
    conf = [r.slot for r in reports if CONFLICT in r.flags]
    if conf:
        used = sum(r.compensated for r in reports)
        warn.append(f"Gasto duplo detectado nas vagas {conf}: {format_units(used)} {sym} do colateral já indenizaram "
                    "recebedores; o cofre está marcado como fraudulento"
                    + (f" e o colateral restante ({format_units(burn)} {sym}) será QUEIMADO no reembolso." if burn and not closed else "."))
    return Report(vault.vault_id, height, vault.state, vault.fraud, deadline, claims_open, can_refund,
                  max(0, deadline - height), reports, total, fee, net, burn, warn)


def render(r: Report, symbol: str = "WFLX") -> str:
    f = lambda v: f"{format_units(v)} {symbol}"
    L = [f"Cofre {r.vault_id[:16]}…  estado={r.state}{'  FRAUDE' if r.fraud else ''}  altura={r.height}",
         f"Prazo de claims: bloco {r.claim_deadline} "
         + ("(ainda aberto; reembolso em ~%d blocos)" % r.blocks_until_refund if r.claims_open else "(encerrado)")]
    for s in r.slots:
        L.append(f"  vaga {s.slot}: {s.status:<11} pago {f(s.paid)} de {f(s.cap)}"
                 + (f" | indenizado {f(s.compensated)}" if s.compensated else "")
                 + (f" | flags: {','.join(s.flags)}" if s.flags else ""))
    if r.state == "OPEN":
        L.append(f"Reembolso {'disponível agora' if r.can_refund_now else 'ainda indisponível'}: "
                 f"{f(r.refund_net)} líquidos (taxa {f(r.refund_fee)}" + (f", queimado {f(r.burned)}" if r.burned else "") + ")")
    L += ["ATENÇÃO: " + w for w in r.warnings]
    return "\n".join(L)
