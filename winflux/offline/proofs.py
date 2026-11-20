"""Checkpoints e provas de cofre para verificação OFFLINE (A1).

Um *checkpoint* é um cabeçalho de bloco assinado por uma autoridade (PoA): carrega a `state_root` do registro de
cofres. Uma *prova de cofre* mostra, com poucas centenas de bytes, que a vaga `i` do cofre `V` existe, com certos
parâmetros e estado, na `state_root` de um checkpoint. O receptor verifica tudo sem consultar a rede.

Limites assumidos (ver docs/security-assumptions.md): a prova só mostra o estado NO checkpoint; um pagador pode
apresentar um checkpoint antigo, por isso o receptor mantém o checkpoint mais novo que já viu (CheckpointStore) e
rejeita provas mais velhas; PoA não tem finalidade, então "checkpoint" prova só que a autoridade assinou.
"""
import re
from dataclasses import dataclass

from ..blockchain import state_root as SR
from ..blockchain.block import Block
from ..blockchain.vaults import KEY_TYPES
from ..crypto.address import is_valid_address
from ..crypto.hashing import canonical_json
from ..errors import ValidationError
from .voucher import chain_id_hash

PROOF_VERSION = 1
_HEX = re.compile(r"^[0-9a-f]*$")


# ------------------------------------------------------------------ validação estrita de campos
def _int(x, lo=0, hi=2**63) -> int:
    if not isinstance(x, int) or isinstance(x, bool) or not lo <= x <= hi:
        raise ValidationError("campo inteiro inválido na prova")
    return x


def _hex(x, n: int, allow_empty=False) -> str:
    if allow_empty and x == "":
        return x
    if not (isinstance(x, str) and len(x) == n and _HEX.match(x)):
        raise ValidationError("campo hexadecimal inválido na prova")
    return x


def _keys(d, keys: set) -> dict:
    if not isinstance(d, dict) or set(d) != keys:
        raise ValidationError("estrutura da prova inválida")
    return d


def _path(p) -> list:
    if not isinstance(p, list) or len(p) > SR.MAX_PATH:
        raise ValidationError("caminho Merkle inválido")
    return [bytes.fromhex(_hex(x, 64)) for x in p]


# ------------------------------------------------------------------ checkpoint
def make_checkpoint(block: Block) -> dict:
    """Checkpoint = cabeçalho assinado (sem as transações)."""
    if not block.signature:
        raise ValidationError("bloco sem assinatura não é checkpoint")
    return {"header": block.header(), "signature": block.signature}


def _block_from_checkpoint(cp) -> Block:
    cp = _keys(cp, {"header", "signature"})
    h = _keys(cp["header"], {"height", "prev_hash", "timestamp", "merkle_root", "producer", "nonce",
                             "meta", "state_root"})
    if not (isinstance(h["meta"], str) and len(h["meta"]) <= 128):
        raise ValidationError("cabeçalho inválido")
    return Block(_int(h["height"]), _hex(h["prev_hash"], 64), _int(h["timestamp"]),
                 _hex(h["merkle_root"], 64), _hex(h["producer"], 64), _int(h["nonce"]), h["meta"], (),
                 _hex(cp["signature"], 128), _hex(h["state_root"], 64))


def verify_checkpoint(cp, params, consensus) -> Block:
    """Verifica a autoridade e a assinatura (sem as transações). Retorna o bloco-cabeçalho."""
    block = _block_from_checkpoint(cp)
    consensus.verify_block(block, None, params)
    return block


# ------------------------------------------------------------------ construção da prova (lado do pagador, online)
def build_vault_proof(chain, vault_id: str, slot_index: int) -> dict:
    """Prova da vaga contra o estado do TOPO da cadeia (o topo é o checkpoint)."""
    vault = chain.get_vault(vault_id)
    if vault is None:
        raise ValidationError("cofre inexistente")
    if not 0 <= slot_index < len(vault.slots):
        raise ValidationError("vaga inexistente")
    tip = chain.tip
    if not tip.signature:
        raise ValidationError("ainda não há bloco assinado para servir de checkpoint")
    chash = chain_id_hash(chain.params.chain_id)
    vaults = chain.vaults.values_sorted()
    vidx = [v.vault_id for v in vaults].index(vault_id)
    vpath = SR.merkle_path([SR.vault_leaf(chash, v) for v in vaults], vidx)
    records = [SR.slot_record(i, s) for i, s in enumerate(vault.slots)]
    spath = SR.merkle_path([SR.slot_leaf(i, r) for i, r in enumerate(records)], slot_index)
    return {
        "v": PROOF_VERSION,
        "checkpoint": make_checkpoint(tip),
        "vault": {"id": vault_id, "static": SR.static_fields(vault), "state": vault.state,
                  "fraud": vault.fraud, "index": vidx, "count": len(vaults),
                  "path": [x.hex() for x in vpath]},
        "slot": {"index": slot_index, "count": len(vault.slots), "record": records[slot_index],
                 "path": [x.hex() for x in spath]},
    }


# ------------------------------------------------------------------ verificação (lado do receptor, offline)
@dataclass(frozen=True)
class VerifiedSlot:
    vault_id: str
    slot: int
    cap: int
    collateral_left: int
    paid: int
    claimed: bool            # a vaga já estava ocupada NO checkpoint
    compensated: int
    slot_key: str            # chave própria da vaga ("" se for vaga de voucher)
    device_key: str
    key_type: str
    refund_address: str
    opened_height: int
    expires_height: int
    state: str               # OPEN | CLOSED
    fraud: bool
    checkpoint_height: int
    checkpoint_hash: str
    checkpoint_timestamp: int


def verify_vault_proof(proof, params, consensus, *, min_checkpoint_height: int = 0) -> VerifiedSlot:
    """Verifica criptograficamente a prova. NÃO decide a política (estado, fraude, valor, prazo): isso é do
    verificador do receptor, que usa o `VerifiedSlot` retornado."""
    p = _keys(proof, {"v", "checkpoint", "vault", "slot"})
    if p["v"] != PROOF_VERSION:
        raise ValidationError("versão de prova não suportada")
    block = verify_checkpoint(p["checkpoint"], params, consensus)
    if block.height < min_checkpoint_height:
        raise ValidationError("checkpoint mais antigo que o já conhecido pelo receptor")

    v = _keys(p["vault"], {"id", "static", "state", "fraud", "index", "count", "path"})
    vid = _hex(v["id"], 64)
    st = _keys(v["static"], {"refund_address", "device_key", "key_type", "opened_height", "expires_height"})
    if not (isinstance(st["key_type"], str) and st["key_type"] in KEY_TYPES):
        raise ValidationError("tipo de chave inválido na prova")
    _hex(st["device_key"], 2 * KEY_TYPES[st["key_type"]])
    if not is_valid_address(st["refund_address"]):
        raise ValidationError("endereço inválido na prova")
    _int(st["opened_height"]); _int(st["expires_height"])
    if not (isinstance(v["state"], str) and v["state"] in SR.STATE_CODES and isinstance(v["fraud"], bool)):
        raise ValidationError("estado do cofre inválido na prova")
    v_index, v_count = _int(v["index"]), _int(v["count"], 1)

    s = _keys(p["slot"], {"index", "count", "record", "path"})
    s_index, s_count = _int(s["index"]), _int(s["count"], 1, 65535)
    r = _keys(s["record"], {"cap", "collateral_left", "paid", "claimed_by", "compensated", "comp_digest", "key"})
    for k in ("cap", "collateral_left", "paid", "compensated"):
        _int(r[k])
    _hex(r["claimed_by"], 64, allow_empty=True)
    _hex(r["comp_digest"], 64)
    _hex(r["key"], 2 * KEY_TYPES[st["key_type"]], allow_empty=True)

    slots_top = SR.top_from_path(SR.slot_leaf(s_index, r), s_index, s_count, _path(s["path"]))
    if slots_top is None:
        raise ValidationError("caminho da vaga inconsistente")
    leaf = SR.vault_leaf_from_parts(chain_id_hash(params.chain_id), vid, st, v["state"], v["fraud"],
                                    SR.bind_slots(s_count, slots_top))
    vault_top = SR.top_from_path(leaf, v_index, v_count, _path(v["path"]))
    if vault_top is None or SR.bind_vaults(v_count, vault_top).hex() != block.state_root:
        raise ValidationError("a prova não confere com a state_root do checkpoint")
    return VerifiedSlot(vid, s_index, r["cap"], r["collateral_left"], r["paid"], r["claimed_by"] != "",
                        r["compensated"], r["key"], st["device_key"], st["key_type"], st["refund_address"],
                        st["opened_height"], st["expires_height"], v["state"], v["fraud"],
                        block.height, block.hash, block.timestamp)


# ------------------------------------------------------------------ relógio e prazos (sem confiar no pagador)
def estimated_height(checkpoint_height: int, checkpoint_timestamp: int, now: int, target_block_time: int) -> int:
    """Altura estimada pelo relógio do PRÓPRIO receptor; nunca usa tempo declarado pelo pagador."""
    return checkpoint_height + max(0, (now - checkpoint_timestamp) // target_block_time)


def blocks_until_claim_deadline(vs: VerifiedSlot, now: int, params) -> int:
    est = estimated_height(vs.checkpoint_height, vs.checkpoint_timestamp, now, params.target_block_time)
    return vs.expires_height + params.claim_window_blocks - est


class CheckpointStore:
    """Memória local do receptor: o checkpoint mais novo já visto. Impede aceitar provas mais antigas (um
    pagador mostrando um estado em que a vaga ainda estava livre) e detecta checkpoints conflitantes."""

    def __init__(self):
        self.height = 0
        self.hash = ""

    def observe(self, height: int, block_hash: str) -> None:
        if height == self.height and self.hash and block_hash != self.hash:
            raise ValidationError("checkpoints conflitantes na mesma altura (possível fork ou fraude)")
        if height > self.height:
            self.height, self.hash = height, block_hash

    def min_height(self) -> int:
        return self.height
