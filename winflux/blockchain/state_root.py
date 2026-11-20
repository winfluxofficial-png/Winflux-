"""Compromisso Merkle com o registro de cofres (raiz de estado) e provas de inclusão.

Consensus-crítico: todo bloco carrega `state_root` e todo nó o recomputa. Estrutura em dois níveis:

    raiz_do_estado = H("WFLX-VAULT-ROOT-V1" ‖ nº_de_cofres ‖ topo(folhas dos cofres, ordenadas por vault_id))
    folha_do_cofre = H(0x00 ‖ hash_da_chain ‖ vault_id ‖ hash_estático ‖ estado ‖ fraude ‖ raiz_das_vagas)
    raiz_das_vagas = H("WFLX-SLOTS-V1" ‖ nº_de_vagas ‖ topo(folhas das vagas))

Defesas: prefixos 0x00 (folha) e 0x01 (nó interno) contra confusão folha/nó; a contagem entra no
compromisso (tamanho da árvore não é maleável); a folha do cofre inclui o hash da rede (uma prova de uma
rede não vale em outra). Árvores completadas até potência de 2 com uma folha de preenchimento fixa.
"""
import struct

from ..crypto.hashing import canonical_json, sha256
from ..offline.voucher import chain_id_hash

_LEAF, _NODE = b"\x00", b"\x01"
_PAD = sha256(b"WFLX-PAD-V1")
_EMPTY_TOP = sha256(b"WFLX-EMPTY-TREE-V1")
_VAULT_TAG, _SLOTS_TAG = b"WFLX-VAULT-ROOT-V1", b"WFLX-SLOTS-V1"
STATE_CODES = {"OPEN": 1, "CLOSED": 2}
MAX_PATH = 40


def _leaf(data: bytes) -> bytes:
    return sha256(_LEAF + data)


def _node(left: bytes, right: bytes) -> bytes:
    return sha256(_NODE + left + right)


def depth_for(count: int) -> int:
    return (count - 1).bit_length() if count > 1 else 0


def merkle_top(leaf_hashes: list) -> bytes:
    n = len(leaf_hashes)
    if n == 0:
        return _EMPTY_TOP
    level = list(leaf_hashes) + [_PAD] * ((1 << depth_for(n)) - n)
    while len(level) > 1:
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_path(leaf_hashes: list, index: int) -> list:
    n = len(leaf_hashes)
    if not 0 <= index < n:
        raise IndexError("índice fora da árvore")
    level = list(leaf_hashes) + [_PAD] * ((1 << depth_for(n)) - n)
    path, i = [], index
    while len(level) > 1:
        path.append(level[i ^ 1])
        level = [_node(level[j], level[j + 1]) for j in range(0, len(level), 2)]
        i //= 2
    return path


def top_from_path(leaf_hash: bytes, index: int, count: int, path: list) -> bytes | None:
    """Recalcula o topo a partir de uma folha e do caminho; None se o formato é inconsistente."""
    if not 0 <= index < count or len(path) != depth_for(count) or len(path) > MAX_PATH:
        return None
    cur = leaf_hash
    for level, sib in enumerate(path):
        cur = _node(sib, cur) if (index >> level) & 1 else _node(cur, sib)
    return cur


def bind(tag: bytes, count: int, top: bytes) -> bytes:
    return sha256(tag + struct.pack(">Q", count) + top)


# ------------------------------------------------------------------ registros
def bind_slots(count: int, top: bytes) -> bytes:
    return bind(_SLOTS_TAG, count, top)


def bind_vaults(count: int, top: bytes) -> bytes:
    return bind(_VAULT_TAG, count, top)


def slot_record(index: int, slot) -> dict:
    return {"cap": slot.cap, "collateral_left": slot.collateral_left, "paid": slot.paid,
            "claimed_by": slot.claimed_by or "", "compensated": slot.compensated,
            "comp_digest": sha256(canonical_json(list(slot.comp_leaves))).hex(), "key": slot.key}


def slot_leaf(index: int, record: dict) -> bytes:
    return _leaf(canonical_json([index, record["cap"], record["collateral_left"], record["paid"],
                                 record["claimed_by"], record["compensated"], record["comp_digest"],
                                 record["key"]]))


def slots_root(slots: list) -> bytes:
    return bind(_SLOTS_TAG, len(slots), merkle_top([slot_leaf(i, slot_record(i, s)) for i, s in enumerate(slots)]))


def static_fields(vault) -> dict:
    return {"refund_address": vault.refund_address, "device_key": vault.device_key,
            "key_type": vault.key_type, "opened_height": vault.opened_height,
            "expires_height": vault.expires_height}


def vault_leaf_from_parts(chain_hash: bytes, vault_id: str, static: dict, state: str, fraud: bool,
                          slots_root_: bytes) -> bytes:
    return _leaf(chain_hash + bytes.fromhex(vault_id) + sha256(canonical_json(static))
                 + bytes([STATE_CODES[state], 1 if fraud else 0]) + slots_root_)


def vault_leaf(chain_hash: bytes, vault) -> bytes:
    return vault_leaf_from_parts(chain_hash, vault.vault_id, static_fields(vault), vault.state,
                                 vault.fraud, slots_root(vault.slots))


def vault_state_root(chain_hash: bytes, vaults_sorted: list) -> str:
    leaves = [vault_leaf(chain_hash, v) for v in vaults_sorted]
    return bind(_VAULT_TAG, len(leaves), merkle_top(leaves)).hex()


EMPTY_VAULT_ROOT = bind(_VAULT_TAG, 0, _EMPTY_TOP).hex()


def registry_root(chain_id: str, registry) -> str:
    return vault_state_root(chain_id_hash(chain_id), registry.values_sorted())
