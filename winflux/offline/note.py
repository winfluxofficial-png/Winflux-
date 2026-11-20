"""Nota transferível e transação offline (A2) — formato binário e cadeia de proveniência.

Modelo (docs/offline-chained-payments.md): a vaga raiz é uma nota de valor `cap`, dona = chave da vaga. Uma TRANSAÇÃO
OFFLINE gasta uma nota e cria até 4 saídas: NOTA (dona = compromisso com a chave nova de alguém, repassável) ou ENDEREÇO
(final, não repassável). Conservação EXATA: Σ saídas = valor da nota gasta. Cada pagamento carrega a cadeia
`[t1 (gasta a raiz), t2 (gasta uma saída de t1), ...]` + a prova do cofre.

    corpo da tx = versão(1) ‖ hash_chain(32) ‖ vault_id(32) ‖ nota_gasta(32) ‖ valor(u64) ‖ n(u8)
                  ‖ n × [ valor(u64) ‖ tipo(u8) ‖ dono(32) ] ‖ request_id(16)
    txid = H("WFLX-OTX-ID-V1" ‖ corpo);  assinatura = chave dona da nota gasta, sobre "WFLX-OTX-SIG-V1" ‖ corpo
A assinatura e a chave pública NÃO entram no txid; a chave pública é revelada só ao gastar (o dono da nota é um
compromisso de hash) — o que limita a exposição da chave (relevante contra ataque quântico).
"""
import re
import struct
from dataclasses import dataclass

from ..crypto.address import address_to_hash, is_valid_address
from ..crypto.hashing import sha256
from ..crypto.keys import verify_device_signature
from ..errors import ValidationError

VERSION = 1
KIND_NOTE, KIND_ADDRESS = 1, 2
MAX_OUTPUTS = 4
MAX_HOPS = 8
KEY_CODES = {"ed25519": 1, "p256": 2}
KEY_LENGTHS = {"ed25519": 32, "p256": 33}
_HEAD = ">B32s32s32sQB"
_HEAD_LEN = struct.calcsize(_HEAD)
_OUT = ">QB32s"
_OUT_LEN = struct.calcsize(_OUT)
_HEX = re.compile(r"^[0-9a-f]*$")
MAX_VALUE = 2**63 - 1


def root_note_id(vault_id: str, slot: int) -> bytes:
    return sha256(b"WFLX-NOTE-ROOT-V1" + bytes.fromhex(vault_id) + struct.pack(">H", slot))


def child_note_id(txid: bytes, index: int) -> bytes:
    return sha256(b"WFLX-NOTE-V1" + txid + bytes([index]))


def owner_commitment(key_type: str, pubkey: bytes) -> bytes:
    """Dona de uma nota NOTA: hash do (tipo, chave). A chave só é revelada ao gastar."""
    if key_type not in KEY_CODES or len(pubkey) != KEY_LENGTHS[key_type]:
        raise ValidationError("chave inválida para compromisso de dono")
    return sha256(b"WFLX-NOTE-OWNER-V1" + bytes([KEY_CODES[key_type]]) + pubkey)


def address_owner(address: str) -> bytes:
    if not is_valid_address(address):
        raise ValidationError("endereço inválido")
    return address_to_hash(address) + bytes(12)


@dataclass(frozen=True)
class NoteOutput:
    value: int
    kind: int
    owner: bytes


@dataclass(frozen=True)
class OfflineTx:
    chain_hash: bytes
    vault_id: str
    input_note: bytes
    input_value: int
    outputs: tuple
    request_id: bytes
    version: int = VERSION

    def body(self) -> bytes:
        try:
            head = struct.pack(_HEAD, self.version, self.chain_hash, bytes.fromhex(self.vault_id), self.input_note,
                               self.input_value, len(self.outputs))
            outs = b"".join(struct.pack(_OUT, o.value, o.kind, o.owner) for o in self.outputs)
            return head + outs + struct.pack(">16s", self.request_id)
        except (struct.error, ValueError, TypeError) as e:
            raise ValidationError(f"transação offline com campos inválidos: {e}") from None

    @property
    def txid(self) -> bytes:
        return sha256(b"WFLX-OTX-ID-V1" + self.body())

    def signing_message(self) -> bytes:
        return b"WFLX-OTX-SIG-V1" + self.body()

    def to_bytes(self) -> bytes:
        return self.body()

    @classmethod
    def from_bytes(cls, raw) -> "OfflineTx":
        if not isinstance(raw, (bytes, bytearray)) or len(raw) < _HEAD_LEN + _OUT_LEN + 16:
            raise ValidationError("transação offline curta demais")
        raw = bytes(raw)
        ver, ch, vid, note, value, n = struct.unpack(_HEAD, raw[:_HEAD_LEN])
        if ver != VERSION:
            raise ValidationError("versão de transação offline não suportada")
        if not 1 <= n <= MAX_OUTPUTS or len(raw) != _HEAD_LEN + n * _OUT_LEN + 16:
            raise ValidationError("transação offline com tamanho/saídas inválidos")
        outs = []
        for i in range(n):
            v, kind, owner = struct.unpack(_OUT, raw[_HEAD_LEN + i * _OUT_LEN: _HEAD_LEN + (i + 1) * _OUT_LEN])
            if v <= 0 or v > MAX_VALUE or kind not in (KIND_NOTE, KIND_ADDRESS):
                raise ValidationError("saída offline inválida")
            if kind == KIND_ADDRESS and owner[20:] != bytes(12):
                raise ValidationError("dono do tipo endereço malformado")
            outs.append(NoteOutput(v, kind, owner))
        tx = cls(ch, vid.hex(), note, value, tuple(outs), raw[-16:], ver)
        if tx.input_value <= 0 or tx.input_value > MAX_VALUE:
            raise ValidationError("valor de entrada inválido")
        return tx


@dataclass(frozen=True)
class Hop:
    """Um salto: transação offline + a chave que a assinou (revelada aqui) + assinatura + atestação (opcional)."""
    tx: OfflineTx
    key_type: str
    pubkey: bytes
    signature: bytes
    attestation: dict | None = None

    def to_dict(self) -> dict:
        return {"tx": self.tx.to_bytes().hex(), "key_type": self.key_type, "pubkey": self.pubkey.hex(),
                "sig": self.signature.hex(), "att": self.attestation}

    @classmethod
    def from_dict(cls, d) -> "Hop":
        if not isinstance(d, dict) or set(d) != {"tx", "key_type", "pubkey", "sig", "att"}:
            raise ValidationError("salto malformado")
        if not (isinstance(d["key_type"], str) and d["key_type"] in KEY_CODES):
            raise ValidationError("tipo de chave inválido no salto")
        for k, n in (("tx", None), ("pubkey", 2 * KEY_LENGTHS[d["key_type"]]), ("sig", 128)):
            if not (isinstance(d[k], str) and _HEX.match(d[k]) and (n is None or len(d[k]) == n)):
                raise ValidationError("campo hexadecimal inválido no salto")
        if len(d["tx"]) > 2 * (_HEAD_LEN + MAX_OUTPUTS * _OUT_LEN + 16):
            raise ValidationError("transação offline grande demais")
        if d["att"] is not None and not isinstance(d["att"], dict):
            raise ValidationError("atestação malformada")
        return cls(OfflineTx.from_bytes(bytes.fromhex(d["tx"])), d["key_type"], bytes.fromhex(d["pubkey"]),
                   bytes.fromhex(d["sig"]), d["att"])


@dataclass(frozen=True)
class OfflinePayment:
    """O que Bob entrega a Carlos: prova do cofre + cadeia de saltos + qual saída é a dele."""
    proof: dict
    slot: int
    hops: tuple
    leaf: int

    def to_dict(self) -> dict:
        return {"v": 1, "proof": self.proof, "slot": self.slot, "hops": [h.to_dict() for h in self.hops],
                "leaf": self.leaf}

    @classmethod
    def from_dict(cls, d) -> "OfflinePayment":
        if not isinstance(d, dict) or set(d) != {"v", "proof", "slot", "hops", "leaf"} or d["v"] != 1:
            raise ValidationError("pagamento offline malformado")
        for k in ("slot", "leaf"):
            if not isinstance(d[k], int) or isinstance(d[k], bool) or not 0 <= d[k] < 65536:
                raise ValidationError("índice inválido no pagamento")
        if not isinstance(d["hops"], list) or not 1 <= len(d["hops"]) <= MAX_HOPS or not isinstance(d["proof"], dict):
            raise ValidationError("cadeia de saltos inválida")
        return cls(d["proof"], d["slot"], tuple(Hop.from_dict(h) for h in d["hops"]), d["leaf"])


# ---------------------------------------------------------------- construção (lado de quem paga)
class SoftwareSigner:
    """Chave em software (sem atestação): nível software."""

    def __init__(self, keypair):
        self._kp = keypair
        self.key_type = keypair.key_type
        self.public_key = keypair.public_key
        self.attestation = None

    @property
    def public_hex(self) -> str:
        return self.public_key.hex()

    def sign(self, message: bytes) -> bytes:
        return self._kp.sign(message)


def make_hop(*, chain_hash: bytes, vault_id: str, input_note: bytes, input_value: int, outputs, request_id: bytes,
             signer) -> Hop:
    """Monta e assina um salto. `signer`: KeyHandle de hardware ou SoftwareSigner (key_type, public_key, attestation, sign)."""
    tx = OfflineTx(chain_hash, vault_id, input_note, input_value, tuple(outputs), request_id)
    return Hop(tx, signer.key_type, signer.public_key, signer.sign(tx.signing_message()), signer.attestation)


def spend_root(*, chain_hash: bytes, vault_id: str, slot: int, cap: int, outputs, request_id: bytes, signer) -> Hop:
    return make_hop(chain_hash=chain_hash, vault_id=vault_id, input_note=root_note_id(vault_id, slot),
                    input_value=cap, outputs=outputs, request_id=request_id, signer=signer)


def spend_output(prev: Hop, index: int, *, outputs, request_id: bytes, signer) -> Hop:
    out = prev.tx.outputs[index]
    return make_hop(chain_hash=prev.tx.chain_hash, vault_id=prev.tx.vault_id,
                    input_note=child_note_id(prev.tx.txid, index), input_value=out.value, outputs=outputs,
                    request_id=request_id, signer=signer)


# ---------------------------------------------------------------- verificação de cadeia (consenso: note_claim)
@dataclass(frozen=True)
class ChainCheck:
    """Resultado da verificação de uma cadeia de saltos até uma folha."""
    leaf: NoteOutput
    leaf_id: bytes              # identificador da folha: child_note_id(txid do último salto, índice)
    links: tuple                # ((nota_gasta_hex, txid_hex), ...) na ordem dos saltos


def verify_hop_chain(hops, *, chain_hash: bytes, vault_id: str, slot: int, cap: int, root_key_type: str,
                     root_key_hex: str, leaf: int) -> ChainCheck:
    """Verifica, de forma PURA e determinística, a cadeia raiz -> folha. Usada pelo consenso no `note_claim`.

    Exige: 1..MAX_HOPS saltos; saltos da rede/cofre certos; primeiro salto gasta a nota raiz da vaga (valor `cap`);
    cada salto seguinte gasta uma saída-NOTA do anterior; conservação exata; dono = chave da vaga (1º) ou compromisso
    de hash da saída-nota anterior; assinatura válida; folha = saída do último salto. Não decide o TIPO da folha.
    """
    if not isinstance(hops, (tuple, list)) or not 1 <= len(hops) <= MAX_HOPS:
        raise ValidationError("número de saltos fora do limite")
    expected_note, expected_value, owner_commit = root_note_id(vault_id, slot), cap, None
    links = []
    for i, hop in enumerate(hops):
        tx = hop.tx
        if tx.chain_hash != chain_hash or tx.vault_id != vault_id:
            raise ValidationError("salto de outra rede ou de outro cofre")
        if tx.input_note != expected_note or tx.input_value != expected_value:
            raise ValidationError("salto não gasta a nota esperada (cadeia quebrada ou valor diferente)")
        if sum(o.value for o in tx.outputs) != tx.input_value:
            raise ValidationError("valor não se conserva no salto")
        if i == 0:
            owner_ok = hop.key_type == root_key_type and hop.pubkey.hex() == root_key_hex
        else:
            owner_ok = owner_commitment(hop.key_type, hop.pubkey) == owner_commit
        if not owner_ok:
            raise ValidationError("a chave que assinou não é a dona da nota gasta")
        if not verify_device_signature(hop.key_type, hop.pubkey, hop.signature, tx.signing_message()):
            raise ValidationError("assinatura do salto inválida")
        links.append((tx.input_note.hex(), tx.txid.hex()))
        if i + 1 < len(hops):
            nxt = hops[i + 1].tx
            j = next((j for j in range(len(tx.outputs)) if child_note_id(tx.txid, j) == nxt.input_note), None)
            if j is None or tx.outputs[j].kind != KIND_NOTE or tx.outputs[j].value != nxt.input_value:
                raise ValidationError("o próximo salto não gasta uma saída-nota do salto anterior")
            expected_note, expected_value, owner_commit = nxt.input_note, nxt.input_value, tx.outputs[j].owner
    last = hops[-1].tx
    if not isinstance(leaf, int) or isinstance(leaf, bool) or not 0 <= leaf < len(last.outputs):
        raise ValidationError("índice da folha fora do último salto")
    return ChainCheck(last.outputs[leaf], child_note_id(last.txid, leaf), tuple(links))
