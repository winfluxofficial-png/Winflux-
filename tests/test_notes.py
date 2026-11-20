"""A2: notas transferíveis, cadeia de proveniência e verificador offline — testes adversariais."""
import copy
import json
import random
from dataclasses import replace

import pytest

from winflux.consensus.poa import ProofOfAuthority
from winflux.crypto.keys import _P256_N, KeyPair, P256KeyPair
from winflux.errors import ValidationError
from winflux.offline import note as N
from winflux.offline import proofs as P
from winflux.offline.hardware_sim import HardwareError, SimulatedRoot
from winflux.offline.verifier import OfflineVerifier, ReceiverPolicy
from winflux.offline.voucher import chain_id_hash
from winflux.wallet.vault_builder import build_vault_open

from .conftest import NOW, T0, WFLX, mine
from .test_vaults import devs, vchain

POA = ProofOfAuthority()
ADDR = KeyPair(b"\x03" * 32).address


def commit(h):
    return N.owner_commitment(h.key_type, h.public_key)


def note_out(value, h):
    return N.NoteOutput(value, N.KIND_NOTE, commit(h))


def addr_out(value, address):
    return N.NoteOutput(value, N.KIND_ADDRESS, N.address_owner(address))


def soft(n, key_type="p256"):
    return N.SoftwareSigner(P256KeyPair(private_value=900 + n) if key_type == "p256" else KeyPair(bytes([n]) * 32))


class World:
    """Cofre com vagas de NOTA: a chave de cada vaga é de hardware (uso único) ou de software."""

    def __init__(self, keys, *, cap=30 * WFLX, n_slots=2, key_type="p256", software_slots=False,
                 alice_level="strongbox", alice_not_after=T0 + 10**7, ttl=8, with_slot_keys=True,
                 slot_single_use=True, pct=100, **over):
        self.keys, self.cap, self.key_type, self.now = keys, cap, key_type, NOW
        self.chain = vchain(keys, **over)
        self.root = SimulatedRoot(seed=b"\x42" * 32)
        self.people = {}
        alice_hw = self.person("alice", alice_level, alice_not_after)
        self.slot_signers = ([soft(i, key_type) for i in range(n_slots)] if software_slots
                             else [alice_hw.generate_key(key_type, bytes(16), single_use=slot_single_use)
                                 for _ in range(n_slots)])
        tx = build_vault_open(keys["alice"], self.chain.utxo.utxos_for(keys["alice"].address), devs()[key_type],
                              (cap,) * n_slots, pct, ttl, keys["alice"].address, self.chain.params,
                              slot_keys=[s.public_hex for s in self.slot_signers] if with_slot_keys else ())
        mine(self.chain, keys, [tx])
        self.vid = tx.txid

    def person(self, name, level="strongbox", not_after=T0 + 10**7):
        if name not in self.people:
            self.people[name] = self.root.provision(level, not_before=T0, not_after=not_after)
        return self.people[name]

    def key(self, name, req, level="strongbox"):
        return self.person(name, level).generate_key(self.key_type, req)

    def proof(self, slot=0):
        return P.build_vault_proof(self.chain, self.vid, slot)

    def chash(self):
        return chain_id_hash(self.chain.params.chain_id)

    def verifier(self, *, revoked=frozenset(), roots=None, params=None, **policy):
        policy.setdefault("min_margin_blocks", 1)
        return OfflineVerifier(params or self.chain.params, POA, roots=roots or [self.root.public_key],
                               revoked=revoked, policy=ReceiverPolicy(**policy))

    def verify(self, v, pay, *, my=None, address=None, req=None, now=None):
        return v.verify(pay, now=now or self.now, my_key=None if my is None else (my.key_type, my.public_key),
                        my_address=address, request_id=req)

    # --- construção de pagamentos
    def first(self, to, req, *, slot=0, outputs=None, signer=None):
        outs = outputs or [note_out(self.cap, to)]
        hop = N.spend_root(chain_hash=self.chash(), vault_id=self.vid, slot=slot, cap=self.cap, outputs=outs,
                           request_id=req, signer=signer or self.slot_signers[slot])
        return N.OfflinePayment(self.proof(slot), slot, (hop,), 0)

    def forward(self, pay, signer, outputs, req, *, spend=None, leaf=0):
        hop = N.spend_output(pay.hops[-1], pay.leaf if spend is None else spend, outputs=outputs, request_id=req,
                             signer=signer)
        return N.OfflinePayment(pay.proof, pay.slot, pay.hops + (hop,), leaf)


R = [bytes([i]) * 16 for i in range(1, 12)]


@pytest.fixture(params=["p256", "ed25519"])
def kt(request):
    return request.param


@pytest.fixture
def w(keys, kt):
    return World(keys, key_type=kt)


# ================================================================== formato
def sample_tx(**kw):
    base = dict(chain_hash=b"\x01" * 32, vault_id="ab" * 32, input_note=b"\x11" * 32, input_value=100,
                outputs=(N.NoteOutput(60, N.KIND_NOTE, b"\x22" * 32), N.NoteOutput(40, N.KIND_ADDRESS, N.address_owner(ADDR))),
                request_id=b"\x07" * 16)
    base.update(kw)
    return N.OfflineTx(**base)


def test_offline_tx_roundtrip_ids_and_size():
    tx = sample_tx()
    raw = tx.to_bytes()
    assert N.OfflineTx.from_bytes(raw) == tx and len(raw) == 106 + 41 * 2 + 16
    assert tx.txid == N.OfflineTx.from_bytes(raw).txid
    for change in (dict(chain_hash=b"\x02" * 32), dict(vault_id="cd" * 32), dict(input_note=b"\x12" * 32),
                   dict(input_value=101), dict(request_id=b"\x08" * 16),
                   dict(outputs=(N.NoteOutput(61, N.KIND_NOTE, b"\x22" * 32), sample_tx().outputs[1])),
                   dict(outputs=(N.NoteOutput(60, N.KIND_NOTE, b"\x23" * 32), sample_tx().outputs[1]))):
        assert sample_tx(**change).txid != tx.txid                       # TODO campo entra no txid


def test_offline_tx_strict_parsing():
    raw = bytearray(sample_tx().to_bytes())

    def mut(i, v):
        b = bytearray(raw)
        b[i] = v
        return bytes(b)
    bad = [b"", raw[:-1], bytes(raw) + b"\x00", mut(0, 2), mut(105, 0), mut(105, 5), mut(105, 1),
           mut(114, 3),                                    # tipo desconhecido
           bytes(raw[:106]) + bytes(8) + bytes(raw[114:]),  # valor 0
           mut(181, 1),                                       # padding do endereço ≠ 0
           "texto", None, 5]
    for b in bad:
        with pytest.raises(ValidationError):
            N.OfflineTx.from_bytes(b)


def test_commitments_and_note_ids_are_distinct():
    a, b = KeyPair(b"\x01" * 32), KeyPair(b"\x02" * 32)
    assert N.owner_commitment("ed25519", a.public_key) != N.owner_commitment("ed25519", b.public_key)
    p = P256KeyPair(private_value=5)
    assert N.owner_commitment("p256", p.public_key) != N.owner_commitment("ed25519", a.public_key)
    ids = {N.root_note_id("ab" * 32, 0), N.root_note_id("ab" * 32, 1), N.root_note_id("cd" * 32, 0),
           N.child_note_id(b"\x01" * 32, 0), N.child_note_id(b"\x01" * 32, 1), N.child_note_id(b"\x02" * 32, 0)}
    assert len(ids) == 6
    with pytest.raises(ValidationError):
        N.owner_commitment("ed25519", b"curta")
    with pytest.raises(ValidationError):
        N.owner_commitment("rsa", b"\x00" * 32)
    with pytest.raises(ValidationError):
        N.address_owner("wflx1invalido")


# ================================================================== caminhos felizes
def test_one_hop_alice_to_bob(w):
    bob = w.key("bob", R[0])
    v = w.verifier()
    vp = w.verify(v, w.first(bob, R[0]), my=bob, req=R[0])
    assert vp.status == "RECEBIDA_OFFLINE" and vp.depth == 1 and vp.level == "hardware"
    assert vp.value == w.cap and vp.hop_levels == ("hardware",) and vp.leaf_kind == N.KIND_NOTE
    assert vp.vault_id == w.vid and len(vp.txids) == 1 and vp.checkpoint_height == w.chain.height
    v.accept(vp)                                             # grava na memória local
    assert v.checkpoints.min_height() == w.chain.height


def test_alice_to_bob_to_carlos_with_change_then_bob_spends_the_change(w):
    bob, carlos, change = w.key("bob", R[0]), w.key("carlos", R[1]), w.key("bob", R[1])
    p1 = w.first(bob, R[0])
    p2 = w.forward(p1, bob, [note_out(10 * WFLX, carlos), note_out(20 * WFLX, change)], R[1])
    vp = w.verify(w.verifier(), p2, my=carlos, req=R[1])
    assert (vp.depth, vp.level, vp.value) == (2, "hardware", 10 * WFLX)
    assert vp.hop_levels == ("hardware", "hardware")
    eve = w.key("eve", R[2])
    p3 = w.forward(replace(p2, leaf=1), change, [note_out(20 * WFLX, eve)], R[2], spend=1)   # Bob gasta o troco
    vp3 = w.verify(w.verifier(), p3, my=eve, req=R[2])
    assert (vp3.depth, vp3.value) == (3, 20 * WFLX)
    assert N.OfflinePayment.from_dict(json.loads(json.dumps(p3.to_dict()))) == p3     # sobrevive a QR/JSON


def test_three_hops_ok_and_four_hops_rejected(w):
    bob, carlos, dave, erin = (w.key(n, R[i]) for i, n in enumerate(["bob", "carlos", "dave", "erin"]))
    p1 = w.first(bob, R[0])
    p2 = w.forward(p1, bob, [note_out(w.cap, carlos)], R[1])
    p3 = w.forward(p2, carlos, [note_out(w.cap, dave)], R[2])
    assert w.verify(w.verifier(), p3, my=dave, req=R[2]).depth == 3
    p4 = w.forward(p3, dave, [note_out(w.cap, erin)], R[3])
    with pytest.raises(ValidationError, match="profundidade 4 acima do máximo de 3"):
        w.verify(w.verifier(), p4, my=erin, req=R[3])


def test_terminal_address_output(w):
    bob = w.key("bob", R[0])
    p1 = w.first(bob, R[0])
    p2 = w.forward(p1, bob, [addr_out(w.cap, ADDR)], R[1])
    vp = w.verify(w.verifier(), p2, address=ADDR, req=R[1])
    assert vp.leaf_kind == N.KIND_ADDRESS and vp.value == w.cap
    with pytest.raises(ValidationError, match="meu endereço"):
        w.verify(w.verifier(), p2, address=KeyPair(b"\x09" * 32).address)


def test_verifier_requires_exactly_one_recipient_identity(w):
    bob = w.key("bob", R[0])
    p1 = w.first(bob, R[0])
    with pytest.raises(ValidationError, match="exatamente um"):
        w.verifier().verify(p1, now=w.now)
    with pytest.raises(ValidationError, match="exatamente um"):
        w.verifier().verify(p1, now=w.now, my_key=(bob.key_type, bob.public_key), my_address=ADDR)


# ================================================================== política: profundidade, nível e teto
def test_software_chain_is_limited_to_one_hop(keys):
    w = World(keys, software_slots=True, cap=4 * WFLX)
    bob, carlos = soft(10), soft(11)
    p1 = w.first(bob, R[0])
    vp = w.verify(w.verifier(), p1, my=bob, req=R[0])
    assert vp.level == "software" and vp.depth == 1
    p2 = w.forward(p1, bob, [note_out(w.cap, carlos)], R[1])
    with pytest.raises(ValidationError, match="profundidade 2 acima do máximo de 1 para nível software"):
        w.verify(w.verifier(), p2, my=carlos, req=R[1])


def test_one_software_hop_downgrades_the_whole_chain(keys):
    w = World(keys)                                            # slot de hardware
    bob_sw, carlos = soft(20), w.key("carlos", R[1])
    p1 = w.first(bob_sw, R[0])
    p2 = w.forward(p1, bob_sw, [note_out(w.cap, carlos)], R[1])
    with pytest.raises(ValidationError, match="nível software"):
        w.verify(w.verifier(), p2, my=carlos, req=R[1])        # o pior salto manda
    assert w.verify(w.verifier(max_hops_software=2, max_value_software=1000), p2, my=carlos,
                    req=R[1]).level == "software"              # política mais frouxa do receptor aceita, como software


def test_value_caps_by_level(keys):
    big = World(keys, cap=101 * WFLX)
    bob = big.key("bob", R[0])
    with pytest.raises(ValidationError, match="teto do nível hardware"):
        big.verify(big.verifier(), big.first(bob, R[0]), my=bob, req=R[0])
    sw = World(keys, software_slots=True, cap=6 * WFLX)
    b2 = soft(30)
    with pytest.raises(ValidationError, match="teto do nível software"):
        sw.verify(sw.verifier(), sw.first(b2, R[0]), my=b2, req=R[0])


class Swapped:
    """Mesma chave de hardware, mas apresentando outra atestação (ou nenhuma)."""

    def __init__(self, inner, attestation):
        self._inner, self.attestation = inner, attestation
        self.key_type, self.public_key = inner.key_type, inner.public_key

    def sign(self, message):
        return self._inner.sign(message)


@pytest.mark.parametrize("case", ["expired_device", "revoked", "other_keys_attestation", "no_attestation",
                                  "wrong_root"])
def test_bad_attestation_downgrades_to_software_never_upgrades(keys, case):
    from winflux.crypto.hashing import sha256
    w = World(keys, cap=4 * WFLX, alice_not_after=(T0 + 5 if case == "expired_device" else T0 + 10**7))
    signer, roots, revoked = w.slot_signers[0], [w.root.public_key], frozenset()
    if case == "revoked":
        revoked = frozenset({sha256(bytes.fromhex(signer.attestation["device"]["device_pubkey"])).hex()})
    if case == "other_keys_attestation":
        signer = Swapped(signer, w.people["alice"].generate_key("p256", bytes(16)).attestation)
    if case == "no_attestation":
        signer = Swapped(signer, None)
    if case == "wrong_root":
        roots = [SimulatedRoot(seed=b"\x77" * 32).public_key]
    bob = w.key("bob", R[0])
    vp = w.verify(w.verifier(revoked=revoked, roots=roots), w.first(bob, R[0], signer=signer), my=bob, req=R[0])
    assert vp.level == "software" and vp.hop_levels == ("software",)


@pytest.mark.parametrize("kwargs", [dict(alice_level="software"), dict(alice_level="tee", slot_single_use=False)])
def test_valid_attestation_without_hardware_properties_counts_as_software(keys, kwargs):
    """Atestação criptograficamente VÁLIDA, mas de chave em software ou sem uso único, não vale como hardware."""
    w = World(keys, cap=4 * WFLX, **kwargs)
    bob, carlos = w.key("bob", R[0]), w.key("carlos", R[1])
    p1 = w.first(bob, R[0])
    vp = w.verify(w.verifier(), p1, my=bob, req=R[0])
    assert vp.level == "software" and vp.hop_levels == ("software",)
    p2 = w.forward(p1, bob, [note_out(w.cap, carlos)], R[1])
    with pytest.raises(ValidationError, match="nível software"):
        w.verify(w.verifier(), p2, my=carlos, req=R[1])


def test_attestation_challenge_must_match_the_request_that_created_the_note(keys):
    w = World(keys, cap=4 * WFLX)
    bob_wrong = w.person("bob").generate_key("p256", b"\xee" * 16)          # desafio ≠ request_id de t1
    carlos = w.key("carlos", R[1])
    p1 = w.first(bob_wrong, R[0])
    p2 = w.forward(p1, bob_wrong, [note_out(w.cap, carlos)], R[1])
    with pytest.raises(ValidationError, match="nível software"):             # hop 2 rebaixado: profundidade 2 > 1
        w.verify(w.verifier(), p2, my=carlos, req=R[1])


# ================================================================== adulteração e quebra de cadeia
@pytest.fixture
def sw(keys):
    return World(keys, software_slots=True, cap=4 * WFLX)


def two_hop(sw):
    bob, carlos = soft(40), soft(41)
    p1 = sw.first(bob, R[0])
    return bob, carlos, p1, sw.forward(p1, bob, [note_out(sw.cap, carlos)], R[1])


def resign(sw, hop, signer, **tx_changes):
    tx = replace(hop.tx, **tx_changes)
    return N.Hop(tx, signer.key_type, signer.public_key, signer.sign(tx.signing_message()), None)


def swap_last(pay, hop):
    return replace(pay, hops=pay.hops[:-1] + (hop,))


@pytest.mark.parametrize("change,msg", [
    (lambda tx: dict(outputs=(replace(tx.outputs[0], value=tx.outputs[0].value - 1),)), "conserva"),
    (lambda tx: dict(input_value=tx.input_value + 1), "nota esperada"),
    (lambda tx: dict(input_value=tx.input_value - 1), "nota esperada"),
    (lambda tx: dict(input_note=b"\x55" * 32), "nota esperada"),
    (lambda tx: dict(vault_id="ee" * 32), "outro cofre"),
    (lambda tx: dict(chain_hash=b"\x66" * 32), "outra rede"),
])
def test_root_hop_violations_even_with_valid_signatures(sw, change, msg):
    bob = soft(40)
    pay = sw.first(bob, R[0])
    hop = resign(sw, pay.hops[0], sw.slot_signers[0], **change(pay.hops[0].tx))
    with pytest.raises(ValidationError, match=msg):
        sw.verify(sw.verifier(), swap_last(pay, hop), my=bob, req=R[0])


def test_signer_that_does_not_own_the_note(sw):
    bob = soft(40)
    pay = sw.first(bob, R[0])
    mallory = soft(99)
    hop = resign(sw, pay.hops[0], mallory)                      # assinatura VÁLIDA, mas de quem não é o dono
    with pytest.raises(ValidationError, match="não é a dona"):
        sw.verify(sw.verifier(), swap_last(pay, hop), my=bob, req=R[0])
    bob2, carlos, p1, p2 = two_hop(sw)
    forged = resign(sw, p2.hops[1], mallory)                    # Mallory gasta a nota de Bob
    with pytest.raises(ValidationError, match="não é a dona"):
        sw.verify(sw.verifier(), swap_last(p2, forged), my=carlos, req=R[1])


def test_signature_tampering(sw):
    bob, carlos, p1, p2 = two_hop(sw)
    for pay, who, req in ((p1, bob, R[0]), (p2, carlos, R[1])):
        h = pay.hops[-1]
        flipped = replace(h, signature=h.signature[:-1] + bytes([h.signature[-1] ^ 1]))
        with pytest.raises(ValidationError, match="assinatura do salto inválida"):
            sw.verify(sw.verifier(), swap_last(pay, flipped), my=who, req=req)
        # alterar o conteúdo depois de assinar
        other = replace(h.tx, outputs=(replace(h.tx.outputs[0], owner=b"\x31" * 32),))
        with pytest.raises(ValidationError):
            sw.verify(sw.verifier(), swap_last(pay, replace(h, tx=other)), my=who, req=req)


def test_p256_high_s_hop_signature_rejected(keys):
    w = World(keys, software_slots=True, cap=4 * WFLX, key_type="p256")
    bob = soft(50)
    pay = w.first(bob, R[0])
    h = pay.hops[0]
    s = int.from_bytes(h.signature[32:], "big")
    bad = replace(h, signature=h.signature[:32] + (_P256_N - s).to_bytes(32, "big"))
    with pytest.raises(ValidationError, match="assinatura"):
        w.verify(w.verifier(), swap_last(pay, bad), my=bob, req=R[0])


def test_chain_structure_attacks(sw):
    bob, carlos, p1, p2 = two_hop(sw)
    v = lambda pay, who, req: sw.verify(sw.verifier(max_hops_software=9, max_value_software=999), pay, my=who, req=req)
    assert v(p2, carlos, R[1]).depth == 2                        # controle (com política frouxa)
    with pytest.raises(ValidationError, match="nota esperada"):
        v(replace(p2, hops=(p2.hops[1],)), carlos, R[1])        # t1 omitido
    with pytest.raises(ValidationError):
        v(replace(p2, hops=(p2.hops[1], p2.hops[0])), carlos, R[1])   # ordem trocada
    eve = soft(60)
    extra = N.spend_output(p2.hops[1], 0, outputs=[note_out(sw.cap, eve)], request_id=R[2], signer=soft(61))
    with pytest.raises(ValidationError, match="não é a dona"):
        v(replace(p2, hops=p2.hops + (extra,), leaf=0), eve, R[2])  # salto extra assinado por quem não é dono
    # emenda: t2 de OUTRA cadeia (outro destinatário) colado em t1
    other_p2 = sw.forward(p1, bob, [note_out(sw.cap, soft(70))], R[3])
    spliced = replace(p2, hops=(p2.hops[0], other_p2.hops[1]))
    with pytest.raises(ValidationError, match="não é uma nota da minha chave"):
        v(spliced, carlos, R[1])


def test_leaf_and_request_binding(sw):
    bob, carlos, p1, p2 = two_hop(sw)
    v = sw.verifier(max_hops_software=9, max_value_software=999)
    for bad_leaf in (1, 7, 65535):
        with pytest.raises(ValidationError, match="folha"):
            sw.verify(v, replace(p2, leaf=bad_leaf), my=carlos, req=R[1])
    with pytest.raises(ValidationError, match="não é uma nota da minha chave"):
        sw.verify(v, p2, my=soft(80), req=R[1])                  # a folha é de Carlos, não dele
    with pytest.raises(ValidationError, match="request_id"):
        sw.verify(v, p2, my=carlos, req=R[5])
    with pytest.raises(ValidationError, match="slot|vaga"):
        sw.verify(v, replace(p2, slot=1), my=carlos, req=R[1])


# ================================================================== prova do cofre / frescor
def test_stale_checkpoint_is_rejected_by_receiver_memory(w):
    bob = w.key("bob", R[0])
    pay = w.first(bob, R[0])
    v = w.verifier()
    v.checkpoints.observe(w.chain.height + 5, "ab" * 32)
    with pytest.raises(ValidationError, match="mais antigo"):
        w.verify(v, pay, my=bob, req=R[0])


def _mutate_registry_and_mine(w, fn):
    fn(w.chain.vaults.get(w.vid))
    mine(w.chain, w.keys)                                       # novo bloco: state_root passa a refletir a mudança


def test_fraud_flagged_or_occupied_slot_in_checkpoint_is_rejected(keys):
    w = World(keys)
    _mutate_registry_and_mine(w, lambda vault: setattr(vault, "fraud", True))
    bob = w.key("bob", R[0])
    pay = w.first(bob, R[0])
    with pytest.raises(ValidationError, match="fraudulento"):
        w.verify(w.verifier(), pay, my=bob, req=R[0])
    assert w.verify(w.verifier(reject_fraud_vault=False), pay, my=bob, req=R[0]).depth == 1   # política do receptor

    w2 = World(keys)

    def occupy(vault):
        vault.slots[0].claimed_by = "ab" * 32
        vault.slots[0].paid = 5
    _mutate_registry_and_mine(w2, occupy)
    bob2 = w2.key("bob", R[0])
    with pytest.raises(ValidationError, match="ocupada"):
        w2.verify(w2.verifier(), w2.first(bob2, R[0]), my=bob2, req=R[0])


def test_margin_and_network_and_legacy_vault(keys):
    w = World(keys)
    bob = w.key("bob", R[0])
    pay = w.first(bob, R[0])
    with pytest.raises(ValidationError, match="margem"):
        w.verify(w.verifier(min_margin_blocks=1), pay, my=bob, req=R[0], now=w.now + 5 * 10_000)
    assert w.verify(w.verifier(min_margin_blocks=1), pay, my=bob, req=R[0], now=w.now).depth == 1
    other = vchain(keys, chain_id="outra-rede")
    with pytest.raises(ValidationError):
        w.verify(w.verifier(params=other.params), pay, my=bob, req=R[0])
    legacy = World(keys, with_slot_keys=False)
    lb = legacy.key("bob", R[0])
    p = legacy.first(lb, R[0], signer=soft(3, legacy.key_type))
    with pytest.raises(ValidationError, match="sem chave própria"):
        legacy.verify(legacy.verifier(), p, my=lb, req=R[0])


# ================================================================== memória local e gasto duplo
def test_receiver_memory_rejects_a_second_spend_of_the_same_note(sw):
    bob, bob2 = soft(90), soft(91)
    p_a = sw.first(bob, R[0])
    p_b = sw.first(bob2, R[1])                                   # a MESMA vaga raiz gasta para outra chave
    v = sw.verifier()
    vp = sw.verify(v, p_a, my=bob, req=R[0])
    v.accept(vp)
    sw.verify(v, p_a, my=bob, req=R[0])                          # reapresentar o MESMO pagamento é idempotente
    with pytest.raises(ValidationError, match="outra forma"):
        sw.verify(v, p_b, my=bob2, req=R[1])
    other_slot = sw.first(bob2, R[2], slot=1)
    assert sw.verify(v, other_slot, my=bob2, req=R[2]).depth == 1          # outra vaga: sem conflito


# ================================================================== risco residual (documentado)
def test_intact_hardware_physically_prevents_a_second_spend(w):
    bob, carlos, eve = w.key("bob", R[0]), w.key("carlos", R[1]), w.key("eve", R[2])
    p1 = w.first(bob, R[0])
    w.forward(p1, bob, [note_out(w.cap, carlos)], R[1])
    with pytest.raises(HardwareError, match="já usada"):
        w.forward(p1, bob, [note_out(w.cap, eve)], R[2])         # Bob não consegue assinar t2'
    with pytest.raises(HardwareError):
        w.first(eve, R[3])                                       # nem Alice reusa a chave da vaga 0 (já gasta)


def test_compromised_hardware_double_spend_is_accepted_offline_by_both_receivers(keys):
    """RISCO RESIDUAL (H1): com hardware quebrado, dois receptores isolados aceitam. Quem perde é compensado por R1-R9
    na liquidação (A3). O verificador NÃO consegue impedir isso offline — e não promete."""
    w = World(keys)
    bob, carlos, eve = w.key("bob", R[0]), w.key("carlos", R[1]), w.key("eve", R[2])
    p1 = w.first(bob, R[0])
    w.people["bob"].break_single_use()                           # adversário: Bob adultera o próprio hardware
    p_carlos = w.forward(p1, bob, [note_out(w.cap, carlos)], R[1])
    p_eve = w.forward(p1, bob, [note_out(w.cap, eve)], R[2])     # mesma nota, outro destino
    assert w.verify(w.verifier(), p_carlos, my=carlos, req=R[1]).level == "hardware"
    assert w.verify(w.verifier(), p_eve, my=eve, req=R[2]).level == "hardware"
    shared = w.verifier()                                        # um MESMO receptor veria o conflito
    shared.accept(w.verify(shared, p_carlos, my=carlos, req=R[1]))
    with pytest.raises(ValidationError, match="outra forma"):
        w.verify(shared, p_eve, my=eve, req=R[2])


def test_software_slot_key_allows_alice_to_double_spend_the_root(keys):
    w = World(keys, software_slots=True, cap=4 * WFLX)
    bob, bob2 = soft(110), soft(111)
    pa, pb = w.first(bob, R[0]), w.first(bob2, R[1])
    assert w.verify(w.verifier(), pa, my=bob, req=R[0]).level == "software"
    assert w.verify(w.verifier(), pb, my=bob2, req=R[1]).level == "software"   # nível software: só limite+colateral


# ================================================================== fuzz e propriedades
def _paths(o, pre=()):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _paths(v, pre + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _paths(v, pre + (i,))
    else:
        yield pre


def _set(o, p, v):
    for k in p[:-1]:
        o = o[k]
    o[p[-1]] = v


def test_payment_fuzz_only_validation_errors(w):
    bob, carlos = w.key("bob", R[0]), w.key("carlos", R[1])
    p2 = w.forward(w.first(bob, R[0]), bob, [note_out(w.cap, carlos)], R[1])
    base = json.loads(json.dumps(p2.to_dict()))
    rnd = random.Random(8)
    junk = [None, -1, 0, 2**70, "", "x", [], {}, True, 1.5, "00" * 32, [1], {"a": 1}, "g" * 64, "ab" * 100]
    v = w.verifier()
    for _ in range(1500):
        m = copy.deepcopy(base)
        for _ in range(rnd.choice([1, 2, 3])):
            _set(m, rnd.choice([p for p in _paths(m) if p]), copy.deepcopy(rnd.choice(junk)))
        try:
            w.verify(v, m, my=carlos, req=R[1])
        except ValidationError:
            continue
        assert m == base                                         # só o pagamento original passa
    for bad in (None, [], "x", {}, 5):
        with pytest.raises(ValidationError):
            w.verify(v, bad, my=carlos, req=R[1])


def test_every_byte_of_every_hop_tx_is_bound(w):
    bob, carlos = w.key("bob", R[0]), w.key("carlos", R[1])
    base = json.loads(json.dumps(w.forward(w.first(bob, R[0]), bob, [note_out(w.cap, carlos)], R[1]).to_dict()))
    v = w.verifier()
    w.verify(v, base, my=carlos, req=R[1])
    checked = 0
    for hop_i, hop in enumerate(base["hops"]):
        raw = bytearray.fromhex(hop["tx"])
        for pos in range(len(raw)):
            m = copy.deepcopy(base)
            b = bytearray(raw)
            b[pos] ^= 0x01
            m["hops"][hop_i]["tx"] = bytes(b).hex()
            with pytest.raises(ValidationError):
                w.verify(v, m, my=carlos, req=R[1])
            checked += 1
    assert checked == sum(len(bytes.fromhex(h["tx"])) for h in base["hops"]) > 300


def test_property_random_hardware_chains(keys):
    rnd = random.Random(17)
    for trial in range(12):
        w = World(keys, key_type=rnd.choice(["p256", "ed25519"]))
        depth = rnd.randint(1, 3)
        holder = w.key("p0", R[0])
        pay = w.first(holder, R[0])
        value = w.cap
        for hop in range(1, depth):
            nxt, change = w.key(f"p{hop}", R[hop]), w.key(f"p{hop}", R[hop])
            part = rnd.randint(1, value - 1) if value > 1 else value
            outs = [note_out(part, nxt)] + ([note_out(value - part, change)] if value - part else [])
            pay = w.forward(pay, holder, outs, R[hop])
            holder, value = nxt, part
        vp = w.verify(w.verifier(), pay, my=holder, req=R[depth - 1])
        assert vp.depth == depth and vp.value == value and vp.level == "hardware"
        assert sum(o.value for o in pay.hops[-1].tx.outputs) == pay.hops[-1].tx.input_value
