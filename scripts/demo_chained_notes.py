"""Demo (A2): pagamento offline ENCADEADO com hardware simulado.

    PYTHONPATH=. python scripts/demo_chained_notes.py

Alice -> Bob -> Carlos -> Dave sem rede, cada receptor verificando localmente. O hardware é SIMULADO (ver
docs/security-assumptions.md): isto demonstra o protocolo, não segurança de hardware real.
"""
from winflux.blockchain.chain import Chain
from winflux.blockchain.genesis import GenesisConfig
from winflux.blockchain.params import ChainParams
from winflux.consensus.poa import ProofOfAuthority
from winflux.crypto.keys import KeyPair, P256KeyPair
from winflux.errors import ValidationError
from winflux.offline import note as N
from winflux.offline import proofs as P
from winflux.offline.hardware_sim import HardwareError, SimulatedRoot
from winflux.offline.verifier import OfflineVerifier, ReceiverPolicy
from winflux.offline.voucher import chain_id_hash
from winflux.units import format_units as fu, to_units
from winflux.wallet.vault_builder import build_vault_open

NOW = 1_700_010_000
producer, alice = KeyPair.generate(), KeyPair.generate()
params = ChainParams("winflux-demo", "Winflux", "WFLX", 8, to_units("100000000"), to_units("50"), 210_000, 1000,
                     (producer.public_hex,), vault_ttl_min_blocks=2, vault_ttl_max_blocks=50, claim_window_blocks=4)
chain = Chain(GenesisConfig(params, 1_700_000_000, ((alice.address, to_units("1000")),)), ProofOfAuthority(),
              clock=lambda: NOW)
poa = chain.consensus


def mine(*txs):
    b = chain.create_block(producer.public_hex, producer.address, list(txs))
    poa.seal(b, producer)
    chain.add_block(b)


root = SimulatedRoot()
hw = {n: root.provision("strongbox", not_before=1_700_000_000, not_after=2**40) for n in ("alice", "bob", "carlos", "dave", "erin")}
req = lambda i: bytes([i]) * 16
commit = lambda h: N.owner_commitment(h.key_type, h.public_key)
out = lambda v, h: N.NoteOutput(to_units(str(v)), N.KIND_NOTE, commit(h))


def verifier():
    return OfflineVerifier(params, poa, roots=[root.public_key], policy=ReceiverPolicy(min_margin_blocks=1))


def receive(who, pay, key, i):
    vp = verifier().verify(pay, now=NOW, my_key=(key.key_type, key.public_key), request_id=req(i))
    print(f"   {who}: {vp.status} | profundidade {vp.depth} | nível {vp.level} | valor {fu(vp.value)} WFLX "
          f"| prazo p/ liquidar: {vp.deadline_blocks} blocos")
    return vp


print("== Alice (online) abre um cofre com 2 vagas de 30 WFLX; a chave de cada vaga está no hardware (uso único)")
slot_key, slot_key2 = (hw["alice"].generate_key("p256", bytes(16)) for _ in range(2))
tx = build_vault_open(alice, chain.utxo.utxos_for(alice.address), P256KeyPair(), (to_units("30"),) * 2, 100, 10,
                      alice.address, params, slot_keys=[slot_key.public_hex, slot_key2.public_hex])
mine(tx)
vid = tx.txid
chash = chain_id_hash(params.chain_id)
proof = P.build_vault_proof(chain, vid, 0)
print(f"   cofre {vid[:12]}…, prova de {len(str(proof))} caracteres, checkpoint altura {chain.height}")

print("\n== OFFLINE 1: Alice -> Bob (30 WFLX)")
bob = hw["bob"].generate_key("p256", req(1))
t1 = N.spend_root(chain_hash=chash, vault_id=vid, slot=0, cap=to_units("30"), outputs=[out(30, bob)],
                  request_id=req(1), signer=slot_key)
pay1 = N.OfflinePayment(proof, 0, (t1,), 0)
receive("Bob   ", pay1, bob, 1)

print("\n== OFFLINE 2: Bob -> Carlos (10), troco 20 para ele mesmo")
carlos, change = hw["carlos"].generate_key("p256", req(2)), hw["bob"].generate_key("p256", req(2))
t2 = N.spend_output(t1, 0, outputs=[out(10, carlos), out(20, change)], request_id=req(2), signer=bob)
pay2 = N.OfflinePayment(proof, 0, (t1, t2), 0)
receive("Carlos", pay2, carlos, 2)

print("\n== OFFLINE 3: Carlos -> Dave (10)")
dave = hw["dave"].generate_key("p256", req(3))
t3 = N.spend_output(t2, 0, outputs=[out(10, dave)], request_id=req(3), signer=carlos)
pay3 = N.OfflinePayment(proof, 0, (t1, t2, t3), 0)
receive("Dave  ", pay3, dave, 3)

print("\n== OFFLINE 4: Dave -> Erin: 4º salto, acima do limite de 3 para nível hardware")
erin = hw["erin"].generate_key("p256", req(4))
t4 = N.spend_output(t3, 0, outputs=[out(10, erin)], request_id=req(4), signer=dave)
try:
    receive("Erin  ", N.OfflinePayment(proof, 0, (t1, t2, t3, t4), 0), erin, 4)
except ValidationError as e:
    print("   Erin  : RECUSADO ->", e)

print("\n== TENTATIVA DE GASTO DUPLO: Bob tenta gastar de novo a mesma nota (já usada)")
try:
    N.spend_output(t1, 0, outputs=[out(30, hw["erin"].generate_key("p256", req(5)))], request_id=req(5), signer=bob)
except HardwareError as e:
    print("   hardware recusa ->", e)

print("\n== RISCO RESIDUAL (vaga 1): Bob2 tem hardware COMPROMETIDO desde o início e assina duas vezes a mesma nota")
bad_hw = root.provision("strongbox", not_before=1_700_000_000, not_after=2**40)
bad_hw.break_single_use()                       # adversário adultera o próprio hardware ANTES de usar a chave
bob2 = bad_hw.generate_key("p256", req(7))
proof1 = P.build_vault_proof(chain, vid, 1)
s1 = N.spend_root(chain_hash=chash, vault_id=vid, slot=1, cap=to_units("30"), outputs=[out(30, bob2)],
                  request_id=req(7), signer=slot_key2)
carlos2, eve = hw["carlos"].generate_key("p256", req(8)), hw["erin"].generate_key("p256", req(9))
to_carlos = N.spend_output(s1, 0, outputs=[out(30, carlos2)], request_id=req(8), signer=bob2)
to_eve = N.spend_output(s1, 0, outputs=[out(30, eve)], request_id=req(9), signer=bob2)     # MESMA nota, outro destino
receive("Carlos", N.OfflinePayment(proof1, 1, (s1, to_carlos), 0), carlos2, 8)
receive("Eve   ", N.OfflinePayment(proof1, 1, (s1, to_eve), 0), eve, 9)
print("   => Carlos e Eve aceitaram offline a MESMA nota; o conflito só aparece na liquidação (A3), onde o colateral")
print("      da vaga raiz compensa sob R1-R9. O verificador NÃO impede isso e não promete impedir.")
