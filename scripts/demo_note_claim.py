"""Demo (A3): liquidação on-chain de notas offline (`note_claim`), com gasto duplo e compensação.

    PYTHONPATH=. python scripts/demo_note_claim.py

Alice abre um cofre (vaga de 30 WFLX com chave própria), paga Bob -> Carlos OFFLINE, e a folha-endereço é liquidada
on-chain. Depois Alice tenta gastar a mesma raiz de novo para Mallory: o segundo ramo é pago pelo COLATERAL (R1-R9),
o cofre fica marcado como fraudulento. Chaves em software (sem hardware): demonstra o consenso, não segurança de hardware.
"""
from winflux.blockchain.chain import Chain
from winflux.blockchain.genesis import GenesisConfig
from winflux.blockchain.params import ChainParams
from winflux.consensus.poa import ProofOfAuthority
from winflux.crypto.keys import KeyPair, P256KeyPair
from winflux.offline import note as N
from winflux.offline.voucher import chain_id_hash
from winflux.units import format_units as fu, to_units
from winflux.wallet.vault_builder import build_note_claim, build_vault_open

producer, alice, carlos, mallory = (KeyPair.generate() for _ in range(4))
params = ChainParams("winflux-demo", "Winflux", "WFLX", 8, to_units("100000000"), to_units("50"), 210_000, 1000,
                     (producer.public_hex,), vault_ttl_min_blocks=2, vault_ttl_max_blocks=50, claim_window_blocks=4)
chain = Chain(GenesisConfig(params, 1_700_000_000, ((alice.address, to_units("1000")),)), ProofOfAuthority(),
              clock=lambda: 1_700_010_000)


def mine(*txs):
    b = chain.create_block(producer.public_hex, producer.address, list(txs))
    chain.consensus.seal(b, producer)
    chain.add_block(b)


soft = lambda: N.SoftwareSigner(P256KeyPair())
slot_key, bob = soft(), soft()
tx = build_vault_open(alice, chain.utxo.utxos_for(alice.address), P256KeyPair(), (to_units("30"),), 100, 10,
                      alice.address, params, slot_keys=[slot_key.public_hex])
mine(tx)
vid, chash, cap = tx.txid, chain_id_hash(params.chain_id), to_units("30")
to_addr = lambda who: N.NoteOutput(cap, N.KIND_ADDRESS, N.address_owner(who.address))
req = lambda i: bytes([i]) * 16

print("== OFFLINE: Alice -> Bob (nota) -> Carlos (endereço)")
t1 = N.spend_root(chain_hash=chash, vault_id=vid, slot=0, cap=cap, request_id=req(1), signer=slot_key,
                  outputs=[N.NoteOutput(cap, N.KIND_NOTE, N.owner_commitment(bob.key_type, bob.public_key))])
t2 = N.spend_output(t1, 0, outputs=[to_addr(carlos)], request_id=req(2), signer=bob)
pay = N.OfflinePayment({}, 0, (t1, t2), 0)

print("== ON-CHAIN: note_claim liquida a folha")
mine(build_note_claim(pay, chain.get_vault(vid), params))
s = chain.get_vault(vid).slots[0]
print(f"   Carlos recebeu {fu(chain.balance(carlos.address))} WFLX | vaga paga={fu(s.paid)} | fraude={chain.get_vault(vid).fraud}")

print("\n== GASTO DUPLO: Alice gasta a mesma raiz para Mallory")
evil = N.spend_root(chain_hash=chash, vault_id=vid, slot=0, cap=cap, outputs=[to_addr(mallory)],
                    request_id=req(9), signer=slot_key)
mine(build_note_claim(N.OfflinePayment({}, 0, (evil,), 0), chain.get_vault(vid), params))
v = chain.get_vault(vid)
print(f"   Mallory recebeu {fu(chain.balance(mallory.address))} WFLX do COLATERAL | fraude={v.fraud} "
      f"| indenizado={fu(v.slots[0].compensated)} | colateral restante={fu(v.slots[0].collateral_left)}")
print(f"   oferta total consistente: {fu(chain.total_supply())} WFLX")
