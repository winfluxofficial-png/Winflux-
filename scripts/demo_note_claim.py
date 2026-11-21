"""Demo (A3): on-chain settlement of offline notes (`note_claim`), with double spend and compensation.

    PYTHONPATH=. python scripts/demo_note_claim.py

Alice opens a vault (a 30 WFLX slot with its own key), pays Bob -> Carlos OFFLINE, and the address leaf is settled
on-chain. Then Alice tries to spend the same root again to Mallory: the second branch is paid by the COLLATERAL (R1-R9),
and the vault is marked as fraudulent. Software keys (no hardware): this demonstrates consensus, not hardware security.
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

print("== OFFLINE: Alice -> Bob (note) -> Carlos (address)")
t1 = N.spend_root(chain_hash=chash, vault_id=vid, slot=0, cap=cap, request_id=req(1), signer=slot_key,
                  outputs=[N.NoteOutput(cap, N.KIND_NOTE, N.owner_commitment(bob.key_type, bob.public_key))])
t2 = N.spend_output(t1, 0, outputs=[to_addr(carlos)], request_id=req(2), signer=bob)
pay = N.OfflinePayment({}, 0, (t1, t2), 0)

print("== ON-CHAIN: note_claim settles the leaf")
mine(build_note_claim(pay, chain.get_vault(vid), params))
s = chain.get_vault(vid).slots[0]
print(f"   Carlos received {fu(chain.balance(carlos.address))} WFLX | slot paid={fu(s.paid)} | fraud={chain.get_vault(vid).fraud}")

print("\n== DOUBLE SPEND: Alice spends the same root again, to Mallory")
evil = N.spend_root(chain_hash=chash, vault_id=vid, slot=0, cap=cap, outputs=[to_addr(mallory)],
                    request_id=req(9), signer=slot_key)
mine(build_note_claim(N.OfflinePayment({}, 0, (evil,), 0), chain.get_vault(vid), params))
v = chain.get_vault(vid)
print(f"   Mallory received {fu(chain.balance(mallory.address))} WFLX from the COLLATERAL | fraud={v.fraud} "
      f"| compensated={fu(v.slots[0].compensated)} | remaining collateral={fu(v.slots[0].collateral_left)}")
print(f"   total supply consistent: {fu(chain.total_supply())} WFLX")
