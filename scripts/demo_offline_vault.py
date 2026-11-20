"""Demo: cofre offline, pagamento por voucher, tentativa de gasto duplo e devolução.

    PYTHONPATH=. python scripts/demo_offline_vault.py
"""
from winflux.blockchain.chain import Chain
from winflux.blockchain.genesis import GenesisConfig
from winflux.blockchain.params import ChainParams
from winflux.consensus.poa import ProofOfAuthority
from winflux.crypto.keys import KeyPair, P256KeyPair
from winflux.errors import ValidationError
from winflux.offline.voucher import Voucher
from winflux.units import format_units as fu, to_units
from winflux.wallet.vault_builder import build_vault_open, build_vault_refund, build_voucher_claim

producer, alice, bob, carol, dave, erin = (KeyPair.generate() for _ in range(6))
phone_key = P256KeyPair()  # no celular real: chave de hardware (Keystore/StrongBox)
params = ChainParams("winflux-demo", "Winflux", "WFLX", 8, to_units("100000000"), to_units("50"), 210_000,
                     1000, (producer.public_hex,), vault_ttl_min_blocks=2, vault_ttl_max_blocks=50,
                     claim_window_blocks=4)
chain = Chain(GenesisConfig(params, 1_700_000_000, ((alice.address, to_units("1000")),)), ProofOfAuthority(),
              clock=lambda: 1_700_010_000)


def mine(*txs):
    b = chain.create_block(producer.public_hex, producer.address, list(txs))
    chain.consensus.seal(b, producer)
    chain.add_block(b)


def line(title):
    print(f"\n=== {title}  [altura {chain.height}]")


def state(vid):
    v = chain.get_vault(vid)
    print(f"   travado nos cofres: {fu(chain.vaults.total_locked)} | oferta: {fu(chain.total_supply())} | fraude: {v.fraud}")
    print(f"   bob {fu(chain.balance(bob.address))} | carol {fu(chain.balance(carol.address))} | alice {fu(chain.balance(alice.address))}")


line("1. Alice (online) abre um cofre: 2 vagas de 10 WFLX + colateral 100%")
tx = build_vault_open(alice, chain.utxo.utxos_for(alice.address), phone_key, (to_units("10"),) * 2, 100, 10,
                      alice.address, params)
mine(tx)
vid = tx.txid
state(vid)

line("2. OFFLINE: Alice paga 7 WFLX a Bob e, ao mesmo tempo, tenta pagar a MESMA vaga a Carol")
v_bob = Voucher.issue(phone_key, params.chain_id, vid, 0, to_units("7"), bob.address, b"\x01" * 16)
v_carol = Voucher.issue(phone_key, params.chain_id, vid, 0, to_units("7"), carol.address, b"\x02" * 16)
print(f"   voucher de {len(v_bob.to_bytes())} bytes cada (cabe em QR); ambos têm assinatura válida:")
print("   Bob  aceita (receptor offline não vê o conflito)  hash", v_bob.hash[:12])
print("   Carol aceita (idem)                                hash", v_carol.hash[:12])

line("3. Bob volta online e liquida primeiro")
mine(build_voucher_claim(v_bob, chain.get_vault(vid), params))
state(vid)

line("4. Carol volta online: a vaga já foi usada, mas ela é compensada pelo colateral (7 de 10 WFLX)")
mine(build_voucher_claim(v_carol, chain.get_vault(vid), params))
state(vid)
print("   => o cofre fica marcado como fraudulento")

line("5. Terceira vítima na mesma vaga: só resta 3 WFLX de colateral; a quarta fica sem nada")
v3 = Voucher.issue(phone_key, params.chain_id, vid, 0, to_units("7"), dave.address, b"\x03" * 16)
mine(build_voucher_claim(v3, chain.get_vault(vid), params))
print(f"   dave recebeu {fu(chain.balance(dave.address))} WFLX (de 7 prometidos): perda de 4 WFLX é o risco residual do nível 1")
v4 = Voucher.issue(phone_key, params.chain_id, vid, 0, to_units("7"), erin.address, b"\x04" * 16)
try:
    build_voucher_claim(v4, chain.get_vault(vid), params)
except ValidationError as e:
    print("   erin: recusado ->", e)

line("6. Passado o prazo, devolução do que sobrou (o colateral restante é queimado)")
v = chain.get_vault(vid)
while chain.height <= v.expires_height + params.claim_window_blocks:
    mine()
before = chain.total_supply()
mine(build_vault_refund(chain.get_vault(vid), params))
state(vid)
print(f"   colateral queimado reduziu a oferta (todo o colateral restante do cofre fraudulento): {fu(before + to_units('50') - chain.total_supply())} WFLX")
