"""Demo: offline vault, voucher payment, double-spend attempt and refund.

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
phone_key = P256KeyPair()  # on a real phone: hardware key (Keystore/StrongBox)
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
    print(f"\n=== {title}  [height {chain.height}]")


def state(vid):
    v = chain.get_vault(vid)
    print(f"   locked in vaults: {fu(chain.vaults.total_locked)} | supply: {fu(chain.total_supply())} | fraud: {v.fraud}")
    print(f"   bob {fu(chain.balance(bob.address))} | carol {fu(chain.balance(carol.address))} | alice {fu(chain.balance(alice.address))}")


line("1. Alice (online) opens a vault: 2 slots of 10 WFLX + 100% collateral")
tx = build_vault_open(alice, chain.utxo.utxos_for(alice.address), phone_key, (to_units("10"),) * 2, 100, 10,
                      alice.address, params)
mine(tx)
vid = tx.txid
state(vid)

line("2. OFFLINE: Alice pays 7 WFLX to Bob and, at the same time, tries to pay the SAME slot to Carol")
v_bob = Voucher.issue(phone_key, params.chain_id, vid, 0, to_units("7"), bob.address, b"\x01" * 16)
v_carol = Voucher.issue(phone_key, params.chain_id, vid, 0, to_units("7"), carol.address, b"\x02" * 16)
print(f"   voucher of {len(v_bob.to_bytes())} bytes each (fits in a QR code); both have a valid signature:")
print("   Bob  accepts (the offline receiver does not see the conflict)  hash", v_bob.hash[:12])
print("   Carol accepts (same)                                hash", v_carol.hash[:12])

line("3. Bob comes back online and settles first")
mine(build_voucher_claim(v_bob, chain.get_vault(vid), params))
state(vid)

line("4. Carol comes back online: the slot was already used, but she is compensated by the collateral (7 of 10 WFLX)")
mine(build_voucher_claim(v_carol, chain.get_vault(vid), params))
state(vid)
print("   => the vault is marked as fraudulent")

line("5. Third victim on the same slot: only 3 WFLX of collateral remain; the fourth gets nothing")
v3 = Voucher.issue(phone_key, params.chain_id, vid, 0, to_units("7"), dave.address, b"\x03" * 16)
mine(build_voucher_claim(v3, chain.get_vault(vid), params))
print(f"   dave received {fu(chain.balance(dave.address))} WFLX (of 7 promised): the 4 WFLX loss is the residual risk of level 1")
v4 = Voucher.issue(phone_key, params.chain_id, vid, 0, to_units("7"), erin.address, b"\x04" * 16)
try:
    build_voucher_claim(v4, chain.get_vault(vid), params)
except ValidationError as e:
    print("   erin: rejected ->", e)

line("6. After the deadline, refund of what is left (the remaining collateral is burned)")
v = chain.get_vault(vid)
while chain.height <= v.expires_height + params.claim_window_blocks:
    mine()
before = chain.total_supply()
mine(build_vault_refund(chain.get_vault(vid), params))
state(vid)
print(f"   burned collateral reduced the supply (all the remaining collateral of the fraudulent vault): {fu(before + to_units('50') - chain.total_supply())} WFLX")
