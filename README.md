# Winflux (WFLX) — Independent Blockchain

> Official name: **Winflux (WFLX)**. Naming history: Nexora/NXR (previously used) → Kelvora/KVRA → Winflux/WFLX.
> Trademark and ticker availability **have not yet been confirmed**: see `docs/naming.md`.
> **Experimental software. Do not use with real funds** before cryptographic audits,
> adversarial testing, and independent review.

| Parameter | Value |
|---|---|
| Maximum supply | 100,000,000 WFLX (`10^16` units) |
| Decimal places | 8 (smallest unit: `0.00000001 WFLX`) |
| Issuance | Limited: genesis + block rewards with halving, always subject to the supply cap |
| Additional issuance | Prohibited (validated by every node: coinbase ≤ reward + fees; supply ≤ cap) |
| Hashing / signatures | SHA-256 / Ed25519 |
| Model | UTXO, integer-denominated values |
| Consensus | **Open PoW** (no authorities, fair launch, zero premine) for the public network; PoA only on the local devnet |

## Status

| Stage | Status |
|---|---|
| 1 Basic blockchain (genesis, blocks, chaining, SQLite persistence) | ✅ tested |
| 2 Cryptography and wallets (Ed25519, `wflx1…` addresses, encrypted keystore) | ✅ tested |
| 3 Monetary system (UTXO, fees, supply cap, double-spend/replay protection) | ✅ tested |
| 0 Consolidation (audit findings: fee per byte, block size limit, HD wallet, recovery key, unique `chain_id`) | ✅ tested (`docs/audit-fase0.md`) |
| 1a Transaction types and offline vaults at the consensus layer (3b-1): `vault_open`, `voucher_claim`, `vault_refund`, binary voucher, Ed25519/P-256, coinbase with previous hash | ✅ tested (239 tests, 13 mutations) |
| A1 `state_root` in the header, checkpoints, and offline-verifiable vault proofs | ✅ tested |
| Deterministic collateral exposure (R1–R9) and fix for the replay/submission bug | ✅ tested |
| A2 Transferable notes: per-slot key, binary format, offline verifier, hardware simulator and attestation (405 tests, 33 mutations) | ✅ tested |
| A3 `note_claim` (on-chain note settlement, conflict/compensation R1–R9, undo, fuzzing and mutations; 497 tests) | ✅ tested (`docs/protocol.md`) |
| A4 Reconciliation (vault API, owner's journal, daily report × chain, `reconcile`/`vault-refund` CLI; no early closure, see `docs/protocol.md`) | ✅ tested (533 tests) |
| 1b Schema identifier and v2 address, post-quantum slot keys (LMS), binary transaction format | ⏳ |
| Android wallet v0.1 (online: HD, send/receive; JVM core tested against Python; UI not compiled) | 🟡 `android-wallet/` |
| Android offline (hardware diagnostics, NFC/BLE), PWA | ⏳ |
| 4 P2P network (handshake, mempool, propagation, synchronization, banning), HTTP API, node and CLI wallet | ✅ tested (3 nodes + real processes) |
| 4b PWA (mobile/desktop) | ⏳ after the API |
| 5 PoW with difficulty adjustment, most-work chain selection, atomic reorganizations, coinbase maturity, fair genesis (`netgen`) | ✅ tested (`docs/decentralization.md`) |
| 6+ Native Android, cross-network testing, public documentation | ⏳ |

## Run a PoW network (without anyone's permission)

```bash
python -m winflux.tools.netgen --name testnet --out genesis.json        # fair genesis: no premine, no authorities
python -m winflux.cli --wallet w.json create                            # wallet + recovery key
python -m winflux.node.main --genesis genesis.json --listen 0.0.0.0:8333 --mine <address>   # node + miner
python -m winflux.node.main --genesis genesis.json --datadir n2 --listen 0.0.0.0:8334 --api 127.0.0.1:8081 --seed IP:8333
python -m winflux.cli --node http://127.0.0.1:8081 --wallet w.json balance | send <address> <amount>
```

Read `docs/decentralization.md` (principles, what the code guarantees and **does not** guarantee, and pending decisions).

## Usage

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

pytest                                   # full test suite
PYTHONPATH=. python scripts/demo_local.py   # genesis -> transfer -> block -> confirmations
PYTHONPATH=. python scripts/demo_offline_vault.py   # offline vault, double spending, compensation and refund
PYTHONPATH=. python scripts/demo_chained_notes.py    # Alice -> Bob -> Carlos -> Dave offline (SIMULATED hardware)
PYTHONPATH=. python scripts/demo_note_claim.py       # on-chain settlement (note_claim), double spending and collateral
python -m winflux.tools.devnet init --dir devnet   # creates genesis.json + encrypted keys (5,000,000 WFLX at genesis)
# the password is read from WINFLUX_DEVNET_PASSWORD or requested through a prompt (never from the command line)
```

`devnet init` creates `genesis.json`, `producer.key.json` (PoA authority), and `faucet.key.json`
(which receives the initial 5,000,000 WFLX). The `chain_id` is derived from the genesis block. The default password (`devnet-only-password`) is
used only when neither an environment variable nor an interactive terminal is available; it is intended for local testing only.

Recommended wallet: `winflux.wallet.hd.HDWallet` (change sent to a new address, recovery key `wflxk1-…`).

## Structure

```text
winflux/
├── crypto/      hashing.py address.py keys.py        SHA-256, addresses, Ed25519, keystore
├── blockchain/  transaction.py block.py params.py genesis.py utxo.py vaults.py ledger.py validation.py chain.py
├── offline/     voucher.py proofs.py note.py verifier.py attestation.py hardware_sim.py
│                                                      vouchers, vault proofs, chained notes, verifier, SIMULATED hardware
├── blockchain/  exposure.py state_root.py             exposure limits (R1–R9), Merkle root for vaults
├── consensus/   interface.py poa.py pow.py            PoA (devnet) and PoW (public network)
├── node/        storage.py mempool.py node.py main.py complete node (chain+mempool+P2P+miner)
├── wallet/      wallet.py hd.py transaction_builder.py vault_builder.py
├── network/p2p.py  api/server.py  cli.py              P2P, HTTP API, command-line wallet
├── tools/       devnet.py netgen.py localnet.py       local PoA devnet; fair PoW genesis; multi-process local testnet
├── logs.py      network/limits.py                     secret-redacting logging; token bucket (P2P/API)
web-wallet/ (PWA)   android-wallet/ (native, future)   tests/   docs/   scripts/
```

Change from the original brief: transaction validation rules are located in
`blockchain/validation.py` (rather than `node/validator.py`) to avoid a circular dependency
between the chain and node, and to allow the Android app and tools to reuse the same validation rules.

Documentation: `docs/offline-chained-payments.md` (**approved architecture for chained offline payments**),
`docs/security-assumptions.md` (security assumptions), `docs/running-a-node.md` (operating a node), `docs/testnet.md` (testnet, local testnet and smoke test), `docs/protocol.md` (Stages 1–3 rules), `docs/offline-payments.md` (vaults and vouchers:
specification and threat model — **core requirement**), and `docs/architecture.md` (risks and decisions).
