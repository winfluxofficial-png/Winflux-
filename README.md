# Winflux (WFLX) — a blockchain of its own

> Official name: **Winflux (WFLX)**.
> adversarial testing and independent review.

| Parameter | Value |
|---|---|
| Maximum supply | 100,000,000 WFLX (`10^16` units) |
| Decimal places | 8 (smallest unit `0.00000001 WFLX`) |
| Issuance | bounded: genesis + block reward with halving, always under the cap |
| Additional creation | forbidden (validated by every node: coinbase ≤ reward + fees; supply ≤ cap) |
| Hash / signature | SHA-256 / Ed25519 |
| Model | UTXO, integer values |
| Consensus | **Open PoW** (no authorities, fair launch, zero premine) for the public network; PoA only on the local devnet |

## Status

| Stage | State |
|---|---|
| 1 Basic blockchain (genesis, blocks, chaining, SQLite persistence) | ✅ tested |
| 2 Cryptography and wallets (Ed25519, `wflx1…` addresses, encrypted keystore) | ✅ tested |
| 3 Monetary system (UTXO, fees, supply cap, anti double-spend/replay) | ✅ tested |
| 0 Consolidation (audit findings: fee per byte, block limit, HD wallet, recovery key, unique `chain_id`) | ✅ tested (`docs/audit-phase0.md`) |
| 1a Transaction types and offline vaults at the consensus layer (3b-1): `vault_open`, `voucher_claim`, `vault_refund`, binary voucher, Ed25519/P-256, coinbase with previous hash | ✅ tested (239 tests, 13 mutations) |
| A1 `state_root` in the header, checkpoints and vault proofs verifiable offline | ✅ tested |
| Deterministic collateral exposure (R1-R9) and fix for the resubmission bug | ✅ tested |
| A2 Transferable notes: per-slot key, binary format, offline verifier, hardware simulator and attestation (405 tests, 33 mutations) | ✅ tested |
| A3 `note_claim` (on-chain note settlement, conflict/compensation R1-R9, undo, fuzz and mutations; 497 tests) | ✅ tested (`docs/protocol.md`) |
| A4 reconciliation (vault API, owner journal, journal × chain report, `reconcile`/`vault-refund` CLI; no early close, see `docs/protocol.md`) | ✅ tested (533 tests) |
| 1b Scheme identifier and v2 address, post-quantum slot keys (LMS), binary transaction format | ⏳ |
| Android wallet v0.1 (online: HD, send/receive; core tested on the JVM against Python; UI not compiled) | 🟡 `android-wallet/` |
| Offline Android (hardware diagnostics, NFC/BLE), PWA | ⏳ |
| 4 P2P network (handshake, mempool, propagation, sync, banning), HTTP API, node and CLI wallet | ✅ tested (3 nodes + real processes) |
| 4b PWA (phone/PC) | ⏳ after the API |
| 5 PoW with difficulty adjustment, heaviest-work, atomic reorganizations, coinbase maturity, fair genesis (`netgen`) | ✅ tested (`docs/decentralization.md`) |
| 6+ Native Android, cross-network tests, public documentation | ⏳ |

## Run a PoW network (nobody's permission needed)

```bash
python -m winflux.tools.netgen --name testnet --out genesis.json        # fair genesis: no premine, no authorities
python -m winflux.cli --wallet w.json create                            # wallet + recovery key
python -m winflux.node.main --genesis genesis.json --listen 0.0.0.0:8333 --mine <address>   # node + miner
python -m winflux.node.main --genesis genesis.json --datadir n2 --listen 0.0.0.0:8334 --api 127.0.0.1:8081 --seed IP:8333
python -m winflux.cli --node http://127.0.0.1:8081 --wallet w.json balance | send <address> <amount>
```
Read `docs/decentralization.md` (principles, what the code guarantees and what it does **not** guarantee, pending decisions).

## Usage

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

pytest                                   # full suite
PYTHONPATH=. python scripts/demo_local.py   # genesis -> transfer -> block -> confirmations
PYTHONPATH=. python scripts/demo_offline_vault.py   # offline vault, double spend, compensation and refund
PYTHONPATH=. python scripts/demo_chained_notes.py    # Alice -> Bob -> Carlos -> Dave offline (SIMULATED hardware)
PYTHONPATH=. python scripts/demo_note_claim.py       # on-chain settlement (note_claim), double spend and collateral
python -m winflux.tools.devnet init --dir devnet   # creates genesis.json + encrypted keys (5,000,000 WFLX in the genesis)
# the password comes from WINFLUX_DEVNET_PASSWORD or from a prompt (never from the command line)
```

`devnet init` creates `genesis.json`, `producer.key.json` (PoA authority) and `faucet.key.json`
(receives the initial 5,000,000 WFLX). The `chain_id` is derived from the genesis. The default password (`devnet-only-password`) is
only used when there is neither a variable nor an interactive terminal; it is for local tests only.

Recommended wallet: `winflux.wallet.hd.HDWallet` (change goes to a new address, recovery key `wflxk1-…`).

## Structure

```text
winflux/
├── crypto/      hashing.py address.py keys.py        SHA-256, addresses, Ed25519, keystore
├── blockchain/  transaction.py block.py params.py genesis.py utxo.py vaults.py ledger.py validation.py chain.py
├── offline/     voucher.py proofs.py note.py verifier.py attestation.py hardware_sim.py
│                                                      voucher, vault proofs, chained notes, verifier, SIMULATED hardware
├── blockchain/  exposure.py state_root.py             exposure limits (R1-R9), Merkle root of vaults
├── consensus/   interface.py poa.py pow.py            PoA (devnet) and PoW (public network)
├── node/        storage.py mempool.py node.py main.py full node (chain+mempool+P2P+miner)
├── wallet/      wallet.py hd.py transaction_builder.py vault_builder.py
├── network/p2p.py  api/server.py  cli.py              P2P, HTTP API, command-line wallet
├── tools/       devnet.py netgen.py localnet.py       local PoA devnet; fair PoW genesis; multi-process local testnet
├── logs.py      network/limits.py                     logging with secret redaction; token bucket (P2P/API)
web-wallet/ (PWA)   android-wallet/ (native, future)   tests/   docs/   scripts/
```

Change relative to the brief: the transaction validation rules live in
`blockchain/validation.py` (not in `node/validator.py`) to avoid a circular dependency
between chain and node and so that the Android app/tools can reuse the same rules code.

Documentation: `docs/offline-chained-payments.md` (**approved architecture of chained offline payments**),
`docs/security-assumptions.md` (security assumptions), `docs/running-a-node.md` (operating a node), `docs/testnet.md` (testnet, local testnet and smoke test), `docs/protocol.md` (rules of Stages 1–3), `docs/offline-payments.md` (vaults and vouchers:
specification and threat model — **central requirement**) and `docs/architecture.md` (risks and decisions).
