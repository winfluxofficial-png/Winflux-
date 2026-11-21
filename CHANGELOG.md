# Changelog

## 0.1.0rc1 — testnet release candidate
First version for real testnet testing. **It is not a version for real money** (no external audit, simulated
attestation hardware).

### Protocol / consensus
- **A3 `note_claim`:** on-chain settlement of chained offline notes in slots with their own key; conflict (double
  spend) compensated by the collateral under R1–R9; `MAX_SETTLED_PER_SLOT = 64`; slot state (`spends`/`settled`)
  committed in the state root via `claimed_by` (`state_root` format unchanged). See `docs/protocol.md`.
- Known limit: the R2 cap uses the slot's value, not that of each contested note.
- No monetary parameter changed.

### Wallets and tools
- **A4 reconciliation:** `GET /api/vault/<id>`, `GET /api/vaults/<address>`, owner journal, `reconcile(...)`; CLI
  `vaults`, `reconcile`, `vault-refund`. No early close of a slot (unsafe; see `docs/protocol.md`).
- **Android wallet v0.1** (`android-wallet/`): online (HD, send/receive). Core tested on the JVM against Python; UI not compiled.
- `build_note_claim`, `Vault.from_dict`, `HDWallet` unchanged.

### Operation / hardening
- Rate limiting in P2P (messages/s, bytes/s, per type, size per type, per-IP limit, reconnect backoff) and in the API
  (per-IP rate before reading the body, own limit for `POST /api/tx`, connection caps, anti-slowloris, strict validation).
- Logging with levels, rotation and secret redaction (`winflux/logs.py`); mining and network loops resilient to errors;
  clear startup errors; flags `--log-level`, `--log-file`, `--max-inbound-per-ip`, `--api-rate`,
  `--api-tx-rate`, `--api-trust-proxy`; `version` in `/api/status`.
- `scripts/run_local_testnet.py` (3 nodes + 1 miner), `scripts/smoke_test.py` (node, mining, tx, sync,
  late node, vault + `note_claim` + reconciliation).
- Docs: `running-a-node.md`, `testnet.md`, `test-plan.md`, `security-assumptions.md`.
- The whole project (code comments, messages, logs, docs and app) is now in English.

### Tests
- `pytest` suite: see `docs/test-plan.md` (exact count and how to run). Smoke test on real processes: `WINFLUX_SMOKE=1`.

## Before
Stages 1–3 and A1–A2 (blockchain, P2P, API, CLI, HD wallet, vaults, vouchers, offline notes, vault proofs,
state_root, R1–R9): see `README.md` and `docs/protocol.md`.
