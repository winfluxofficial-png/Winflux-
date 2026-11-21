# Test plan — Winflux 0.1.0rc1 (testnet)

Goal: give whoever is going to test a clear script of what is already automated, what needs human eyes and what
**cannot be tested yet**. Use a clean machine; nothing here should be done with real money.

## 0. Automatic gates (must pass before any manual test)
```bash
pip install -r requirements.txt
python -m pytest -q                                   # full suite (≈20 s)
WINFLUX_SMOKE=1 python -m pytest tests/test_localnet_smoke.py -q     # 5 real processes (≈1 min)
PYTHONPATH=. python scripts/smoke_test.py             # the same, with step-by-step output
```
Criterion: 0 failures; `5/5 steps OK`. If it fails, keep the output and the logs (`--keep` preserves `logs/`).

## 1. Local network (1 machine)
`PYTHONPATH=. python scripts/run_local_testnet.py --dir local-testnet --block-time 4`

| # | What to do | Expected |
|---|---|---|
| 1.1 | `curl :18080/api/status` on each node | same `chain_id`, `peers ≥ 1`, `height` growing, `version` = 0.1.0rc1 |
| 1.2 | Kill a node (`kill`) and bring it back with the same `--datadir` | returns at the previous height and recovers the missed blocks |
| 1.3 | Stop the miner for 1 min and restart it | the network keeps going; the miner resumes without an unexpected reorg |
| 1.4 | Send a tx via the CLI to a non-mining node | shows up in the others' mempool and is mined; balance matches on all |
| 1.5 | Send the same tx twice / spend the same coin in two txs | the second is refused (400) |
| 1.6 | Restart everything with `--keep` | chain resumed, balances equal |

## 2. Several machines (real network)
Same genesis on all (check the `chain_id`), `--seed` pointing to 2+ nodes from different operators, P2P port open.
Check convergence of the tip (`tip`) and of `supply`; take down a seed and confirm the others stay connected;
start a new node from scratch and confirm it syncs the whole chain. **Not tested yet:** high latency, NAT, IPv6.

## 3. Abuse resistance (carefully, only on your own network)
| # | Simulated attack | Expected |
|---|---|---|
| 3.1 | 1000 `GET /api/status` in a burst from the same IP | `429` with `Retry-After` after the burst; node keeps working |
| 3.2 | `POST /api/tx` with a 5 MB body, fake Content-Length, invalid JSON | `413`/`400`, never `500`; no noticeable memory cost |
| 3.3 | Open 100 idle connections on the API | `503` above the per-IP limit; idle ones drop within ≤ 20 s (`408`) |
| 3.4 | Raw P2P client sending garbage / a 1 MB message before the handshake | disconnected and banned (`banned <ip>` in the log) |
| 3.5 | Flood of `ping`/`inv` | dropped without bringing the node down |
| 3.6 | Read the logs after 3.1–3.5 | no message body, no key/password |
For 3.x: example scripts are in `tests/test_hardening.py` (the same scenarios, automated).

## 4. Wallet
Create, write down the recovery key, delete the keystore, **restore** with `recover`, check that balance and addresses
come back; send with change; send more than the balance (clear error); send to an invalid address (clear error). In the
Android app: build in Android Studio (the UI **has not been compiled yet**), create/restore/send against a local node.

## 5. Offline payments
| # | Scenario | How | Expected |
|---|---|---|---|
| 5.1 | Happy path | `scripts/smoke_test.py` (step 5) or `scripts/demo_note_claim.py` | vault opened, Bob→Carol note settled, Carol's balance = value − fee |
| 5.2 | Double spend | `scripts/demo_note_claim.py` | 2nd branch paid by the collateral; vault marked `fraud` |
| 5.3 | Reconciliation | `winflux.cli … reconcile <vault_id> --journal vault-journal.json` | states per slot and coherent warnings |
| 5.4 | Resubmit the same chain | send the `note_claim` again | refused (`already settled`) |
| 5.5 | **Refund after the deadline** | `vault-refund` | **only automated in unit tests.** Live it requires waiting `vault_ttl_min` (≥ 1 day) + `claim_window` (7 days) in real time, whatever the block time (the deadlines are `DAY // block_time`). To test it live a genesis with short deadlines is needed (a design decision, outside this version). |

## 6. What is NOT covered in this version
Real hardware attestation, NFC/BLE, PWA, per-address history, native TLS, eclipse/Sybil protection, long-running
tests (days), load with thousands of txs/s, external audit, compiled Android UI. See
`docs/security-assumptions.md` and `docs/testnet.md`.

## 7. How to report
Version (`/api/status` → `version`), `chain_id`, `--log-level debug` of the relevant excerpt, steps to reproduce.
Vulnerabilities: privately (see `docs/testnet.md`).
