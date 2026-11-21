# Phase 0 audit (Stages 1-3) — findings and status

Method: existing tests + adversarial probes (parsing and validation fuzz, properties under random
operations, signature malleability, scale) + code review. **This is not a formal audit.**
The probe tests are now permanent in `tests/test_robustness.py`.

| # | Finding | Status |
|---|---|---|
| 1 | Fixed fee per transaction (block space underpriced) | **Fixed**: `fee ≥ max(min_fee, min_fee_per_byte × bytes)` + tests and mutation |
| 2 | No bytes-per-block limit (theoretical 200 MB) | **Fixed**: `max_block_bytes` (default 1 MB), validation and block builder |
| 3 | Change went back to the source address | **Fixed in the new wallet** `HDWallet`: change always goes to a new address, skipping addresses already seen; the legacy `build_transfer` still uses the source address (documented, will be deprecated) |
| 4 | Repeated `chain_id` across different geneses allows replay (identical coinbases) | **Fixed**: the coinbase commits to the previous block hash (distinct txids across networks, test) and `devnet init` derives the `chain_id` from the genesis |
| 5 | Single-authority PoA (censorship, no finality) | Expected on testnet; handled at the consensus gate (Phase 6) |
| 6 | Timestamps without a median of previous blocks | Deferred to public consensus |
| 7 | No coinbase maturity / reorganization | Deferred (required before PoW) |
| 8 | Whole UTXO set in memory, loading revalidates everything | Acceptable on testnet (3,000 blocks in 0.8 s); snapshots later |
| 9 | JSON serialization (simple tx = 550 B) | Open: binary format with a scheme identifier (Phase 1, remaining part). The offline voucher is already binary (175 B) |
| 10 | Seed in memory without zeroing; no recovery phrase; password on the command line | **Partially fixed**: recovery key (`wflxk1-…`, with checksum and canonical form) and devnet password only via environment variable or prompt. Python cannot zero memory with a guarantee (known limitation) |

Bugs found *during* the fix (all covered by tests):
- The `HDWallet` change reused an address that had already received funds without being "handed out" by the wallet.
- The recovery key accepted a tampered last character (non-canonical base32).

No problems found: txid malleability, unexpected exceptions in parsing, supply invariant violations,
double-spend acceptance (tested with 20 thousand block mutations, 5 thousand transaction mutations and 400 random operations).


## Phase 1a / A1 review
| Finding | Status |
|---|---|
| An already-compensated voucher could be resubmitted: it brought down block production (`ValueError`) or paid again (9.99998 for an 8 voucher) | **Fixed** (R3, duplicate-outpoint guard), regression and mutation tests |
| The proof verifier broke with `TypeError` on unhashable `state`/`key_type` | **Fixed** (found by fuzz), only `ValidationError` now |
| Recomputing the `state_root` is O(vaults × slots) per block | **Open** (incremental cache before public use) |
| `ValueError` outside `ValidationError` in `Ledger.apply` can bring down the producer if `check` fails | **Mitigated** by the guard in `check`; keep the ledger fuzz |


## A2 review
| Finding | Status |
|---|---|
| **Unhashable `key_type` in `vault_open` raised `TypeError` inside CONSENSUS validation** (it would bring down the block producer) | **Fixed**, permanent payload fuzz for `vault_open`, `voucher_claim` and `vault_refund` |
| Same defect (`x in dict` with an unhashable value) in attestation verification | **Fixed** (found by fuzz); grep audit of every `in <dict>` without `isinstance` |
| Test gap: a valid attestation without hardware properties (software, no single use) was not exercised | **Fixed** (mutation V7 detected) |
| Compromised hardware is only an adversary if tampered with BEFORE the key's first use (once erased, it does not come back) | Modeled in the simulator and in the demo |
| P1: type validation of the `key` field in the proof | Equivalent mutant (the Merkle leaf already binds the value); kept as defense in depth |
