# Chained offline payments in Winflux — approved architecture

Status: decisions **approved**; **A1, the collateral exposure rules and A2 (notes, offline verifier, hardware simulator)
implemented and tested**; the rest (A3, A4, B, C) is plan. Complements `offline-payments.md` (vaults and vouchers) and replaces its "no
transitivity" decision: money received offline can now be passed on offline, under the limits below.
Security assumptions: `security-assumptions.md`.

## 1. Approved decisions
1. **Transferable notes** (Alice → Bob → Carlos offline), with a verifiable provenance chain.
2. **Maximum offline pass-on depth: 1 without secure hardware; 3 with secure hardware** that is attested and single-use.
   A note's effective level is that of its **worst hop**.
3. **The root slot's collateral answers for fraud at any hop**, **with deterministic exposure limits**
   (§3): multiple frauds or claims on the same chain never produce a compensation above the guaranteed value.
4. No promise of absolute prevention of offline double spend: without a network there is no guaranteed consistency (CAP theorem).
   We guarantee **prevention under hardware assumptions**, **bounded loss** and **deterministic compensation** when those fail.

## 2. Model
- **Vault/root slot** (already implemented): value + collateral locked on the chain; the slot is the root note, of value `cap`.
- **Note**: value bound to a single-use key. Spending it signs an **offline transaction** with outputs
  (value, new owner key or final address). Conservation: Σ outputs ≤ note value; no offline fee.
- **Provenance**: each payment carries the chain `[root slot → t1 → t2 …]` + the vault proof + attestations.
- **The receiver verifies locally**: vault proof (checkpoint, A1), signatures of each hop, conservation,
  depth and level cap, attestation, deadline margin, slot/note never seen before, block list.
- **States**: `RECEIVED_OFFLINE` → `SETTLING` → `CONFIRMED(n)` → `FINAL`; failures `CONFLICT_REJECTED`, `COMPENSATED`,
  `LOSS`, `EXPIRED`. An offline note is never shown as confirmed.

### Levels and limits (testnet, to be calibrated)
| Level proven at every hop | Depth | Cap per note |
|---|---|---|
| Software (cloneable key) | 1 | small |
| Attested hardware, single use | 3 | medium |
| Secure element with balance (future) | 5 | high |

## 3. Collateral exposure (implemented in `blockchain/exposure.py`)
For a slot with cap `C` and initial collateral `K = ceil(C·ρ)`, a **contested** note `x` (two distinct transactions
spend the same note) has value `v(x)`. When a claim loses the race, the compensation is a **pure function of the on-chain
state**:

| Rule | Statement |
|---|---|
| R1 | Σ of the slot's compensations ≤ remaining collateral (≤ K) |
| R2 | Σ of compensations per contested note ≤ `v(x)` (the value actually at stake) |
| R3 | The same claim is compensated at most once (resubmission refused) |
| R4 | Each compensation ≤ value of the claimed leaf |
| R5 | Payment order = order of application on the chain (block, position); once the cap is exhausted, the rest get 0 |
| R8 | A compensation below the minimum (`max(min_voucher, min_fee+1)`) is refused (dust) |
| R9 | At most `max_compensations_per_slot` (default 16) compensations per slot (bounds state and cost) |

**Guarantees (tested invariants):** total outflow of a slot ≤ `C + min(K, C)`; total outflow of the vault ≤ value locked
at opening; each claim is paid once; `locked ≥ 0`; supply conserved (UTXO + locked = supply). The collateral that
is left after fraud is **burned** in the refund (see `offline-payments.md`, R6).

**Alice's maximum exposure per slot: `min(K, C)`**, even if a malicious intermediary (with accomplices) generates
many conflicting branches. Alice controls this risk by choosing `C`, `ρ` and the pass-on policy. With ρ > 100 %, the
surplus does not enlarge compensations (R2), it only adds deterrence through the burn.

Example (`C = 10`, `ρ = 300 %`, `K = 30`): voucher A of 10 occupies the slot; B of 7 is compensated (7); C of 7 receives only 3
(R2: 3 of the value 10 remain); D of 5 is refused (R2); the remaining collateral, 20, is burned in the refund.

**Current × planned state:** rules R1-R4, R8, R9 already apply to the voucher (root note with one final output;
contested note = the root, `v = C`). For chained notes (A3) the **same function** will be used with a map
`contested note → total compensated` in the registry.

### Bug found and fixed in this stage
The previous rule allowed **resubmitting an already-compensated voucher**: with the same value, the identical transaction brought down
block production (`ValueError` outside `ValidationError`); with a different value (partial collateral), it paid again
(Carol received 9.99998 for a voucher of 8). Fixed by R3 + a duplicate-outpoint guard; regression and
mutation tests cover both cases.

## 4. Flows
**Alice → Bob → Carlos** (slot of 30, collateral 30):
```
online  : Alice opens a vault (slot 30 + collateral 30); registers the key root
offline : Bob  -> Alice : request {Bob's new key, request_id}
          Alice -> Bob  : t1 {root note -> 30 to Bob's key} + vault proof + attestation   [Bob verifies]
          Carlos -> Bob : request {Carlos's new key}
          Bob -> Carlos : [t1, t2 {30 -> 10 to Carlos, 20 to Bob's change}] + proof + attestations [Carlos verifies]
online  : anyone settles (note_claim): the chain applies each offline transaction ONCE, by id
          (idempotent: the sync order does not matter)
fraud   : Bob signs t2' (30 -> Eve) with the same note: whoever applies first wins; the other is compensated
          under R1-R9 and the vault is marked as fraudulent
```

## 5. Protocol changes
| Item | Status |
|---|---|
| `state_root` (Merkle of the vault registry) in the block header | **Done (A1)** |
| Checkpoints (signed header) and vault proofs (~1.2-1.9 KB JSON, 0.2 ms to verify) | **Done (A1)** |
| Exposure limits R1-R9 | **Done** (voucher); notes in A3 |
| Own key per slot (`slot_keys`), binary format of the offline transaction, offline verifier | **Done (A2)** |
| `note_claim` + registry of applied notes/transactions, with undo | A3 |
| Maximum consensus depth, fee per byte on chain claims | A3 |
| Hybrid LM-OTS, list of fraudulent devices in the checkpoints | C |

## 6. Plan
| Phase | Deliverable | Hardware |
|---|---|---|
| A1 | Checkpoints and vault proofs | no — **completed** |
| A2 | Note format, recipient's offline verifier, hardware simulator (single use + test attestation) | no — **completed** |
| A3 | `note_claim`, registry, conflicts and adversarial tests (conflicting, cloning, backup, tampering, reuse, ordering) | no |
| A4 | Wallet reconciliation (deadlines, conflicts, repetition) | no |
| B1 | Diagnostic app on Android (StrongBox, attestation, single use, key erasure, backup) | **phone** |
| B2 | QR transports (PWA), NFC and BLE (native) | phone |
| C | API/P2P for settlement, PWA/Android integration, hybrid LM-OTS | phone |


## 7. A2 — what was implemented
**Consensus (additive):** `vault_open` accepts `slot_keys` (one public key per slot). The key goes in the record, in the `state_root` and in the
vault proof. A slot with its own key **cannot** be settled by `voucher_claim` (only by `note_claim`, A3): this way the single-use key
is the only authority over the slot. While `note_claim` does not exist, a vault with `slot_keys` can only be refunded
(`vault_refund`) after the deadline.

**Format (`offline/note.py`):** root note = slot (`H(vault_id, slot)`); binary offline transaction (106 + 41·n + 16 bytes, n ≤ 4
outputs): `version, network hash, vault_id, spent note, value, outputs[value, type NOTE|ADDRESS, owner], request_id`. Owner of a
NOTE = hash commitment `H(type, key)`: the key is only revealed when spending. Exact conservation (Σ outputs = note value).
The `txid` does not cover the signature/key (harmless malleability).

**Verifier (`offline/verifier.py`)** — what it proves, in order: (1) vault proof against a signed checkpoint, with monotonic
memory on the receiver's side; free slot, open vault with no fraud, with its own key and enough deadline; (2) each hop: right network and vault,
expected spent note and value, conservation, the key that signed is the owner (1st hop: the slot's key; following: the
output's commitment), valid signature (P-256 with low S), contiguous chaining; (3) the leaf belongs to the recipient (key or
address) and the `request_id` matches; (4) **effective level = worst hop** and policy: depth 1 (software) / 3 (hardware),
caps per level; (5) local memory of notes already seen (double spend seen by this receiver).
Result: `RECEIVED_OFFLINE` (pending). `accept()` writes to local memory before confirming to the payer.

**A hop's hardware level:** only with a valid attestation **of that key**, single use and TEE/StrongBox; for hops ≥ 2 the attestation
challenge must be the `request_id` of the transaction that created the note. Any problem (expired, revoked, another root, another key,
wrong challenge, no attestation, software, no single use) **downgrades to software**, which has the most restrictive limits.

**Simulator (`offline/hardware_sim.py`) and attestation (`offline/attestation.py`):** simulated JSON format with the semantics of Android
key attestation; the real verifier goes in behind the same interface in Phase B. The simulator models: a non-exportable key, non-
clonable, erased after single use (restoring a backup does not resurrect it) and the `break_single_use()` adversary.

**Demo:** `scripts/demo_chained_notes.py`.
