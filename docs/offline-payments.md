# Offline payments in Winflux — specification and threat model (Stage 3b-0)

Status: **Revision 2. Consensus layer (3b-1) IMPLEMENTED and tested**: types `vault_open`, `voucher_claim`,
`vault_refund`, vault registry with undo, binary voucher (175 B), Ed25519 and P-256 (low S), coinbase with the previous
block hash. **NOT yet implemented:** receiver's offline verifier, request/receipt, checkpoints and vault proofs
(3b-2/3b-3), QR/BLE/NFC transport, post-quantum vault keys (§15, decision 6) and Android hardware.

> **Update (approval of transferable notes):** this document's "no transitivity" decision was replaced by
> `offline-chained-payments.md`. Vaults/vouchers remain the base; the voucher is the particular case of a root note with a final output.
> The compensation rule was hardened (R1-R9, `blockchain/exposure.py`) after a resubmission bug was discovered.

### Revision 2 — what changed and why
The adversarial review of Revision 1 found three flaws, fixed below:
1. **`vault_close` removed.** An owner could close the vault right after opening it and keep paying
   offline; receivers with an old proof did not know the real deadline (`close + window`) was already short.
   Now only expiry exists: the claim deadline is always `expires_height + claim_window` and the minimum TTL is short.
2. **`voucher_hash` now covers only the voucher body**, not the signature. With ECDSA P-256 (malleable), a
   third party could resubmit the same voucher with another valid signature; the chain would treat it as a
   "distinct voucher" and pay from the collateral. In addition, P-256 signatures must have a **low S** (mandatory).
3. **The device key `D` is public on the chain** (the receiver needs it), so it is a target for a relevant quantum
   computer, which would forge vouchers against every open vault. Decision pending approval (§15):
   single-use keys based only on SHA-256 (LMS/LM-OTS), one per slot, with the chain storing only the Merkle root.
Also: the coinbase must commit to the previous block hash (§12) so there are no equal coinbase txids across networks.
 The numbers marked
"(to be calibrated)" are initial testnet values, not final decisions.

> No digital signature, by itself, prevents whoever controls a key from signing two
> conflicting transfers while disconnected. This document does not promise absolute
> security: it separates what the protocol **guarantees**, what **depends on hardware** and what
> **remains as risk**.

## 1. Goal and non-goals

Goal: two people, both without internet, transfer WFLX by QR Code, BLE or NFC, with
signing on the originating device, storage and receipt on the destination, later settlement
on the blockchain, protection against reuse and explicit states.

Non-goals (design decisions):
- **No "level 0" as payment.** An ordinary signed transaction is never accepted as an offline *payment*: without a prior
  reservation on the chain the receiver cannot assess the double-spend risk. At most it can be
  kept as a **pending receipt without guarantee** (`PENDING_NO_GUARANTEE`): it does not become balance, does not release
  goods or services, and the interface never shows it as "paid".
- **No transitivity.** Value received offline only becomes spendable after the claim is confirmed.
  Vouchers are not forwardable.
- **No central authority** (no mint, no server that registers tokens).
- Strong privacy (blind e-cash) is out of scope for this phase.

## 2. Terminology

| Term | Meaning |
|---|---|
| Vault | Consensus state that locks value + collateral for offline payments |
| Slot | Unit of the vault; pays at most once; has a value cap |
| Device key `D` | Key that signs vouchers; may be in hardware. Ed25519 or P-256 |
| Owner key | Key of the ordinary wallet; controls opening, closing and refund |
| Voucher | Promise signed by `D`: "slot `i` of vault `V` pays `a` to address `R`" |
| Claim | On-chain transaction that redeems a voucher |
| Collateral | Additional value locked per slot, used to compensate victims of duplicity |
| Checkpoint | Commitment signed by the authorities with the root of the vault registry |

## 3. Guarantees, dependencies and risks

**G — guaranteed by the protocol (without special hardware):**
- G1. A vault's value cannot be spent online in parallel (it is locked in the registry).
- G2. Each slot pays the full value at most once (`vault_id, slot` unique).
- G3. A voucher is only valid for the receiver, the request and the network it was issued for.
- G4. The receiver can verify the voucher's authenticity and the vault's existence without internet.
- G5. Settlement is deterministic: all nodes reach the same result.
- G6. Whoever was harmed by duplicity is compensated by the slot's collateral, up to its limit.
- G7. The owner is never harmed by the receiver; if they lose the device, they recover the balance after the window.

**H — depends on secure hardware:**
- H1. Preventing the key `D` from being copied to another device (non-exportable key + attestation).
- H2. Preventing reuse of a slot after restoring a backup (single-use key per voucher, or a counter in a
  secure element).

**R — risk that remains:**
- R1. Without hardware, the attacker can sell the same slot to `m` receivers. With cap `c` and collateral
  `ρ·c`, they obtain goods worth `m·c` and lose at most `(1+ρ)·c`; it pays off when `m > 1+ρ`. The
  victims lose up to `(m−1−ρ)·c`. **The collateral deters, it does not prevent.**
- R2. The receiver loses the right if they do not settle within the window.
- R3. Hardware compromise (broken TEE/SE, attestation revoked without the receiver knowing).
- R4. Linking of identities (vault, addresses, receipts) reduces privacy.
- R5. Trust in the authorities for checkpoints (PoA) until PoW defines another solution.
- R6. In case of fraud, **all** of the vault's remaining collateral is burned (including that of honest slots). It deters, but
  also punishes the owner whose key was cloned by a thief. Alternative to evaluate: burn only the defrauded slot's.

## 4. Payer security levels

| Level | Key `D` | Prevents cloning | Prevents rollback | Use |
|---|---|---|---|---|
| L1 | Software (PWA, Android without suitable hardware) | No | No | Low values; collateral deters |
| L2 | Attested hardware, **one key per voucher** with single use | Yes, if non-exportable | Yes, if the hardware enforces the limit | Medium values |
| L3 | Secure element with internal balance/counter | Yes | Yes | High values (future) |

Observations verified in public documentation (see §14): Android 12 (API 31) allows limiting
the uses of a key and erases the key when the counter is exhausted; there are flags to know whether the hardware
enforces this. Attestation has a longer chain of variable size, short-lived certificates and
an ECDSA P-384 root (besides the old RSA one). Ed25519 in hardware **has not been verified**: that is why `D` may
be P-256.

### Receiver policy (limits per voucher — testnet values, to be calibrated)

| Proven level | Cap per voucher | Requires |
|---|---|---|
| L1 | 5 WFLX | Active vault, collateral ≥ 100 % |
| L2 | 100 WFLX | + valid attestation, TEE/StrongBox security level, attested single use |
| L3 | 1,000 WFLX | + secure element attestation |

The receiver may adopt stricter limits. No level is accepted without a vault proof.

## 5. Network parameters (new, in `ChainParams`)

| Parameter | Initial value | Note |
|---|---|---|
| `target_block_time` | 5 s (devnet) / 60 s (public target) | Converts time ↔ height |
| `vault_max_slots` | 64 | Bounds the state per vault |
| `vault_collateral_min_pct` | 100 (ρ=1) | Minimum collateral per slot |
| `vault_ttl_min_blocks` | 1 day | Minimum life (short, so the owner recovers the balance early) |
| `vault_ttl_max_blocks` | 30 days | Maximum life before expiry |
| `claim_window_blocks` | 7 days | Contestation window after closing/expiry |
| `min_voucher` | 10 × `min_fee` | Below this the claim does not pay for the fee |
| `vault_max_value` | 10,000 WFLX | Exposure cap per vault |
| `checkpoint_interval` | 100 blocks | Checkpoint frequency |
| `receiver_min_margin` | 48 h | Minimum margin to the end of the window for the receiver to accept |

## 6. Consensus state: vault registry

Registry derived from the chain (rebuilt and revalidated on load, with undo per block), next to the
UTXO set.

```text
Vault {
  vault_id        = txid of the vault_open transaction
  owner_address, refund_address
  device_key, key_type ("ed25519" | "p256")
  opened_height, expires_height, state ∈ {OPEN, CLOSED}
  fraud: bool
  slots[i] = { cap, collateral_left, claimed_by: voucher_hash | null }
}
```

**Supply accounting:** `supply = Σ UTXO + Σ (free caps + remaining collateral of the vaults)`.
Burned collateral reduces the supply. The `max_supply` cap applies to that sum.

### 6.1 Transaction types (new `kind` + `payload` field, strict validation)

**`vault_open`** — ordinary inputs fund the vault.
- payload: `device_key, key_type, slots:[cap…], collateral_pct, ttl_blocks, refund_address, pop`
- `pop` = signature of `D` over the body hash (proof of possession; prevents registering someone else's key).
- Rules: `1 ≤ N ≤ vault_max_slots`; `cap_i ≥ min_voucher`; `collateral_pct ≥ minimum`;
  `vault_ttl_min ≤ ttl ≤ vault_ttl_max`; `Σ(cap_i + collateral_i) ≤ vault_max_value`; outputs = change only;
  inputs = `Σ(cap_i + col_i) + outputs + fee`; `expires_height = h + ttl`.

**`voucher_claim`** — no inputs; anyone can submit.
- payload: `voucher` (175 bytes, §7) .
- Rules: the vault exists and `height ≤ claim_limit` (§6.2); `slot < N`; `min_voucher ≤ amount ≤ cap`;
  valid signature of `D`; single output `(amount − min_fee) → receiver` and a fee of exactly `min_fee`.
- Effect, free slot: pays from `cap`; sets `claimed_by = H(voucher)`; the rest of `cap` comes back in the refund.
- Effect, slot already used by another voucher: if `collateral_left > 0`, pays
  `min(amount, collateral_left) − min_fee` from the collateral and sets `fraud = true` (if that value is ≤ 0, the claim is rejected). If it is the **same**
  voucher: rejected (reuse).

**`vault_close` — REMOVED in Revision 2** (see above). The vault ends only by expiry at `expires_height`;
whoever wants to recover the balance early opens vaults with a short TTL.

**`vault_refund`** — no signature; anyone can submit after the end of the window.
- Effect: returns to `refund_address` the free caps and the difference `cap − amount` of the paid slots;
  returns the remaining collateral if `fraud = false`; **burns** the remaining collateral if `fraud = true`.
  The fee is deducted from the total returned.

### 6.2 Claim limit
`limit = expires_height + claim_window`, always. Since `expires_height` is fixed at opening and appears in the
vault proof, the receiver knows the real deadline. Nothing the owner does afterwards shortens that deadline, so they
cannot pay offline and withdraw the balance before the receiver syncs.

### 6.3 Order and dispute
Within a block the transaction order applies; across blocks, the chain order. At the first
settlement of the slot the value is paid; the following ones pay from the collateral.

## 7. Message formats (fixed binary, no ambiguity)

Choice: fixed binary layout for the signed voucher (≈175 bytes, fits in a single QR); no CBOR dependency.

```text
voucher_body (111 bytes) =
  version(1) ‖ chain_id_hash(32) ‖ vault_id(32) ‖ slot(u16 BE) ‖ amount(u64 BE)
  ‖ receiver_hash160(20) ‖ request_id(16)
voucher = voucher_body ‖ signature(64)
signature of D over: "WFLX-VOUCHER-V1" ‖ voucher_body
voucher_hash = SHA-256("WFLX-VOUCHER-ID-V1" ‖ voucher_body)      # WITHOUT the signature (anti-malleability)
```
(P-256: raw `r ‖ s` signature of 64 bytes, with **S ≤ n/2 mandatory**; Android clients must
normalize the Keystore's DER signature to a low S before sending.)

**Request** (receiver → payer): `version, chain_id_hash, receiver_address, amount?, request_id (16 random B),
eph_pub (X25519), request_expiry`.

**Voucher + proofs** (payer → receiver, encrypted): `voucher`, `vault_proof`, `attestation?`.

**Receipt** (receiver → payer): `voucher_hash, request_id, receiver_pubkey, signature` over
`"WFLX-RECEIPT-V1" ‖ voucher_hash ‖ request_id`.

**Vault proof** (hundreds of bytes to ~1 KB): vault record + Merkle path to the
`vault_root` of a **checkpoint** + checkpoint certificate (height, block hash, `vault_root`, signatures of the
authorities). The vault is only usable after it enters a checkpoint (activation delay ≤ `checkpoint_interval`).

**Attestation**: X.509 chain (2–5 KB), sent once and kept by the receiver (cache by hash of `D`).

**Channel**: ephemeral X25519 + ChaCha20-Poly1305 at the application layer, independent of the transport;
the `request_id` and the receiver's address enter the session key context.

**Transports**
- QR: animated frames when needed (a plain voucher fits in one QR).
- BLE: GATT/L2CAP service with fragmentation; pairing is not a prerequisite.
- NFC: native Android (reader + card emulation, HCE). Not available in the PWA.

## 8. Verification by the receiver (checklist; any failure rejects)

1. `chain_id_hash`, version and lengths correct.
2. `receiver_hash160` and `request_id` equal to the request's; value equal to the agreed one.
3. Valid signature of `D`.
4. Valid vault proof against a signed checkpoint, **not older than the latest checkpoint the receiver already knows**; vault `OPEN`, without `fraud`, outside the local block list.
5. `slot < N`, `min_voucher ≤ amount ≤ cap`.
6. Slot **not seen before** in the receiver's local database (any sender).
7. Margin: `claim_limit − estimated_height ≥ receiver_min_margin`. The height is estimated with the
   receiver's **own** clock and the latest checkpoint. No time declared by the payer is used.
8. Proven level and cap per voucher (§4). For L2/L3: attestation with pinned roots, cached revocation list, hardware security level, single-use key.
9. (Optional) exchange of hashes of seen slots with nearby receivers.

## 9. States

**Payer:**
`DRAFT → SIGNED_OFFLINE → DELIVERED → SETTLING → CONFIRMED(n) → FINAL`
Failures: `EXPIRED`, `CONFLICT_REJECTED`, `COLLATERAL_LOST`.
Golden rule: the slot is recorded as used **before** the voucher leaves the device (write-ahead).
If the device crashes midway, the slot is lost; it is never reused.

**Receiver:**
`REQUEST → RECEIVED_UNVERIFIED → ACCEPTED_OFFLINE(level, cap) → CLAIM_SENT → CONFIRMED(n) → FINAL`
Failures: `REJECTED(reason)`, `CLAIM_REJECTED → COMPENSATED | LOSS`, `DEADLINE_MISSED`.

`ACCEPTED_OFFLINE` shows up as **pending**, never as spendable balance. The interface shows the deadline.
If a claim is undone by a reorganization, the state goes back to `ACCEPTED_OFFLINE` with the same deadline.

## 10. Settlement and reconciliation
1. The receiver, on coming online, submits `voucher_claim` (via API → mempool → block).
2. The payer, on coming online, compares the issued vouchers (local write-ahead log) with the vault state.
   A slot paid to another voucher, or a claim that does not match the log, indicates **cloning or rollback** → alert and stop using the vault.
3. The vault expires at `expires_height`; after `expires_height + claim_window`, `vault_refund`.
4. The receiver's app warns of the deadline countdown and submits the claim as soon as there is a network.

## 11. Threat model

| # | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | Presenting the same voucher to another receiver | Binding to `receiver`/`request_id` | — |
| T2 | Two distinct vouchers for the same slot to distinct receivers | Compensation by collateral; L2/L3 prevent it | R1 in L1 |
| T3 | Cloning the wallet onto a 2nd phone | Non-exportable key `D` + attestation (L2/L3) | L1 accepts |
| T4 | Restoring a backup and reusing the slot | Single-use key per voucher / SE | Depends on hardware (H2) |
| T5 | Withdrawing the balance before the claim | No early close; refund only after `expires_height + claim_window` | Balance locked until then |
| T6 | Spending the same balance online | Balance locked in the registry | — |
| T7 | Resending the claim | Slot marked with the voucher hash | — |
| T8 | Changing the voucher's value/destination | Signature over all the fields | — |
| T9 | MITM/relay over BLE/NFC | Encrypted channel, value and address confirmation on both screens; payment goes to the receiver's address | A relay only makes them pay whoever they chose |
| T10 | Fake, expired or revoked attestation | Pinned roots; cached revocation; policy per level | Stale revocation |
| T11 | Manipulating the payer's clock | No payer time is trusted | — |
| T12 | Spam of vaults/claims | Minimum fee, `min_voucher`, `vault_max_value`, per-block limit | To be calibrated |
| T13 | Receiver misses the window | Alerts; long window | R2 |
| T14 | Producer reorders claims | PoA: trusted authority | PoW: miner's order |
| T15 | Sender colluding with themselves | Compensation comes out of their collateral | Neutral |
| T16 | Forged checkpoint | Signatures of the authorities | R5 |
| T17 | Identity tracking | New addresses per request | R4 |
| T18 | Loss of the device | Refund to the owner after the window | Funds locked for up to TTL+window |
| T19 | Voucher resubmitted with a changed signature (malleable P-256) | Hash of the body only; low S mandatory | — |
| T20 | Quantum computer forges vouchers with the public key `D` | Single-use per-slot keys based on SHA-256 (§15, decision 6) | Pending until the decision; without it, `D` is a target |

## 12. Compatibility with the existing code (planned, **not executed**)

Preserved with no change in behavior: `crypto/*`, `units`, `blockchain/utxo.py` (UTXO),
`wallet/*`, `node/storage.py`, the 103 tests.

Changes planned in Stage 3b-1/3b-3:
- `Transaction`: fields `kind` (default `"transfer"`) and `payload` (default `None`).
- `Block`: `vault_root` in the header (default empty); checkpoints.
- `ChainParams`: the parameters of §5.
- `blockchain/vaults.py` (new): registry + undo; `validation.py`: rules for the new types.
- `crypto/keys.py`: P-256 (ECDSA) verification in addition to Ed25519.
- Genesis and txids change value (new fields); the tests do not depend on fixed values, but
  this will be checked at implementation.

## 13. Test plan (acceptance criteria of 3b-1)
Double spend of the same slot; same voucher resubmitted; voucher for another receiver; signature
tampered in each field; claim after the limit; claim inside and outside the window (`expires_height + claim_window`);
refund before the end of the window rejected; P-256 voucher with high S rejected and hash independent of the signature; fraud with partial and exhausted collateral; supply accounting
(burned collateral); vault cap; vault spam; reorganization undoing a claim and a refund;
atomicity of an invalid block; determinism between two nodes replaying the same chain.

## 14. Sources consulted (re-check when implementing)
- Android: `KeyGenParameterSpec.Builder.setMaxUsageCount` (API 31) and flags
  `FEATURE_KEYSTORE_SINGLE_USE_KEY` / `FEATURE_KEYSTORE_LIMITED_USE_KEY` —
  https://learn.microsoft.com/en-us/dotnet/api/android.security.keystore.keygenparameterspec.builder.setmaxusagecount
- Android Developers Blog, "Upgrading Android Attestation: Remote Provisioning" (2022) —
  https://android-developers.googleblog.com/2022/03/upgrading-android-attestation-remote.html
- Attestation root rotation (RSA → ECDSA P-384), third-party analysis —
  https://protectt.ai/blog/android-key-attestation-root-certificate-rotation
- Chrome, Web NFC (NDEF only, no peer-to-peer or HCE; secure context) —
  https://developer.chrome.com/docs/capabilities/nfc

## 15. Decisions that need your approval
1. Voucher in a **fixed binary layout** (175 bytes) instead of CBOR.
2. Initial values of §5 and the per-level caps of §4.
3. `D` may be **Ed25519 or P-256**.
4. **Authority-signed checkpoints** for offline proofs (valid on the PoA testnet; PoW will require a new solution).
5. No offline transitivity and no "level 0".
6. **Quantum-resistant vault keys:** each slot with a single-use key based on SHA-256
   (LMS/LM-OTS, RFC 8554 and NIST SP 800-208; confirm at implementation), with the chain storing only the Merkle root and
   the voucher carrying ~1.1-1.3 KB of signature. Optionally combined with a hardware P-256 signature.
7. **Coinbase committing to the previous block hash** (field in the Phase 1 payload), so that distinct networks never
   produce the same coinbase txid.
8. **Scope of the collateral burn** in case of fraud: the whole vault (implemented) or only the defrauded slot (see R6).
