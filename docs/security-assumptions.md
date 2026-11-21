# Security assumptions (Winflux)

> Test software. Nothing here is a promise of absolute security. Offline payment **never** prevents a double spend by
> itself: it limits the damage and compensates it deterministically.

## What consensus GUARANTEES (verified by every node, tested)
- Supply ≤ cap; no coin creation outside the coinbase; integer values.
- Each note/slot pays at most once with deposit value; a double spend of a note is detected at settlement (`note_claim`)
  and the losing branch is only compensated by the collateral, under limits R1–R9 (never above the collateral or the slot's value).
- Deterministic and reversible state (reorganizations), committed in each block's `state_root`.

## What is NOT guaranteed
- **Offline double spend** is not prevented: whoever holds the slot key can spend it in two places. The receiver only sees the
  problem at settlement. The protection is: collateral (ρ ≥ 1), value and depth caps, hardware level, deadline.
- **Hardware**: attestation (Secure Element/TEE/StrongBox) and the single-use key are SIMULATED (`hardware_sim.py`).
  Every hardware-based protection depends on: an intact manufacturer root of trust, flawless firmware,
  and the impossibility of cloning/restoring the key's state. None of this has been verified on real devices.
- **Software without hardware**: depth 1 and a low cap (receiver policy, not consensus).
- **Quantum**: a note's key is only revealed when spending (hash commitment), reducing exposure; Ed25519/P-256
  can still be broken by a quantum computer. Post-quantum slot keys (LMS) are on the roadmap (phase 1b).
- **Availability**: if the owner does not settle within `claim_window`, the value goes back to the vault owner (`vault_refund`).
  Receivers must submit the `note_claim` before the deadline; that is why the verifier requires a minimum margin.
- **Dust**: leaves below `max(min_voucher_value, min_fee+1)` cannot be settled.
- **State limits**: ≤ 16 compensations (R9) and ≤ 64 settled leaves per slot.
- **No external audit.** Parameters (collateral, windows, caps) are testnet values and need to be calibrated.
