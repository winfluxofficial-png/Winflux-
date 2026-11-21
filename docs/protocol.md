# Winflux protocol — specification (Stages 1–3)

## Units and addresses
- 1 WFLX = 10^8 units. Every value is an integer; floats are forbidden in the protocol.
- Address = `wflx1` + lowercase base32 of `SHA-256(pubkey)[:20] ‖ checksum(4)`,
  `checksum = SHA-256("WFLX-ADDR-V1" ‖ hash160)[:4]`. Only the canonical form is valid.

## Serialization
Canonical JSON (sorted keys, no spaces, ASCII, no NaN). Strict parsing: extra fields,
wrong types and absurd sizes are rejected before any expensive verification.

## Transaction
`{version, chain_id, coinbase_height, inputs[{txid,index,pubkey,signature}], outputs[{value,address}]}`
- `txid = SHA-256("WFLX-TXID-V1" ‖ JSON(body without signatures))`.
- Signed message: `"WFLX-TX-SIGN-V1" ‖ txid` (commits to chain_id, inputs and outputs ⇒ no replay across networks).
- Fee = Σ inputs − Σ outputs (implicit), ≥ `min_fee`.

### Validation rules (plain transaction)
1. `version == 1`, `chain_id` equal to the network's, ≥1 input and ≥1 output, size/count limits.
2. Outputs: integer, `0 < value ≤ max_supply`, valid address, sum ≤ `max_supply`.
3. Each input exists in the UTXO set, with no duplicate inside the transaction (internal double spend).
4. `pubkey` hashes to the address that owns the spent output; valid Ed25519 signature.
5. Σ inputs ≥ Σ outputs (conservation) and fee ≥ `max(min_fee, min_fee_per_byte × tx_size)` (size = canonical JSON, with signatures).

## Block
Header `{height, prev_hash, timestamp, merkle_root, producer, nonce, meta}`;
`hash = SHA-256("WFLX-BLOCK-HEADER-V1" ‖ JSON(header))`. The producer's signature is not part of the hash.
- Genesis: height 0, `meta = hash of the network parameters`; one coinbase with the allocations.
- Rules: total size of the transactions ≤ `max_block_bytes`; height = previous+1; correct `prev_hash`; `timestamp` > previous and ≤ now+2h;
  correct Merkle root; unique txids; valid consensus; exactly one coinbase, at position 0;
  transactions applied in order (one may spend an output created earlier in the same block).
- Coinbase: `coinbase_height == height`, no inputs, value ≤ `min(reward(height), max_supply − current_supply) + fees`.
- An invalid block does not change the state (atomic application with undo).

## Monetary policy
`reward(h) = block_reward >> (h // halving_interval)`, limited by the remaining supply.
Configurable genesis (devnet default: 5,000,000 WFLX). No other way to create coins exists.

## Consensus (testnet)
Round-robin PoA: the producer of block `h` is `authorities[(h−1) mod n]`, Ed25519 signature over
`"WFLX-BLOCK-SIG-V1" ‖ hash`. Limitation: if the authority whose turn it is is offline, the chain halts.


## Offline vaults (Stage 3b-1)
Transaction types (`kind` + `payload`, strict parsing): `transfer`, `vault_open`, `voucher_claim`, `vault_refund`, `note_claim`.
There is no early close of a vault. Full specification and threat model: `offline-payments.md`.

- **Supply**: `Σ UTXO + Σ value locked in vaults ≤ max_supply`; burned collateral leaves the count.
- **`vault_open`**: inputs fund `Σ(cap + collateral)`; payload `{device_key, key_type, slots, collateral_pct,
  ttl_blocks, refund_address, pop}`; `pop` = signature of the device key over the tx body (without the `pop`).
  Fee ≥ `max(min_fee, min_fee_per_byte × size)`.
- **`voucher_claim`**: payload `{voucher}` (175 B hex); no inputs; single output `(value − min_fee) → receiver`, fixed fee
  `min_fee`; anyone can relay. A free slot pays from the cap; a slot occupied by another voucher pays from the collateral
  (`min(value, collateral)`), marks the vault as fraudulent; the same voucher is never settled twice.
  Deadline: inclusion block ≤ `expires_height + claim_window_blocks`.
- **`vault_refund`**: only in a block `> expires_height + claim_window_blocks`; returns the unpaid cap (+ collateral if there was no
  fraud; if there was, the remaining collateral is burned), minus `min_fee`.
- **Coinbase**: `payload = {"prev_hash": previous block hash}` (coinbase txids never coincide across networks).
- **Voucher**: fixed binary layout; identity = SHA-256 of the body (without signature); P-256 requires low S.


## `note_claim` — settlement of offline notes (A3)
Settles **one address leaf** of an offline note chain in a slot with its own key (`slot.key`). Slots with their own
key do **not** accept `voucher_claim`; slots without a key do **not** accept `note_claim`.

- **Payload** (strict parsing): `{vault_id, slot, leaf, hops:[{tx, key_type, pubkey, sig}]}`; `tx` = binary `OfflineTx`
  in hex. No inputs; single output `(leaf value or compensation − min_fee) → leaf address`; fixed fee `min_fee`;
  anyone can submit (the output is determined by the leaf). The vault proof does **not** go on the chain: the state is already there.
- **Chain** (`offline.note.verify_hop_chain`, pure function): 1..`MAX_HOPS` hops; correct network and vault; the 1st hop spends
  `root_note_id(vault_id, slot)` with value `cap` and is signed by the slot key; each following hop spends a
  **NOTE** output of the previous one and is signed by the key whose commitment is that output's owner; exact conservation; valid signatures
  (P-256 with low S). Hardware attestation is **not** a consensus rule (it is the offline receiver's policy).
- **Leaf**: must be KIND_ADDRESS and ≥ `max(min_voucher_value, min_fee+1)` (smaller leaves stay unsettled and go back
  to the owner in `vault_refund`). Deadline equal to the voucher's: inclusion ≤ `expires_height + claim_window_blocks`.
- **Slot state** (per slot): `spends` (note → offline txid that spent it on the chain) and `settled` (settled leaves),
  committed in the state root via `claimed_by = H("WFLX-NOTESTATE-V1" ‖ spends ‖ settled)` (`state_root` format
  unchanged). At most `MAX_SETTLED_PER_SLOT = 64` leaves per slot.
- **No conflict** (every hop is new or equal to what is already recorded): pays the leaf value from the deposit (`paid += value`) and
  records the new hops. Distinct leaves of the same consistent tree settle normally (conservation guarantees
  `Σ ≤ cap`). **Conflict** (some hop spends a note already spent by *another* offline tx): the losing branch is compensated by the
  collateral through `plan_compensation` (R1–R5, R8, R9), marks the vault as fraudulent and is **not** recorded (its
  descendants keep conflicting). Payment order = order on the chain (R5). The same leaf is never paid twice (R3).
- **Known limit**: R2 uses the slot's value (`cap`) as the ceiling on the sum of the slot's compensations, not the value of each
  contested note separately. It is a valid limit (and still subject to R1, the collateral), but looser than ideal for
  conflicts on intermediate notes of smaller value; refining it requires a per-note counter (state change; new tests).

## Vault owner reconciliation (A4)
**Design decision: no new consensus transaction.** An "early close" of the slot would be unsafe: the owner
could close the slot after already issuing the offline note, undoing payments the receiver accepted. So the
only exit remains `vault_refund` after `expires_height + claim_window_blocks` (and consensus is the same as in A3).
A4 delivers the tools for the owner to **know** what happened before refunding:

- **Read API** (no privilege): `GET /api/vault/<id>` (slots, collateral, `claim_deadline`, height) and
  `GET /api/vaults/<refund-address>` (up to 100 vaults of the address).
- **Owner journal** (`wallet/reconcile.py::Journal`, JSON `v:1`, 0600 file): each root note signed by the owner
  (`vault_id`, `slot`, `root_txid`). `record_hop` refuses hops that do not spend the vault's root.
- **`reconcile(vault, journal, params, height)`** compares journal × chain and uses `plan_refund` (the same arithmetic as consensus)
  to project the refund. State per slot: `UNUSED`, `OUTSTANDING` (issued, window open), `PARTIAL`, `SETTLED`,
  `LAPSED` (window closed with something unsettled: the receiver lost the right and the value goes back to the owner). Flags:
  `DIVERGENT` (the chain shows a spend of the root that the journal does not record: key possibly exposed/cloned or journal
  incomplete), `CONFLICT` (collateral already compensated: double spend), `DOUBLE_ISSUED` (the journal has two roots in the same slot).
  The window follows consensus: claims are accepted while the inclusion height ≤ `claim_deadline`; the refund is valid when
  the inclusion height > `claim_deadline` (tested at every boundary height).
- **CLI**: `vaults`, `reconcile <vault_id> [--journal file]`, `vault-refund <vault_id>` (asks for no password: the refund goes
  to the address recorded in the vault; anyone can submit it).
- **Limits**: the journal is only trustworthy if the owner records it at every issuance (the offline device is what knows); it proves
  nothing to the chain and serves the owner themselves. A malicious owner is not stopped by A4: it is stopped by collateral and R1–R9.

## State root, checkpoints and proofs (A1)
- Every block has a `state_root` in the header (it enters the hash): Merkle root of the vault registry AFTER the block. Every node
  recomputes it and rejects the block if it does not match. Structure and defenses in `blockchain/state_root.py`.
- **Checkpoint** = block header signed by an authority (PoA). **Vault proof** = checkpoint + static vault
  parameters + state + slot record + two Merkle paths. Verifiable offline in ~0.2 ms; 1.2-1.9 KB in JSON.
- New parameter: `max_compensations_per_slot` (R9). Collateral compensation rules (R1-R9): `offline-chained-payments.md` §3.
- Limitation: recomputing the root is O(vaults × slots) per block; it needs an incremental cache before a public network.


## Transferable notes (A2)
- `vault_open` accepts `slot_keys` (a list with one public key per slot, same `key_type` as the vault; compressed P-256, no repeats).
  The key goes in the record, in the `state_root` and in the proof. A slot with its own key does **not** accept `voucher_claim` (only `note_claim`, A3).
- Binary format of the offline transaction and verifier rules: `offline-chained-payments.md` §7. Settlement is done by `note_claim` (A3, above).


## PoW consensus, forks and reorganizations (Phase 5)
- `consensus = "pow"`: a block is valid if `int(header_hash) ≤ target`; `producer` and `signature` empty; the reward goes to the coinbase address.
- **Target derived from history** (not in the header): every `pow_retarget_interval` blocks,
  `target' = target × clamp(actual_time, expected/4, expected×4) / expected`, with `expected = (interval−1) × target_block_time`, limited to `pow_limit`.
- **Most accumulated work wins** (`work(block) = 2²⁵⁶ ÷ (target+1)`). Tie: the first seen stays.
- Side blocks pass only the stateless rules; when they overtake the active chain, the ledger undoes back to the common ancestor and applies the new branch
  validating everything. Invalid branch ⇒ restoration of the previous chain and marking the branch (and descendants) invalid. Reorg persistence is atomic (SQLite).
- `coinbase_maturity`: rewards (height > 0) can only be spent after that number of blocks. The genesis is exempt.
- New parameters (they enter the genesis hash): `consensus`, `pow_limit`, `pow_retarget_interval`, `coinbase_maturity`.

## P2P network (Phase 4)
TCP, messages `uint32 BE size + JSON {"t","d"}` (max. 4 MiB). `version`(proto, chain_id, genesis hash, nonce, height, work, port) → `verack`;
`inv/getdata/block/tx`; locator-based sync: `getblocks{locator}` → `blocks{blocks,more}` (≤ 500 blocks/2 MiB); `getaddr/addr`; `getmempool`; `ping/pong`.
Defenses: incompatible genesis/chain_id ⇒ ban; self-connection and duplicates detected; misbehavior score with decay and a ban at 100;
`inv` bursts are dropped without punishment; invalid message/block ⇒ penalty; orphans (≤ 100) stay in memory until the parent arrives.
Mempool: only transactions valid against the current state, no replacement (first wins), eviction by lowest fee/byte, revalidation at every block.

## HTTP API (read-only + submission)
`GET /api/{status,params,peers,mempool,block/<height|hash>,tx/<txid>,address/<address>}`, `POST /api/tx`. Listens on 127.0.0.1 by default.
