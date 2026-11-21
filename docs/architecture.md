# Architecture and risks

## Layers
`crypto` → `blockchain` (pure rules, no network/IO) → `consensus` (pluggable) → `node` (storage, mempool, network, API) →
clients (PWA, Android). Rules and clients share the same protocol documented in `protocol.md`;
the wallet never stores a balance: it queries nodes, and the private key never leaves the device.

## Decisions
- The UTXO set is derived state: rebuilt and **revalidated** on every startup (the disk is not trusted).
- SQLite (WAL, `synchronous=FULL`) for blocks; no central balance database.
- Keystore: scrypt (n=2^15) + AES-256-GCM, address as authenticated data; file `0600`, never overwrites.

## Known pending items (do not forget)
- **No mempool/network yet** (Stage 4). No per-peer fee/DoS limits yet.
- **Coinbase maturity** and **reorganizations**: required before PoW (Stage 5); `UTXOSet` already has undo.
- **PoA** is centralized and halts if the authority whose turn it is goes down; it only serves the testnet.
- **Trademark**: the name "Winflux"/symbol "WFLX" has not yet had an availability search.
- **Key backup/recovery** (seed phrase) does not exist yet: losing the password = losing the funds.
- No external audit has been done.
