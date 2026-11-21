# Winflux's decentralization principle

Winflux is an open, public and *permissionless* monetary protocol. It has no owner, central administrator or
entity with privileged authority over the network.

Anyone can run a node, verify transactions, take part in the consensus mechanism and develop implementations
compatible with the protocol, without needing authorization.

Monetary issuance, transaction validation, payment settlement and security rules are determined by the
protocol and independently verified by the participants.

No entity has administrative powers to create coins arbitrarily, freeze wallets, reverse transactions,
change balances or force upgrades on participants.

The protocol evolves through open development, public review and voluntary adoption of versions by the network operators.

Winflux's continuity does not depend on its original developers, on their servers or on any specific organization.

The goal is to build a decentralized, censorship-resistant monetary infrastructure able to keep working
regardless of who created it.

---

## How each statement is guaranteed in the code (and tested)

| Principle | Mechanism | Test |
|---|---|---|
| No owner/administrator | The PoW network **rejects** `authorities` in the parameters; there is no special key anywhere | `test_decentralization.py::test_public_network_has_no_privileged_party` |
| Fair launch | `netgen` generates a genesis with **zero allocations** (no premine, no faucet) | `test_fair_launch_genesis_has_no_premine_no_authority` |
| Anyone takes part in consensus | Any address mines; nothing identifies the producer (`producer`/`signature` empty) | `test_any_address_can_mine_without_permission` |
| Anyone runs a node | `python -m winflux.node.main` with the genesis; the node verifies everything by itself | `test_network.py` (3 nodes, sync) |
| Issuance only by the protocol | Coinbase ≤ reward(height) + fees; supply ≤ cap, verified by every node | `test_money.py`, `test_only_mining_creates_coins…` |
| Nobody freezes/reverses/changes balances | Spending depends only on the owner's signature; there is no administrative transaction type | `test_only_mining…`, `test_no_admin_backdoors_in_source` |
| No forced upgrade | Nodes with different rules reject each other's genesis/version: adoption is voluntary (a fork for those who disagree) | `test_different_network_is_refused` |
| Works without the creators | No central servers: peer discovery (`addr`), seeds are just replaceable starting points; wallets talk to **any** node | `test_partition_then_heal…`, `test_api_and_cli_end_to_end` |
| Censorship resistance | Open mempool, P2P broadcast, open mining; the heaviest-work chain wins (reorg) | `test_pow_reorg.py` |

## Technical honesty: what the software does NOT guarantee on its own

A protocol is only decentralized **in practice** when many independent people operate it. That depends on the world, not on the code:

1. **Decentralization is a social fact.** With few miners/nodes, whoever controls them controls the network (51% attack).
   The code does not prevent that; it only makes everything verifiable.
2. **"Nobody reverses transactions" is probabilistic.** Reorganizations exist: a transaction is only practically final after
   several confirmations. Mining rewards mature after `coinbase_maturity` blocks.
3. **Fair launch ≠ fair distribution.** Without a premine, whoever mines early and with more hardware accumulates more. The
   creators can mine too; what they cannot have is a protocol privilege.
4. **Seeds (`--seed`) are entry points, not authorities.** Publish several, from different people. There are no DNS seeds today.
5. **PoW security depends on the algorithm.** SHA-256 allows ASICs (hardware centralization). Open decision
   (see "Pending decisions").
6. **Nobody has audited this code.** It is test software. Do not use it with real money before an independent audit.

## Pending decisions (need public review before a network with value)

| Decision | Current state | Note |
|---|---|---|
| PoW algorithm | SHA-256 of the header | Switching to something ASIC-resistant just means implementing `Consensus` |
| Block time | 60 s in `netgen` (vaults scale along with it) | The devnet uses 5 s; public PoW with 5 s would have many orphans |
| Initial difficulty | `--initial-hashes` (default 2²⁰) | Choose according to the hashrate expected at launch |
| Coinbase maturity | 100 blocks | |
| Offline payments over PoW | **NOT adapted**: vault proofs use an *authority-signed checkpoint* (PoA) | In PoW the checkpoint must be a header with work + target; see `security-assumptions.md` H3/H11 |
| Binary tx format, post-quantum signatures | Phase 1b | |
| "Winflux/WFLX" brand | No availability search | `docs/naming.md` |

## How to launch a network (needs nobody's permission)

```bash
python -m winflux.tools.netgen --name mainnet --out genesis.json   # generates the fair genesis (zero premine)
# PUBLISH genesis.json (or just the chain_id + genesis hash) in several independent places.
python -m winflux.node.main --genesis genesis.json --listen 0.0.0.0:8333 --mine <your address>
# others: --seed YOUR_IP:8333
python -m winflux.cli --wallet w.json create      # HD wallet with a recovery key
```
