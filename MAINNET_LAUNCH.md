# Winflux (WFLX) --- Mainnet Launch Plan

> **Status:** Draft launch checklist\
> **Document version:** 1.0\
> **Basis:** Winflux Whitepaper, Extended Technical Edition v1.1 (22
> November 2026)\
> **Purpose:** Define the conditions, decisions, and operational steps
> required to activate the first public Winflux mainnet.

This document is a launch-control checklist, not a declaration that
mainnet is ready. The whitepaper v1.1 states that mainnet has **not**
been launched, the public testnet is being prepared, and no independent
security audit has been completed.

The first public release should be treated as a monetary network launch,
not merely as publication of a repository or a working local node. Once
independent miners begin producing blocks on the canonical genesis, the
network's history and monetary issuance become public.

------------------------------------------------------------------------

## 1. Launch objective and scope

### 1.1 Initial objective

Launch Winflux as an independent Layer 1 UTXO blockchain with:

-   permissionless Proof of Work (PoW) mining;
-   no premine, no initial allocation, and no administrator key;
-   public verification of transactions, blocks, monetary issuance, and
    the supply cap;
-   independent full-node operation;
-   free participation in mining and coin distribution;
-   no requirement for an exchange, custodian, or central account
    provider.

The initial launch objective is **network operation and fair issuance**,
not price discovery or trading. The project must not imply that WFLX has
a market price, guaranteed liquidity, or investment value.

### 1.2 Scope of the first mainnet

The first mainnet should include only features that are ready to operate
under the public PoW consensus rules.

The core UTXO chain, transactions, fees, supply cap, wallets, PoW
validation, difficulty adjustment, reorganizations, P2P networking, and
coinbase maturity are described as implemented and tested in the
reference implementation.

The offline-payment subsystem needs a separate launch decision. In
whitepaper v1.1, vaults, vouchers, claims, refunds, notes, and
settlement rules are implemented and tested, but **offline
proofs/checkpoints for a public PoW network are not complete**: the
documented checkpoint mode is authority-signed PoA, and a PoW-compatible
checkpoint is still open. Hardware attestation is simulated, not
verified on real devices.

**Launch rule:** do not advertise or enable public-mainnet offline
payments until PoW-compatible proofs, real-device security, and the
remaining offline-protocol decisions have been implemented, reviewed,
and tested. If the current software cannot safely disable or isolate
those features, that is a launch blocker requiring a code-level change
and tests.

------------------------------------------------------------------------

## 2. Launch blockers

Do not activate mainnet until every blocker below has an explicit
resolution recorded in the release notes or launch record.

### 2.1 Consensus and monetary rules

-   [ ] Freeze the Proof-of-Work algorithm. Whitepaper v1.1 describes
    SHA-256 over the block header and identifies the design as
    ASIC-friendly, while also marking the final PoW choice as an open
    decision before a network with value.
-   [ ] Freeze the block format, header serialization, hashing rules,
    target comparison, chain selection by accumulated work, and
    reorganization behavior.
-   [ ] Freeze the difficulty-retarget rules, including interval,
    timestamp constraints, clamp limits, and edge cases.
-   [ ] Decide and document whether to add a median-time-past rule. The
    whitepaper says it is not currently implemented.
-   [ ] Freeze the monetary schedule, fee rules, coinbase maturity,
    maximum supply, and all integer-rounding behavior.
-   [ ] Confirm that all consensus-critical arithmetic is integer-only
    and that no node can create coins outside valid coinbase issuance.
-   [ ] Verify reward calculations at every halving boundary and at the
    final issuance boundary.
-   [ ] Resolve any remaining consensus ambiguity in the specification
    and reference implementation. Different implementations must not
    interpret the same block differently.

### 2.2 Genesis and network identity

-   [ ] Generate the final mainnet genesis block using the frozen
    parameters.
-   [ ] Generate and publish the final `chain_id` and genesis
    fingerprint.
-   [ ] Independently reproduce the genesis result from the published
    parameters and generator.
-   [ ] Verify that a node configured for another network rejects
    mainnet data and that mainnet signatures/objects cannot be replayed
    across networks.
-   [ ] Publish the exact genesis header, block hash, initial
    target/difficulty, timestamp, network parameters, and generator
    version.
-   [ ] Ensure the genesis contains no premine, allocation, founder
    output, hidden balance, or privileged issuance mechanism.
-   [ ] Confirm that the production configuration does not accidentally
    reuse devnet or private-testnet genesis data, keys, ports, seeds, or
    databases.

**Important:** the whitepaper's generator values are defaults, not proof
that a final mainnet genesis has already been generated. The final
genesis and `chain_id` must be fixed and independently verified before
activation.

### 2.3 Security and independent review

-   [ ] Complete an independent review of consensus-critical code.
-   [ ] Review cryptographic implementation and protocol-domain
    separation.
-   [ ] Review transaction validation, UTXO accounting, coinbase
    issuance, fees, and supply-cap enforcement.
-   [ ] Review difficulty adjustment, timestamp handling, chain
    selection, and reorganization/undo logic.
-   [ ] Review P2P parsing, peer management, denial-of-service controls,
    and eclipse/Sybil exposure.
-   [ ] Review wallet key generation, encryption, recovery, signing, and
    transaction construction.
-   [ ] Resolve all critical and high-severity findings before mainnet.
-   [ ] Publish the review scope, findings, fixes, and remaining
    accepted risks.

The project's unit, integration, adversarial, fuzzing, and smoke tests
are valuable evidence, but they are not an independent security audit.
The whitepaper explicitly records that no external audit has been
performed.

### 2.4 Operational readiness

-   [ ] Publish reproducible release artifacts and their cryptographic
    checksums.
-   [ ] Document installation, configuration, node operation, wallet
    creation, backup, restore, mining, and troubleshooting.
-   [ ] Have multiple independent operators successfully run
    mainnet-compatible nodes before activation.
-   [ ] Ensure seed nodes are operated independently. Seeds are
    discovery entry points, not authorities.
-   [ ] Verify peer discovery and synchronization without depending on
    one central server.
-   [ ] Verify that a new node can synchronize from genesis and
    independently validate the chain.
-   [ ] Confirm that node software has safe defaults for API binding,
    firewall exposure, logging, and data directories.
-   [ ] Publish a clear incident-reporting and vulnerability-disclosure
    contact/process.

------------------------------------------------------------------------

## 3. Monetary parameters to freeze

The following are the **documented generator defaults** in whitepaper
v1.1. They must be reviewed and explicitly accepted or changed before
genesis generation.

  Parameter                                        Whitepaper v1.1 default
  ---------------------------- -------------------------------------------
  Maximum supply                                          100,000,000 WFLX
  Decimal places                                                         8
  Smallest unit                                   1 unit = 0.00000001 WFLX
  Initial block reward              4,756,468,797 units = 47.56468797 WFLX
  Target block time                                             60 seconds
  Halving interval                                        1,051,200 blocks
  Approximate halving period                  2 years at target block time
  Initial PoW difficulty         Derived from 2\^20 expected hash attempts
  Coinbase maturity                                             100 blocks
  Default minimum fee                           1,000 units = 0.00001 WFLX
  Fee floor                                                1 unit per byte
  Issuance mechanism                             Valid mining rewards only
  Premine / allocations                                               None

The schedule uses integer right-shift halving. The whitepaper calculates
scheduled total issuance as **99,999,999.809424 WFLX**, slightly below
the 100,000,000 WFLX cap because of integer rounding. Each node must
enforce the cap independently.

### 3.1 Parameter-freeze record

Complete this record before publishing the genesis:

  Item                             Final value
  -------------------------------- ------------------------------------
  Protocol/specification version   `TBD`
  Software release/tag             `TBD`
  PoW algorithm                    `TBD — explicit approval required`
  Target block time                `TBD — confirm or change 60 s`
  Retarget interval and formula    `TBD`
  Timestamp rule                   `TBD`
  Initial difficulty/target        `TBD`
  Initial block reward             `TBD`
  Halving interval                 `TBD`
  Coinbase maturity                `TBD`
  Fee policy                       `TBD`
  Maximum supply                   `TBD — confirm 100,000,000 WFLX`
  Genesis timestamp                `TBD`
  Genesis block hash               `TBD`
  Chain ID                         `TBD`
  Genesis generator checksum       `TBD`

Do not leave a `TBD` in a consensus-critical field when declaring the
network live.

------------------------------------------------------------------------

## 4. Testnet exit criteria

The public testnet is a required operational rehearsal, not a substitute
for mainnet security review.

-   [ ] Publish a testnet release and genesis separately from mainnet.
-   [ ] Recruit independent node operators and miners.
-   [ ] Test clean installation and synchronization on different
    machines and networks.
-   [ ] Test transaction creation, propagation, inclusion, confirmation,
    and rejection of invalid transactions.
-   [ ] Test mining, reward maturity, fee handling, and halving-boundary
    calculations using controlled test parameters.
-   [ ] Test competing blocks, reorganizations, stale blocks, and
    recovery after node restart.
-   [ ] Test peer disconnection, reconnection, malicious messages, rate
    limits, and resource exhaustion.
-   [ ] Test wallet backup and restoration from the recovery key.
-   [ ] Test that different nodes calculate identical balances, UTXO
    state, and chain work.
-   [ ] Run the testnet long enough to expose operational failures;
    publish the duration and observed issues.
-   [ ] Collect external reports and resolve launch-critical defects.
-   [ ] Verify that testnet coins and keys cannot be mistaken for
    mainnet coins and keys.

A testnet that is operated only by the project creator does not
demonstrate independent network operation.

------------------------------------------------------------------------

## 5. Release and repository preparation

Before announcing the launch:

-   [ ] Freeze a release candidate and stop adding consensus changes.
-   [ ] Tag the exact source revision.
-   [ ] Build release artifacts from the tagged source.
-   [ ] Publish checksums and reproducible build instructions.
-   [ ] Publish the final whitepaper/specification matching the released
    code.
-   [ ] Publish the final mainnet configuration template.
-   [ ] Publish a clean node setup guide for Linux and other supported
    platforms.
-   [ ] Publish wallet setup, recovery, and security instructions.
-   [ ] Publish miner setup and reward-address instructions.
-   [ ] Publish the list of official seed endpoints and their operators.
-   [ ] Publish known limitations and explicitly unsupported features.
-   [ ] Ensure the release does not present simulated hardware security
    or incomplete PoW offline checkpoints as production-ready.

The whitepaper records the Android wallet's protocol core as verified on
the JVM, but its UI was not compiled and the app was not tested on
devices. NFC/BLE, PWA, and real hardware attestation are not launch
prerequisites for a core desktop/CLI network unless the launch
announcement claims to support them. Do not advertise unfinished client
capabilities.

------------------------------------------------------------------------

## 6. Mainnet activation procedure

Use a public, timestamped launch record. The order below is intended to
make the launch reproducible and prevent ambiguity about which chain is
canonical.

### Phase A --- Public announcement

1.  Publish the final release tag and checksums.
2.  Publish the final protocol parameters and genesis-generation
    procedure.
3.  Publish the planned activation time in UTC.
4.  Publish the genesis fingerprint and `chain_id` as soon as they are
    fixed.
5.  State clearly that mining is permissionless and that the project
    does not guarantee price, liquidity, or exchange listing.
6.  State which features are enabled and which are disabled or
    experimental.

### Phase B --- Genesis verification

1.  Generate the genesis from the frozen configuration.
2.  Have at least two independent operators reproduce and verify the
    genesis.
3.  Compare the genesis hash, chain ID, target, timestamp, and all
    committed parameters.
4.  Publish the exact values and the generator checksum.
5.  Reject activation if any independent reproduction differs.

### Phase C --- Independent node readiness

1.  Independent operators install the release from the published
    artifacts.
2.  Each operator verifies the release checksum and genesis fingerprint.
3.  Nodes connect to multiple independently operated peers.
4.  Operators confirm that their nodes agree on network identity and
    initial chain state.
5.  At least several independent miners confirm that they can mine valid
    blocks and propagate them.
6.  No single node, seed, API endpoint, or operator should be required
    for the network to continue.

### Phase D --- Activation

1.  At the announced activation time, miners begin producing blocks
    against the canonical genesis.
2.  Nodes validate blocks and transactions under the frozen rules.
3.  Publish the first block hash and height.
4.  Monitor block intervals, difficulty, orphan/stale blocks, peer
    count, propagation, and node errors.
5.  Keep the launch record updated with observed incidents and
    resolutions.

### Phase E --- Post-activation observation

For the initial observation period:

-   monitor whether independent nodes remain synchronized;
-   compare block hashes and chain work across operators;
-   verify coinbase rewards and supply accounting;
-   monitor peer diversity and connectivity;
-   monitor resource usage and database growth;
-   publish incidents and software fixes transparently;
-   do not make silent consensus changes.

A consensus-breaking change after activation may split the network. If a
critical defect requires a reset, follow the reset policy published
before launch.

------------------------------------------------------------------------

## 7. Reset and emergency policy

A public mainnet should not be described as permanent in the sense that
its history can never change. Proof of Work permits reorganizations, and
software defects can require emergency action.

Before activation, publish one of these policies:

### Policy A --- No planned reset

The chain is intended to continue from its genesis. A reset is
considered only if a critical consensus or security defect makes
continued operation unsafe. Any proposed reset must be publicly
explained, independently reviewed where possible, and coordinated
transparently.

### Policy B --- Experimental launch with possible reset

The network is explicitly experimental. The project reserves the
possibility of replacing the chain if a critical defect is found. Users
and miners are warned that balances and history may not carry over to a
replacement genesis.

**Do not use vague language such as "permanent mainnet, unless we need
to reset it."** State the policy plainly. A reset is not a routine
database cleanup: it creates a new chain history and a new genesis
identity.

------------------------------------------------------------------------

## 8. Mining and distribution principles

The intended initial distribution is through mining, with no premine or
founder allocation.

-   Mining must be open to anyone who can run compatible software and
    contribute valid Proof of Work.
-   The protocol must not reserve rewards for a project-controlled
    address.
-   Mining rewards are created only through valid coinbase transactions.
-   Nodes independently enforce the reward schedule and supply cap.
-   The project should publish simple mining instructions and explain
    that hardware performance affects expected reward share.
-   Do not promise that every participant will receive coins or that
    rewards will be proportional to time online.
-   Do not imply that a low-powered computer can compete equally with
    specialized hardware.

Whitepaper v1.1 identifies SHA-256 as ASIC-friendly. This matters for
distribution: a fair launch means no premine or privileged allocation;
it does **not** mean equal mining opportunity or equal distribution. The
project should state this clearly.

------------------------------------------------------------------------

## 9. Security and operational limitations to disclose

The launch announcement and documentation should not hide these known
limitations from whitepaper v1.1:

1.  No independent security audit has been completed.
2.  SHA-256 PoW is ASIC-friendly.
3.  A majority of hash power can reorganize recent blocks or censor
    transactions.
4.  The reference P2P layer does not claim complete eclipse-attack
    resistance.
5.  The timestamp rules do not yet include median-time-past.
6.  Offline PoW-compatible checkpoints are not implemented.
7.  Hardware attestation is simulated and has not been verified on real
    devices.
8.  NFC/BLE transports and PWA are not implemented.
9.  Post-quantum slot keys are planned, not implemented.
10. The vault state-root calculation is linear in vaults and slots and
    needs an incremental cache.
11. The name "Winflux" and ticker "WFLX" have not been legally verified.
12. Wallet recovery uses the project's recovery-key format; BIP-39
    mnemonic support is not implemented.

These limitations do not all have the same severity. The project must
distinguish launch blockers from features that can remain outside the
initial core network. Do not claim that an unresolved feature is
implemented merely because related code exists in the reference
implementation.

------------------------------------------------------------------------

## 10. Post-launch roadmap

After the core mainnet is stable:

-   [ ] Continue independent node and miner onboarding.
-   [ ] Publish network statistics and operational reports.
-   [ ] Improve peer diversity and network resilience.
-   [ ] Complete the incremental state-root cache and measure
    performance under realistic registry growth.
-   [ ] Decide and implement the median-time-past rule if adopted.
-   [ ] Complete independent security review and remediation.
-   [ ] Complete the PoW-compatible offline checkpoint design before
    enabling offline payments on mainnet.
-   [ ] Refine per-note collateral exposure (R2) and finalize the
    collateral-burn policy.
-   [ ] Implement and test real hardware attestation on supported
    devices before making hardware-security claims.
-   [ ] Develop and test NFC/BLE transports and the PWA if those clients
    remain in scope.
-   [ ] Evaluate post-quantum key support and migration implications.
-   [ ] Consider a binary on-chain transaction format only through a
    versioned, consensus-safe upgrade process.

Do not bundle unrelated new features into an emergency consensus
release.

------------------------------------------------------------------------

## 11. Launch decision

The launch owner should complete this section and publish it with the
release.

  -----------------------------------------------------------------------
  Decision                            Result
  ----------------------------------- -----------------------------------
  Consensus rules frozen              `PENDING`

  Monetary parameters frozen          `PENDING`

  PoW algorithm formally selected     `PENDING`

  Genesis independently reproduced    `PENDING`

  Chain ID fixed and published        `PENDING`

  Public testnet completed            `PENDING`

  Independent node operators ready    `PENDING`

  Independent miners ready            `PENDING`

  External security review completed  `PENDING`
  or explicit risk decision published 

  Offline subsystem disabled from     `PENDING`
  mainnet or PoW proof gap resolved   

  Reproducible release published      `PENDING`

  Reset policy published              `PENDING`

  Final go/no-go decision             `NOT APPROVED`
  -----------------------------------------------------------------------

### Go/no-go rule

**GO** only when all consensus, genesis, operational, and scope blockers
are resolved, the release is reproducible, independent operators can
validate the same chain, and the remaining risks are publicly disclosed.

**NO-GO** if the PoW algorithm or monetary rules remain ambiguous, the
genesis cannot be independently reproduced, independent nodes disagree,
the release does not match the specification, or an incomplete feature
can affect public-mainnet consensus or user funds.

------------------------------------------------------------------------

## 12. Launch record

Complete this record at activation.

  Field                              Value
  ---------------------------------- -------
  Activation date and time (UTC)     `TBD`
  Release tag                        `TBD`
  Source commit                      `TBD`
  Release checksums                  `TBD`
  Whitepaper/specification version   `TBD`
  Genesis hash                       `TBD`
  Chain ID                           `TBD`
  Initial difficulty/target          `TBD`
  Initial seed operators             `TBD`
  Independent node operators         `TBD`
  Initial miners                     `TBD`
  Enabled features                   `TBD`
  Disabled/experimental features     `TBD`
  Reset policy                       `TBD`
  Known launch issues                `TBD`

------------------------------------------------------------------------

## 13. Source alignment

This launch plan is derived primarily from **Winflux Whitepaper ---
Extended Technical Edition v1.1, dated 22 November 2026**, especially:

-   Important Notice and Abstract;
-   monetary policy and Proof-of-Work specification;
-   client software and operation;
-   security model and known risks;
-   offline-payment proofs and checkpoint limitations;
-   implementation status and verification;
-   open decisions and known limitations;
-   development roadmap.

Where the whitepaper distinguishes implemented, simulated, proposed, and
open functionality, this document preserves those distinctions. The
launch checklist adds operational recommendations and decision gates;
those recommendations should not be mistaken for claims that the
corresponding work has already been completed.
