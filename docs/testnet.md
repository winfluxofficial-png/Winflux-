# Winflux testnet

> **For testing, not for storing value.** The testnet may be restarted at any time (new genesis = new
> `chain_id`), the coins **have no value** and the software has not been externally audited. The hardware cryptography
> of offline payment is **simulated**; there is no attestation of real devices yet (see `docs/security-assumptions.md`).

## What it is
A public PoW network with a **fair launch**: zero premine, zero allocations, zero authorities and no administrative
key (`docs/decentralization.md`). Every coin is born from open mining. `netgen` default parameters:
60 s target block time, initial difficulty of ~2^20 hashes, reward maturity of 100 blocks, minimum fee of
1000 units (1 WFLX = 10⁸ units). What is tested here, beyond the basics: chained offline payments with
vaults (`vault_open`, `note_claim`, `vault_refund`), owner reconciliation and the network defenses.

## Joining the public testnet
1. Get the `genesis-testnet.json` and a list of seeds (`host:8333`) from whoever operates it, and **verify the `chain_id` over a
   second channel**. Whoever publishes the file gains no power at all: every node recomputes the genesis hash.
2. Run the node (`docs/running-a-node.md`):
   `python -m winflux.node.main --genesis genesis-testnet.json --seed SEED1:8333 --seed SEED2:8333`
3. Check: `curl -s http://127.0.0.1:8080/api/status` → `peers ≥ 1` and the `height` growing.
4. Wallet: `python -m winflux.cli --node http://127.0.0.1:8080 --wallet mine.json create` and use `balance`, `send`.
5. Test coins: **there is no faucet** (it would be a point of control). Mine with `--mine <your address>` or ask someone who
   mines. Rewards are only spendable after 100 blocks.

## Launching a new testnet (whoever operates the 1st node)
```bash
python -m winflux.tools.netgen --name testnet --out genesis-testnet.json      # note the printed chain_id
python -m winflux.node.main --genesis genesis-testnet.json --listen 0.0.0.0:8333 --mine wflx1... --seed ...
```
Publish the file (repository, page, whatever you prefer) **together with the `chain_id`** and 2+ seeds from independent
operators. First review the parameters in `docs/decentralization.md` (block time, initial difficulty,
maturity): they are design decisions, not the script's.

## Local testnet (4 processes on your machine)
```bash
PYTHONPATH=. python scripts/run_local_testnet.py --dir local-testnet --block-time 4
```
Starts **3 connected nodes + 1 miner** (P2P `18333–18336`, API `18080–18083`, all on 127.0.0.1), with a genesis generated
by `netgen` and the difficulty calibrated for ~`--block-time` s per block. Creates `genesis.json`, `miner.wallet.json`
(devnet password: **local only**), `logs/<node>.log`. `Ctrl+C` stops it; `--keep` resumes the previous network. Example:
```bash
WINFLUX_WALLET_PASSWORD=devnet-only-password PYTHONPATH=. python -m winflux.cli \
    --node http://127.0.0.1:18081 --wallet local-testnet/miner.wallet.json balance
```
On the local network the maturity is 2 blocks and the block time is short; the other parameters are `netgen`'s.

## Smoke test
```bash
PYTHONPATH=. python scripts/smoke_test.py          # starts the local testnet, tests and tears it down (≈1 min)
PYTHONPATH=. python scripts/smoke_test.py --nodes http://127.0.0.1:18080,http://127.0.0.1:18081 \
    --wallet local-testnet/miner.wallet.json       # against an already running network
```
Steps: (1) nodes start, same network, connected; (2) mining produces blocks and pays the miner; (3) a transaction sent to a
non-mining node propagates, is mined and shows up on all; (4) tip/supply convergence and a **late node** that syncs the
whole chain; (5) **offline flow**: opens a vault with a key per slot, pays Bob → Carol offline, settles with `note_claim`
on a different node, checks the balance, the vault state, the reconciliation report and the rejection of resubmission. Exit `0`
= everything passed. `SMOKE_TRACE=1` shows the traceback of a failure; `--keep` preserves the logs.

## Known limitations (read before testing)
- Offline payment with real hardware (NFC/BLE, attestation) does **not exist** yet; the simulator only covers the logic.
- No TLS on the API (use a proxy), no explorer, no faucet, per-address history unavailable on the API.
- No "real" DoS protection: the limits help against simple abuse; an attacker with many IPs and hash power can degrade the
  network. No protection against *eclipse* (use seeds from independent operators).
- The network may be restarted; keep only what you can afford to lose.

## Reporting problems
Include: version (commit), `chain_id`, a log excerpt **with `--log-level debug`** (the log already omits secrets, but reread it before
pasting), steps to reproduce and the output of `python scripts/smoke_test.py`. Vulnerabilities: do not open a public issue;
contact the maintainers privately.
