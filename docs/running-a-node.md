# Running a Winflux node

> **Test software (testnet).** No external audit. Do not use it with real money or keep relevant value on it.
> Anyone can run a node without asking permission; your node verifies everything on its own.

## 1. Requirements
- Python 3.11+ and `pip install -r requirements.txt` (only `cryptography`; `pytest` for the tests).
- Disk: the chain lives in a SQLite file (`<datadir>/chain.db`); the testnet is small (tens of MB at first).
- Network: one P2P TCP port (default **8333**) open for inbound if you want to receive connections; the **API** (default
  `127.0.0.1:8080`) is local-only by default.

## 2. Getting the genesis (the network's identity)
The genesis is just a data file. The `chain_id` is derived from it and **every node verifies it by itself**: two nodes only
connect if they have exactly the same genesis. Get the `genesis-testnet.json` published by the community (see
`docs/testnet.md`) **and check the `chain_id` with someone you trust over another channel**. To generate your own:

```bash
python -m winflux.tools.netgen --name testnet --out genesis-testnet.json
```

## 3. Running
```bash
python -m winflux.node.main --genesis genesis-testnet.json --datadir ~/.winflux \
    --listen 0.0.0.0:8333 --api 127.0.0.1:8080 --seed IP_OF_A_NODE:8333
```
To mine, create a wallet and pass its address (the key does **not** stay on the node):
```bash
python -m winflux.cli --wallet mine.json create          # password via WINFLUX_WALLET_PASSWORD or prompt; shows the wflx1… address
python -m winflux.node.main --genesis genesis-testnet.json --seed IP:8333 --mine wflx1...
```
Write down the **recovery key** (`wflxk1-…`) that the wallet shows when it is created: it is the only way to recover the funds.
The node stops on `Ctrl+C`/`SIGTERM` (it closes the database and the API gracefully).

### Options
| Option | Default | What it is for |
|---|---|---|
| `--genesis` | (required) | genesis file |
| `--datadir` | `winflux-data` | chain (`chain.db`) and `peers.json` |
| `--listen` | `0.0.0.0:8333` | P2P |
| `--api` | `127.0.0.1:8080` | HTTP/JSON API (empty disables it) |
| `--seed` | — | `host:port` of a known node (repeatable). Without seeds, the node only accepts inbound connections |
| `--mine` | — | address that receives the rewards; turns mining on (PoW network) |
| `--max-outbound` / `--max-inbound` | 8 / 32 | P2P connections |
| `--max-inbound-per-ip` | 8 | inbound connections per IP (loopback exempt) |
| `--api-rate` | 600 | requests/min **per IP** on the API |
| `--api-tx-rate` | 60 | `POST /api/tx` per min per IP |
| `--api-trust-proxy` | off | uses the last `X-Forwarded-For` (only behind **your own** proxy) |
| `--log-level` | `info` | `debug`, `info`, `warning`, `error` |
| `--log-file` | — | besides the console, writes to a file (rotation 5 MB × 3) |

## 4. Exposing the API safely
The API has no accounts or privileges (any wallet uses any node), but it **has no TLS**. To expose it to the internet,
put a reverse proxy with HTTPS in front (nginx, Caddy…), keep `--api 127.0.0.1:8080` and pass
`--api-trust-proxy` **only** if the proxy is yours and overwrites/appends `X-Forwarded-For`. Without that option the
header is ignored (it can be forged) and all clients behind the proxy would share a single rate-limit bucket.

## 5. Limits and abuse protection (already built in)
- **P2P:** maximum message 4 MB (16 KB before the handshake and smaller per-type caps: ping 256 B, inv 256 KB, tx 512 KB…);
  limit on messages/s overall and per type, and on bytes/s per peer. Excess hints (`inv`/`addr`/`ping`) are
  dropped; excess requests are **delayed** and add misbehavior points (100 points = a 1 h ban).
  Blocks that your own node requested during sync do not count toward the byte limit.
- **Connections:** total and per-IP limit; reconnect with exponential backoff (5 s, 10 s… up to 5 min) and forgetting of
  dead addresses (never the `--seed` ones).
- **API:** body ≤ 200 KB, headers ≤ 16 KB, 256 connections (32 per IP), 20 s timeout per request (anti-slowloris),
  rate limit **before** reading the body, and a stricter limit for `POST /api/tx`. Responses: `429` (with
  `Retry-After`), `413`, `431`, `408`, `503`; internal errors become `500 {"error":"internal error"}` without details.

## 6. Logs
Format: `YYYY-MM-DDTHH:MM:SS LEVEL logger: message`. What is **never** logged: P2P or HTTP message bodies,
transactions, passwords, seeds, private/recovery keys, wallet contents. Errors coming from peers/clients
log only the exception **type**; protocol rule messages (`block 12 rejected: ...`) may appear. As a safety
net, all text goes through a filter that redacts patterns such as `password=…`, `seed: …`, `wflxk1-…`, `Bearer …`.
Peer IP addresses show up at `info`/`debug` (needed to operate); if that is sensitive in your case, use
`--log-level warning`.
Useful messages: `peer ready`, `new tip N hash`, `block mined`, `REORG`, `banned <ip>`, `STORAGE FAILURE`.

## 7. Operation
- **Backup:** copy `<datadir>/` with the node stopped (or use `sqlite3 chain.db ".backup ..."`). The chain is rebuilt from the network if
  lost; **what cannot be rebuilt is your wallet** (`mine.json` + recovery key).
- **Upgrading:** stop the node, update the code, restart. A change to a consensus rule becomes a new protocol version
  announced in advance; the `proto` is checked in the handshake.
- **Testnet reset:** a new genesis produces another `chain_id`; delete the old `--datadir`.
- **Exit codes:** `0` normal; `2` missing/invalid genesis or corrupted database; `1` system error (port in use etc.).

## 8. Common problems
| Symptom | Likely cause |
|---|---|
| `system error while starting the node: Address already in use` | P2P/API port busy: change `--listen`/`--api` |
| `peers=0` and height stuck | no `--seed`, the seed's port is closed or **different genesis** (check the `chain_id`) |
| `banned <ip>` in the logs | the peer violated limits/rules (or is from another network): this is the expected behavior |
| `429` on the API | exceeded the per-IP limit: wait or adjust `--api-rate` |
| `STORAGE FAILURE` | disk full/no permission; stop the node and check `<datadir>/chain.db` |
