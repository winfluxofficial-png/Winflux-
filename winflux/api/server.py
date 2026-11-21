"""Minimal HTTP/JSON API (read-only + transaction submission) for wallets and explorers.

By default the node listens on 127.0.0.1. To expose it publicly, put it behind a proxy with TLS.
Any wallet can use ANY node: the API has no accounts, keys or privileges.
Routes:
  GET  /api/status            GET /api/params           GET /api/peers          GET /api/mempool
  GET  /api/block/<height|hash>                          GET /api/tx/<txid>
  GET  /api/address/<address>                            POST /api/tx   {body = tx as JSON}
  GET  /api/vault/<id>        vault state (slots, collateral, deadline)      GET /api/vaults/<refund-address>
"""
import asyncio
import json
import re
import time

from ..blockchain import vaults as V
from ..blockchain.transaction import Transaction
from ..crypto.address import is_valid_address
from ..errors import ValidationError
from ..logs import exc_label, noop_log
from ..network.limits import KeyedLimiter

MAX_BODY = 200_000
MAX_HEADER_BYTES = 16_384
MAX_HEADERS = 64
MAX_REQUEST_LINE = 2_048
REQUEST_TIMEOUT = 20                 # s to receive the whole request (anti-slowloris)
MAX_REQ_PER_MIN = 600                # reads per IP (default)
MAX_TX_PER_MIN = 60                  # POST /api/tx per IP (default): more expensive, more restricted
MAX_CONNECTIONS = 256
MAX_CONN_PER_IP = 32
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_IP = re.compile(r"^[0-9a-fA-F:.]{2,45}$")
_REASONS = {200: "OK", 204: "No Content", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
            408: "Request Timeout", 413: "Payload Too Large", 414: "URI Too Long", 429: "Too Many Requests",
            431: "Request Header Fields Too Large", 500: "Internal Server Error", 503: "Service Unavailable"}


class _Reject(Exception):
    """Request rejected before routing: (HTTP code, message)."""

    def __init__(self, code: int, msg: str):
        super().__init__(msg)
        self.code, self.msg = code, msg


class ApiServer:
    def __init__(self, node, host="127.0.0.1", port=0, *, rate_per_min=MAX_REQ_PER_MIN, tx_rate_per_min=MAX_TX_PER_MIN,
                 max_connections=MAX_CONNECTIONS, max_conn_per_ip=MAX_CONN_PER_IP, trust_proxy=False,
                 log=noop_log, clock=time.monotonic):
        self.node, self.host, self.port = node, host, port
        self.max_connections, self.max_conn_per_ip = max_connections, max_conn_per_ip
        self.trust_proxy, self.log = trust_proxy, log
        self._server = None
        self._reads = KeyedLimiter(rate_per_min / 60, max(10, rate_per_min / 6), clock=clock)
        self._txs = KeyedLimiter(tx_rate_per_min / 60, max(5, tx_rate_per_min / 2), clock=clock)
        self._conns: dict[str, int] = {}
        self._total = 0

    async def start(self):
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    def _client_ip(self, sock_ip: str, headers: dict) -> str:
        """Behind a trusted proxy (--api-trust-proxy), the real IP is the LAST entry of X-Forwarded-For (the one the proxy
        appended); earlier values can be forged by the client. Without a trusted proxy, the header is ignored."""
        if self.trust_proxy:
            xff = headers.get("x-forwarded-for", "").split(",")[-1].strip()
            if xff and _IP.match(xff):
                return xff
        return sock_ip

    async def _handle(self, reader, writer):
        sock_ip = (writer.get_extra_info("peername") or ("?",))[0]
        if self._total >= self.max_connections or self._conns.get(sock_ip, 0) >= self.max_conn_per_ip:
            self.log(f"API: connection refused from {sock_ip} (connection limit)", "debug")
            try:
                await self._send(writer, 503, {"error": "server busy"})
            except Exception:
                pass
            writer.close()
            return
        self._total += 1
        self._conns[sock_ip] = self._conns.get(sock_ip, 0) + 1
        try:
            code, obj = await asyncio.wait_for(self._serve(reader, sock_ip), REQUEST_TIMEOUT)
            await self._send(writer, code, obj)
        except _Reject as r:
            await self._safe_send(writer, r.code, {"error": r.msg})
        except asyncio.TimeoutError:
            self.log(f"API: slow request from {sock_ip} cancelled", "debug")
            await self._safe_send(writer, 408, {"error": "timed out"})
        except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError):
            await self._safe_send(writer, 400, {"error": "invalid request"})
        except Exception as e:                           # our bug: logs only the type, never the content
            self.log(f"API: internal error {exc_label(e)}", "error")
            await self._safe_send(writer, 500, {"error": "internal error"})
        finally:
            self._total -= 1
            self._conns[sock_ip] -= 1
            if self._conns[sock_ip] <= 0:
                del self._conns[sock_ip]
            try:
                writer.close()
            except Exception:
                pass

    async def _serve(self, reader, sock_ip):
        line = await reader.readline()
        if len(line) > MAX_REQUEST_LINE:
            raise _Reject(414, "request too long")
        parts = line.decode("latin1").split()
        if len(parts) < 2:
            raise _Reject(400, "invalid request")
        method, path = parts[0], parts[1].split("?")[0]
        if method not in ("GET", "POST", "OPTIONS"):
            raise _Reject(405, "method not allowed")
        headers, total = {}, len(line)
        for _ in range(MAX_HEADERS + 1):
            h = await reader.readline()
            total += len(h)
            if total > MAX_HEADER_BYTES:
                raise _Reject(431, "headers too large")
            if h in (b"\r\n", b"\n", b""):
                break
            k, _, v = h.decode("latin1").partition(":")
            k = k.strip().lower()
            if k in headers and k == "content-length" and headers[k] != v.strip():
                raise _Reject(400, "conflicting Content-Length")
            headers[k] = v.strip()
        else:
            raise _Reject(431, "too many headers")
        if "transfer-encoding" in headers:
            raise _Reject(400, "Transfer-Encoding not supported")
        cl = headers.get("content-length", "0") or "0"
        if not re.fullmatch(r"[0-9]{1,9}", cl):
            raise _Reject(400, "invalid Content-Length")
        clen = int(cl)
        ip = self._client_ip(sock_ip, headers)
        # Rate BEFORE reading the body: whoever exceeds the limit consumes neither bandwidth nor node memory.
        if not self._reads.allow(ip) or (method == "POST" and path == "/api/tx" and not self._txs.allow(ip)):
            self.log(f"API: request limit exceeded by {ip}", "debug")
            raise _Reject(429, "request limit")
        if clen > MAX_BODY:
            raise _Reject(413, "body too large")
        body = await reader.readexactly(clen) if clen else b""
        if method == "OPTIONS":
            return 204, None
        try:
            return await self._route(method, path, body)
        except ValidationError as e:
            return 400, {"error": str(e)}
        except (ValueError, TypeError, KeyError, AttributeError):
            return 400, {"error": "invalid request"}

    async def _safe_send(self, writer, code, obj):
        try:
            await self._send(writer, code, obj)
        except Exception:
            pass

    async def _send(self, writer, code, obj):
        raw = b"" if obj is None else json.dumps(obj).encode()
        extra = "Retry-After: 10\r\n" if code == 429 else ""
        head = (f"HTTP/1.1 {code} {_REASONS.get(code, 'OK')}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(raw)}\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n{extra}"
                "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type\r\n"
                "Connection: close\r\n\r\n").encode()
        writer.write(head + raw)
        await writer.drain()

    async def _route(self, method, path, body):
        n, c = self.node, self.node.chain
        seg = [s for s in path.split("/") if s]
        if len(seg) < 2 or seg[0] != "api":
            return 404, {"error": "unknown route"}
        what = seg[1]
        if method == "GET" and what == "status" and len(seg) == 2:
            return 200, n.status()
        if method == "GET" and what == "params" and len(seg) == 2:
            return 200, c.params.to_dict()
        if method == "GET" and what == "peers":
            return 200, [{"addr": f"{p.addr[0]}:{p.addr[1]}", "outbound": p.outbound, "height": p.height}
                         for p in n.p2p.ready_peers()]
        if method == "GET" and what == "mempool":
            return 200, {"count": len(n.mempool), "bytes": n.mempool.total_bytes, "txids": n.mempool.txids()[:1000]}
        if method == "GET" and what == "block" and len(seg) == 3:
            key = seg[2]
            if not ((key.isascii() and key.isdigit() and len(key) <= 12) or _HEX64.match(key)):
                return 400, {"error": "invalid block height or hash"}
            b = c.get_block(int(key)) if key.isdigit() else c.get_block_by_hash(key)
            if b is None:
                return 404, {"error": "block not found"}
            return 200, {"hash": b.hash, "confirmations": c.height - b.height + 1, **b.to_dict()}
        if method == "GET" and what == "tx" and len(seg) == 3:
            if not _HEX64.match(seg[2]):
                return 400, {"error": "invalid txid"}
            r = c.get_transaction(seg[2])
            if r:
                return 200, {"confirmations": c.confirmations(seg[2]), "height": r[1], "tx": r[0].to_dict()}
            t = n.mempool.get(seg[2])
            if t:
                return 200, {"confirmations": 0, "height": None, "tx": t.to_dict()}
            return 404, {"error": "transaction not found"}
        if method == "GET" and what == "address" and len(seg) == 3:
            a = seg[2]
            if not is_valid_address(a):
                return 400, {"error": "invalid address"}
            utxos = c.utxo.utxos_for(a)[:1000]
            m = c.params.coinbase_maturity
            out = []
            for (txid, idx), o in utxos:
                ch = c.ledger._coinbase_height.get((txid, idx))
                out.append({"txid": txid, "index": idx, "value": o.value,
                            "spendable_at_height": (ch + m) if ch is not None else 0})
            return 200, {"address": a, "balance": c.balance(a), "seen": c.address_seen(a),
                         "height": c.height, "utxos": out}
        if method == "GET" and what == "vault" and len(seg) == 3:
            vid = seg[2]
            if not (len(vid) == 64 and V._HEX.match(vid)):
                return 400, {"error": "invalid vault_id"}
            v = c.get_vault(vid)
            if v is None:
                return 404, {"error": "vault not found"}
            return 200, {**v.to_dict(), "claim_deadline": V.claim_deadline(v, c.params), "height": c.height,
                         "locked": v.locked()}
        if method == "GET" and what == "vaults" and len(seg) == 3:
            if not is_valid_address(seg[2]):
                return 400, {"error": "invalid address"}
            return 200, {"address": seg[2], "height": c.height, "vaults": [
                {"vault_id": v.vault_id, "state": v.state, "fraud": v.fraud, "expires_height": v.expires_height,
                 "claim_deadline": V.claim_deadline(v, c.params), "locked": v.locked()}
                for v in c.vaults.for_refund_address(seg[2])]}
        if method == "POST" and what == "tx" and len(seg) == 2:
            try:
                tx = Transaction.from_dict(json.loads(body))
            except ValidationError as e:
                return 400, {"error": str(e)}
            except (ValueError, TypeError, KeyError, AttributeError):
                return 400, {"error": "malformed transaction (invalid JSON)"}
            txid = await n.submit_tx(tx)                  # ValidationError bubbles up and becomes 400 in _serve
            return 200, {"txid": txid}
        return 404, {"error": "unknown route"}
