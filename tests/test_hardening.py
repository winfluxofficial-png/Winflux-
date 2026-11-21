"""Pre-testnet hardening: rate limiting (P2P and API), size limits, network errors and leak-free logs."""
import asyncio
import io
import json
import logging
import time
from types import SimpleNamespace

import pytest

from winflux.api import server as api_mod
from winflux.api.server import MAX_BODY, ApiServer
from winflux.logs import RedactingFormatter, exc_label, make_log, redact, setup_logging
from winflux.network import p2p as p2p_mod
from winflux.network.limits import KeyedLimiter, TokenBucket
from winflux.network.p2p import MAX_BY_TYPE, Peer

from .conftest import kp, make_chain
from .test_network import genesis, run, start, wait_for


# ================================================================== limiters
class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def test_token_bucket_burst_refill_and_wait_time():
    c = Clock()
    b = TokenBucket(rate=2, burst=5, clock=c)
    assert [b.allow() for _ in range(6)] == [True] * 5 + [False]
    assert 0.49 < b.wait_time() <= 0.5
    c.t += 0.5
    assert b.allow() and not b.allow()
    c.t += 1000
    assert b.allow(5) and not b.allow(1)                 # never accumulates above the burst
    assert not b.allow(6)                                # a cost larger than the burst never passes


def test_keyed_limiter_isolates_keys_and_bounds_memory():
    c = Clock()
    lim = KeyedLimiter(rate=1, burst=2, max_keys=8, clock=c)
    assert lim.allow("a") and lim.allow("a") and not lim.allow("a")
    assert lim.allow("b")                                # another key is not affected
    for i in range(100):                                 # attack with thousands of IPs: bounded memory
        lim.allow(f"ip{i}")
        c.t += 0.001
    assert len(lim) <= 8


# ================================================================== logs
def test_redact_hides_secrets_and_keeps_public_data():
    txid = "ab" * 32
    for secret_line, leaked in (("password=abc123 ok", "abc123"), ("seed: deadbeefcafe", "deadbeefcafe"),
                                ("recovery wflxk1-a4dq-obyh-a4dq-obyh-a4d6", "a4dq"),
                                ("Authorization: Bearer xyz.abc", "xyz"), ("bearer tok123", "tok123"),
                                ("private_key=aa11bb", "aa11bb"), ('{"secret_key": "s3cr3t"}', "s3cr3t"),
                                ("password 'hunter2'", "hunter2")):
        out = redact(secret_line)
        assert leaked not in out and "REDACTED" in out, secret_line
    assert redact(f"tx {txid} height 5") == f"tx {txid} height 5"          # txids/hashes are public


def test_formatter_redacts_tracebacks_and_setup_is_idempotent(tmp_path):
    buf = io.StringIO()
    path = str(tmp_path / "n.log")
    for _ in range(3):                                   # calling it several times does not duplicate handlers
        lg = setup_logging("debug", path, stream=buf)
    assert len(lg.handlers) == 2
    log = make_log("test")
    log("connected seed=topsecret123 end", "info")
    try:
        raise ValueError("failed with password=hunter2")
    except ValueError:
        logging.getLogger("winflux.test").exception("error")
    for h in lg.handlers:
        h.flush()
    text = buf.getvalue() + open(path).read()
    assert "topsecret123" not in text and "hunter2" not in text and "REDACTED" in text
    assert "INFO" in text and "winflux.test" in text
    log("detail", "debug")
    setup_logging("warning", None, stream=buf)
    log("should not appear", "info")
    assert "should not appear" not in buf.getvalue()
    with pytest.raises(ValueError):
        setup_logging("verbose")
    setup_logging("info", None, stream=io.StringIO())    # restores


def test_exc_label_never_echoes_foreign_error_text():
    from winflux.errors import ValidationError
    assert exc_label(ValidationError("public rule violated")) == "public rule violated"
    assert exc_label(ConnectionResetError("peer 10.0.0.1 sent seed=abc")) == "ConnectionResetError"
    assert exc_label(KeyError("secret")) == "KeyError"


# ================================================================== P2P: units
def _peer():
    return Peer(SimpleNamespace(log=lambda *a, **k: None), None, None, False, ("1.2.3.4", 1))


def test_rate_check_policy_hints_dropped_requests_slowed_sync_exempt_from_bytes():
    p = _peer()
    assert p.rate_check("tx", 100) == "ok"
    verdicts = [p.rate_check("ping", 10) for _ in range(30)]
    assert "drop" in verdicts and verdicts[0] == "ok"                       # excess hint: dropped
    p = _peer()
    v = [p.rate_check("getblocks", 100) for _ in range(40)]
    assert v[:20] == ["ok"] * 20 and "slow" in v and "drop" not in v         # excess request: delays, does not drop
    p = _peer()
    assert p.rate_check("tx", p2p_mod.BYTES_BURST + 1) == "slow"             # byte budget exceeded
    assert p.rate_check("blocks", 3 * p2p_mod.BYTES_BURST, solicited=True) == "ok"   # blocks we asked for: exempt


def test_backoff_doubles_and_forgets_dead_non_seed_addresses():
    p2p = p2p_mod.P2P(SimpleNamespace(), seeds=["10.9.9.9:1"])
    a, seed = ("10.0.0.1", 5), ("10.9.9.9", 1)
    p2p.known_addrs[a] = 0
    delays = []
    for _ in range(6):
        p2p._note_failure(a)
        delays.append(p2p._retry_delay(a))
    assert delays == [5, 10, 20, 40, 80, 160]
    for _ in range(p2p_mod.MAX_FAILS):
        p2p._note_failure(a)
        p2p._note_failure(seed)
    assert a not in p2p.known_addrs and seed in p2p.known_addrs              # seeds are never forgotten


# ================================================================== P2P: with real nodes and a raw client
async def raw_handshake(node, chain_id=None):
    """Raw TCP client that completes the handshake; returns (reader, writer, send)."""
    r, w = await asyncio.open_connection("127.0.0.1", node.port)

    async def send(t, d=None, raw=None):
        body = raw if raw is not None else json.dumps({"t": t, "d": d}, separators=(",", ":")).encode()
        w.write(len(body).to_bytes(4, "big") + body)
        await w.drain()

    async def recv():
        n = int.from_bytes(await asyncio.wait_for(r.readexactly(4), 5), "big")
        return json.loads(await asyncio.wait_for(r.readexactly(n), 5))
    first = await recv()                                  # node's version
    assert first["t"] == "version"
    v = node.version_payload()
    await send("version", {**v, "nonce": "ff" * 8, "height": 0, "work": "0", "port": 0})
    await send("verack")
    return r, w, send, recv


def server_peer(node):
    return next(p for p in node.p2p.peers if p.ready)


def test_oversized_prehandshake_message_is_refused_and_peer_banned():
    async def go():
        n = await start(genesis())
        try:
            r, w = await asyncio.open_connection("127.0.0.1", n.port)
            await r.readexactly(4)                        # reads the node's version and ignores it
            w.write((1_000_000).to_bytes(4, "big"))       # 1 MB before the handshake (limit 16 KB)
            await w.drain()
            assert await wait_for(lambda: n.p2p.is_banned("127.0.0.1"), 5)
            assert await asyncio.wait_for(r.read(10_000), 5) is not None
        finally:
            await n.stop()
    run(go())


def test_per_type_size_cap_flood_and_node_stays_responsive():
    async def go():
        n = await start(genesis())
        try:
            r, w, send, recv = await raw_handshake(n)
            assert await wait_for(lambda: any(p.ready for p in n.p2p.peers))
            sp = server_peer(n)
            await send("ping", {"x": "a" * 400})          # > MAX_BY_TYPE["ping"] (256)
            assert await wait_for(lambda: sp.score >= 45, 5)
            assert MAX_BY_TYPE["ping"] == 256
            before = sp.score
            for _ in range(200):                          # flood of pings: hints dropped without scoring
                await send("ping", 1)
            await asyncio.sleep(0.3)
            assert sp.score <= before + 1 and not sp.closed
            for _ in range(30):                           # excess requests: delayed and scored
                await send("getblocks", {"locator": []})
            assert await wait_for(lambda: sp.score > before + 2, 10)
            # the node keeps serving: a legitimate ping (after the queue drains) still gets a pong
            await asyncio.sleep(3)
            await send("ping", {"n": 7})
            seen = set()
            for _ in range(60):
                try:
                    seen.add((await recv())["t"])
                except Exception:
                    break
                if "pong" in seen:
                    break
            assert "pong" in seen
        finally:
            await n.stop()
    run(go())


def test_inbound_per_ip_limit_when_not_loopback_exempt():
    async def go():
        n = await start(genesis(), max_inbound_per_ip=2)
        n.p2p.exempt_loopback = False
        try:
            conns = []
            for _ in range(3):
                conns.append(await asyncio.open_connection("127.0.0.1", n.port))
                await asyncio.sleep(0.1)
            ok = []
            for r, _ in conns:
                try:
                    data = await asyncio.wait_for(r.read(4), 2)   # b"" = closed by the node
                    ok.append(bool(data))
                except asyncio.TimeoutError:
                    ok.append(True)
            assert ok == [True, True, False]
            for _, w in conns:
                w.close()
        finally:
            await n.stop()
    run(go())


def test_connect_failure_is_counted_and_logged_without_payload():
    async def go():
        logs = []
        n = await start(genesis(), log=lambda m, level="info": logs.append((level, m)))
        try:
            dead = ("127.0.0.1", 1)                       # closed port
            await n.p2p.connect(dead)
            assert n.p2p._fails[dead] == 1
            assert any("failed to connect" in m and "ConnectionRefusedError" in m for _, m in logs)
        finally:
            await n.stop()
    run(go())


def test_mining_loop_survives_an_internal_error():
    async def go():
        logs = []
        cfg = genesis()
        from winflux.node.node import Node
        n = Node(cfg, log=lambda m, level="info": logs.append((level, m)))
        await n.start()
        calls = {"n": 0}
        orig = n.build_template

        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("transient failure with seed=abc123")
            return orig()
        n.build_template = flaky
        n.start_mining(kp(4).address)
        try:
            assert await wait_for(lambda: n.chain.height >= 1, 20)
            errs = [m for lv, m in logs if lv == "error"]
            assert errs and "RuntimeError" in errs[0] and "abc123" not in errs[0]
        finally:
            await n.stop()
    run(go())


# ================================================================== API
async def http(port, raw: bytes, read=True, timeout=5):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(raw)
    await w.drain()
    out = b""
    if read:
        try:
            out = await asyncio.wait_for(r.read(1_000_000), timeout)
        except asyncio.TimeoutError:
            out = b"<timeout>"
    w.close()
    head, _, body = out.partition(b"\r\n\r\n")
    status = int(head.split()[1]) if head.startswith(b"HTTP/1.1") else 0
    return status, head, body


def GET(path, extra=b""):
    return b"GET " + path.encode() + b" HTTP/1.1\r\nHost: x\r\n" + extra + b"\r\n"


def POST(path, body: bytes, extra=b""):
    return (b"POST " + path.encode() + b" HTTP/1.1\r\nHost: x\r\nContent-Length: " + str(len(body)).encode()
            + b"\r\n" + extra + b"\r\n" + body)


def fake_node(keys):
    chain = make_chain(keys)
    node = SimpleNamespace(chain=chain, mempool=SimpleNamespace(get=lambda t: None, __len__=lambda s: 0),
                           p2p=SimpleNamespace(ready_peers=lambda: []), status=lambda: {"ok": True})

    async def submit_tx(tx):
        raise api_mod.ValidationError("rejected by the mempool")
    node.submit_tx = submit_tx
    return node


def with_api(keys, coro, **kw):
    async def go():
        logs = []
        api = ApiServer(fake_node(keys), log=lambda m, level="info": logs.append((level, m)), **kw)
        await api.start()
        try:
            return await coro(api, logs)
        finally:
            await api.stop()
    return run(go())


def test_api_rejects_malformed_and_oversized_requests(keys):
    async def t(api, logs):
        p = api.port
        assert (await http(p, GET("/api/status")))[0] == 200
        assert (await http(p, POST("/api/tx", b"x", b"Content-Length: 5000000\r\n")))[0] in (400, 413)
        big = b"POST /api/tx HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % (MAX_BODY + 1)
        assert (await http(p, big))[0] == 413                                  # refuses WITHOUT reading the body
        for cl in (b"abc", b"-5", b"1e3", b"", b"99999999999"):
            st = (await http(p, b"POST /api/tx HTTP/1.1\r\nContent-Length: " + cl + b"\r\n\r\n"))[0]
            assert st in (400, 413), cl
        assert (await http(p, b"POST /api/tx HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nab"))[0] == 400
        assert (await http(p, b"GET /api/status HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"))[0] == 400
        assert (await http(p, GET("/api/status", b"X: " + b"a" * 20_000 + b"\r\n")))[0] == 431
        assert (await http(p, GET("/" + "a" * 3000)))[0] == 414
        assert (await http(p, b"DELETE /api/status HTTP/1.1\r\n\r\n"))[0] == 405
        assert (await http(p, b"\r\n"))[0] == 400
        for bad in (b"[]", b"123", b"null", b'"x"', b"{", b'{"version": 1}'):
            st, _, body = await http(p, POST("/api/tx", bad))
            assert st == 400 and b"error" in body, bad
        for path in ("/api/block/xyz", f"/api/block/{'9' * 40}", "/api/tx/zz", "/api/address/garbage"):
            assert (await http(p, GET(path)))[0] == 400, path
        assert (await http(p, GET("/api/block/" + "ab" * 32)))[0] == 404
    with_api(keys, t)


def test_api_rate_limit_happens_before_reading_the_body_and_tx_is_stricter(keys):
    async def t(api, logs):
        p = api.port
        codes = [(await http(p, GET("/api/status")))[0] for _ in range(14)]
        assert codes[:10] == [200] * 10 and 429 in codes[10:]                   # burst = 10, then 429
        st, head, _ = await http(p, b"POST /api/tx HTTP/1.1\r\nContent-Length: 100000\r\n\r\n", timeout=3)
        assert st == 429 and b"Retry-After" in head                              # without waiting for the body (there was no timeout)
    with_api(keys, t, rate_per_min=60)

    async def t2(api, logs):
        p = api.port
        posts = [(await http(p, POST("/api/tx", b"{}")))[0] for _ in range(8)]
        assert posts[:5] == [400] * 5 and 429 in posts[5:]
        assert (await http(p, GET("/api/status")))[0] == 200                      # reads stay free
    with_api(keys, t2, tx_rate_per_min=10)


def test_api_forwarded_for_is_ignored_unless_proxy_is_trusted(keys):
    async def spoof(api, logs):
        codes = [(await http(api.port, GET("/api/status", b"X-Forwarded-For: 9.9.9.%d\r\n" % i)))[0] for i in range(14)]
        assert 429 in codes                                                       # forging the header does not help
    with_api(keys, spoof, rate_per_min=60)

    async def trusted(api, logs):
        codes = [(await http(api.port, GET("/api/status", b"X-Forwarded-For: 1.1.1.1, 9.9.9.%d\r\n" % i)))[0]
                 for i in range(14)]
        assert 429 not in codes                                                   # each real client has its own bucket
        codes = [(await http(api.port, GET("/api/status", b"X-Forwarded-For: 8.8.8.8\r\n")))[0] for _ in range(14)]
        assert 429 in codes
    with_api(keys, trusted, rate_per_min=60, trust_proxy=True)


def test_api_connection_caps_and_slow_clients(keys, monkeypatch):
    monkeypatch.setattr(api_mod, "REQUEST_TIMEOUT", 1)

    async def t(api, logs):
        idle = [await asyncio.open_connection("127.0.0.1", api.port) for _ in range(2)]
        await asyncio.sleep(0.1)
        assert (await http(api.port, GET("/api/status")))[0] == 503               # 3rd connection from the same IP
        r, _ = idle[0]
        data = await asyncio.wait_for(r.read(10_000), 4)                          # slow client (slowloris)
        assert data.startswith(b"HTTP/1.1 408")
        for _, w in idle:
            w.close()
        await asyncio.sleep(0.2)
        assert (await http(api.port, GET("/api/status")))[0] == 200               # counters released
        assert api._total == 0
    with_api(keys, t, max_conn_per_ip=2)


def test_api_internal_errors_are_500_and_logs_leak_nothing(keys):
    async def t(api, logs):
        def boom():
            raise RuntimeError("internal failure with seed=abc123 and password=hunter2")
        api.node.status = boom
        st, _, body = await http(api.port, GET("/api/status"))
        assert st == 500 and json.loads(body) == {"error": "internal error"}
        flat = " ".join(m for _, m in logs)
        assert "RuntimeError" in flat and "abc123" not in flat and "hunter2" not in flat
        assert (await http(api.port, GET("/api/params")))[0] == 200               # the server is still standing
    with_api(keys, t)


def test_type_cap_also_applies_when_json_key_order_hides_the_type():
    async def go():
        n = await start(genesis())
        try:
            r, w, send, recv = await raw_handshake(n)
            assert await wait_for(lambda: any(p.ready for p in n.p2p.peers))
            sp = server_peer(n)
            body = json.dumps({"d": "a" * 400, "t": "ping"}).encode()       # "t" after "d": the read shortcut does not see it
            await send(None, raw=body)
            assert await wait_for(lambda: sp.score >= 45, 5)
        finally:
            await n.stop()
    run(go())


def test_blocks_we_asked_for_do_not_count_against_the_byte_budget():
    async def go():
        n = await start(genesis())
        try:
            r, w, send, recv = await raw_handshake(n)
            assert await wait_for(lambda: any(p.ready for p in n.p2p.peers))
            sp = server_peer(n)
            for _ in range(7):                            # 7 x ~3 MB > 16 MB of burst
                sp.sync_inflight = True                   # we are syncing with this peer: the reply is expected
                await send("blocks", {"blocks": [], "pad": "x" * 3_000_000})
                await wait_for(lambda: not sp.sync_inflight, 5)
            assert sp.score == 0 and not sp.closed
            for _ in range(7):                            # without a request from us, the same volume blows the budget
                await send("blocks", {"blocks": [], "pad": "x" * 3_000_000})
            assert await wait_for(lambda: sp.score > 0, 10)
        finally:
            await n.stop()
    run(go())
