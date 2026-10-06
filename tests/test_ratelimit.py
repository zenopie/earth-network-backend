"""Per-client limits (services/ratelimit): who a client is (an IPv4 address,
an IPv6 /48 for requests, a /64 for refusals), the sliding window, bounded
memory, one gas-check in flight, and how /gas/register applies them.
"""
import ipaddress
import tracemalloc

import pytest

import config
from services import gascheck, ratelimit
from tests.gas_fixtures import reg_body


BASE6 = int(ipaddress.IPv6Address("2001:db8:1:2::"))


def v6(i: int) -> str:
    return str(ipaddress.IPv6Address(BASE6 + i))


def test_every_address_in_one_64_is_one_client(monkeypatch):
    monkeypatch.setattr(config, "REGISTER_IPV6_PREFIX", 64)
    keys = {ratelimit.client_key(v6(i)) for i in (0, 1, 2**63, 2**64 - 1)}
    assert len(keys) == 1
    assert ratelimit.client_key(v6(2**64)) not in keys  # the next /64


def test_one_48_is_one_client_by_default():
    """2000 /64s of one VPS customer's /48 are one client, not 2000 (20000
    requests a window; audit 3)."""
    assert config.REGISTER_IPV6_PREFIX == 48
    base = "2001:db8:abcd:{:x}::1"
    allowed = 0
    for sub in range(2000):
        k = ratelimit.client_key(base.format(sub))
        allowed += sum(ratelimit.allow(k, now=1000.0) for _ in range(config.REGISTER_IP_MAX_PER_WINDOW))
    assert allowed == config.REGISTER_IP_MAX_PER_WINDOW
    assert len(ratelimit._windows) == 1
    assert ratelimit.client_key("2001:db8:abce::1") != ratelimit.client_key(base.format(0))  # the next /48


def test_ipv6_prefix_is_configurable(monkeypatch):
    monkeypatch.setattr(config, "REGISTER_IPV6_PREFIX", 56)
    base = int(ipaddress.IPv6Address("2001:db8:1:200::"))  # /56-aligned
    key = ratelimit.client_key
    assert key(str(ipaddress.IPv6Address(base))) == key(str(ipaddress.IPv6Address(base + (255 << 64) + 9)))
    assert key(str(ipaddress.IPv6Address(base))) != key(str(ipaddress.IPv6Address(base + (256 << 64))))


def test_ipv4_is_per_address_and_mapped_v6_is_ipv4():
    assert ratelimit.client_key("198.51.100.7") != ratelimit.client_key("198.51.100.8")
    assert ratelimit.client_key("::ffff:198.51.100.7") == ratelimit.client_key("198.51.100.7")
    # An IPv6 prefix never collides with an IPv4 address.
    assert ratelimit.client_key("::c633:6407") != ratelimit.client_key("198.51.100.7")
    assert ratelimit.client_key("unknown") == "unknown"


def test_rotating_addresses_in_a_64_share_one_budget():
    lim = config.REGISTER_IP_MAX_PER_WINDOW
    allowed = sum(ratelimit.allow(ratelimit.client_key(v6(i)), now=1000.0) for i in range(lim * 3))
    assert allowed == lim


def test_memory_is_bounded_at_the_cap(monkeypatch):
    """REGISTER_IP_MAX_TRACKED distinct clients cost one small fixed-size
    entry each, and the table is never cleared wholesale."""
    cap = 20_000
    monkeypatch.setattr(config, "REGISTER_IP_MAX_TRACKED", cap)
    tracemalloc.start()
    try:
        base = tracemalloc.get_traced_memory()[0]
        for i in range(cap * 2):
            assert ratelimit.allow(ratelimit.client_key(v6(i << 80)), now=1000.0)  # distinct /48s
        held = tracemalloc.get_traced_memory()[0] - base
    finally:
        tracemalloc.stop()
    assert len(ratelimit._windows) == cap
    assert held < 300 * cap, f"{held / cap:.0f} bytes per client"


def test_eviction_is_least_recently_seen_not_clear_all(monkeypatch):
    monkeypatch.setattr(config, "REGISTER_IP_MAX_TRACKED", 3)
    monkeypatch.setattr(config, "REGISTER_IP_MAX_PER_WINDOW", 1)
    for k in ("a", "b", "c"):
        assert ratelimit.allow(k, now=1000.0)
    assert not ratelimit.allow("a", now=1001.0)  # a is now the most recent
    assert ratelimit.allow("d", now=1002.0)      # evicts b, the least recent
    assert list(ratelimit._windows) == ["c", "a", "d"]
    assert not ratelimit.allow("a", now=1003.0), "a busy client is not forgotten by a flood of others"


def test_the_window_slides_with_weighting(monkeypatch):
    monkeypatch.setattr(config, "REGISTER_IP_MAX_PER_WINDOW", 10)
    monkeypatch.setattr(config, "REGISTER_IP_WINDOW_SECONDS", 100.0)
    for _ in range(10):
        assert ratelimit.allow("k", now=150.0)
    assert not ratelimit.allow("k", now=199.0)
    # Half-way into the next window half of the last one still counts: 5 left.
    assert sum(ratelimit.allow("k", now=250.0) for _ in range(10)) == 5
    # Two windows on, nothing counts.
    assert sum(ratelimit.allow("k", now=400.0) for _ in range(20)) == 10


def test_refusal_budget(monkeypatch):
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_MINUTE", 3)
    for _ in range(2):
        ratelimit.note_refusal(now=60.0)
    assert not ratelimit.shedding(now=61.0)
    ratelimit.note_refusal(now=62.0)
    assert ratelimit.shedding(now=63.0)
    ratelimit.note_refusal(now=64.0)
    assert ratelimit.shedding(now=125.0)       # 4 refusals, still weighted in the next minute
    assert not ratelimit.shedding(now=240.0)   # and gone after it


def test_refusal_budget_off(monkeypatch):
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_MINUTE", 0)
    for _ in range(100):
        ratelimit.note_refusal(now=60.0)
    assert not ratelimit.shedding(now=60.0)


def test_refusals_are_keyed_per_64_and_requests_per_48():
    a, b = "2001:db8:1:0::1", "2001:db8:1:1::1"
    assert ratelimit.client_key(a) == ratelimit.client_key(b)
    assert ratelimit.refusal_key(a) != ratelimit.refusal_key(b)
    assert ratelimit.refusal_key("2001:db8:1:0::1") == ratelimit.refusal_key("2001:db8:1:0:ffff::2")
    assert ratelimit.refusal_key("::ffff:100.64.0.1") == ratelimit.refusal_key("100.64.0.1") == \
        ratelimit.client_key("100.64.0.1")


def test_the_window_slides():
    ratelimit.reset()
    lim = config.REGISTER_IP_MAX_PER_WINDOW
    for i in range(lim):
        assert ratelimit.allow("x", now=1000.0 + i)
    assert not ratelimit.allow("x", now=1000.0 + lim)
    assert ratelimit.allow("x", now=1000.0 + config.REGISTER_IP_WINDOW_SECONDS + 0.5)


def test_per_ip_window_counts_junk_too(client, shields, chain_says, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_IP_MAX_PER_WINDOW", 2)
    assert client.post("/gas/register", json=reg_body(proof="")).status_code == 400
    assert client.post("/gas/register", json=reg_body()).status_code == 200
    resp = client.post("/gas/register", json=reg_body(nf=2))
    assert resp.status_code == 429
    assert len(chain_says["asked"]) == 1


def test_cf_connecting_ip_separates_clients(client, shields, chain_says, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_IP_MAX_PER_WINDOW", 1)
    monkeypatch.setattr(config, "TRUST_CF_CONNECTING_IP", True)
    a, b = {"CF-Connecting-IP": "203.0.113.1"}, {"CF-Connecting-IP": "203.0.113.2"}
    assert client.post("/gas/register", json=reg_body(nf=1), headers=a).status_code == 200
    assert client.post("/gas/register", json=reg_body(nf=2), headers=a).status_code == 429
    assert client.post("/gas/register", json=reg_body(nf=3), headers=b).status_code == 200


def test_cf_connecting_ip_ignored_when_not_trusted(client, shields, chain_says, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_IP_MAX_PER_WINDOW", 1)
    monkeypatch.setattr(config, "TRUST_CF_CONNECTING_IP", False)
    assert client.post("/gas/register", json=reg_body(nf=1), headers={"CF-Connecting-IP": "203.0.113.1"}).status_code == 200
    # A new header value is not a new client: the peer is the same.
    assert client.post("/gas/register", json=reg_body(nf=2), headers={"CF-Connecting-IP": "203.0.113.2"}).status_code == 429


def test_one_gas_check_per_client_at_a_time(client, shields, chain_says, monkeypatch):
    monkeypatch.setattr(config, "TRUST_CF_CONNECTING_IP", True)
    ratelimit._busy.add(ratelimit.client_key("203.0.113.9"))  # a check of this client's is in flight
    resp = client.post("/gas/register", json=reg_body(), headers={"CF-Connecting-IP": "203.0.113.9"})
    assert resp.status_code == 429
    assert chain_says["asked"] == []
    assert client.post("/gas/register", json=reg_body(), headers={"CF-Connecting-IP": "203.0.113.10"}).status_code == 200


def test_the_client_slot_is_freed_after_the_check(client, shields, chain_says, monkeypatch):
    chain_says["registration"] = gascheck.Unavailable("node down")
    assert client.post("/gas/register", json=reg_body()).status_code == 503
    assert ratelimit._busy == set()
    chain_says["registration"] = None
    assert client.post("/gas/register", json=reg_body()).status_code == 200


@pytest.mark.parametrize("raw", [b"{", b"[]", b'{"proof": 1}', b"\xff"])
def test_a_body_that_fails_the_schema_counts_against_the_client(client, monkeypatch, raw):
    monkeypatch.setattr(config, "REGISTER_IP_MAX_PER_WINDOW", 2)
    codes = [client.post("/gas/register", content=raw, headers={"content-type": "application/json"}).status_code
             for _ in range(3)]
    assert codes == [422, 422, 429]


def test_quiet_tables_are_swept_within_two_windows(monkeypatch):
    """R2-BD-2 / NO_LOGS policy 3: an IP-derived key is gone two windows after
    its client's last request even if that table never sees another request;
    a sweep (timer or any other table's call) drops it."""
    monkeypatch.setattr(config, "REGISTER_IP_WINDOW_SECONDS", 100.0)
    monkeypatch.setattr(config, "PRIVACY_IP_WINDOW_SECONDS", 10.0)
    monkeypatch.setattr(config, "REGISTER_CLIENT_REFUSAL_WINDOW_SECONDS", 100.0)
    ip = ratelimit.client_key("198.51.100.7")
    t0 = 1000.0  # the start of register window 10 and privacy window 100
    ratelimit.allow(ip, now=t0)
    ratelimit.allow_privacy(ip, now=t0)
    ratelimit.note_client_refusal(ip, now=t0)
    # Within two windows, a sweep keeps each live entry.
    ratelimit.sweep(now=t0 + 19.9)
    assert ip in ratelimit._privacy_windows
    ratelimit.sweep(now=t0 + 199.9)
    assert ip in ratelimit._windows and ip in ratelimit._client_refusals
    assert ip not in ratelimit._privacy_windows  # 2 privacy windows passed
    ratelimit.sweep(now=t0 + 200.0)
    assert not ratelimit._windows and not ratelimit._client_refusals


def test_a_read_of_one_table_prunes_the_others(monkeypatch):
    """A refusal-budget read (client_refused_out) used to prune nothing; now
    every entry point sweeps every table."""
    monkeypatch.setattr(config, "REGISTER_IP_WINDOW_SECONDS", 100.0)
    monkeypatch.setattr(config, "REGISTER_CLIENT_REFUSAL_WINDOW_SECONDS", 100.0)
    a, b = ratelimit.client_key("198.51.100.8"), ratelimit.client_key("198.51.100.9")
    ratelimit.note_client_refusal(a, now=1000.0)
    ratelimit.allow(a, now=1000.0)
    assert not ratelimit.client_refused_out(b, now=1250.0)
    assert a not in ratelimit._client_refusals and a not in ratelimit._windows


def test_sweep_timer_runs_and_stops(monkeypatch):
    import asyncio

    monkeypatch.setattr(ratelimit, "SWEEP_INTERVAL_SECONDS", 0.01)
    calls = []
    monkeypatch.setattr(ratelimit, "sweep", lambda now=None: calls.append(now))

    async def go():
        stop = asyncio.Event()
        task = asyncio.create_task(ratelimit.run(stop))
        await asyncio.sleep(0.05)
        stop.set()
        await asyncio.wait_for(task, 1)

    asyncio.run(go())
    assert len(calls) >= 2


def test_a_failed_sweep_does_not_end_the_timer(monkeypatch, caplog):
    """R3-BD-4: one exception in sweep() used to kill the task silently, and
    the 10 s expiry NO_LOGS policy 3 promises stopped for the process's life.
    The error line names the exception class, never a key."""
    import asyncio
    import logging

    monkeypatch.setattr(ratelimit, "SWEEP_INTERVAL_SECONDS", 0.01)
    calls = []

    def flaky(now=None):
        calls.append(now)
        if len(calls) == 1:
            raise KeyError(3232235777)  # what a racing popitem would raise: a key

    monkeypatch.setattr(ratelimit, "sweep", flaky)

    async def go():
        stop = asyncio.Event()
        task = asyncio.create_task(ratelimit.run(stop))
        await asyncio.sleep(0.05)
        stop.set()
        await asyncio.wait_for(task, 1)

    with caplog.at_level(logging.ERROR, logger="services.ratelimit"):
        asyncio.run(go())
    assert len(calls) >= 2
    assert "ratelimit sweep failed: KeyError" in caplog.text
    assert "3232235777" not in caplog.text


def test_routes_reaching_the_tables_run_on_the_loop():
    """R3-BD-4: a sync route runs in Starlette's threadpool, where its prune
    would race the loop's. Every route that calls into ratelimit is async."""
    import inspect

    from routers import gas

    for fn in (gas.pow_params, gas.register):
        assert inspect.iscoroutinefunction(fn), fn.__name__
