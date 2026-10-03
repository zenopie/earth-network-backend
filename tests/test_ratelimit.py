"""The per-client limiter: keyed by network, fixed-size entries, LRU-bounded
(re-audit K2/K3; poc_limiter_mem.py, poc_queue_starve.py's per-address keying)."""
import ipaddress
import tracemalloc

import pytest

import config
from services import ratelimit

BASE6 = int(ipaddress.IPv6Address("2001:db8:1:2::"))


def v6(i: int) -> str:
    return str(ipaddress.IPv6Address(BASE6 + i))


def test_every_address_in_one_64_is_one_client(monkeypatch):
    monkeypatch.setattr(config, "REGISTER_IPV6_PREFIX", 64)
    keys = {ratelimit.client_key(v6(i)) for i in (0, 1, 2**63, 2**64 - 1)}
    assert len(keys) == 1
    assert ratelimit.client_key(v6(2**64)) not in keys  # the next /64


def test_one_48_is_one_client_by_default():
    """audit-3 poc_ipv6.py: 2000 /64s of one VPS customer's /48 were 2000
    clients (20000 requests a window); keyed by /48 they are one."""
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
    """poc_limiter_mem.py: REGISTER_IP_MAX_TRACKED distinct clients used to hold
    a deque each and then be cleared wholesale."""
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
