"""Per-client and global limits for /gas/register, in front of the expensive check.

`earthd gas-check` runs one at a time (gascheck: ~120 MB a proof on a 256 MiB
lease), so without bounds one script could hold the queue and every real
registrant would wait behind its junk or be refused. All of it in memory (one
replica; a restart forgets it, which only loosens the limits for a while).

The client is a network, not an address: an IPv4 /32, or the IPv6 prefix of
REGISTER_IPV6_PREFIX bits (default /48: a VPS host routinely hands one
customer a /48, and keyed by /64 that customer held 65536 budgets; /56 or
/64 are looser, for an ingress where unrelated users share a /48). One /64 is
2^64 addresses, so a per-address key is no limit at all against IPv6.

Per client:

- a sliding window: at most REGISTER_IP_MAX_PER_WINDOW requests in
  REGISTER_IP_WINDOW_SECONDS, counted on arrival, malformed ones included. A
  sliding-window counter (this window's count, the last one's, weighted by
  overlap), so every client costs one fixed-size entry however many requests
  it makes. At most REGISTER_IP_MAX_TRACKED clients are kept; past that the
  least recently seen is evicted (and gets a fresh budget if it comes back),
  never the whole table.
- concurrency: at most one gas-check per client at a time. A second request
  while the first is queued or running fails fast with 429.

Refusal budgets: gas-check refusals that cost a proof verification (the
chain's "invalid registration proof": everything else it refuses on — the
DSC not chaining, a country or signer at its daily cap, a used binding — is
decided before the verifier runs, and a legitimate cap refusal must not shed
anyone) are counted over a minute, three ways: per DSC commitment
(REGISTER_REFUSALS_PER_DSC_PER_MINUTE), per issuing country
(REGISTER_REFUSALS_PER_COUNTRY_PER_MINUTE) and, as a backstop, network-wide
(REGISTER_REFUSALS_PER_MINUTE). A request whose signer, country or the
network has spent its budget is shed: it is queued only with a proof of work
at the shedding difficulty (services/pow), and refused 428 without one.
Junk that names one signer or country sheds that signer's or country's
registrants (who can still pay the work), not everyone's.

DSC cooldown: REGISTER_DSC_FAILURES_BEFORE_COOLDOWN verification failures
naming one DSC within REGISTER_DSC_COOLDOWN_SECONDS take it out of the
reserved lane (routers/gas) until they age out of that sliding window. A
commitment is public, so junk can copy a known one into the lane; doing so
now costs a proof of work a request and gets the signer demoted, not the
lane flooded.

The client address is CF-Connecting-IP when TRUST_CF_CONNECTING_IP is on
(right only where Cloudflare is the sole ingress — the Akash lease is
tunnel-only, so every request reaches it from cloudflared and the peer
address says nothing). Off (the default), it is the TCP peer. Anywhere else a
client chooses its own header and the limit is per-request.
"""
import ipaddress
import time
from collections import OrderedDict
from contextlib import contextmanager

from fastapi import Request

import config

# client key -> packed (window index << 32 | previous count << 16 | count).
# One small int per client, ordered least recently seen first.
_windows: "OrderedDict[int | str, int]" = OrderedDict()
_busy: set = set()
# Refusal budgets, keyed "*" (the network), ("dsc", commitment) and ("cc",
# country): one packed sliding-minute counter each, least recently touched
# first, at most REGISTER_REFUSAL_KEYS_TRACKED.
_refusals: "OrderedDict[object, int]" = OrderedDict()
# Verification failures per DSC commitment, a sliding window of
# REGISTER_DSC_COOLDOWN_SECONDS each, same bound.
_dsc_failures: "OrderedDict[bytes, int]" = OrderedDict()
NETWORK = "*"

_V6_TAG = 1 << 128  # keeps an IPv6 prefix's key apart from every IPv4 address's


def client_ip(request: Request) -> str:
    if config.TRUST_CF_CONNECTING_IP:
        ip = request.headers.get("cf-connecting-ip", "").strip()
        if ip:
            return ip
    return request.client.host if request.client else "unknown"


def client_key(ip: str) -> int | str:
    """The network a request is limited as: an IPv4 /32 or an IPv6 /REGISTER_IPV6_PREFIX.

    An IPv4-mapped IPv6 address is its IPv4 address. Anything unparseable is
    keyed as given (only the TCP peer or a trusted header reaches here).
    """
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return ip[:64]
    if addr.version == 6:
        if addr.ipv4_mapped is not None:
            return int(addr.ipv4_mapped)
        bits = max(0, min(128, config.REGISTER_IPV6_PREFIX))
        return _V6_TAG | (int(addr) >> (128 - bits))
    return int(addr)


def _count(entry: int, now: float, window: float) -> tuple[int, int, int]:
    """(window index, previous count, count) of a packed entry, rolled forward to now."""
    idx = int(now // window)
    e_idx, prev, cur = entry >> 32, (entry >> 16) & 0xFFFF, entry & 0xFFFF
    if e_idx == idx:
        return idx, prev, cur
    if e_idx == idx - 1:
        return idx, cur, 0
    return idx, 0, 0


def _estimate(prev: int, cur: int, now: float, window: float) -> float:
    overlap = 1.0 - (now % window) / window
    return prev * overlap + cur


def allow(key, now: float | None = None) -> bool:
    """Counts a request from client key; False when it is over the window's limit."""
    now = time.monotonic() if now is None else now
    window = config.REGISTER_IP_WINDOW_SECONDS
    entry = _windows.pop(key, 0)
    idx, prev, cur = _count(entry, now, window)
    ok = _estimate(prev, cur, now, window) < config.REGISTER_IP_MAX_PER_WINDOW
    if ok:
        cur = min(cur + 1, 0xFFFF)
    _windows[key] = idx << 32 | prev << 16 | cur  # re-inserted: now the most recent
    while len(_windows) > config.REGISTER_IP_MAX_TRACKED:
        _windows.popitem(last=False)
    return ok


def _bump(table: OrderedDict, key, now: float, window: float) -> None:
    idx, prev, cur = _count(table.pop(key, 0), now, window)
    table[key] = idx << 32 | prev << 16 | min(cur + 1, 0xFFFF)
    while len(table) > config.REGISTER_REFUSAL_KEYS_TRACKED:
        table.popitem(last=False)


def _rate(table: OrderedDict, key, now: float, window: float) -> float:
    if key not in table:
        return 0.0
    _, prev, cur = _count(table[key], now, window)
    return _estimate(prev, cur, now, window)


def _budgets(dsc: bytes | None, country: str | None):
    """(budget key, limit a minute) a request falls under; a limit <= 0 is off."""
    yield NETWORK, config.REGISTER_REFUSALS_PER_MINUTE
    if dsc is not None:
        yield ("dsc", dsc), config.REGISTER_REFUSALS_PER_DSC_PER_MINUTE
    if country is not None:
        yield ("cc", country), config.REGISTER_REFUSALS_PER_COUNTRY_PER_MINUTE


def note_refusal(dsc: bytes | None = None, country: str | None = None, now: float | None = None) -> None:
    """Counts one verification failure against the network's, the signer's and the country's budgets."""
    now = time.monotonic() if now is None else now
    for key, _ in _budgets(dsc, country):
        _bump(_refusals, key, now, 60.0)
    if dsc is not None:
        _bump(_dsc_failures, dsc, now, config.REGISTER_DSC_COOLDOWN_SECONDS)


def shedding(dsc: bytes | None = None, country: str | None = None, now: float | None = None) -> str | None:
    """Which budget this request falls under is spent ("network", "signer",
    "country"), or None. A shed request needs a proof of work to be queued."""
    now = time.monotonic() if now is None else now
    names = {NETWORK: "network"}
    for key, limit in _budgets(dsc, country):
        if limit > 0 and _rate(_refusals, key, now, 60.0) >= limit:
            return names.get(key) or ("signer" if key[0] == "dsc" else "country")
    return None


def dsc_cooling(dsc: bytes, now: float | None = None) -> bool:
    """Whether a DSC is out of the reserved lane: too many verification failures name it."""
    if config.REGISTER_DSC_FAILURES_BEFORE_COOLDOWN <= 0:
        return False
    now = time.monotonic() if now is None else now
    window = config.REGISTER_DSC_COOLDOWN_SECONDS
    return _rate(_dsc_failures, dsc, now, window) >= config.REGISTER_DSC_FAILURES_BEFORE_COOLDOWN


class Busy(Exception):
    """This client already has a check queued or running."""


@contextmanager
def one_at_a_time(key):
    """Holds key's single gas-check slot; raises Busy if it is taken."""
    if key in _busy:
        raise Busy(key)
    _busy.add(key)
    try:
        yield
    finally:
        _busy.discard(key)


def reset() -> None:
    _windows.clear()
    _busy.clear()
    _refusals.clear()
    _dsc_failures.clear()
