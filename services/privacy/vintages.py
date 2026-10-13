"""Stake vintages (chain v1.3.0; x/shieldedstaking/types/vintage.go, chain
ORCHARD_DESIGN.md 8.9), pinned to the chain's Go by zk_vectors.json.

A stake note's asset names its validator and its vintage, the UTC month
(YYYYMM) its stake was last checked in:

    derth/<valoper>/<YYYYMM>     every vintage but the base one
    derth/<valoper>              the base vintage (earth-1: the v1.3.0 upgrade
                                 month): every note made before v1.3.0

One denom per (validator, vintage): the suffixed spelling of the base month
is a different asset the chain never supplies. A vintage is live in its own
month and the 12 after it, and retires at 00:00 UTC on the 1st of month + 13
(from then every msg on it but a withdrawal is refused); its value is booked
at the next epoch end (it is "retiring" until then).

A credit (a delegation, a redelegation's credit lane, a check-in) lands in
the current month's vintage, or, during a month's first GRACE_SECONDS, in the
previous month's (types.NewVintageCtx, VintageCtx.CheckCredit): a proof built
before the boundary and included after it.

The indexer reads vintages only from events (a check-in's, a retirement's, a
withdrawal's, the msgs' vintage attributes), to check them against the
block's month; it stores none. Nothing here is keyed by a note or an owner.
"""
import calendar
import re
from datetime import datetime, timezone

DERTH_PREFIX = "derth/"
# The current month and the 12 before it.
LIVE_VINTAGE_MONTHS = 13
MIN_VINTAGE_YEAR = 2000
MAX_VINTAGE_YEAR = 9999
# types.VintageGraceSeconds (= ClearBeforeSlackSeconds).
GRACE_SECONDS = 3600

_SUFFIX = re.compile(r"[0-9]{6}")


def is_vintage(m: int) -> bool:
    """types.ValidateVintage: a YYYYMM month, year 2000..9999."""
    y, mo = divmod(m, 100)
    return MIN_VINTAGE_YEAR <= y <= MAX_VINTAGE_YEAR and 1 <= mo <= 12


def index(m: int) -> int:
    """types.VintageIndex: m as months since year 0."""
    return (m // 100) * 12 + m % 100 - 1


def from_index(i: int) -> int:
    return 0 if i < 0 else (i // 12) * 100 + i % 12 + 1


def add_months(m: int, n: int) -> int:
    return from_index(index(m) + n)


def month_of(unix: int) -> int:
    """types.MonthOf: the UTC month of a unix time (a block's)."""
    t = datetime.fromtimestamp(unix, timezone.utc)
    return t.year * 100 + t.month


def start(m: int) -> int:
    """types.VintageStart, as unix seconds: 00:00 UTC on the 1st of m."""
    return calendar.timegm((m // 100, m % 100, 1, 0, 0, 0))


def retires_at(m: int) -> int:
    """types.VintageRetiresAt, as unix seconds: the 1st of m + 13."""
    return start(add_months(m, LIVE_VINTAGE_MONTHS))


def oldest_live(cur: int) -> int:
    return add_months(cur, -(LIVE_VINTAGE_MONTHS - 1))


def is_live(m: int, cur: int) -> bool:
    """types.VintageLive: cur - 12 <= m <= cur."""
    i, c = index(m), index(cur)
    return c - LIVE_VINTAGE_MONTHS < i <= c


def is_retired(m: int, cur: int) -> bool:
    """types.VintageRetired: m has retired by month cur."""
    return index(m) <= index(cur) - LIVE_VINTAGE_MONTHS


def grace(unix: int) -> int:
    """types.NewVintageCtx's Grace at block time unix: the previous month
    during the current one's first GRACE_SECONDS, else 0."""
    cur = month_of(unix)
    return add_months(cur, -1) if unix - start(cur) < GRACE_SECONDS else 0


def credit_ok(m: int, unix: int) -> bool:
    """VintageCtx.CheckCredit at block time unix: m is the block's month, or
    the previous one during the grace."""
    g = grace(unix)
    return m == month_of(unix) or (g != 0 and m == g)


def denom(valoper: str, m: int, base: int) -> str:
    """types.VintageDenom: the one denom of valoper's vintage m."""
    if m == base:
        return DERTH_PREFIX + valoper
    return f"{DERTH_PREFIX}{valoper}/{m:06d}"


def parse_denom(d: str) -> tuple[str, int] | None:
    """types.ParseDerthDenom: (valoper, month) of a derth denom, month 0 for
    the unsuffixed (base vintage) form; None for anything else (no prefix, an
    empty validator, a suffix that is not exactly a six-digit vintage)."""
    if not d.startswith(DERTH_PREFIX):
        return None
    rest = d[len(DERTH_PREFIX):]
    v, slash, suffix = rest.partition("/")
    if not v:
        return None
    if not slash:
        return v, 0
    if not _SUFFIX.fullmatch(suffix) or not is_vintage(int(suffix)):
        return None
    return v, int(suffix)
