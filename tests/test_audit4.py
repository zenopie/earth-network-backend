"""Audit round 4 (backend): regressions for each finding.

B5: _yymmdd_unix took Feb 31 as Mar 3 (Go's time.Date normalisation); the
chain's yymmddToUnix now refuses a date that does not round-trip, so must we.
"""
import pytest

from routers import gas


@pytest.mark.parametrize("v", [250231, 250230, 250431, 230229, 251131])
def test_impossible_dates_are_refused_like_the_chain(v):
    with pytest.raises(ValueError, match="calendar date"):
        gas._yymmdd_unix(v)


def test_real_dates_still_parse():
    assert gas._yymmdd_unix(240229) == 1709164800  # 2024 is a leap year
    assert gas._yymmdd_unix(250101) == 1735689600
    assert gas._yymmdd_unix(251231) == 1767139200
