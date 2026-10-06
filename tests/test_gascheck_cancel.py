"""BD-7: a cancelled check kills its earthd before the slot is released."""
import asyncio
import os
import stat

import config
from services import gascheck


def _fake_earthd(tmp_path, body: str) -> str:
    p = tmp_path / "earthd"
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


def test_cancel_kills_earthd_and_frees_the_slot(tmp_path, monkeypatch):
    pidfile = tmp_path / "pid"
    monkeypatch.setattr(config, "EARTHD_BIN", _fake_earthd(tmp_path, f"echo $$ > {pidfile}\nexec sleep 30\n"))
    monkeypatch.setattr(config, "GAS_CHECK_TIMEOUT", 60)
    monkeypatch.setattr(gascheck, "_waiting", 0)

    async def go():
        task = asyncio.create_task(gascheck.registration({"x": 1}))
        for _ in range(200):
            if pidfile.exists() and pidfile.read_text().strip():
                break
            await asyncio.sleep(0.01)
        pid = int(pidfile.read_text())
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return pid

    pid = asyncio.run(go())
    try:
        os.kill(pid, 0)
        alive = True
    except ProcessLookupError:
        alive = False
    assert not alive, "earthd outlived the cancelled check"
    assert gascheck._slot._held is False
    assert gascheck._waiting == 0


def test_failure_message_is_the_last_stderr_line(tmp_path, monkeypatch):
    """BD-13: the Unavailable reason is a string, not a one-element list."""
    monkeypatch.setattr(config, "EARTHD_BIN", _fake_earthd(tmp_path, "echo first >&2\necho 'node status: refused' >&2\nexit 1\n"))
    monkeypatch.setattr(gascheck, "_waiting", 0)
    try:
        asyncio.run(gascheck.registration({}))
    except gascheck.Unavailable as e:
        assert str(e) == "node status: refused"
    else:
        raise AssertionError("no Unavailable")


def test_rate_limit_entries_expire_two_windows_after_last_use():
    """NO_LOGS: an IP-derived key is not kept past two windows of silence."""
    from collections import OrderedDict
    from services import ratelimit
    t = OrderedDict()
    assert ratelimit._allow(t, "a", 0.0, 10, 60.0, 100)
    assert ratelimit._allow(t, "b", 100.0, 10, 60.0, 100)
    assert "a" in t                      # window 0 is still the previous one at t=100
    ratelimit._allow(t, "c", 130.0, 10, 60.0, 100)
    assert "a" not in t and "b" in t     # a: last seen in window 0, now window 2
