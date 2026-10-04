"""The gas-check queue under a flood of junk: one place per client, the
reserved places and their priority, and refusing before the queue once a
refusal budget is spent.
"""
import asyncio
import ipaddress
import json

import httpx
import pytest

import config
from services import gascheck, knowndsc, ratelimit
from services.zk import privacy
from tests.gas_fixtures import gas_app, reg_body, weak_pow, with_pow
from tests.gas_fixtures import DSC_KEY as KNOWN_DSC  # reg_body's public_signals[3]


BASE6 = int(ipaddress.IPv6Address("2001:db8:1:2::"))


@pytest.fixture
def slow_gas_check(monkeypatch):
    """Stands in for `earthd gas-check` as a slow proof verify: refuses junk,
    accepts nullifier 999 (the real registrant). Records the order it ran in."""
    ran = []

    async def fake_exec(*args, **kwargs):
        class Proc:
            returncode = 0

            async def communicate(self, stdin):
                msg = json.loads(stdin)
                nf = int(msg["public_signals"][2])
                ran.append(nf)
                # The first check runs longer: requests sent after it (the
                # real registrant, 20 ms into a flood) must be queued before
                # it ends, or the next ordinary waiter takes the slot and
                # the order under test is a race (it was, ~1 run in 20).
                await asyncio.sleep(0.3 if len(ran) == 1 else 0.05)
                if nf == 999:
                    return json.dumps({"ok": True, "nullifier": privacy.field_bytes(nf).hex()}).encode(), b""
                return b'{"ok": false, "error": "invalid registration proof"}', b""
        return Proc()

    monkeypatch.setattr(gascheck.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(config, "TRUST_CF_CONNECTING_IP", True)
    monkeypatch.setattr(config, "POW_RESERVED_BITS", 6)
    monkeypatch.setattr(config, "POW_SHED_BITS", 8)
    monkeypatch.setattr(config, "POW_LOAD_EXTRA_BITS", 0)
    return ran


def junk(i: int, dsc: int = 123456) -> dict:
    body = reg_body(nf=1000 + i)
    body["public_signals"][3] = str(dsc)
    return body


async def _flood(junk_ips, real_ip, real_body, *, settle=0.02):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gas_app()), base_url="http://t", timeout=60) as c:
        tasks = [asyncio.create_task(c.post("/gas/register", json=junk(i), headers={"cf-connecting-ip": ip}))
                 for i, ip in enumerate(junk_ips)]
        await asyncio.sleep(settle)
        real = await c.post("/gas/register", json=real_body, headers={"cf-connecting-ip": real_ip})
        return [await t for t in tasks], real


def test_one_64_holds_one_place(slow_gas_check, shields):
    """21 addresses from one /64 hold one place."""
    ips = [str(ipaddress.IPv6Address(BASE6 + i)) for i in range(21)]
    rs, real = asyncio.run(_flood(ips, "198.51.100.7", reg_body(nf=999)))
    assert real.status_code == 200, real.text
    assert sorted(r.status_code for r in rs).count(429) == 20
    assert len([n for n in slow_gas_check if n != 999]) == 1


def test_a_known_dsc_registrant_gets_a_reserved_place_and_goes_first(slow_gas_check, shields):
    """Junk from many separate networks fills the ordinary lane."""
    knowndsc.set_known({privacy.field_bytes(KNOWN_DSC)})
    ips = [f"203.0.113.{i}" for i in range(1, 30)]
    rs, real = asyncio.run(_flood(ips, "198.51.100.7", with_pow(reg_body(nf=999), config.POW_RESERVED_BITS)))
    assert real.status_code == 200, real.text
    ordinary = config.GAS_CHECK_MAX_WAITING - config.GAS_CHECK_RESERVED_WAITING
    assert sum(r.status_code == 503 for r in rs) >= len(ips) - ordinary
    # Served right after the check that was already running, ahead of the queue.
    assert slow_gas_check.index(999) == 1


def test_without_a_known_dsc_the_ordinary_lane_can_be_full(slow_gas_check, shields):
    ips = [f"203.0.113.{i}" for i in range(1, 30)]
    _, real = asyncio.run(_flood(ips, "198.51.100.7", reg_body(nf=999)))
    assert real.status_code in (429, 503)


def test_spent_refusal_budget_turns_requests_without_work_away_before_the_queue(slow_gas_check, shields, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_MINUTE", 3)
    for _ in range(3):
        ratelimit.note_refusal()
    ran = len(slow_gas_check)

    async def go(body, ip):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gas_app()), base_url="http://t") as c:
            return await c.post("/gas/register", json=body, headers={"cf-connecting-ip": ip})

    resp = asyncio.run(go(junk(1), "203.0.113.50"))
    assert resp.status_code == 428 and "failed registrations" in resp.json()["message"]
    assert resp.json()["pow"]["bits"] == config.POW_SHED_BITS
    assert len(slow_gas_check) == ran, "never queued"
    # Too little work is not enough either.
    assert asyncio.run(go(weak_pow(junk(2), config.POW_SHED_BITS), "203.0.113.51")).status_code == 428
    assert len(slow_gas_check) == ran
    # A registrant who pays the shedding work is queued, known signer or not.
    assert asyncio.run(go(with_pow(reg_body(nf=999), config.POW_SHED_BITS), "198.51.100.7")).status_code == 200


def test_proof_refusals_spend_the_budget(slow_gas_check, shields, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_MINUTE", 2)
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_DSC_PER_MINUTE", 0)
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_COUNTRY_PER_MINUTE", 0)

    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gas_app()), base_url="http://t") as c:
            return [(await c.post("/gas/register", json=junk(i), headers={"cf-connecting-ip": f"203.0.113.{i + 1}"})).status_code
                    for i in range(4)]

    assert asyncio.run(go()) == [403, 403, 428, 428]


def test_priority_slot_serves_priority_first_then_fifo():
    order = []

    async def worker(name, prio):
        async with gascheck._slot.hold(prio):
            order.append(name)
            await asyncio.sleep(0.01)

    async def go():
        first = asyncio.create_task(worker("first", False))
        await asyncio.sleep(0)
        tasks = [asyncio.create_task(worker(n, p)) for n, p in (("o1", False), ("p1", True), ("o2", False), ("p2", True))]
        await asyncio.gather(first, *tasks)

    asyncio.run(go())
    assert order == ["first", "p1", "p2", "o1", "o2"]


def test_priority_slot_survives_a_cancelled_waiter():
    async def go():
        async def hold(t):
            async with gascheck._slot.hold(False):
                await asyncio.sleep(t)
        a = asyncio.create_task(hold(0.02))
        await asyncio.sleep(0)
        b = asyncio.create_task(hold(0))
        await asyncio.sleep(0)
        b.cancel()
        await a
        with pytest.raises(asyncio.CancelledError):
            await b
        await asyncio.wait_for(hold(0), 1)  # the slot is free again
    asyncio.run(go())
