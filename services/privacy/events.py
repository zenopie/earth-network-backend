"""Turning one block's CometBFT results into the shielded pool's public changes.

What the chain emits (privacy/main; names in x/shielded/types/events.go,
x/personhood/keeper/identity.go, x/shieldedstaking/types/events.go):

    shielded_note        position, commitment (hex), ciphertext (base64)
    shielded_shield      sender, amount, position     (a public-value note)
    shielded_mint        module, amount, position     (a public-value note)
    shielded_nullifier   nullifier (hex)
    shielded_root        root (hex), tree_size, height        EndBlock
    identity_leaf        index, leaf (hex; 64 zeros when zeroed)
    identity_root        root (hex), tree_size, height        EndBlock
    shieldedstaking_epoch_validator  validator, rewards, delegated,
                                     undelegated, rate, supply   EndBlock
    shieldedstaking_epoch            epoch (the one that just ended)

Order. A block's state changes run PreBlock, BeginBlock, each tx in order,
EndBlock. block_results gives the txs' events per tx and everything else in
one finalize_block_events list, where the SDK marks BeginBlock and EndBlock
events with a `mode` attribute (PreBlock events carry none). So: unmarked and
BeginBlock events, then the txs, then EndBlock events — the order notes were
appended in, which the store checks.

Failed txs. A private tx's notes and nullifiers are written by the ante
(x/shielded/ante). SDK v0.53 commits the ante's writes before running the
msgs, and when a msg then fails, DeliverTx still returns the ante's events
(and only those) in the failed tx's result (baseapp.runTx returns anteEvents
on every path after msCache.Write; deliverTx puts them in the ExecTxResult).
A tx whose ante fails writes nothing and returns no events. So every event in
every tx result describes state that persisted, whatever the code, and every
tx is read regardless of its code.
"""
import base64
from dataclasses import dataclass, field

ZERO32 = bytes(32)


class EventError(Exception):
    """An event the chain should never emit: a malformed attribute."""


@dataclass
class Note:
    position: int
    cm: bytes
    ciphertext: bytes
    amount: str | None = None  # "<n><denom>" when the note's value is public (shield, mint)


@dataclass
class IdentityWrite:
    index: int
    leaf: bytes  # ZERO32 when zeroed


@dataclass
class Root:
    root: bytes
    tree_size: int


@dataclass
class Rate:
    validator: str
    rate: str
    supply: str
    rewards: str
    delegated: str
    undelegated: str
    epoch: int | None = None


@dataclass
class BlockDelta:
    height: int
    time: int  # unix seconds of the block header, as RootRecord.time
    hash: str
    notes: list[Note] = field(default_factory=list)
    nullifiers: list[bytes] = field(default_factory=list)
    identity: list[IdentityWrite] = field(default_factory=list)
    note_root: Root | None = None
    identity_root: Root | None = None
    rates: list[Rate] = field(default_factory=list)


def _attrs(event: dict) -> dict[str, str]:
    out = {}
    for a in event.get("attributes") or []:
        out[a.get("key", "")] = a.get("value", "")
    return out


def _hex32(value: str, what: str) -> bytes:
    try:
        b = bytes.fromhex(value)
    except ValueError as exc:
        raise EventError(f"{what}: not hex") from exc
    if len(b) != 32:
        raise EventError(f"{what}: {len(b)} bytes, want 32")
    return b


def _int(value: str, what: str) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError) as exc:
        raise EventError(f"{what}: not an integer") from exc
    if v < 0:
        raise EventError(f"{what}: negative")
    return v


def ordered_events(results: dict) -> list[dict]:
    """A block's events in execution order (see the module docstring)."""
    finalize = results.get("finalize_block_events") or []
    before = [e for e in finalize if _attrs(e).get("mode") != "EndBlock"]
    after = [e for e in finalize if _attrs(e).get("mode") == "EndBlock"]
    txs = []
    for tx in results.get("txs_results") or []:
        txs.extend(tx.get("events") or [])
    return before + txs + after


def parse_block(height: int, time: int, block_hash: str, results: dict) -> BlockDelta:
    if int(results.get("height", height)) != height:
        raise EventError(f"block_results for height {results.get('height')}, asked {height}")
    d = BlockDelta(height=height, time=time, hash=block_hash)
    notes_by_pos: dict[int, Note] = {}
    pending_rates: list[Rate] = []
    for ev in ordered_events(results):
        t = ev.get("type")
        if t == "shielded_note":
            a = _attrs(ev)
            try:
                ct = base64.b64decode(a.get("ciphertext", ""), validate=True)
            except ValueError as exc:
                raise EventError("shielded_note ciphertext: not base64") from exc
            n = Note(_int(a.get("position"), "shielded_note position"), _hex32(a.get("commitment", ""), "shielded_note commitment"), ct)
            d.notes.append(n)
            notes_by_pos[n.position] = n
        elif t in ("shielded_shield", "shielded_mint"):
            a = _attrs(ev)
            n = notes_by_pos.get(_int(a.get("position"), f"{t} position"))
            if n is None:
                raise EventError(f"{t} names position {a.get('position')}, not a note of this block")
            n.amount = a.get("amount") or None
        elif t == "shielded_nullifier":
            d.nullifiers.append(_hex32(_attrs(ev).get("nullifier", ""), "shielded_nullifier"))
        elif t == "shielded_root":
            a = _attrs(ev)
            d.note_root = Root(_hex32(a.get("root", ""), "shielded_root"), _int(a.get("tree_size"), "shielded_root tree_size"))
            if "height" in a and _int(a["height"], "shielded_root height") != height:
                raise EventError("shielded_root height is not the block's")
        elif t == "identity_leaf":
            a = _attrs(ev)
            d.identity.append(IdentityWrite(_int(a.get("index"), "identity_leaf index"), _hex32(a.get("leaf", ""), "identity_leaf leaf")))
        elif t == "identity_root":
            a = _attrs(ev)
            d.identity_root = Root(_hex32(a.get("root", ""), "identity_root"), _int(a.get("tree_size"), "identity_root tree_size"))
            if "height" in a and _int(a["height"], "identity_root height") != height:
                raise EventError("identity_root height is not the block's")
        elif t == "shieldedstaking_epoch_validator":
            a = _attrs(ev)
            pending_rates.append(Rate(
                validator=a.get("validator", ""), rate=a.get("rate", ""), supply=a.get("supply", ""),
                rewards=a.get("rewards", ""), delegated=a.get("delegated", ""), undelegated=a.get("undelegated", ""),
            ))
        elif t == "shieldedstaking_epoch":
            # Emitted after the epoch's validator events, naming the epoch
            # that just ended. An epoch end that failed before this event
            # leaves its validator rows without an epoch (they are still the
            # rates the validators now have) and is retried next block.
            epoch = _int(_attrs(ev).get("epoch"), "shieldedstaking_epoch epoch")
            for r in pending_rates:
                r.epoch = epoch
            d.rates.extend(pending_rates)
            pending_rates = []
    d.rates.extend(pending_rates)
    return d
