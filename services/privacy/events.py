"""Turning one block's CometBFT results into the shielded pool's public changes.

What the chain emits (privacy/orchard; names in x/shielded/types/events.go,
x/personhood/keeper/identity.go, x/shieldedstaking/types/events.go and
x/shieldedstaking/keeper/stake_tree.go):

    shielded_note        position, commitment (hex), ciphertext (base64)
                         (a bundle's action outputs, MsgSend's included, and
                         every chain-minted note; a minted note's ciphertext
                         is its required 177-byte amount-blind v2 one)
    shielded_shield      sender, amount, position, ciphertext  (a public-value note)
    shielded_mint        module, amount, position, ciphertext  (a public-value note)
                         ciphertext repeats the shielded_note's; checked equal
    shielded_nullifier   nullifier (hex)
    shielded_root        root (hex), tree_size, height        EndBlock
    identity_leaf        index, leaf (hex; 64 zeros when zeroed)
    identity_root        root (hex), tree_size, height        EndBlock
    handle_bound / handle_moved / handle_released
                         a handle directory record changed (attributes
                         not read: the directory is re-read whole from the
                         Handles query, services/privacy/handles)
    shieldedstaking_epoch_validator  validator, rewards, delegated,
                                     undelegated, rate, supply   EndBlock
    shieldedstaking_epoch            epoch (the one that just ended)

The stake note tree (x/shieldedstaking's own append-only depth-32 Poseidon2
tree of owner-locked derth/<valoper> and unbond/<valoper>/<epoch> notes, its
own nullifier set and roots):

    shieldedstaking_stake_note       position_id, commitment (hex), ciphertext
                                     (base64), and for a note the chain minted
                                     (value public) also denom, amount, spc (hex).
                                     A minted note's ciphertext is its blind
                                     stake ciphertext (177 bytes, salt
                                     "earth.stake.v1", version 0x03); a created
                                     one's is the stake proof's.
    shieldedstaking_stake_nullifier  nullifier (hex), index (its leaf index in
                                     the stake nullifier tree: 1, 2, 3, ... in
                                     insertion order; leaf 0 is the sentinel)
    shieldedstaking_stake_root       root (hex), tree_size              EndBlock
    shieldedstaking_snapshot         proposal_id, root (hex), tree_size,
                                     nf_root (hex), nf_size: the stake note
                                     tree and the stake nullifier tree a
                                     proposal's stake votes prove against

The stake nullifier tree (ORCHARD_DESIGN.md section 15) is an indexed
(sorted) Merkle tree whose leaf positions are insertion order, so wallets
rebuild it from the nullifiers in index order; the store refuses an index
that is not exactly the next one.

Most stake notes and nullifiers are written by the msg, so a failed staking
msg leaves none of them. A claim (MsgClaimUnbonding) runs in the private ante
(it pays its fee from what it claims): its nullifiers and its change note
persist, and their events are in the tx result, even when the tx then fails.
Every tx is read whatever its code (below), so both cases come out right.

Not read, because they change no tree and no rate a wallet derives:
shielded_unshield / _spend_to_module / _fee / _asset, the dex's LP events
(private LP shares are ordinary shielded_note events; add/remove/complete
liquidity events name no provider), shieldedstaking_delegate / _undelegate /
_claim / _position / _stake_vote (its vote_nullifier is per proposal and
spends nothing) / _matured and
shieldedstaking_self_bond_compounded (an operator's own SDK self-bond grows;
derth rates come from shieldedstaking_epoch_validator as before).

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
HANDLE_EVENTS = frozenset({"handle_bound", "handle_moved", "handle_released"})


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
class StakeNote:
    position: int
    cm: bytes
    ciphertext: bytes = b""          # every stake note (minted: the blind stake ciphertext)
    denom: str | None = None         # a note the chain minted: denom, amount, spc public
    amount: str | None = None
    spc: bytes | None = None


@dataclass
class StakeNullifier:
    nf: bytes
    index: int  # leaf index in the stake nullifier tree (first value: 1)


@dataclass
class Snapshot:
    proposal_id: int
    root: bytes      # stake note tree root (empty when the tree had none)
    tree_size: int
    nf_root: bytes   # stake nullifier tree root at nf_size
    nf_size: int     # leaf count, sentinel included (0: nothing inserted)


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
    stake_notes: list[StakeNote] = field(default_factory=list)
    stake_nullifiers: list[StakeNullifier] = field(default_factory=list)
    stake_root: Root | None = None
    snapshots: list[Snapshot] = field(default_factory=list)
    # The epoch a shieldedstaking_epoch event in this block ended, if any.
    epoch_ended: int | None = None
    # A handle directory record changed in this block.
    handles_changed: bool = False


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


def _b64(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise EventError(f"{what}: not base64") from exc


def _stake_note(a: dict[str, str]) -> StakeNote:
    n = StakeNote(_int(a.get("position_id"), "shieldedstaking_stake_note position_id"),
                  _hex32(a.get("commitment", ""), "shieldedstaking_stake_note commitment"))
    if "ciphertext" not in a:
        raise EventError("shieldedstaking_stake_note: no ciphertext")
    n.ciphertext = _b64(a["ciphertext"], "shieldedstaking_stake_note ciphertext")
    minted = "spc" in a or "denom" in a or "amount" in a
    if minted:
        n.denom = a.get("denom") or ""
        if not n.denom:
            raise EventError("shieldedstaking_stake_note: empty denom")
        n.amount = str(_int(a.get("amount"), "shieldedstaking_stake_note amount"))
        n.spc = _hex32(a.get("spc", ""), "shieldedstaking_stake_note spc")
    return n


def ordered_events(results: dict) -> list[dict]:
    """A block's events in execution order (see the module docstring)."""
    finalize = results.get("finalize_block_events") or []
    before = [e for e in finalize if _attrs(e).get("mode") != "EndBlock"]
    after = [e for e in finalize if _attrs(e).get("mode") == "EndBlock"]
    txs = []
    for tx in results.get("txs_results") or []:
        # Every tx, whatever its code. Do NOT skip code != 0: a failed private
        # tx's ante already appended its notes and nullifiers to the trees, and
        # dropping them would put every later position (and every root) out of
        # step with the chain. See "Failed txs" above and
        # test_failed_tx_ante_events_are_indexed.
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
            ct = _b64(a.get("ciphertext", ""), "shielded_note ciphertext")
            n = Note(_int(a.get("position"), "shielded_note position"), _hex32(a.get("commitment", ""), "shielded_note commitment"), ct)
            d.notes.append(n)
            notes_by_pos[n.position] = n
        elif t in ("shielded_shield", "shielded_mint"):
            a = _attrs(ev)
            n = notes_by_pos.get(_int(a.get("position"), f"{t} position"))
            if n is None:
                raise EventError(f"{t} names position {a.get('position')}, not a note of this block")
            n.amount = a.get("amount") or None
            if "ciphertext" in a and _b64(a["ciphertext"], f"{t} ciphertext") != n.ciphertext:
                raise EventError(f"{t} at position {n.position}: ciphertext differs from its shielded_note's")
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
        elif t in HANDLE_EVENTS:
            d.handles_changed = True
        elif t == "shieldedstaking_stake_note":
            d.stake_notes.append(_stake_note(_attrs(ev)))
        elif t == "shieldedstaking_stake_nullifier":
            a = _attrs(ev)
            if "index" not in a:
                raise EventError("shieldedstaking_stake_nullifier: no index (a chain before the stake nullifier tree)")
            d.stake_nullifiers.append(StakeNullifier(
                _hex32(a.get("nullifier", ""), "shieldedstaking_stake_nullifier"),
                _int(a["index"], "shieldedstaking_stake_nullifier index")))
        elif t == "shieldedstaking_snapshot":
            a = _attrs(ev)
            root = a.get("root", "")
            d.snapshots.append(Snapshot(
                proposal_id=_int(a.get("proposal_id"), "shieldedstaking_snapshot proposal_id"),
                # A snapshot taken before any stake note has an empty root.
                root=_hex32(root, "shieldedstaking_snapshot root") if root else b"",
                tree_size=_int(a.get("tree_size"), "shieldedstaking_snapshot tree_size"),
                nf_root=_hex32(a.get("nf_root", ""), "shieldedstaking_snapshot nf_root"),
                nf_size=_int(a.get("nf_size"), "shieldedstaking_snapshot nf_size"),
            ))
        elif t == "shieldedstaking_stake_root":
            a = _attrs(ev)
            d.stake_root = Root(_hex32(a.get("root", ""), "shieldedstaking_stake_root"),
                                _int(a.get("tree_size"), "shieldedstaking_stake_root tree_size"))
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
            #
            # The sweep over validator books is EpochValidatorLimit (200) a
            # block: past 200 validators the epoch's later books are
            # processed in the following blocks, whose validator events have
            # no epoch event after them. Those rows come out epoch-less here
            # and the store labels them with the epoch the sweep belongs to
            # (the last one ended, Store.apply).
            epoch = _int(_attrs(ev).get("epoch"), "shieldedstaking_epoch epoch")
            for r in pending_rates:
                r.epoch = epoch
            d.rates.extend(pending_rates)
            pending_rates = []
            d.epoch_ended = epoch
    d.rates.extend(pending_rates)
    return d
