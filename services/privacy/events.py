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
                         ciphertext repeats the shielded_note's; checked equal.
                         An open note (x/shielded MintOpenNote: the referral
                         note a registration mints to its referrer handle's
                         address) has no ciphertext ("" on both events) and
                         adds owner_pk, rho, rcm (hex): the opening, public,
                         so the owner matches it by owner_pk and recomputes
                         pc and cm. A split payout (MintNoteSplit: a
                         payout above 2^63-1) is several notes, each its
                         own shielded_note + shielded_mint at its own
                         position, all with the same ciphertext. An
                         undelegation's payout (x/shieldedstaking, module
                         "shieldedstaking", EndBlock) is such a mint, split
                         or not: its notes are ordinary rows of the note
                         stream, with the undelegate msg's ciphertext.
    shieldedstaking_unbond_payout
                         payout_id, validator, epoch, value, amount (uerth,
                         an integer), notes, positions (comma-separated,
                         "" when the amount is 0): after its mints. Checked
                         to name exactly the shieldedstaking mints of this
                         block at those positions, one ciphertext, amounts
                         summing to amount (nothing about it is stored)
    register             nullifier, leaf_index, reward, switched, and for a
                         referred registration handle, referral (amount)
                         and, when the referral was paid, referral_position:
                         checked to name an open-note mint of this block
                         with that amount (nothing about it is stored)
    shielded_nullifier   nullifier (hex)
    shielded_root        root (hex), tree_size, height        EndBlock
    identity_leaf        index, leaf (hex; 64 zeros when zeroed)
    identity_root        root (hex), tree_size, height        EndBlock
    handle_*             handle_bound / handle_released / handle_moved: a
                         handle directory record changed; each carries owner
                         (the handle-scope nullifier, hex). Matched by
                         prefix. The directory, owner included, is re-read
                         whole from the Handles query
                         (services/privacy/handles), which is checked there.
    handle_moved         handle, nullifier, owner, previous_owner (hex): a
                         move (circuits/move) from an identity to its
                         successor under the same passport. Checked: owner
                         and previous_owner 32 bytes and different, nullifier
                         = owner. Nothing about it is stored beyond the
                         directory refresh.
    move_caretaker       nullifier, previous_nullifier (caretaker-scope, hex),
                         expires_at: a caretaker split's move along the same
                         succession. Checked the same way; nothing is
                         stored (the backend serves no caretaker directory).

Groundworks (chain v1.2.0: votes by stake note, read by wallets from the
chain's own Query/GroundworksVotes; nothing here is stored). Blocks from
before v1.2.0 carry shieldedstaking_position events of the retired
positions: ignored.

    split_lapsed         stream, voter (an account), expires_at: an
                         operator's MsgSetAllocations split lapsed
                         (x/allocation). Checked (expires_at at or before
                         the block); nothing is stored: operator votes are
                         public chain state (Query/Voter expires_at).

Lease alerts (x/allocation/types/events.go, chain 7033eac; none halts the
chain, none changes anything this index stores). Logged, never checked, so
an attribute the chain adds or drops cannot halt the indexer:

    lease_retire_failed  stream, lapser (account | groundworks_votes), key,
                         expires_at, retry_at, error: a lease due could
                         not be retired; its weight counts until retry_at
                         (a day later). Logged as an error: page on it.
    lease_settle_held    stream, expires_at: a settle outside the sweep
                         found a lease due (should never happen). Error.
    lease_backlog_drained  stream, lapse_seconds: one sweep drained a
                         halt's backlog (a slow block). Info.
    shieldedstaking_epoch_validator  validator, rewards, delegated,
                                     undelegated, rate, supply   EndBlock
    shieldedstaking_epoch            epoch (the one that just ended)

The stake note tree (x/shieldedstaking's own append-only depth-32 Poseidon2
tree of owner-locked derth/<valoper> notes, its own nullifier set and roots).
The chain mints no stake note: every one is a stake proof output
(ORCHARD_DESIGN.md section 20), and an undelegation's payout is pool notes
(above):

    shieldedstaking_stake_note       position_id, commitment (hex), ciphertext
                                     (base64): the stake proof's commitment
                                     (lane A) or credit_commitment (the credit
                                     lane), in that order, each with its
                                     wallet stake ciphertext, exactly 201
                                     bytes (the slash label inside). A zero
                                     note (a full exit's padding output) is a
                                     note like any other. A note with denom,
                                     amount or spc (a chain-minted note) is
                                     refused.
    shieldedstaking_stake_nullifier  nullifier (hex), index (its leaf index in
                                     the stake nullifier tree: 1, 2, 3, ... in
                                     insertion order; leaf 0 is the sentinel).
                                     Every non-zero nullifier of a stake proof
                                     (nf_0, nf_1, credit_nullifier), padding
                                     ones included: the chain cannot tell them
                                     apart, and inserts each.
    shieldedstaking_stake_root       root (hex), tree_size              EndBlock
                                     (the empty tree's root too, at the first
                                     block: tree_size 0)
    shieldedstaking_snapshot         proposal_id, root (hex), tree_size,
                                     nf_root (hex), nf_size: the stake note
                                     tree and the stake nullifier tree a
                                     proposal's stake votes prove against

The slash debt tree (zk/debt, ORCHARD_DESIGN.md section 20.6: one row per
slashed private redelegation, written in BeginBlock when a slash reaches the
module's redelegation entries):

    shieldedstaking_debt_row         move_key (hex), retained (derth, an
                                     integer), index (the row's leaf: the
                                     next one for a new key, its own for a
                                     rewritten one), root (hex, the tree's
                                     root after the write). Stored.
    shieldedstaking_move_slashed     move_key, src_validator, dst_validator,
                                     debt, retained: right after its row,
                                     checked to repeat its key and retained.
    shieldedstaking_slash_debt       src_validator, dst_validator, value, debt,
                                     entries: after its moves, checked to
                                     name their validators and a debt of at
                                     most theirs summed (the book may cap it).
    shieldedstaking_redelegate       src_validator, dst_validator, derth,
                                     value, credited, queued, bonded,
                                     completion_time, move_key (the credit
                                     nullifier), move_time: move_key checked
                                     to be a stake nullifier of the block;
                                     an event with `minted` is refused.
                                     Nothing of it is stored.

The stake nullifier tree (ORCHARD_DESIGN.md section 15) is an indexed
(sorted) Merkle tree whose leaf positions are insertion order, so wallets
rebuild it from the nullifiers in index order; the store refuses an index
that is not exactly the next one.

Stake notes and nullifiers are written by the msg, so a failed staking msg
leaves none of them (only its fee bundle's pool events, from the ante; see
"Failed txs" below).

Not read, because they change no tree and no rate a wallet derives:
shielded_unshield / _spend_to_module / _fee / _asset, the dex's LP events
(private LP shares are ordinary shielded_note events; add/remove/complete
liquidity events name no provider), shieldedstaking_delegate / _undelegate
(validator, derth, value, epoch, payout_id) / _matured
(validator, epoch, value, payout) / _unbond_payout_failed (payout_id,
validator, epoch, attempts, retry_at, error: kept and retried, nothing
minted) / _stake_vote (vote_nullifiers: both slots' vote nullifiers, a padded
slot's included, comma-separated hex; per proposal, they spend nothing and are in no tree) and
shieldedstaking_self_bond_compounded (an operator's own SDK self-bond grows;
derth rates come from shieldedstaking_epoch_validator).

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
import re
from dataclasses import dataclass, field

ZERO32 = bytes(32)
# Every x/personhood handle directory event is "handle_<what>" (handle_bound,
# handle_released, handle_moved). Any of them means the directory changed;
# nothing else in the chain's events starts this way.
HANDLE_EVENT_PREFIX = "handle_"

# x/allocation lease alerts: logged by the indexer, never stored or checked.
LEASE_ALERTS = ("lease_retire_failed", "lease_settle_held", "lease_backlog_drained")


def is_handle_event(event_type: str) -> bool:
    return event_type.startswith(HANDLE_EVENT_PREFIX)


class EventError(Exception):
    """An event the chain should never emit: a malformed attribute."""


@dataclass
class Note:
    position: int
    cm: bytes
    ciphertext: bytes  # b"" for an open note (no ciphertext)
    amount: str | None = None  # "<n><denom>" when the note's value is public (shield, mint)
    # An open note's opening (shielded_mint owner_pk, rho, rcm), else None.
    owner_pk: bytes | None = None
    rho: bytes | None = None
    rcm: bytes | None = None


@dataclass
class Referral:
    """A register event's paid referral: where the note is and its amount."""
    position: int
    amount: int


@dataclass
class UnbondPayout:
    """A shieldedstaking_unbond_payout event, checked against its mints."""
    payout_id: int
    amount: int
    positions: list[int]


@dataclass
class IdentityWrite:
    index: int
    leaf: bytes  # ZERO32 when zeroed


@dataclass
class Root:
    root: bytes
    tree_size: int


# A wallet stake ciphertext (privacy.WalletStakeCiphertextBytes): epk ||
# AEAD(0x04 || asset || amount || rho || rcm || move_key || move_time ||
# exposed) || tag. Every stake note carries one.
STAKE_CIPHERTEXT_BYTES = 201
# A debt row's retained is at most its move's credit, a note amount
# (<= 2^63-1): it fits SQLite's signed 64-bit integers.
MAX_NOTE_VALUE = 2**63 - 1


@dataclass
class StakeNote:
    position: int
    cm: bytes
    ciphertext: bytes  # the wallet stake ciphertext, STAKE_CIPHERTEXT_BYTES


@dataclass
class DebtRow:
    """A shieldedstaking_debt_row event: the row of move key `key` at leaf
    `index` is now worth `retained`; the debt tree's root after it is `root`."""
    key: bytes
    retained: int
    index: int
    root: bytes


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
class SplitLapse:
    """An x/allocation split_lapsed event: an operator's split lapsed."""
    stream: str
    voter: str
    expires_at: int


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
    # Paid referrals (register events), checked against the open notes.
    referrals: list[Referral] = field(default_factory=list)
    # Undelegation payouts, checked against their shieldedstaking mints.
    payouts: list[UnbondPayout] = field(default_factory=list)
    # Slash debt tree writes, in order (BeginBlock).
    debt_rows: list[DebtRow] = field(default_factory=list)
    # Operators' Groundworks splits that lapsed (checked, not stored).
    split_lapses: list[SplitLapse] = field(default_factory=list)
    # Lease alerts (event type, attributes), for the log only.
    lease_alerts: list[tuple[str, dict[str, str]]] = field(default_factory=list)


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
    w = "shieldedstaking_stake_note"
    if "spc" in a or "denom" in a or "amount" in a:
        raise EventError(f"{w}: a chain-minted stake note (denom/amount/spc): a chain before dff3a9b")
    if "ciphertext" not in a:
        raise EventError(f"{w}: no ciphertext")
    ct = _b64(a["ciphertext"], f"{w} ciphertext")
    if len(ct) != STAKE_CIPHERTEXT_BYTES:
        raise EventError(f"{w}: ciphertext of {len(ct)} bytes, want {STAKE_CIPHERTEXT_BYTES}")
    return StakeNote(_int(a.get("position_id"), f"{w} position_id"), _hex32(a.get("commitment", ""), f"{w} commitment"), ct)


def _debt_row(a: dict[str, str]) -> DebtRow:
    w = "shieldedstaking_debt_row"
    r = DebtRow(_hex32(a.get("move_key", ""), f"{w} move_key"), _int(a.get("retained"), f"{w} retained"),
                _int(a.get("index"), f"{w} index"), _hex32(a.get("root", ""), f"{w} root"))
    if r.key == ZERO32:
        raise EventError(f"{w}: move_key 0 (the sentinel's)")
    if r.index == 0:
        raise EventError(f"{w}: index 0 (the sentinel's leaf)")
    if r.retained > MAX_NOTE_VALUE:
        raise EventError(f"{w}: retained {r.retained} above a note's maximum")
    return r


def _split_lapse(a: dict[str, str], time: int) -> SplitLapse:
    w = "split_lapsed"
    s = SplitLapse(a.get("stream", ""), a.get("voter", ""), _int(a.get("expires_at"), f"{w} expires_at"))
    if not s.stream or not s.voter:
        raise EventError(f"{w}: no stream or voter")
    if s.expires_at == 0 or s.expires_at > time:
        raise EventError(f"{w} {s.voter}: expires_at {s.expires_at}, block at {time}")
    return s


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


def _check_move(a: dict[str, str], what: str, new_key: str, old_key: str) -> None:
    """A move event names two distinct 32-byte nullifiers: the successor's
    (new_key) and the moved-out identity's (old_key)."""
    new = _hex32(a.get(new_key, ""), f"{what} {new_key}")
    old = _hex32(a.get(old_key, ""), f"{what} {old_key}")
    if new == old:
        raise EventError(f"{what}: {new_key} and {old_key} are the same")


def parse_block(height: int, time: int, block_hash: str, results: dict) -> BlockDelta:
    if int(results.get("height", height)) != height:
        raise EventError(f"block_results for height {results.get('height')}, asked {height}")
    d = BlockDelta(height=height, time=time, hash=block_hash)
    notes_by_pos: dict[int, Note] = {}
    mint_module: dict[int, str] = {}  # position -> shielded_mint module
    pending_rates: list[Rate] = []
    unmatched_row: DebtRow | None = None    # a debt row awaiting its move_slashed
    slashed: list[tuple[str, str, int]] = []  # (src, dst, debt) since the last slash_debt
    move_keys: list[bytes] = []               # shieldedstaking_redelegate move keys
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
            if t == "shielded_mint":
                mint_module[n.position] = a.get("module", "")
            if "ciphertext" in a and _b64(a["ciphertext"], f"{t} ciphertext") != n.ciphertext:
                raise EventError(f"{t} at position {n.position}: ciphertext differs from its shielded_note's")
            if t == "shielded_mint" and ("owner_pk" in a or "rho" in a or "rcm" in a):
                if n.ciphertext:
                    raise EventError(f"shielded_mint at position {n.position}: an opening and a ciphertext")
                n.owner_pk = _hex32(a.get("owner_pk", ""), "shielded_mint owner_pk")
                n.rho = _hex32(a.get("rho", ""), "shielded_mint rho")
                n.rcm = _hex32(a.get("rcm", ""), "shielded_mint rcm")
        elif t == "register":
            a = _attrs(ev)
            if "referral_position" in a:
                d.referrals.append(Referral(_int(a["referral_position"], "register referral_position"),
                                            _int(a.get("referral"), "register referral")))
        elif t == "shieldedstaking_unbond_payout":
            d.payouts.append(_unbond_payout(_attrs(ev)))
        elif t == "shieldedstaking_debt_row":
            if unmatched_row is not None:
                raise EventError(f"shieldedstaking_debt_row {unmatched_row.key.hex()} without its move_slashed")
            unmatched_row = _debt_row(_attrs(ev))
            d.debt_rows.append(unmatched_row)
        elif t == "shieldedstaking_move_slashed":
            a = _attrs(ev)
            w = "shieldedstaking_move_slashed"
            key = _hex32(a.get("move_key", ""), f"{w} move_key")
            retained = _int(a.get("retained"), f"{w} retained")
            if unmatched_row is None or (unmatched_row.key, unmatched_row.retained) != (key, retained):
                raise EventError(f"{w} {key.hex()} (retained {retained}) does not follow its debt row")
            unmatched_row = None
            slashed.append((a.get("src_validator", ""), a.get("dst_validator", ""), _int(a.get("debt"), f"{w} debt")))
        elif t == "shieldedstaking_slash_debt":
            _check_slash_debt(_attrs(ev), slashed)
            slashed = []
        elif t == "shieldedstaking_redelegate":
            a = _attrs(ev)
            w = "shieldedstaking_redelegate"
            if "minted" in a:
                raise EventError(f"{w}: `minted` (a chain-minted derth/<dst> note): a chain before dff3a9b")
            _int(a.get("credited"), f"{w} credited")
            _int(a.get("move_time"), f"{w} move_time")
            move_keys.append(_hex32(a.get("move_key", ""), f"{w} move_key"))
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
        elif t == "handle_moved":
            a = _attrs(ev)
            _check_move(a, t, "owner", "previous_owner")
            if a.get("nullifier") != a.get("owner"):
                raise EventError("handle_moved: nullifier is not owner")
            d.handles_changed = True
        elif is_handle_event(t):
            d.handles_changed = True
        elif t == "move_caretaker":
            a = _attrs(ev)
            _check_move(a, t, "nullifier", "previous_nullifier")
            _int(a.get("expires_at"), "move_caretaker expires_at")
        elif t == "split_lapsed":
            d.split_lapses.append(_split_lapse(_attrs(ev), time))
        elif t in LEASE_ALERTS:
            d.lease_alerts.append((t, _attrs(ev)))
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
    if unmatched_row is not None:
        raise EventError(f"shieldedstaking_debt_row {unmatched_row.key.hex()} without its move_slashed")
    if slashed:
        raise EventError("shieldedstaking_move_slashed without its slash_debt")
    # A move's key is its credit nullifier, spent in the same msg.
    spent = {n.nf for n in d.stake_nullifiers}
    for k in move_keys:
        if k not in spent:
            raise EventError(f"shieldedstaking_redelegate move_key {k.hex()} is not a stake nullifier of this block")
    for r in d.referrals:
        n = notes_by_pos.get(r.position)
        if n is None or n.owner_pk is None:
            raise EventError(f"register names referral_position {r.position}, not an open note of this block")
        if n.amount is None or _amount_value(n.amount) != r.amount:
            raise EventError(f"register referral {r.amount} differs from the note at {r.position} ({n.amount})")
    paid: set[int] = set()
    for p in d.payouts:
        _check_payout(p, notes_by_pos, mint_module, paid)
    return d


def _check_slash_debt(a: dict[str, str], moves: list[tuple[str, str, int]]) -> None:
    """A slash_debt names the validators of the moves it charged (those
    since the previous slash_debt) and at most their debt summed: the module
    books the moves' debt, capped by the destination's supply."""
    w = "shieldedstaking_slash_debt"
    src, dst = a.get("src_validator", ""), a.get("dst_validator", "")
    if not src or not dst:
        raise EventError(f"{w}: no src_validator or dst_validator")
    debt = _int(a.get("debt"), f"{w} debt")
    _int(a.get("value"), f"{w} value")
    _int(a.get("entries"), f"{w} entries")
    for s_, d_, _ in moves:
        if (s_, d_) != (src, dst):
            raise EventError(f"{w} {src} -> {dst}: a move of {s_} -> {d_} before it")
    if debt > sum(x for _, _, x in moves):
        raise EventError(f"{w} {src} -> {dst}: debt {debt}, its moves owe {sum(x for _, _, x in moves)}")


PAYOUT_MODULE = "shieldedstaking"
PAYOUT_DENOM = "uerth"


def _unbond_payout(a: dict[str, str]) -> UnbondPayout:
    w = "shieldedstaking_unbond_payout"
    p = UnbondPayout(_int(a.get("payout_id"), f"{w} payout_id"), _int(a.get("amount"), f"{w} amount"),
                     [_int(x, f"{w} positions") for x in a["positions"].split(",")] if a.get("positions") else [])
    if _int(a.get("notes"), f"{w} notes") != len(p.positions):
        raise EventError(f"{w} {p.payout_id}: notes {a.get('notes')}, {len(p.positions)} positions")
    if len(set(p.positions)) != len(p.positions):
        raise EventError(f"{w} {p.payout_id}: a position twice")
    if (p.amount == 0) != (not p.positions):
        raise EventError(f"{w} {p.payout_id}: amount {p.amount} in {len(p.positions)} notes")
    return p


def _check_payout(p: UnbondPayout, notes_by_pos: dict[int, Note], mint_module: dict[int, str], paid: set[int]) -> None:
    """A payout's positions are its own shieldedstaking mints of this block:
    plain notes (no opening) with one ciphertext and uerth amounts summing to
    the payout's amount (a split payout is several of them)."""
    w = f"shieldedstaking_unbond_payout {p.payout_id}"
    total, cts = 0, set()
    for pos in p.positions:
        n = notes_by_pos.get(pos)
        if n is None or mint_module.get(pos) != PAYOUT_MODULE:
            raise EventError(f"{w} names position {pos}, not a {PAYOUT_MODULE} mint of this block")
        if pos in paid:
            raise EventError(f"{w}: position {pos} is another payout's")
        paid.add(pos)
        if n.owner_pk is not None or not n.ciphertext:
            raise EventError(f"{w}: the note at {pos} has no ciphertext")
        m = re.fullmatch(r"(\d+)" + PAYOUT_DENOM, n.amount or "")
        if m is None:
            raise EventError(f"{w}: the note at {pos} is {n.amount}, not {PAYOUT_DENOM}")
        total += int(m.group(1))
        cts.add(n.ciphertext)
    if len(cts) > 1:
        raise EventError(f"{w}: its notes' ciphertexts differ")
    if total != p.amount:
        raise EventError(f"{w}: amount {p.amount}, its notes hold {total}")


def _amount_value(coin: str) -> int | None:
    """The integer part of a coin string "<n><denom>"."""
    i = 0
    while i < len(coin) and coin[i].isdigit():
        i += 1
    return int(coin[:i]) if i else None
