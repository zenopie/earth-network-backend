from tests.conftest import ADDRESS, call, callback_prefix, signed_query


def test_valid_callback_is_paid_once(client, sends):
    query = signed_query(callback_prefix())
    assert call(client, query)["status"] == "success"
    assert call(client, query)["message"] == "already granted"
    assert sends == [ADDRESS]


def test_tampered_callback_is_refused(client, sends):
    query = signed_query(callback_prefix()).replace("tx-1", "tx-2", 1)
    assert call(client, query)["message"] == "invalid signature"
    assert sends == []


def test_percent_encoded_ampersand_cannot_mint_a_second_transaction_id(client, sends):
    # user_id is set by the app, so the attacker chooses it: Google encodes the
    # `&` and `=` in it, and signs the decoded form.
    original = callback_prefix(user_id="x&transaction_id=forged")
    query = signed_query(original)
    # Read as signed, the smuggled id is a second transaction_id, so the carrier
    # itself is refused. (Before the fix it was paid, and so was the replay.)
    assert call(client, query)["message"] == "duplicate parameters"

    # Re-encode the real transaction_id so it folds into a parameter *name*, and
    # un-encode the injected one. The decoded bytes — what the signature covers —
    # are unchanged.
    replayed_prefix = original.replace(
        "&transaction_id=tx-1&user_id=x%26transaction_id%3Dforged",
        "&transaction_id%3Dtx-1%26user_id%3Dx&transaction_id=forged",
    )
    assert replayed_prefix != original
    replayed = replayed_prefix + query[len(original):]

    assert call(client, replayed)["message"] == "duplicate parameters"
    assert sends == []


def test_reencoding_a_callback_does_not_change_its_parameters(client, sends):
    # `&` <-> `%26` rewrites of an honest callback read identically, so the
    # replay table still sees the id it already honoured.
    original = callback_prefix()
    query = signed_query(original)
    assert call(client, query)["status"] == "success"

    reencoded = query.replace("&transaction_id=tx-1", "%26transaction_id%3Dtx-1", 1)
    assert call(client, reencoded)["message"] == "already granted"
    assert sends == [ADDRESS]


def _stamped(seconds_from_now: float) -> str:
    import time

    return str(int((time.time() + seconds_from_now) * 1000))


def test_stale_callback_is_refused(client, sends):
    query = signed_query(callback_prefix(timestamp=_stamped(-2 * 3600)))
    assert call(client, query)["message"] == "stale callback"
    assert sends == []


def test_future_callback_is_refused(client, sends):
    query = signed_query(callback_prefix(timestamp=_stamped(3600)))
    assert call(client, query)["message"] == "stale callback"
    assert sends == []


def test_callback_inside_the_window_is_paid(client, sends):
    query = signed_query(callback_prefix(timestamp=_stamped(-600)))
    assert call(client, query)["status"] == "success"


def test_missing_or_garbage_timestamp_is_refused(client, sends):
    for ts in ("", "soon"):
        query = signed_query(callback_prefix(timestamp=ts, transaction_id="tx-" + ts))
        assert call(client, query)["message"] == "missing parameters"
    assert sends == []
