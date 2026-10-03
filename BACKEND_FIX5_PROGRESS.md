# Backend fix 5: chain privacy/orchard 4a663d5 (handles, predecessor_at)

Chain: wt/chain-orch 4a663d5 (CHANGELOG [Unreleased]: handles replace
public referrer addresses; predecessor-aware activation; error codes
1120-1126). Baseline: pytest 266 passed, 1 skipped.

## Steps
- [x] A zk: identity_leaf(.., predecessor_at), affiliate_field; zk_vectors
      re-generated from 4a663d5
- [x] B /gas/register: affiliate_handle / affiliate_pc / affiliate_ciphertext
      (all or none), referrer address gone; refusal kinds for 1120-1126
- [x] C fixtures re-recorded from 4a663d5 (recorder also records the
      Handles query per block)
- [x] D handle directory stream {base}/handles
- [x] E referral-mint note indexed (test on the C2/D1 registrations)

## Notes
- Membership public inputs (max_activation, max_predecessor): the backend
  builds and checks none (no membership proof passes through it; the
  reserved lane reads only the passport proof's signals 0..3, whose layout
  is unchanged). Identity leaves are served as the chain emits them; the
  Python identity_leaf (verify / vectors only) takes predecessor_at.
- Error codes: the backend has no code table; gas-check returns error text.
  _REFUSAL_KINDS gains 1120 (identity tree full) and 1121 (not a live
  handle); 1123/1124 annotated. 1122/1125/1126 and dex 1120 belong to msgs
  no registration check reaches.
- Referral-mint note: MintNote emits shielded_note + shielded_mint as every
  chain mint; indexed with no change (test on C2/D1 in
  TestPrivatePersonhood).
- Fixtures: bin/record-chain-fixtures.sh and bin/zk-vectors.sh at 4a663d5
  (they use the chain's committed proof fixtures; the chain's own
  scripts/*-fixtures.sh were already re-run in af30f73 / 6e5924f).

## Left
- Dockerfile EARTHD_VERSION (v1.0.0) predates handles: gas-check from that
  binary does not know affiliate_handle/pc/ciphertext. Bump it (and its
  sha256) once the chain cuts a release from privacy/orchard.
- Wallets: read {base}/handles whole (restart on a height change); send
  affiliate_handle/affiliate_pc/affiliate_ciphertext to /gas/register,
  never an address.

pytest: 321 passed, 1 skipped (live-earthd test).
