# Backend fix 5: chain privacy/orchard 4a663d5 (handles, predecessor_at)

Chain: wt/chain-orch 4a663d5 (CHANGELOG [Unreleased]: handles replace
public referrer addresses; predecessor-aware activation; error codes
1120-1126). Baseline: pytest 266 passed, 1 skipped.

## Steps
- [x] A zk: identity_leaf(.., predecessor_at), affiliate_field; zk_vectors
      re-generated from 4a663d5
- [x] B /gas/register: affiliate_handle / affiliate_pc / affiliate_ciphertext
      (all or none), referrer address gone; refusal kinds for 1120-1126
- [ ] C fixtures re-recorded from 4a663d5 (recorder also records the
      Handles query per block)
- [ ] D handle directory stream {base}/handles
- [ ] E referral-mint note indexed (test on the C2/D1 registrations)
