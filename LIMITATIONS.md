# Limitations

A full, honest accounting of what this project does not do, has not
proven, or has proven wrong once and then fixed. This expands
DECISIONS.md's "Open items" into the complete picture, and puts the
defect history on the record explicitly rather than leaving it
scattered across commit messages — a system that found and fixed six
numbered defects under adversarial and concurrent testing is a stronger
claim than a system that reports zero, and hiding the six would make
this a weaker document, not a cleaner one.

## Defect history — found, proven, fixed, regression-tested

Each of these was found by deliberately auditing for its class of bug
(TOCTOU races, states that don't say what they mean), reproduced with a
failing test *before* being fixed, and is now covered by a permanent
regression test that would fail again if the fix ever regressed.

| ID | What it was | How it's covered now |
|---|---|---|
| **D1** | Replay protection was check-then-add (`mandate_id in seen_nonces`, then separately `.add()`) — two concurrent requests against the same single-use mandate could both read "not yet spent" and both get `ALLOW`. | `nonce_store.NonceStore.claim()` is a single atomic `INSERT` (the `mandate_id` PRIMARY KEY constraint does the enforcing), called as `evaluate()`'s last check. `tests/test_concurrency.py::test_D1_replay_protection_allows_exactly_one_under_concurrency` — 8 concurrent threads against one mandate, verified (in the fix's own testing round) at 50 threads × 15 runs, consistently exactly one `ALLOW`. |
| **D2** | `audit_log.append_entry()` read the file's last line for `prev_hash`, then wrote — two concurrent writers could both read the same tip and both chain off it, forking the log with no tampering involved at all. | The whole read-tip-then-write sequence is wrapped in a `portalocker.Lock` on a sidecar `<file>.lock`, making it atomic across threads and processes. `tests/test_concurrency.py::test_D2_audit_chain_does_not_fork_under_concurrent_appends`. |
| **D3** | `nonce_store.py`/`approval_queue.py` shared one `sqlite3.Connection` across threads (`check_same_thread=False`) — concurrent `execute()`/`commit()` calls interleaved that connection's implicit transaction state, producing real `OperationalError`/`InterfaceError`/`DatabaseError`, and once, a raw interpreter-level `SystemError`. | Each thread gets its own connection (`threading.local`), plus `PRAGMA journal_mode=WAL` and `PRAGMA busy_timeout=5000` so those separate connections don't just fail differently when they contend for the file. `tests/test_concurrency.py::test_D3_nonce_store_survives_concurrent_access_without_sqlite_errors` and `::test_D3_approval_queue_survives_concurrent_enqueue_without_sqlite_errors`. |
| **D4** | A mandate that reached `NEEDS_HUMAN` did not reserve its nonce — the same single-use mandate could be resubmitted any number of times, each producing an independent, independently-approvable queue entry (three `simulate needs-human` calls against the same mandate_id produced three separate Razorpay-order-eligible rows from one authorization). | `evaluate()` now claims the nonce the moment a mandate reaches `NEEDS_HUMAN`, not only on eventual human approval — a denial does not release it (fail closed; a genuinely-reconsidered purchase needs a new mandate, not a resubmit). `tests/test_replay_reservation.py::test_D4_needs_human_reserves_nonce_so_it_cannot_be_resubmitted` and `::test_D4_only_one_of_the_duplicate_approvals_can_be_approved`. |
| **D5** | Neither the schema nor `evaluate()` ever expressed a *lower* bound on `proposed_tx.amount` — a spend cap written as "not more than X" only bounds one direction. `0.0`, negative amounts, and `float('nan')` all returned `ALLOW`; `nan <= 0` is `False` (NaN is unordered), so even a naive `if amount <= 0: deny` guard would silently never fire for it. | `ProposedTransaction.amount` carries `gt=0, allow_inf_nan=False` at the schema level, and `evaluate()` independently checks `math.isfinite(amount) and amount > 0` as its very first check (defence in depth — `evaluate()` cannot assume every caller went through normal Pydantic construction). `tests/test_defect_hunt.py::test_D5_schema_rejects_non_finite_or_non_positive_amount` and `::test_D5_evaluate_denies_non_finite_or_non_positive_amount`, parametrized over zero, negative, large-negative, NaN, and both infinities. |
| **D6** | `approval_queue.resolve(approved=True)` committed a terminal `approved` status *before* `razorpay_client.create_order()` ever ran. A process killed in that gap left a row saying `approved` with no way to tell, from queue state alone, whether the Razorpay order was ever actually created — identical to a row where it really was. | `resolve(approved=True)` now lands on `approved_pending_execution`, a real, retryable, non-terminal state; only a *successful* Razorpay call (`mark_executed()`) advances it to `executed`. `execute_approval()` retries just the Razorpay step, any number of times, without repeating the human decision or re-claiming the nonce. `tests/test_defect_hunt.py::test_D6_approved_status_does_not_distinguish_execution_from_a_crash` (proves the gap existed) and `::test_D6_execute_approval_recovers_from_exactly_that_crash` (proves the recovery path actually works, not just that the status is now honest). |

## The signature-binding gap (Stage 7)

Before decision #18, every principal in the system shared **one**
Ed25519 keypair. `keys.verify()` could only ever prove "this mandate was
signed by *a* key this system trusts" — never "principal p1
specifically signed this, and not principal p2" — because there was
only one key, and the signature check was never tied to the
`principal_id` field it was supposedly authenticating. Proven directly
against the pre-fix code before the fix was written (not just argued):
a freshly-signed, internally-consistent mandate claiming
`principal_id="p2"` verified cleanly, and so did an otherwise-identical
mandate claiming `principal_id="p3"` — the exact same signing operation
passed as either identity. **Closed** by replacing the single shared
keypair with a small per-principal registry (`keys.py`): `sign()`/
`verify()` now take `principal_id` and check against *that principal's
own* registered key; an unregistered principal gets its own
`failed_check="unknown_principal"`, distinct from a registered
principal's wrong signature (`failed_check="signature"`). See
`tests/test_attacks.py::test_attack_forged_principal_id_signed_by_a_
different_principals_key_is_denied` for the permanent regression test,
and DECISIONS.md #18 for the full reasoning, including the precise
distinction between this gap and the (already-closed, independently)
question of tampering an already-signed mandate's `principal_id` field.

## The one process gap worth naming honestly

At one point in this project's history, a stage's work (Stage 6) was
fully implemented and tested locally but existed only as **uncommitted**
changes — `git status` showed the modified files, but no commit had
been made. This was caught only because someone independently ran `git
status` and noticed, not because the development process itself flagged
it. Had that check not happened, the work would have looked "done" in
conversation while being completely absent from the repository's actual
history — recoverable in that instance (nothing was lost), but a real
gap in how "done" was being verified.

This is why **"actually run `git commit` and confirm the hash, don't
just report that a stage is complete"** is now a standing rule for
every stage in this project (see the CLAUDE-facing instructions this
project has followed since), and why every commit in this project's
history from that point forward is confirmed with a pasted `git log
--oneline -1` and `git status --short`, not a summary of what those
commands would show. The lesson generalizes past this one project: a
process step that only a human's incidental double-check catches is a
process step that will eventually get missed when no one happens to
double-check.

## Remaining named-not-built items

- **Key rotation and registration are out of scope.** `keys.py` (as of
  decision #18) correctly scopes signature verification per-principal,
  but the registry is three hardcoded demo keypairs in source, not a
  system that can issue, rotate, or revoke a key at runtime. Adding a
  fourth principal means editing `keys.py` and redeploying, not calling
  an API — that's the actual, still-true line between "a demo registry"
  and "a KMS."
- **Multi-instance coordination beyond Stage 1 is not built.** Every
  concurrency guarantee in this project (D1/D2/D3, re-verified) holds
  for *one process, one set of SQLite/JSONL files*. Two separate
  instances of the same deployment sharing load behind a load balancer
  are not coordinated with each other today — see `docs/SCALING.md`'s
  Stage 2 for exactly what would change (Postgres `ON CONFLICT`, a
  shared rate-limit counter, per-merchant audit chains) and, just as
  importantly, what would *not* need to change (`policy_engine.py`
  itself, by design — decision #2/#10).
- **The 0.5 human-review threshold is a placeholder, not a tuned risk
  model.** It's an easy, round, defensible number ("more than half the
  mandate's stated ceiling, in one request, gets a human's eyes"), not
  a value derived from any real fraud/risk data. A real deployment would
  tune this per-merchant or per-category (decision #5).
- **`buyer_agent.decide_with_llm()`'s live path is untested by CI.** It
  requires a real `ANTHROPIC_API_KEY` and calls a live model, which
  isn't reproducible enough to assert on in an automated suite — the
  deterministic path (`decide_deterministic()`, which reproduces the
  same poisoned-catalog failure mode without a live model) is what's
  actually proven to work in CI. `decide_with_llm()` is the "wire in a
  real key and watch it happen live" demo path, left for a human to run
  and observe, not a claim CI backs.
- **Razorpay execution stops at order creation, not a full payment
  round-trip.** `razorpay_client.create_order()` (with real
  retry/timeout/idempotency-by-receipt, decision #17) proves the
  authorization decision reaches a real payment processor in test
  mode — it does not simulate an actual card/UPI payment completing,
  which requires Razorpay's Checkout (a real frontend flow) or a
  separate test-mode payment-simulation call, both out of scope for an
  authorization gateway that isn't also a checkout UI.
- **A true create-create receipt race isn't ruled out.** Razorpay's
  Orders API doesn't itself enforce receipt uniqueness server-side —
  two concurrent callers using the *same* receipt for their *first*
  `order.create()` call (not a retry of an already-successful one)
  could still both succeed and produce two orders. This system's own
  call pattern (one `request_id`, and therefore one receipt, only ever
  driven through `_attempt_execution()` by a single initial call or
  serialized retries) avoids hitting this in practice, but that's a
  property of how this code happens to call the API, not a guarantee
  Razorpay's API makes on its own (decision #17).
- **Only three demo principals exist, and their private keys are
  checked into source control on purpose** (decision #3, #18) — this
  demo runs with no setup step for anyone who clones the repo, at the
  explicit cost of these keys having zero value as real credentials.
  Never acceptable for a real signing key; stated here again because it
  is the single most important thing not to generalize from this
  project to a real deployment.
