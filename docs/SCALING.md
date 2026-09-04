# Scaling

Three stages. Only the first is built. The other two are named
precisely — what would change, and specifically what in the existing
code would *not* need to change — but not implemented, and this file
says so plainly rather than describing them as if they existed.

## Stage 1 (built, today): single process, SQLite, correct under concurrency

One process. `nonce_store.py` and `approval_queue.py` are each a single
SQLite file, WAL mode, `busy_timeout=5000`, one connection per thread.
`audit_log.py` is a single JSONL file guarded by an OS-level lock
(`portalocker`) plus an in-process tip cache. Rate limiting
(`rate_limit.py`) and observability counters (`observability.py`) are
in-process memory, reset on restart.

This is correct, not merely "good enough for a demo" — it was proven
wrong once (D1: replay TOCTOU, D2: audit chain fork, D3: shared-
connection crashes, all under concurrency — see LIMITATIONS.md) and
then fixed and re-verified under real concurrent load, not just argued
into correctness:

- **D1 (replay race):** `NonceStore.claim()` — one atomic `INSERT`
  relying on the `mandate_id` PRIMARY KEY constraint — verified with 50
  concurrent threads × 15 runs against the same single-use mandate,
  consistently exactly one `ALLOW` (DECISIONS.md #10).
- **D2 (audit chain fork):** `append_entry()`'s read-tip-then-write
  sequence wrapped in a `portalocker.Lock`, so two concurrent writers
  can no longer both read the same `prev_hash` (DECISIONS.md #11).
- **D3 (shared-connection crashes):** one `sqlite3.Connection` per
  thread instead of one shared connection — the shared-connection
  version produced real `OperationalError`/`InterfaceError`/`SystemError`
  under load; per-thread connections plus WAL + `busy_timeout` made 20
  concurrent threads succeed cleanly (DECISIONS.md #12).

**What "Stage 1" means as a scope boundary, precisely:** one file per
store, one process. Two *separate* merchant deployments each running
their own `nonces.db` are correctly uncoordinated with each other —
they were never meant to be the same store. What doesn't work yet is
multiple *instances of the same deployment* sharing load behind a load
balancer, which is exactly what Stage 2 is for.

## Stage 2 (designed, not built): stateless instances behind a load balancer

**What changes:**

- **`nonce_store.py`** → Postgres, with the same atomic-claim contract
  `NonceStore.claim()` already has, expressed as
  `INSERT INTO spent_mandates (mandate_id) VALUES ($1) ON CONFLICT
  (mandate_id) DO NOTHING RETURNING mandate_id` — a claim succeeded iff
  a row came back. This is the same "let the database's own constraint
  make the operation atomic" strategy `NonceStore.claim()` already uses
  against SQLite's PRIMARY KEY; Postgres's `ON CONFLICT` is the
  multi-instance-safe version of the identical idea, not a different
  one.
- **`approval_queue.py`** → the same move, same reasoning: Postgres
  table, same status machine (`pending` → `approved_pending_execution`
  → `executed` / `denied`), same atomic `UPDATE ... WHERE status = ...`
  guards `mark_executed()`/`resolve()` already use — those guards are
  already written as conditional updates whose result you check, not
  "read then decide then write," which is exactly what survives the
  move to a real multi-writer database unchanged.
- **API instances** → `api.py` (FastAPI) becomes N stateless replicas
  behind a load balancer. This is the actual payoff of a decision made
  back at Stage 1, not something Stage 2 has to newly engineer:
  **`policy_engine.evaluate()` takes every piece of state it needs as an
  explicit argument (the mandate, the transaction, a `NonceClaimer`) and
  holds none of its own — it was already "pure enough" that swapping
  what `NonceClaimer` is backed by (SQLite today, Postgres at Stage 2)
  requires zero changes to `policy_engine.py` itself.** `service.py`
  already takes store paths/connections as parameters rather than
  hardcoding them, for the identical reason.
- **Audit log** → per-merchant chains instead of one global tail, so N
  API instances serving different merchants aren't all contending on
  one `<audit_log>.lock` for every single append. Each merchant's chain
  is independently hash-linked and independently verifiable — this
  doesn't change what `verify_chain()` proves, only how many files it's
  proving it about.
- **Rate limiting** → `rate_limit.RateLimiter`'s in-process
  `dict[(agent_key, mandate_id), TokenBucket]` becomes a shared counter
  (Redis, most likely — `INCR` + `EXPIRE` or a Lua-scripted token
  bucket) so N instances agree on one budget per agent/mandate pair
  instead of each instance enforcing its own.

**What does NOT change:** the check order inside `evaluate()`, the
`Decision`/`Outcome` shapes, the `failed_check` taxonomy, the
signature-verification logic in `keys.py`, the AP2/ACP normalization in
`schema.py`. Stage 2 is entirely a storage/deployment change underneath
an enforcement layer that was deliberately built not to know or care
where its state lives.

## Stage 3 (named, not built): partitioning, a hot cache, async execution

- **Partitioned audit chain** — Stage 2's per-merchant chains, further
  split (by time window, say) so a single merchant's chain isn't one
  ever-growing contention point either at very high volume.
- **Redis for the hot nonce set, Postgres as durable backstop** — a
  `claim()` checked against Redis first (sub-millisecond, handles the
  request-rate hot path) with every claim also durably recorded in
  Postgres (the source of truth if Redis is ever flushed/restarted) —
  the nonce store gets a cache in front of its already-correct atomic
  backend, not a replacement for atomicity.
- **Async Razorpay execution off a queue** — `execute_approval()`
  (decision #17) already separates "a human approved this" from "the
  Razorpay call succeeded," specifically so retrying is safe and
  doesn't have to happen synchronously inside the request that
  triggered it. Stage 3 takes advantage of that separation: instead of
  `resolve_approval()` calling `razorpay_client.create_order()` inline,
  it would enqueue the request and a worker pool would drain it,
  retrying with the same idempotency-by-receipt guarantee already
  built — this is a deployment change to *how* `_attempt_execution()`
  gets invoked, not a change to what it does or the safety property it
  already provides.

## Why Stage 2 and Stage 3 are deliberately not implemented

This is a demo/interview artifact built to prove specific properties —
a deterministic policy engine, real signature verification, atomic
replay protection, a tamper-evident audit trail, a working human
approval loop, and now a scored eval corpus and CI — under genuinely
adversarial and concurrent conditions, not a production system carrying
real merchant load. Building Postgres failover, a Redis cluster, and a
worker queue for a system with no real traffic would be effort spent
proving nothing that isn't already proven by Stage 1's own concurrency
tests (D1–D3, re-verified, see LIMITATIONS.md) — it would look like
progress without being evidence of anything. What's valuable to show
instead is that the Stage 1 design didn't quietly bake in assumptions
that would force a rewrite later: `evaluate()`'s explicit-state,
no-hidden-mutation shape (decision #2, #10) is *why* Stage 2 is a
storage swap and not an enforcement-logic rewrite, and that's the claim
this file is making — not that Stage 2 has been built.
