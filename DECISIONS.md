# Decisions

This file records why Darwaza is built the way it is, not just what it does.
Each entry: what we chose, what we rejected, and why.

## 1. Normalize two protocol shapes instead of integrating one protocol deeply

**Chosen:** Darwaza defines a single `NormalizedMandate` shape that both an
AP2-style Intent Mandate and an ACP-style scoped token get mapped into
before they ever reach the policy engine. The engine only ever sees the
normalized shape — it has no knowledge of AP2 or ACP as protocols.

**Rejected:** Building a deep, first-class integration with one protocol
(e.g. fully implementing AP2's mandate chain, delegation semantics, and
crypto suite) and treating the other as an afterthought or a later
"adapter."

**Why:** The whole point of a merchant-side authorization gateway is that
merchants will face buying agents speaking *different* protocols, and new
ones will show up. If the policy engine is written against one protocol's
assumptions, every new protocol requires touching enforcement logic — the
highest-risk code in the system. Normalizing early means protocol-specific
parsing is a thin, swappable layer, and the enforcement logic is written
once against a stable shape. It also forces an honest question up front:
what do these protocols actually guarantee in common? (Answer, see
decision below and `schema.py`: not much — ACP tokens don't carry stated
intent at all.) A deep single-protocol integration would have hidden that
asymmetry instead of surfacing it as a first-class modeling concern.

## 2. The policy engine is pure deterministic code with zero LLM calls in the enforcement path

**Chosen:** `evaluate()` is a pure function: same inputs always produce the
same output, no network calls, no model inference, no hidden state beyond
an explicitly-passed replay set. Every check it performs (signature,
expiry, replay, merchant match, amount cap, category scope) is a plain
comparison against fields already present in the mandate and the proposed
transaction.

**Rejected:** Using an LLM to review the proposed transaction against the
mandate's intent and decide ALLOW/DENY/NEEDS_HUMAN, which is the more
"agentic" and flexible-looking option and was tempting given the rest of
the system talks to AI buying agents.

**Why:** This is an authorization gateway — its job is to be the thing you
can trust *even when* the agents on either side of it are compromised,
buggy, or being actively attacked (prompt injection, adversarial catalog
data, etc.). An LLM in the enforcement path means the gate itself becomes
attackable by the same techniques used against buying agents, and its
decisions stop being reproducible or auditable in the way a hash-chained
log demands — "the model said no" is not a defensible answer to a
merchant or a regulator. Determinism also makes the test suite meaningful:
`test_attacks.py` can assert an exact DENY for an exact reason, which is
not possible against a system with non-deterministic reasoning. If natural-language
reasoning is ever useful (e.g. summarizing *why* something looks
suspicious for a human reviewer), it belongs strictly downstream of the
ALLOW/DENY/NEEDS_HUMAN decision, never as part of making it.

## 3. Ed25519 signature verification with one hardcoded demo keypair

**Chosen:** `NormalizedMandate.signing_payload()` (schema.py) serializes
every field except `signature` into deterministic bytes (sorted keys,
fixed separators). `keys.sign()`/`keys.verify()` wrap a single hardcoded
Ed25519 keypair. `policy_engine.verify_signature()` now actually checks:
does this signature verify against these exact bytes, with this key? Any
mismatch — forged signature, or a legitimate signature over fields that
were changed afterward — returns False, which `evaluate()` turns into
`DENY / failed_check="signature"`.

**Rejected (for this build):** Per-principal keys with a registration
flow; a KMS or hardware-backed key store; key rotation.

**Why:** The signature check exists to answer one question: did the
transaction the gate is looking at actually come from something the
principal signed, unmodified? A single fixed keypair is enough to prove
that mechanism works — real forgery is rejected, real tampering is
detected — without building the much bigger (and out-of-scope, see the
build plan's cuts) problem of key management for many principals. This
is explicitly a demo shortcut, not a claim that key management is solved;
said so directly in the code (`keys.py`) and here, so it can't be
mistaken for something it isn't in front of a panel.

**What changed as a result:** every mandate fixture and every mandate
built in the tests now carries a real signature (see `_signed()` helpers
in `test_policy_engine.py` / `test_attacks.py`, and the regenerated
`tests/fixtures/*.json`). A new adversarial test,
`test_attack_forged_signature_is_denied`, covers the attack class this
closes: an agent impersonating a principal it doesn't represent, without
holding that principal's key.

## 4. Persistent replay detection via a single-table SQLite store

**Chosen:** `nonce_store.py` adds `NonceStore`, a thin SQLite-backed
class implementing exactly the two operations `evaluate()` already used
on `seen_nonces` — `x in store` and `store.add(x)`. The CLI now passes a
`NonceStore` pointed at `nonces.db` instead of a `set()`.

**Rejected:** A "real" queue/cache system (Redis, a message broker);
changing `evaluate()`'s signature to take something more specific than
"a thing that supports `in` and `add`."

**Why:** The bug being fixed is narrow: a mandate marked as spent must
stay spent after the process restarts. SQLite in a single file solves
exactly that, with no new service to run or configure — appropriate for
a demo/single-merchant-instance system, called out explicitly as not
sufficient for multiple concurrent instances (see open items). Keeping
`evaluate()`'s parameter untyped beyond "supports `in`/`add`" means the
pure-function contract from decision #2 doesn't change at all — tests
can still pass a plain `set()`, and the persistence choice lives entirely
in the caller (the CLI), not in the policy engine.

## 5. NEEDS_HUMAN is produced by a plain threshold rule, never by the LLM

**Chosen:** `evaluate()` gained exactly one new branch (check g.): for an
AP2-style mandate (has `max_amount`, i.e. expresses a ceiling rather than
one exact transaction), if the proposed amount is more than
`HUMAN_REVIEW_FRACTION_OF_CAP` (0.5) of that ceiling, the outcome is
`NEEDS_HUMAN` — a plain, reproducible, deterministic rule, computed the
same way every other check in this function is. ACP-style tokens
(`exact_amount` set) never hit this branch — they're single-use and
bound to one exact amount, so there's no "fraction of a ceiling" for
them to be ambiguous about.

**Rejected:** Having the LLM decide when a transaction needs human
review — e.g. "ask the model whether this cart plausibly matches the
mandate's stated intent, and route to NEEDS_HUMAN if it says no."

**Why:** This is the direct, load-bearing consequence of decision #2. It
isn't enough to say "no LLM call inside `evaluate()`" — decision #2 also
says natural-language reasoning belongs "strictly downstream of the
ALLOW/DENY/NEEDS_HUMAN decision, never as part of making it." If the LLM
decided *whether* something needs human review, it would be back inside
the decision path in every way that matters: a buying agent's inputs
(product listings, seller descriptions, catalog metadata) are
attacker-controlled text, and anything an LLM reads from that surface can
carry instructions aimed at the model rather than at the merchant. Keeping
the LLM strictly downstream of a decision that's already been made
deterministically means a successful prompt injection can at worst
produce a misleading *explanation* for a human reviewer to read — it can
never flip ALLOW/DENY/NEEDS_HUMAN itself. The LLM's only job (see
decision #6, `llm_explainer.py`) is to explain a NEEDS_HUMAN case in
plain language *after* the threshold rule already flagged it.

**Where the 0.5 threshold came from:** it's a placeholder that's honest
about being one — chosen because it's an easy, round number to defend
("more than half the mandate's stated ceiling, in one request, gets a
human's eyes") rather than derived from any real risk model. A real
deployment would tune this per-merchant or per-category; that tuning is
out of scope here.

## 6. The one LLM call is a downstream explainer, not a decision-maker

**Chosen:** `llm_explainer.py` exposes one function,
`explain(mandate, proposed_tx, decision) -> str`, called only after
`evaluate()` has already returned `NEEDS_HUMAN`. It produces a
plain-language summary for the human reviewer ("this request would spend
80% of the mandate's ₹1000 electronics allowance in one transaction") —
it never receives the ability to change `decision.outcome`, and nothing
downstream re-parses its output as a decision. If no `ANTHROPIC_API_KEY`
is configured, it falls back to a deterministic template string built
from the same fields, clearly labeled as a fallback — so the demo runs
end-to-end with or without a live API key, and the fallback path can
never be mistaken for a real model output.

**Why this shape specifically:** a function that takes a decision that
was already made, and returns a string, cannot — structurally, not just
by policy — become the thing deciding ALLOW/DENY/NEEDS_HUMAN. That's a
stronger guarantee than "we told the model not to decide": the code path
that could let it decide doesn't exist.

## 7. The human approval gate is a persistent queue + CLI, and "Razorpay execution" honestly means order creation, not a full payment round-trip

**Chosen:** `approval_queue.py` (`ApprovalQueue`, SQLite-backed, same
pattern as `nonce_store.py`) holds NEEDS_HUMAN requests until a person
resolves them via `python -m darwaza.cli review` /
`approve <id>` / `deny <id>`. Approving or denying appends a *second*
audit log entry for that mandate_id — so the audit trail for a
NEEDS_HUMAN mandate reads as two lines: the deterministic flag, then the
human's resolution, each independently hash-chained. Approving also
triggers `razorpay_client.create_order()`, which creates a real
Razorpay test-mode order (fails loudly, not silently, if
`RAZORPAY_KEY_ID`/`RAZORPAY_KEY_SECRET` aren't set).

**What "execution" honestly means here:** `create_order()` proves the
authorization decision reaches a real payment processor in test mode —
it does not simulate an actual card/UPI payment completing, because that
requires Razorpay's Checkout (a real frontend flow) or a separate
test-mode payment-simulation call. Darwaza's stated scope is the
authorization gateway, not the checkout UI (see the project's problem
statement) — so "order create + capture" in the build plan is satisfied
as "a real order exists in Razorpay's test environment, correctly
configured to auto-capture," not as "money moved end-to-end with no
human or frontend involved anywhere." Said directly here rather than
implied by a reassuring function name.

**Why the audit trail gets two entries instead of one being edited:**
the append-only hash-chained log (see the original audit_log.py
decision) cannot edit a past entry without breaking the chain, which is
the entire point of it — a NEEDS_HUMAN flag is not corrected in place
into an ALLOW, it is followed by a new, separately-chained entry
recording that a human made a decision. A dispute reconstruction reads
both lines and sees exactly what the deterministic engine flagged and
exactly what a human then decided, with a timestamp and reason for each.

## 8. Amount validity is checked before the signature, and `isfinite()` is
   used instead of a plain `<= 0` guard

**Chosen:** `evaluate()` now begins with a check that
`proposed_tx.amount` is a positive, finite number
(`math.isfinite(amount) and amount > 0`), placed *before* signature
verification, and `ProposedTransaction.amount` also carries a matching
Pydantic constraint (`gt=0, allow_inf_nan=False`) at the schema level.

**Rejected:** A single `if amount <= 0: deny` guard, and/or relying on
the schema constraint alone without a corresponding check inside
`evaluate()`.

**Why this was a real defect, not a hypothetical one:** neither check e.
(amount cap: `amount > max_amount`) nor check g. (human review:
`amount > 0.5 * max_amount`) ever expressed a lower bound. A spend cap
written as "not more than X" only bounds one direction — nothing in the
model ever stated that money is assumed to flow from principal to
merchant. Verified directly against the running code: `0.0`, `-1000.0`,
`-999999.0`, and `float('nan')` all returned `ALLOW` against a mandate
with `max_amount=1000.0`; only `float('inf')` was (incidentally) caught,
by the `>` in check e. `float('-inf')` also passed as `ALLOW` — it's
less than any finite cap and less than half of one.

**Why `<= 0` alone is not a sufficient fix:** NaN is unordered by
definition — every comparison against NaN except `!=` returns `False`,
including `nan <= 0`. A guard written as `if amount <= 0: deny` silently
never fires for NaN, which is the exact mechanism that let it slip past
checks e. and g. in the first place. `math.isfinite()` rejects NaN and
both infinities explicitly, by construction, rather than by relying on
comparison semantics that happen to work for ordinary numbers.

**Why this check runs before check a. (signature) rather than after
it:** every other check in this function reads a field from the
*mandate*, which is exactly why signature verification has to run
first — DECISIONS.md's original ordering rationale ("every later check
is reading fields from a document we haven't confirmed the principal
actually signed") is about the mandate, not about `proposed_tx`.
`proposed_tx` was never signed by anyone; it's the buyer agent's own
live claim about what it wants to buy right now, not part of what the
principal authorized. Confirming its shape is sane doesn't require
trusting the mandate at all, so there is no reason to spend an Ed25519
verification on a request whose amount isn't even a real number.

**Why both the schema constraint and the `evaluate()` check exist, when
either one alone would stop most of this:** the Pydantic constraint on
`ProposedTransaction.amount` stops an invalid value from ever becoming a
constructed object anywhere in the system — including in code that
doesn't route through `evaluate()` at all, like a future HTTP API layer
deserializing a request body. But `evaluate()` cannot assume every
caller went through normal Pydantic construction: `buyer_agent.py` and
`simulate.py` build `ProposedTransaction` values directly in Python, a
future caller could use `model_construct()` to skip validation
deliberately (tests use exactly this to exercise the `evaluate()`-level
check in isolation), and `evaluate()` is meant to be a self-contained,
trustworthy gate regardless of what already validated its inputs
upstream. Defence in depth here means neither layer is allowed to be
"the one that actually does it."

## 9. NEEDS_HUMAN reserves the nonce; denial leaves it spent

**Chosen:** the nonce is now marked spent the moment a mandate reaches
NEEDS_HUMAN, not only once a human later approves it (`cli.py`'s
`decide()` and `simulate.py`'s `_run()` both changed from
`if outcome == ALLOW` to `if outcome in (ALLOW, NEEDS_HUMAN)`). If a
human later denies the request, the reservation is *not* released — the
mandate stays spent. This is deliberate, not an oversight: there is no
code path anywhere that removes a mandate_id from the nonce store once
added, for either outcome.

**Rejected:** releasing the reservation on denial (so a denied mandate
could be resubmitted), or reserving only a "soft hold" distinct from a
full spend that a human could reverse.

**Why reserve at NEEDS_HUMAN instead of waiting for the human's
decision:** a mandate that reaches NEEDS_HUMAN is already spoken for —
it is sitting in a queue, on its way to a real decision. Leaving it
claimable in the meantime means the same single-use mandate can produce
any number of separate pending approvals (reproduced directly: three
`simulate needs-human` calls against the same mandate_id produced three
independent queue rows, each independently approvable, i.e. three
Razorpay orders from one authorization). The nonce isn't "spent" in the
sense of money having moved — it's spent in the sense that this mandate
has already committed to one outcome-in-progress, and a second,
concurrent claim on the same mandate is never legitimate regardless of
how the first one resolves.

**Why a denial doesn't un-spend it (fail closed):** the alternative —
releasing the nonce so the same mandate can be resubmitted after a
human denial — would mean a denial is not actually a denial, just a
delay until someone tries again (or an attacker retries automatically).
A human explicitly declining a transaction should be the end of that
mandate's story, not a retry prompt. If the principal genuinely wants to
authorize the same purchase again, that requires a new mandate with a
new `mandate_id` — cheap to obtain from the principal in a real flow,
and the correct place for a second, independent decision to be made.

**What this does not yet fix:** reservation still happens via the
non-atomic check-then-add pattern (`evaluate()` checks membership,
the caller calls `.add()` afterward) — this closes the *sequential*
version of D4 (proven by three separate CLI invocations, one after
another) but not the concurrent version, which is Stage 3's
`NonceStore.claim()` fix.

## 10. evaluate() stops being a pure function: checking and claiming the
    nonce fuse into one atomic operation, and the check moves last

**Chosen:** `policy_engine.evaluate()`'s third parameter changed from
`NonceRegistry` (`__contains__`-only, read-only) to `NonceClaimer`
(`claim(mandate_id) -> bool`, a single atomic check-and-reserve). Replay
protection is no longer "check `x in seen_nonces`, and trust the caller
to separately call `.add()` after a successful ALLOW" — it's now
`nonce_claimer.claim(mandate.mandate_id)`, called once, inside
`evaluate()` itself, as the function's *last* check (moved from its old
position third, right after expiry). `nonce_store.NonceStore.claim()`
implements this as a single `INSERT`, relying on the `mandate_id`
PRIMARY KEY constraint to reject a duplicate — the database itself is
what makes the operation atomic, not application-level locking.

**Rejected:** Keeping `evaluate()` pure and instead trying to fix D1 in
the caller (e.g. wrapping the caller's check-then-add in a
`threading.Lock`). This doesn't work: `cli.py` and `simulate.py` are
separate, independently-invoked processes for every CLI command, so an
in-process lock protects nothing across the process boundary a real
replay attack would actually cross (see D1's original reproduction:
separate threads, but the identical race exists across separate
processes hitting a shared `nonces.db`). The fix has to live where the
atomicity actually is: the database transaction.

**Why decision #2's original purity choice was correct at the time,
and why it stopped being sufficient:** decision #2 chose "no side
effects, no hidden mutation" specifically to keep the *decision rules*
reproducible and auditable — `evaluate()`'s callers, not `evaluate()`
itself, were made responsible for persistence, so the same rule logic
could be tested with a plain `set()` and deployed with a SQLite-backed
store with zero changes to the function computing the rules. That
reasoning held right up until "checking membership" and "reserving the
nonce" needed to become *one* operation instead of two — at that point,
"evaluate() never mutates anything" and "replay protection is atomic"
became mutually exclusive, and D1 is what happens when you pick the
former. Purity was a means to an end (rules that are reproducible,
explainable by exact rule, and testable without a database); it was
never the actual goal. The actual goal — every check being a plain,
deterministic rule computed the same way from the same inputs, with no
model and no ambiguity in what triggers it — is completely unchanged
by this: `claim()`'s *result* (True/False) still deterministically
follows from state that's either already committed or not; nothing
about the decision became probabilistic or judgment-based. What changed
is where that state lives and how it's touched, not what governs the
decision.

**Why replay had to move from check c. to last (now check g.):** once
"check" and "claim" fuse into one call, running that call in the
*middle* of `evaluate()` (its old position, before merchant/amount/
category) would mean a mandate that was always going to fail on, say,
amount_cap still consumes its nonce on the way to that DENY. That
converts replay protection into a denial-of-service primitive: an
attacker who cannot forge a signature can still replay someone else's
*legitimate* `mandate_id` attached to a deliberately out-of-policy
`proposed_tx`, purely to burn the real principal's nonce before they
get to use it — a free, un-forgeable way to invalidate someone else's
mandate. Running every other check first, and claiming only once the
mandate is already known to end in ALLOW or NEEDS_HUMAN, means a
mandate can only ever consume its one legitimate use — never be
sacrificed by an attacker on a request that was never going to succeed
anyway.

**What this closes vs. what it doesn't:** this closes D1 for real,
including across separate processes (not just threads) — verified with
50 concurrent threads x 15 runs (recorded in the Stage 3 report),
consistently exactly one ALLOW. It does not change the multi-instance
scope limit named in decision #4 and the open items: one SQLite file
is still one instance's store; two *separate* merchant deployments each
running their own `nonces.db` are (correctly) not coordinated with each
other, because they were never meant to be the same store.

## 11. Audit log concurrency: an OS-level lock plus an in-memory tip
    cache, not a database

**Chosen:** `audit_log.append_entry()` wraps its read-tip-then-write
sequence in a `portalocker.Lock` on a sidecar `<file>.lock`, and caches
each log file's `(seq, hash)` tip in memory after the first read so
later appends in the same process don't re-scan the whole file. Each
entry now also carries an explicit `seq` integer.

**Rejected:** Moving the audit log into SQLite (consistent with
`nonce_store.py`/`approval_queue.py`), or using `fcntl` for the file
lock.

**Why not SQLite here, when it was the right call for the nonce store
and approval queue:** those two are *reservation* systems — the thing
that matters is "has this id already been claimed," a query SQLite's
transactional guarantees answer for free. The audit log's job is
different: it's an external, human/dispute-facing artifact whose value
partly comes from being a plain, greppable, append-only text file
(JSONL) that doesn't require a SQLite client to inspect during a
dispute. Moving it into SQLite would solve the concurrency problem too,
but at the cost of the format decision this project already made and
never revisited — not worth relitigating just to reuse one mechanism
everywhere.

**Why `portalocker` and not bare `fcntl`:** `fcntl` doesn't exist on
Windows, and this system runs on Windows (see the environment notes in
this repo). `portalocker` wraps the platform-appropriate primitive
(`msvcrt.locking` on Windows, `fcntl.flock` on POSIX) behind one API,
so the same code path is what's actually tested here.

**Why a sidecar lock file instead of locking `audit_log.jsonl`
itself:** a reader (`verify_chain()`, a human tailing the file, this
project's own `docs/LLD.md` dispute-reconstruction story) should never
have to contend with a writer's lock just to read a file that's
supposed to be append-only and safe to read at any time. Locking a
separate `<file>.lock` guards only the critical section that actually
needs serializing — computing the next `seq`/`prev_hash` and appending
— without making reads block on it.

**Why the in-memory tip cache is safe to assume single-process:** this
matches the same "one file for one instance" scope already named for
`nonce_store.py` and `approval_queue.py` (decision #4, open items). If
two processes ever appended to the same log file, this process's cache
could go stale relative to what the other process wrote, and its next
append would chain off the wrong tip — but `verify_chain()` would
(correctly, by design) report exactly that as a break, so the failure
mode is "loudly detected," not "silently wrong."

## 12. SQLite concurrency: one connection per thread, not one shared
    connection with `check_same_thread=False`

**Chosen:** `nonce_store.NonceStore` and `approval_queue.ApprovalQueue`
each give every thread that touches them its own `sqlite3.Connection`
(via `threading.local`), with `PRAGMA journal_mode=WAL` and
`PRAGMA busy_timeout=5000` set on each connection. `check_same_thread`
is still passed as `False` on each of those per-thread connections —
but only so a coordinating thread can `close()` them all during cleanup
after their owning threads are done; no two threads ever operate on the
same connection concurrently, which is what actually caused D3.

**Rejected:** Keeping one shared connection with
`check_same_thread=False` and just adding WAL mode / `busy_timeout` on
top of it.

**Why the shared connection was the actual defect, not just missing
pragmas:** a `sqlite3.Connection` object tracks its own implicit
transaction state in the Python DB-API layer. When multiple threads
issue `execute()`/`commit()` against the *same* connection object
without external synchronization, their transaction boundaries
interleave — thread A's implicit transaction can get committed by
thread B's `commit()` call, or thread B can try to commit a transaction
thread A already closed. That's exactly what produced
`"cannot start a transaction within a transaction"` and
`"cannot commit — no transaction is active"`: not lock contention on
the database file (which WAL/`busy_timeout` would fix), but confused
in-process bookkeeping about whose transaction is whose.
`check_same_thread=False` didn't cause this — it only removed the
guardrail that would have raised a clear error the moment a second
thread touched the connection, which is precisely why D3 surfaced as
data-layer chaos instead of an obvious, early `ProgrammingError`.

**Why WAL mode and `busy_timeout` are still added, given one-connection-
per-thread already fixes the interleaving:** they solve a different,
real problem — once every thread has its own connection, those
connections *do* still contend for the database file itself (SQLite
allows only one writer at a time by default). WAL mode lets readers
proceed without blocking on a writer; `busy_timeout` makes a writer that
loses a brief lock race wait and retry instead of raising
`OperationalError` immediately. Both together are what make 20
concurrent threads each getting their own connection actually succeed,
rather than just fail with a *different*, more honest-looking error.

## 13. One service layer, two entry points — the CLI stays, it doesn't
    get replaced by the HTTP API

**Chosen:** `service.py` holds every operation that used to be
duplicated between `cli.decide()`/`cli.simulate()` (`authorize()`) and,
as of this stage, between what would otherwise have become duplicated
`approve`/`deny`/`review` handlers in `cli.py` and `api.py`
(`resolve_approval()`, `list_pending_approvals()`). Both `cli.py` (a
human at a terminal) and `api.py` (a buying agent over HTTP, added this
stage) call into `service.py` and do nothing else with the policy
engine, the nonce store, the audit log, the explainer, or the approval
queue directly — `cli.py` is now pure presentation: load input, call a
`service.py` function, print whatever comes back.

**Rejected:** Building the HTTP API as the primary interface and
demoting or removing the CLI; or building `api.py` as a second,
independent implementation of "evaluate -> claim -> log -> explain ->
enqueue" and "resolve -> log -> execute" that happens to produce
similar results to the CLI's.

**Why the CLI doesn't go away:** a buying agent is a machine on a
network — it needs a network interface, which is what `api.py` is for.
A human reviewing a NEEDS_HUMAN request and typing `approve <id>` is a
person making a judgment call at a terminal, which is what a CLI is
for and an HTTP API is not a more "modern" replacement for. These are
different consumers with different reasons to exist side by side, not
two versions of the same thing where the newer one wins.

**Why the duplication had to be eliminated by extraction, not just by
one caller wrapping the other:** having `api.py` call into `cli.py`'s
functions (or vice versa) would couple a presentation module's
interface — CLI argument parsing, `print()`, `sys.exit()` — to logic
that has nothing to do with either presentation surface. `service.py`
functions raise typed exceptions (`ApprovalNotFoundError`,
`ApprovalAlreadyResolvedError`) and return plain result objects
(`AuthorizationResult`, `ResolutionResult`) precisely so each
presentation layer decides for itself how to represent them — an exit
code and a printed message for the CLI, an HTTP status code and a JSON
body for the API — without service.py knowing or caring which one is
asking.

## 14. Credentials are loaded and validated at import time, not read
    from `os.environ` per call — and a live Razorpay key refuses to
    even start the process

**Chosen:** `config.py` reads every credential and configurable path
from `os.environ` exactly once, at module import time, and immediately
validates `RAZORPAY_KEY_ID` if one is configured: if it doesn't start
with `rzp_test_`, `config.py` raises `ConfigError` and the import
fails — nothing else in the package can run. Every other module reads
its configuration via `from darwaza import config` then `config.X`
(attribute access on the live module), never `from darwaza.config
import X` (which would copy the value once and stop tracking updates)
and never `os.environ` directly.

**Rejected:** Leaving credential reads where they were (inside
`razorpay_client.create_order()` and `llm_explainer.explain()`,
per-call, as before Stage 5) and only adding the `rzp_test_` format
check as an assertion inside `create_order()` itself.

**Why validating at import time instead of at the point of use is the
actual point, not a style preference:** the dangerous case is a human
approving a NEEDS_HUMAN request that consumes most of a mandate's
cap — precisely the moment this project's whole thesis says deserves
the most scrutiny — and *that* being the first time a live-key
misconfiguration is discovered, with a real charge potentially already
in flight. Validating at process start means a misconfigured deployment
never serves a single request; the failure happens at the most boring,
consequence-free possible moment (an import), not the highest-stakes
one.

**Why `config.X` attribute access instead of importing the names
directly:** this is what keeps every module's configuration testable
without needing a fresh subprocess per test. `monkeypatch.setattr(config,
"RAZORPAY_KEY_ID", None)` mutates the actual `config` module namespace;
any code doing `config.RAZORPAY_KEY_ID` *at the moment it needs the
value* sees the patched value, exactly as if the environment had really
changed. A name bound once via `from darwaza.config import
RAZORPAY_KEY_ID` would freeze that value into the importing module's
own namespace at import time, and no later monkeypatch of `config`
would reach it — this is not a hypothetical: it's exactly what broke
`tests/test_razorpay_client.py`'s `monkeypatch.delenv(...)` calls when
this stage moved credential reads to `config.py` (fixed by switching
those tests to `monkeypatch.setattr(config, ...)` instead — see that
test file's docstring).

**A real, deliberate side effect: importing `darwaza.config` with a
live key set now crashes the whole process, including running the test
suite.** This is treated as correct, not as friction to design around —
if a developer's shell happens to have a real Razorpay key exported
while running `pytest` or `python -m darwaza.cli`, refusing to start at
all is exactly the outcome wanted. Nothing in this codebase should ever
run against real payment credentials, on purpose or by accident.

**What's still explicitly not validated, and why that's fine:**
`RAZORPAY_KEY_SECRET` and `ANTHROPIC_API_KEY` have no format Razorpay
or Anthropic exposes to check against — unlike `RAZORPAY_KEY_ID`,
there's no `test_`/`live_` prefix convention for a secret or an API
key, so there's nothing safe to assert about their shape beyond
"configured or not." Both remain genuinely optional, exactly as before
this stage — this project runs end-to-end with neither set.

## Open items

- **Multi-instance replay protection isn't solved** — this is
  specifically about multiple *separate processes/instances* sharing
  load (e.g. horizontally scaled behind a load balancer), not about
  concurrency within one instance. Concurrent access *within* one
  process/one SQLite file — many threads, many requests against one
  running instance — is solved as of Stage 3 (decisions #10-#12): an
  atomic `claim()`, WAL mode, `busy_timeout`, and per-thread
  connections together closed D1/D2/D3, verified under repeated
  concurrent-load test runs (see the Stage 3 report/commit for pass
  counts). What remains unsolved is coordination *across* multiple
  separate SQLite files/instances, which only a shared service (Redis,
  a real DB) would provide — see `docs/SCALING.md` for the designed,
  not-built path there. The approval queue has the identical remaining
  limitation, for the identical reason.
- **Key management is out of scope.** One hardcoded keypair stands in for
  every principal (see decision 3 above) — no registration, issuance, or
  rotation flow exists.
- **The 0.5 human-review threshold is a placeholder**, not a tuned risk
  model (see decision #5). Naming this directly rather than presenting
  0.5 as considered.
- **Razorpay execution stops at order creation** (see decision #7) — no
  actual payment is simulated end-to-end without a frontend or a
  separate test-payment call.
- **`decide_with_llm()` in buyer_agent.py is untested by the automated
  suite** — it requires a live `ANTHROPIC_API_KEY` and isn't
  reproducible enough to assert on in CI; the deterministic path is
  what's actually proven to work.
