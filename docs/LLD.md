# Low-Level Design

Sequence diagrams, the full check order inside `policy_engine.evaluate()`
and why that order is load-bearing, the actual data model, and the
`failed_check` taxonomy. Everything here matches the code as it exists
today (see `git log` / DECISIONS.md for how it got this way).

## Sequence diagrams

### ALLOW path

```mermaid
sequenceDiagram
    participant Agent as Buying agent
    participant API as api.py
    participant RL as rate_limit.RateLimiter
    participant Svc as service.authorize()
    participant Eng as policy_engine.evaluate()
    participant Keys as keys.py
    participant Nonce as nonce_store.NonceStore
    participant Audit as audit_log.append_entry()
    participant Obs as observability.py

    Agent->>API: POST /v1/authorize {mandate, proposed_tx}
    API->>RL: allow(agent_key, mandate_id)
    RL-->>API: allowed=True
    API->>Svc: authorize(mandate, proposed_tx)
    Svc->>Obs: new_decision_id()
    Svc->>Eng: evaluate(mandate, proposed_tx, nonce_claimer)
    Eng->>Eng: check 0: amount finite & > 0
    Eng->>Keys: verify(principal_id) registered? (check a0)
    Eng->>Keys: verify(principal_id, payload, signature) (check a)
    Eng->>Eng: checks b-f pass (expiry, merchant, cap, category, threshold)
    Eng->>Nonce: claim(mandate_id) (check g)
    Nonce-->>Eng: True (not previously spent)
    Eng-->>Svc: Decision(ALLOW, failed_check=None)
    Svc->>Audit: append_entry(decision_id, ALLOW)
    Svc->>Obs: log_decision(...)
    Svc-->>API: AuthorizationResult
    API-->>Agent: 200 {outcome: "ALLOW"}
```

### DENY path

```mermaid
sequenceDiagram
    participant Agent as Buying agent
    participant API as api.py
    participant Svc as service.authorize()
    participant Eng as policy_engine.evaluate()
    participant Audit as audit_log.append_entry()

    Agent->>API: POST /v1/authorize {mandate, proposed_tx}
    API->>Svc: authorize(mandate, proposed_tx)
    Svc->>Eng: evaluate(mandate, proposed_tx, nonce_claimer)
    Note over Eng: Fails at the FIRST check that doesn't hold --<br/>invalid_amount, unknown_principal, signature,<br/>expiry, merchant_match, amount_cap, or<br/>category_scope. Every one of these returns<br/>BEFORE check g. (replay claim) ever runs --<br/>the nonce is untouched. Only "replay" itself<br/>DENIES *at* check g., because claim() returning<br/>False *is* that DENY reason.
    Eng-->>Svc: Decision(DENY, failed_check="<one of the above>")
    Svc->>Audit: append_entry(decision_id, DENY, failed_check)
    Svc-->>API: AuthorizationResult
    API-->>Agent: 403 {outcome: "DENY", failed_check: "..."}
```

### NEEDS_HUMAN → approve → execute path

```mermaid
sequenceDiagram
    participant Agent as Buying agent
    participant API as api.py
    participant Svc as service.py
    participant Eng as policy_engine.evaluate()
    participant Nonce as nonce_store.NonceStore
    participant Explain as llm_explainer.explain()
    participant Queue as approval_queue.ApprovalQueue
    participant Human as Human reviewer (CLI)
    participant RZP as razorpay_client.create_order()

    Agent->>API: POST /v1/authorize
    API->>Svc: authorize(mandate, proposed_tx)
    Svc->>Eng: evaluate(...)
    Eng->>Nonce: claim(mandate_id) (check g. -- reserved NOW, decision #9)
    Nonce-->>Eng: True
    Eng-->>Svc: Decision(NEEDS_HUMAN, failed_check="human_review_threshold")
    Svc->>Svc: append_entry() -- audit entry #1 for this mandate
    Svc->>Explain: explain(mandate, proposed_tx, decision)
    Explain-->>Svc: plain-language string (never alters the decision)
    Svc->>Queue: enqueue(...) status="pending"
    Svc-->>API: request_id
    API-->>Agent: 202 Accepted {request_id, explanation}

    Human->>Queue: review  (GET /v1/approvals or `cli.py review`)
    Human->>Svc: resolve_approval(request_id, approved=True)
    Svc->>Queue: resolve(request_id, approved=True)
    Queue-->>Svc: status="approved_pending_execution"
    Svc->>Svc: append_entry() -- audit entry #2, independently chained (decision #7)
    Svc->>RZP: create_order(amount, receipt=request_id)
    Note over RZP: internal retry (timeout/5xx, up to 3 attempts)<br/>+ idempotency-by-receipt lookup before create (decision #17)
    alt Razorpay call succeeds
        RZP-->>Svc: order
        Svc->>Queue: mark_executed(request_id, order_id)
        Queue-->>Svc: status="executed"
    else Razorpay call fails (all retries exhausted, or no keys)
        RZP-->>Svc: raises
        Svc->>Queue: record_execution_failure(request_id, error)
        Queue-->>Svc: status stays "approved_pending_execution" (retryable)
        Human->>Svc: execute_approval(request_id)  (later retry, any number of times)
        Svc->>RZP: create_order(amount, receipt=request_id)
        RZP-->>Svc: order (idempotent lookup finds nothing new to create, or creates fresh)
        Svc->>Queue: mark_executed(request_id, order_id)
    end
```

### NEEDS_HUMAN → deny path

```mermaid
sequenceDiagram
    participant Human as Human reviewer (CLI)
    participant Svc as service.resolve_approval()
    participant Queue as approval_queue.ApprovalQueue
    participant Audit as audit_log.append_entry()

    Note over Queue: mandate_id's nonce was already claimed when this<br/>request first reached NEEDS_HUMAN (decision #9) --<br/>a denial does NOT release it (fail closed).
    Human->>Svc: resolve_approval(request_id, approved=False)
    Svc->>Queue: resolve(request_id, approved=False)
    Queue-->>Svc: status="denied" (terminal)
    Svc->>Audit: append_entry() -- audit entry #2:<br/>Decision(DENY, failed_check="human_review_denied")
    Note over Svc: razorpay_client.create_order() is never called.<br/>No new mandate can reuse this mandate_id --<br/>a genuinely-changed-mind principal needs a new mandate.
    Svc-->>Human: ResolutionResult(approved=False)
```

## The check order inside `evaluate()`, and why it's load-bearing

```
0.  Amount validity        -- math.isfinite(amount) and amount > 0
a0. Unknown principal      -- principal_id in keys.PUBLIC_KEYS
a.  Signature               -- keys.verify(principal_id, payload, signature)
b.  Expiry                  -- mandate.expiry > now
c.  Merchant match          -- ACP-only: mandate.merchant_id == proposed_tx.merchant_id
d.  Amount cap               -- ACP: exact match. AP2: proposed_tx.amount <= max_amount
e.  Category scope           -- AP2-only: proposed_tx.category in category_scope
f.  Human review threshold  -- AP2-only: amount > 0.5 * max_amount -> NEEDS_HUMAN (not DENY)
g.  Replay/claim            -- nonce_claimer.claim(mandate_id), LAST
```

`evaluate()` returns at the **first** check that fails — this is not
incidental, it's what makes the check order itself a correctness
property, not just a style choice:

- **0 and a0/a run before everything else.** Every check from b. onward
  reads a *field of the mandate* (`expiry`, `merchant_id`, `max_amount`,
  `category_scope`) — and until check a. has confirmed the mandate was
  actually signed by the principal it claims to be from, **every one of
  those fields is attacker-controlled**. Reading `mandate.max_amount`
  to decide anything before the signature is verified would mean an
  attacker could raise their own cap simply by editing the JSON, with
  no cryptography required to make the gate believe it. Check a0 (an
  unregistered principal, decision #18) sits immediately before check
  a. rather than after it, because an unregistered principal has no key
  to check the signature against *at all* — there's nothing for check
  a. to even attempt in that case. Check 0 (amount validity) is the one
  exception allowed to run first: `proposed_tx` was never signed by
  anyone (it's the agent's live claim about what it wants to buy right
  now, not part of what the principal authorized), so confirming its
  shape is sane doesn't require trusting the mandate at all — see
  DECISIONS.md #8.
- **g. (replay/claim) runs LAST, deliberately, and is fused into one
  atomic operation with the check itself (decision #10).** If the nonce
  claim ran earlier (its original position, third), a mandate that was
  always going to fail on, say, `amount_cap` would still burn its nonce
  on the way to that DENY. That turns replay protection into a
  denial-of-service primitive: an attacker who cannot forge a signature
  can still replay someone else's *legitimate* `mandate_id` attached to
  a deliberately out-of-policy `proposed_tx`, purely to exhaust the real
  principal's one legitimate use before they get to it. Running every
  other check first, and claiming only once the mandate is already
  known to end in ALLOW or NEEDS_HUMAN, closes that: a mandate can only
  ever be consumed by its own legitimate use.

Rate limiting (`rate_limit.py`, HTTP 429) is deliberately **not** a
check inside `evaluate()` at all — it runs in `api.py`, ahead of
`service.authorize()`, and never touches the nonce store, audit log, or
`Decision`/`Outcome` (decision #16). A 429 is "this request wasn't
evaluated yet," not a ninth policy check with an opinion about the
mandate's content.

## Data model

The actual Pydantic schemas (`schema.py`), unmodified:

```python
class ProposedTransaction(BaseModel):
    merchant_id: str
    amount: float = Field(gt=0, allow_inf_nan=False)
    category: str | None = None


class Outcome(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    NEEDS_HUMAN = "NEEDS_HUMAN"


class Decision(BaseModel):
    outcome: Outcome
    reason: str
    failed_check: str | None = None


class NormalizedMandate(BaseModel):
    # Present on both AP2 and ACP shapes
    mandate_id: str          # AP2: nonce/jti. ACP: single-use token id.
    principal_id: str
    expiry: datetime
    signature: str

    # AP2-only -- standing intent, not a bound transaction
    agent_id: str | None = None
    max_amount: float | None = None
    category_scope: list[str] | None = None

    # ACP-only -- exact, merchant-bound, single-use permission
    merchant_id: str | None = None
    exact_amount: float | None = None

    def signing_payload(self) -> bytes:
        """Every field except `signature`, canonical JSON (sorted
        keys, fixed separators) -- what a signature is computed over
        and verified against."""
```

The AP2/ACP asymmetry is real, not sloppy modeling (decision #1): an
AP2 mandate has `max_amount`/`category_scope`/`agent_id` and no
`merchant_id`/`exact_amount`; an ACP token is the reverse. `evaluate()`
branches on which fields are populated (`mandate.exact_amount is not
None` vs. `mandate.max_amount is not None`), not on an explicit
`protocol` discriminator field — there isn't one, by design, because
the normalized shape is supposed to make the two protocols
indistinguishable to every check except the ones that structurally
must differ (check c., d., e., f.).

## `failed_check` taxonomy

| `failed_check` value | Outcome | Meaning | Check |
|---|---|---|---|
| `invalid_amount` | DENY | `proposed_tx.amount` isn't a positive finite number (zero, negative, NaN, ±infinity) | 0 |
| `unknown_principal` | DENY | `principal_id` has no entry in `keys.PUBLIC_KEYS` — nothing to check the signature against at all | a0 |
| `signature` | DENY | Registered principal, but the signature doesn't verify against their key (forged, corrupted, or a field was tampered post-signing) | a |
| `expiry` | DENY | `mandate.expiry` is in the past | b |
| `merchant_match` | DENY | ACP token's bound `merchant_id` doesn't match `proposed_tx.merchant_id` | c |
| `amount_cap` | DENY | AP2: amount exceeds `max_amount`. ACP: amount doesn't exactly equal `exact_amount` | d |
| `category_scope` | DENY | AP2 mandate's `category_scope` doesn't include `proposed_tx.category` | e |
| `human_review_threshold` | **NEEDS_HUMAN** | AP2 amount exceeds 50% of `max_amount` — a correct, non-error outcome, not a failure | f |
| `replay` | DENY | `mandate_id` was already claimed by an earlier request | g |
| `human_review_denied` | DENY | Not from `evaluate()` — set by `service.resolve_approval()` when a human denies a NEEDS_HUMAN request (the mandate's *second* audit entry) | n/a (post-`evaluate()`) |
| `None` | ALLOW | Every check passed | — |

Not a `failed_check` value at all, listed here because it's easy to
mistake for one: a **429 rate-limit response** carries no
`failed_check` — it's an HTTP-layer response from `rate_limit.py`,
produced before `evaluate()` ever runs, and `Decision`/`Outcome` has no
representation for it on purpose (decision #16).
