# Dashboard

A static, self-contained frontend for Darwaza — no build step, no
framework, no `node_modules`. Three files (`index.html`, `styles.css`,
`app.js`) plus a single vendored library (`vendor/mermaid.min.js`, for
the Architecture/Design tabs' diagrams — vendored rather than loaded
from a CDN so a live demo never depends on the panel room's network).

## Running it

It's mounted onto the same FastAPI app `api.py` already serves, so
there's nothing extra to start:

```
uvicorn darwaza.api:app --reload
```

Then open http://127.0.0.1:8000/dashboard/.

## What it is, precisely

A read/demo layer, not a new surface for the enforcement path. Every
tab does one of two things:

- **Reads** state that already exists — `/metrics`, `/v1/approvals`,
  `/v1/approvals/pending-execution`, and the one new read-only addition
  this needed, `GET /v1/audit-log` (a paginated view over the same
  `audit_log.jsonl` `/metrics` already summarizes).
- **Triggers** a scenario that already exists — `POST
  /v1/demo/simulate/{scenario}` is a thin wrapper around
  `simulate.py`'s `SCENARIOS` dict, the exact same
  `buyer_agent → service.authorize()` path `cli.py simulate` runs. It
  mints a fresh `mandate_id` per call (see the endpoint's docstring in
  `api.py`) so a dashboard button is safe to click more than once.

Neither of those two additions touches `policy_engine.evaluate()`,
`service.py`'s enforcement path, or any existing write path. See
`docs/HLD.md`'s component table — this folder and its two endpoints
are listed there as **outside** the trust boundary, the same category
as `buyer_agent.py`/`catalog.py`.

## Removing it

Delete this folder, the `app.mount("/dashboard", ...)` call and the
two endpoints (`GET /v1/audit-log`, `POST /v1/demo/simulate/{scenario}`)
in `api.py`, and the `mandate_id` keyword-argument override on
`simulate.py`'s three scenario functions (safe to leave — it defaults
to the original hardcoded ids and changes no existing behavior — but
nothing else would use it once this folder is gone). Nothing else in
the repo references any of this; the CLI, the API's core endpoints,
and every test outside `tests/test_dashboard_api.py` are unaffected.
