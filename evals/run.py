"""Runs evals/dataset.jsonl through policy_engine.evaluate() and reports
a scored result: pass rate, block rate on attacks, false-positive rate
on legitimate traffic, and a per-attack-class breakdown.

This is a *different* artifact from the pytest suite (test_attacks.py,
test_defect_hunt.py, etc.): those are unit tests — one input, one
expected output, pass/fail, run by a test framework, meant to gate a
merge. This is a scored corpus — the same shape a security/ML team
would use to track detection quality across changes over time (block
rate, false-positive rate, per-class breakdown), runnable on its own,
outside pytest, by anyone who wants to see the numbers without reading
source. The dataset is disjoint from the pytest suite's own cases on
purpose: this is measuring the *same* enforcement logic through an
*independent* corpus, not re-running the unit tests under a different
name.

Cases are run through evaluate() directly, not service.authorize() —
evaluate() is the actual enforcement decision (ALLOW/DENY/NEEDS_HUMAN);
service.authorize() wraps it with audit logging, LLM explanation, and
approval-queue enqueueing, none of which this eval is measuring. Cases
run in file order against ONE shared in-memory nonce claimer for the
whole corpus (see _EvalNonceClaimer below) — this is what makes the
replay attack_class meaningful: a mandate_id's "legitimate" first-use
case and its "replay" case are two separate rows, and the second one
only DENIES on replay because the first one already claimed it earlier
in this same run.

proposed_tx dicts are loaded via ProposedTransaction.model_construct()
(bypassing Pydantic's own gt=0/allow_inf_nan=False constraint)
deliberately, for every case, not just the invalid_amount ones — this
eval measures evaluate()'s OWN defence-in-depth amount check
(DECISIONS.md #8), independent of whatever a caller's schema layer
already validated. A real HTTP caller would have most invalid_amount
cases rejected at 400 before evaluate() ever ran (see api.py) — that's
a real, additional layer this eval doesn't exercise, and isn't meant to.
mandate dicts are loaded via NormalizedMandate.model_validate() (normal
validation/coercion — expiry needs to become a real datetime for
evaluate()'s expiry check to make sense), since no case in this corpus
is testing the mandate schema layer itself.

Usage:
    python evals/run.py

Exit code is non-zero if any case's actual outcome/failed_check doesn't
match its expected values — this is CI-able (see .github/workflows/ci.yml).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from darwaza.policy_engine import evaluate
from darwaza.schema import NormalizedMandate, ProposedTransaction

DATASET_PATH = Path(__file__).resolve().parent / "dataset.jsonl"


class _EvalNonceClaimer:
    """In-memory NonceClaimer (see policy_engine.NonceClaimer) scoped to
    one eval run — not nonce_store.NonceStore, because this eval has no
    reason to touch disk or survive a restart; it only needs the same
    atomic claim-once contract evaluate() requires, held for exactly the
    lifetime of one `python evals/run.py` invocation, so a case appearing
    twice in the dataset (the replay attack_class) behaves correctly
    within that one run."""

    def __init__(self) -> None:
        self._claimed: set[str] = set()

    def claim(self, mandate_id: str) -> bool:
        if mandate_id in self._claimed:
            return False
        self._claimed.add(mandate_id)
        return True


def load_dataset(path: Path) -> list[dict]:
    cases = []
    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                cases.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_num}: invalid JSON: {exc}") from exc
    return cases


def run_case(case: dict, nonce_claimer: _EvalNonceClaimer) -> dict:
    mandate = NormalizedMandate.model_validate(case["mandate"])
    proposed_tx = ProposedTransaction.model_construct(**case["proposed_tx"])

    decision = evaluate(mandate, proposed_tx, nonce_claimer)

    outcome_match = decision.outcome.value == case["expected_outcome"]
    failed_check_match = decision.failed_check == case["expected_failed_check"]

    return {
        "case_id": case["case_id"],
        "attack_class": case["attack_class"],
        "expected_outcome": case["expected_outcome"],
        "expected_failed_check": case["expected_failed_check"],
        "actual_outcome": decision.outcome.value,
        "actual_failed_check": decision.failed_check,
        "passed": outcome_match and failed_check_match,
    }


# Attack classes whose expected_outcome is DENY -- what "block rate"
# below is computed over. needs_human_threshold and legitimate are
# handled as their own buckets (see main()): NEEDS_HUMAN is a correct,
# legitimate *flagged* outcome, not a blocked attack, and folding it
# into either "attack" or "legitimate" would make both numbers lie.
ATTACK_CLASSES = {
    "forged_signature",
    "unknown_principal",
    "replay",
    "expired_mandate",
    "cross_merchant_token_misuse",
    "amount_cap_violation",
    "invalid_amount",
    "category_scope_violation",
}


def main() -> int:
    cases = load_dataset(DATASET_PATH)
    nonce_claimer = _EvalNonceClaimer()

    results = [run_case(case, nonce_claimer) for case in cases]

    total = len(results)
    passed = [r for r in results if r["passed"]]
    failed = [r for r in results if not r["passed"]]

    attacks = [r for r in results if r["attack_class"] in ATTACK_CLASSES]
    attacks_blocked = [r for r in attacks if r["actual_outcome"] == "DENY"]

    legitimate = [r for r in results if r["attack_class"] == "legitimate"]
    legitimate_allowed = [r for r in legitimate if r["actual_outcome"] == "ALLOW"]

    needs_human = [r for r in results if r["attack_class"] == "needs_human_threshold"]
    needs_human_correct = [r for r in needs_human if r["actual_outcome"] == "NEEDS_HUMAN"]

    by_class: dict[str, list[dict]] = {}
    for r in results:
        by_class.setdefault(r["attack_class"], []).append(r)

    print("=" * 72)
    print("DARWAZA EVAL REPORT")
    print("=" * 72)
    print(f"Dataset:              {DATASET_PATH}")
    print(f"Total cases:          {total}")
    print(f"Overall pass rate:    {len(passed)}/{total} ({100 * len(passed) / total:.1f}%)")
    print()
    print(
        f"Attack block rate:    {len(attacks_blocked)}/{len(attacks)} "
        f"({100 * len(attacks_blocked) / len(attacks):.1f}%)  "
        "-- fraction of attack-class cases that resulted in DENY"
    )
    print(
        f"False-positive rate:  {len(legitimate) - len(legitimate_allowed)}/{len(legitimate)} "
        f"({100 * (len(legitimate) - len(legitimate_allowed)) / len(legitimate):.1f}%)  "
        "-- fraction of legitimate cases that did NOT get ALLOW"
    )
    print(
        f"NEEDS_HUMAN accuracy: {len(needs_human_correct)}/{len(needs_human)} "
        f"({100 * len(needs_human_correct) / len(needs_human):.1f}%)  "
        "-- fraction of needs_human_threshold cases correctly flagged"
    )
    print()
    print(f"{'attack_class':<32} {'cases':>6} {'passed':>7} {'pass_rate':>10}")
    print("-" * 72)
    for attack_class in sorted(by_class):
        class_results = by_class[attack_class]
        class_passed = sum(1 for r in class_results if r["passed"])
        rate = 100 * class_passed / len(class_results)
        print(f"{attack_class:<32} {len(class_results):>6} {class_passed:>7} {rate:>9.1f}%")
    print("=" * 72)

    if failed:
        print(f"\n{len(failed)} FAILING CASE(S):")
        for r in failed:
            print(
                f"  [{r['case_id']}] expected outcome={r['expected_outcome']} "
                f"failed_check={r['expected_failed_check']!r}, "
                f"got outcome={r['actual_outcome']} failed_check={r['actual_failed_check']!r}"
            )
        return 1

    print("\nAll cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
