"""The meta-test harness — the tool checking itself against ground truth.

Phase 1  self-validation : every check must pass its own self-tests or be
          REJECTED and excluded. 'Each check earns its place by being
          falsifiable.'
Phase 2  corpus evaluation: validated checks run on labelled samples; the tool
          measures its own TP/FP/FN. Ground-truth floor, not more judgement.

What the harness deliberately does NOT claim: completeness. It reports coverage
over the ENCODED classes only. A class nobody encoded scores NOTHING, not low —
it is absent, not missed-with-low-confidence. Novel classes stay the foreign
seat's job, by construction (Rice's theorem + distribution shift).
"""
from .check import validate_check
from . import corpus


def self_validate(checks):
    results = [validate_check(c) for c in checks]
    trusted = [c for c, r in zip(checks, results) if r.passed]
    rejected = [(c, r) for c, r in zip(checks, results) if not r.passed]
    return trusted, rejected, results


def evaluate_corpus(checks):
    tp = {c.id: 0 for c in checks}
    fp = {c.id: 0 for c in checks}
    fn = {c.id: 0 for c in checks}
    fired_map = {}

    for s in corpus.VULNERABLE:
        fired = {c.id: c.run(s["source"]) for c in checks if c.run(s["source"])}
        fired_map[s["name"]] = fired
        for c in checks:
            if c.cwe == s["cwe"]:
                (tp if c.id in fired else fn)[c.id] += 1
            elif c.id in fired:
                fp[c.id] += 1  # fired on an isolated sample that isn't its class -> false positive

    for s in corpus.CLEAN:
        fired = {c.id: c.run(s["source"]) for c in checks if c.run(s["source"])}
        fired_map[s["name"]] = fired
        for c in checks:
            if c.id in fired:
                fp[c.id] += 1

    return tp, fp, fn, fired_map
