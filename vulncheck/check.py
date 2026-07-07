"""Core abstractions.

A Check is CODE, and code has bugs. A check's bugs are its false positives
(fires on clean code) and false negatives (misses a real one). So a check earns
trust the way any artefact does: it must PROVE it fires on a known positive and
stays silent on a known negative before it ever runs against real code. A check
that fails its own self-tests is rejected, not trusted. The tool checks itself
before it checks you.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass(frozen=True)
class Finding:
    check_id: str
    cwe: str
    message: str
    line: Optional[int] = None
    confidence: str = "pattern"   # "pattern" (static match) | "executed" (reproduced by running)
    evidence: str = ""            # what the run showed, when confidence == "executed"


@dataclass(frozen=True)
class SelfTest:
    """Ground truth for one check: it MUST fire on every positive and stay
    silent on every negative, or it is not trusted."""
    positives: tuple           # code snippets that DO contain the bug
    negatives: tuple           # code snippets that do NOT


@dataclass
class Check:
    id: str
    cwe: str
    description: str
    detect: Callable                       # detect(source) -> list[Finding]
    self_test: SelfTest
    confirm: Optional[Callable] = None     # optional: confirm(source) -> (bool, evidence) by EXECUTION

    def run(self, source: str):
        findings = self.detect(source)
        if self.confirm is None:
            return findings
        out = []
        for f in findings:
            ok, evidence = self.confirm(source)
            if ok:
                out.append(Finding(f.check_id, f.cwe, f.message, f.line, "executed", evidence))
            else:
                out.append(f)  # execution couldn't reproduce -> keep pattern confidence, don't inflate
        return out


@dataclass
class SelfTestResult:
    check_id: str
    passed: bool
    missed_positives: list = field(default_factory=list)  # should have fired, didn't (FN in prod)
    false_fires: list = field(default_factory=list)       # fired on a negative (FP in prod)


def validate_check(check: Check) -> SelfTestResult:
    """The tool checking itself: fire on known positives, silent on known
    negatives?"""
    missed = [p for p in check.self_test.positives if not check.detect(p)]
    false_fires = [n for n in check.self_test.negatives if check.detect(n)]
    return SelfTestResult(check.id, not missed and not false_fires, missed, false_fires)
