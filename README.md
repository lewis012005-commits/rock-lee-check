# vulncheck

A meta-testable, execution-grounded, catalogue-tier code checker for **defensive
hardening** — the executable form of the Rock Lee doctrine's conclusion about
checkers: *a checker is a bar-raiser, never a sealer.* It is complete over the
classes it encodes (the past) and honestly silent on the ones it doesn't (the
future, which stays imagination-bound). Detection only — it flags defects in
your own code so they can be fixed. It generates, delivers, and weaponises
nothing.

Run:

```
python3 -m vulncheck              # self-check: validate every check, grade the tool on the corpus
python3 -m vulncheck <paths...>   # scan real code with the TRUSTED checks (self-validation runs first)
```

Exit codes: `0` = green ("clean against what it knows", never "clean"); `1` =
scan findings; `2` = the tool failed its own self-validation and refuses to
grade your code at all.

## Catalogue (16 checks, all self-tested)

CWE-95 eval/exec · CWE-1188 mutable default (execution-grounded) · CWE-396 bare
except · CWE-617 assert-as-check · CWE-89 SQL string-building · CWE-798
hardcoded secret · CWE-78 shell command from data · CWE-502 unsafe deserialize ·
CWE-916 weak hash for secret · CWE-330 non-crypto random token · CWE-295 TLS
verify disabled · CWE-377 insecure tempfile · CWE-732 world-writable chmod ·
CWE-208 timing-unsafe compare · CWE-489 web debug mode · CWE-390 silent typed
except. Detection only; every one ships falsifiable self-tests and is rejected
until `validate_check` passes.

## Architecture

| file | job |
|---|---|
| `check.py` | `Check` + `Finding` + `validate_check` — a check is an artefact that ships with its own falsifiable self-tests; `skip_path` lets a check exempt whole files (e.g. tests) in scan mode |
| `checks.py` | the concrete checks (catalogue tier): each a known bug class with a CWE ref, detector, self-tests, optional execution-grounded confirm |
| `corpus.py` | labelled ground-truth (vulnerable + clean, all inert defect fixtures) — the tool's meta-test |
| `harness.py` | self-validation + corpus evaluation; measures the tool's own TP/FP/FN |
| `__main__.py` | runner: self-check mode + scan mode over real files; exits non-zero if the tool fails its own self-validation |

## The five disciplines (do not drop any of these when scaling)

1. **The tool checks itself before it checks you.** Every check must fire on a
   known positive and stay silent on a known negative (`validate_check`). A
   check that fails is *rejected*, never trusted. This is what stops a growing
   checker from crying wolf.
2. **The regress bottoms out on facts.** "Who checks the checker" doesn't
   recurse forever, because the checks are graded against a corpus with known
   answers. The sample trips a check or it doesn't; execution decides, not
   judgement.
3. **Execution grounds confidence.** Where a check can *reproduce* the bug by
   running it (see `mutable-default`), the finding is `executed`, not `pattern`.
   A reproduced bug is a fact; a pattern match is a candidate. Never inflate the
   second into the first.
4. **Two tiers, never averaged.** The catalogue tier (encoded known classes)
   handles *breadth*. The *frontier* — novel classes specific to your artefact —
   is out of scope by construction and belongs to a foreign-model seat. A class
   nobody encoded scores *nothing*, not low; it is absent, not missed.
5. **Bar-raiser, never sealer.** Green means "clean against what it knows,"
   never "clean." Rice's theorem (complete bug detection is undecidable) and
   distribution shift (a pattern-matcher can't reach a class it never saw) both
   forbid completeness. This tool is honest about that in output section [4].

## Extending it (the Guy clause, executable)

- **Add a check:** write the detector, write self-tests that PROVE it, append to
  `ALL_CHECKS`. The harness refuses to trust it until it passes. Every finding a
  relay draws becomes a permanent, one-call regression check this way.
- **Ingest the catalogue:** turn CWE/CVE/OWASP/Semgrep/CodeQL patterns into
  checks — but each ingested pattern earns trust the same way: falsifiable
  self-tests first. Bulk-importing patterns bulk-imports false positives (P4 at
  scale); the self-test gate is the calibration that stops it.
- **Adversarially narrow, then lock it in (how batch 2 was built):** the ten
  checks CWE-78…CWE-390 were authored in parallel, then each handed to a
  false-positive hunter that *reproduced by execution* a realistic clean idiom
  the first cut fired on — Gravatar's `md5(author_email)`, `shlex.quote()`'d
  shell commands, `random.uniform` jitter inside `refresh_access_token`, a
  server-side `CERT_NONE`, an `asyncio.run(debug=True)`. Every reproduced FP is
  now a permanent self-test **negative**: the narrowed detector does not run
  until it stays silent on the idiom that fooled it. Where a clean idiom is
  syntactically indistinguishable from the bug without data-flow (a bare-variable
  shell command, a stored-password `==`), recall is surrendered **honestly** and
  recorded as an accepted miss — never faked to keep a number at 100%.
- **Grow the corpus:** for production, replace the toy corpus with real labelled
  sets (NIST Juliet, OWASP Benchmark) so the FP/FN numbers mean something.

## Production TODO for Claude Code

- [ ] Real catalogue ingestion (CWE mappings; Semgrep/CodeQL rule import), each
      wrapped as a self-tested `Check`.
- [ ] A real labelled corpus (Juliet / OWASP Benchmark) driving calibrated
      precision/recall per check.
- [ ] Confidence *calibration tracking*: verify each confidence band actually
      hits at its stated rate; recalibrate on drift. An uncalibrated score is
      P2 with a decimal bolted on.
- [ ] Cross-seat agreement weighted by *seat diversity* (same-family agreement
      is weak; cross-model agreement is the real signal) as a confidence input.
- [x] Scope-narrowing the FP-prone checks: `assert-validation` skips test
      scopes/files; the batch-2 checks were each narrowed against a reproduced
      adversary FP (whole-word name gates, import-attributed sinks, `skip_path`
      for test files), and every exposing snippet stays as a regression negative.
      Residual accepted misses (bare-variable shell command, guard-insensitive
      `config['DEBUG']=True`, retry-loop `except: pass`) are documented in the
      check comments, not silently dropped.
- [ ] The frontier handoff: what the tool does NOT cover routes to a foreign
      seat, not to a lower-confidence bucket.

## Dogfood

`python3 -m vulncheck vulncheck/` — the tool scanning itself — reports exactly
one finding: its own `exec(compile(...))` inside the mutable-default confirm
harness. That is a true pattern-level hit on a deliberate, documented use
(executing inert corpus fixtures to reproduce a bug), and it stays reported
rather than suppressed: the tool does not special-case itself, and a `pattern`
finding is a candidate for human judgement, which is the correct tier here.

## Boundary

Detection + **inert defect fixtures** only. A string-concatenated SQL query is
the injection *anti-pattern* — a defect in code, connected to nothing. This tool
never writes functional exploits or anything that does harm. Code that *has* a
bug, never code that *is* a weapon.
