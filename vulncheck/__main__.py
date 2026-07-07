"""vulncheck — run: python3 -m vulncheck [paths...]

Two modes, one discipline:

  python3 -m vulncheck              self-check: validate every check against its
                                    own falsifiable tests, then grade the whole
                                    tool against the labelled corpus.
  python3 -m vulncheck <paths...>   scan: run the TRUSTED checks over real code.
                                    Self-validation still runs first — a tool
                                    that cannot pass its own tests has no
                                    business grading yours.

Exit codes:
  0  self-validation passed; no findings (scan mode) — "clean against what it
     knows", never "clean"
  1  self-validation passed but the scan reported findings (scan mode only)
  2  self-validation FAILED — one or more checks rejected; the tool refuses to
     trust itself, and in scan mode refuses to grade your code at all
"""
import argparse
import os
import sys
from .checks import ALL_CHECKS
from .harness import self_validate, evaluate_corpus
from . import corpus

BAR = "=" * 72


def print_self_validation(results, trusted, rejected):
    print("\n[1] SELF-VALIDATION  (every check must pass its own falsifiable tests)\n")
    for r in results:
        print(f"  [{'TRUST ' if r.passed else 'REJECT'}] {r.check_id}")
        for _ in r.missed_positives:
            print("           - missed a known positive (would be a FALSE NEGATIVE in prod)")
        for _ in r.false_fires:
            print("           - fired on a known negative (would be a FALSE POSITIVE in prod)")
    print(f"\n  {len(trusted)} trusted, {len(rejected)} rejected. "
          f"Rejected checks never run against real code.")


def print_honesty(trusted):
    print("\n[4] WHAT THIS TOOL DOES NOT CLAIM\n")
    print(f"  Coverage is over the {len(trusted)} ENCODED classes only. A bug class nobody")
    print("  encoded scores NOTHING, not low — absent, not missed. Novel classes are")
    print("  the foreign-seat's job, by construction (Rice's theorem + distribution")
    print("  shift). Bar-raiser over a known past; never a sealer over the future.")
    print("  Green here means 'clean against what it knows', never 'clean'.")


def self_check():
    print(BAR)
    print("vulncheck — the tool checks itself before it checks you")
    print(BAR)

    trusted, rejected, results = self_validate(ALL_CHECKS)
    print_self_validation(results, trusted, rejected)

    print("\n[2] CORPUS EVALUATION  (measure the tool's OWN FP/FN on labelled code)\n")
    tp, fp, fn, fired = evaluate_corpus(trusted)
    print(f"  corpus: {len(corpus.VULNERABLE)} vulnerable + {len(corpus.CLEAN)} clean\n")
    print(f"  {'check':<24}{'TP':>4}{'FP':>4}{'FN':>4}   prec   recall")
    ttp = tfp = tfn = 0
    for c in trusted:
        t, p, n = tp[c.id], fp[c.id], fn[c.id]
        ttp += t; tfp += p; tfn += n
        prec = t / (t + p) if (t + p) else 1.0
        rec = t / (t + n) if (t + n) else 1.0
        note = "   <- FALSE POSITIVE: narrow before trusting" if p else ""
        print(f"  {c.id:<24}{t:>4}{p:>4}{n:>4}   {prec:>4.0%}   {rec:>4.0%}{note}")
    P = ttp / (ttp + tfp) if (ttp + tfp) else 1.0
    R = ttp / (ttp + tfn) if (ttp + tfn) else 1.0
    print(f"\n  AGGREGATE over encoded classes: precision {P:.0%}, recall {R:.0%}")

    print("\n[3] EXECUTION-GROUNDED CONFIDENCE  (a finding CONFIRMED by running it)\n")
    any_exec = False
    for s in corpus.VULNERABLE:
        for c in trusted:
            for f in c.run(s["source"]):
                if f.confidence == "executed":
                    any_exec = True
                    print(f"  {f.check_id} on '{s['name']}': CONFIRMED, not guessed")
                    print(f"       {f.evidence}")
    if not any_exec:
        print("  (no execution-grounded checks fired on this corpus)")

    print_honesty(trusted)
    print("\n" + BAR)

    return 2 if rejected else 0


def collect_py_files(paths):
    files, missing = [], []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs[:] = sorted(d for d in dirs
                                 if not d.startswith(".") and d != "__pycache__")
                files.extend(os.path.join(root, n) for n in sorted(names)
                             if n.endswith(".py"))
        else:
            missing.append(p)
    return files, missing


def scan(paths):
    print(BAR)
    print("vulncheck — scan (the tool checked itself first)")
    print(BAR)

    trusted, rejected, results = self_validate(ALL_CHECKS)
    print_self_validation(results, trusted, rejected)
    if rejected:
        print("\n  SELF-VALIDATION FAILED — refusing to scan with an untrusted tool.")
        print("\n" + BAR)
        return 2

    files, missing = collect_py_files(paths)
    for m in missing:
        print(f"\n  warning: no such file or directory: {m}")

    print(f"\n[2] SCAN  ({len(files)} file(s), {len(trusted)} trusted checks)\n")
    total, executed_count, scanned = 0, 0, 0
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                source = fh.read()
        except OSError as e:
            print(f"  warning: could not read {path}: {e}")
            continue
        scanned += 1
        file_findings = []
        for c in trusted:
            if c.skip_path is not None and c.skip_path(path):
                continue
            file_findings.extend(c.run(source))
        for f in sorted(file_findings, key=lambda f: (f.line or 0)):
            total += 1
            if f.confidence == "executed":
                executed_count += 1
            loc = f"{path}:{f.line}" if f.line else path
            print(f"  {loc}")
            print(f"      [{f.confidence}] {f.check_id} ({f.cwe}): {f.message}")
            if f.evidence:
                print(f"      evidence: {f.evidence}")
    if total == 0:
        print("  no findings — over the encoded classes (see [4] for what that does NOT mean)")

    print(f"\n[3] SUMMARY\n")
    print(f"  {scanned} file(s) scanned, {total} finding(s): "
          f"{executed_count} executed (reproduced by running), "
          f"{total - executed_count} pattern (candidates, not facts)")

    print_honesty(trusted)
    print("\n" + BAR)

    return 1 if total else 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="vulncheck",
        description="A self-checking code checker: complete over the bug classes "
                    "it encodes, honestly silent on the ones it doesn't.")
    ap.add_argument("paths", nargs="*",
                    help="files or directories to scan; with no paths, "
                         "run the tool's own self-check + corpus grading")
    args = ap.parse_args(argv)
    return scan(args.paths) if args.paths else self_check()


if __name__ == "__main__":
    sys.exit(main())
