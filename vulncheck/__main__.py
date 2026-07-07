"""vulncheck — run: python3 -m vulncheck

Exit code is non-zero if the tool fails its OWN self-validation: a check that
cannot prove it fires on a positive and stays silent on a negative is a bug in
the tool, and the tool refuses to trust it rather than ship it green.
"""
import sys
from .checks import ALL_CHECKS
from .harness import self_validate, evaluate_corpus
from . import corpus

BAR = "=" * 72


def main():
    print(BAR)
    print("vulncheck — the tool checks itself before it checks you")
    print(BAR)

    print("\n[1] SELF-VALIDATION  (every check must pass its own falsifiable tests)\n")
    trusted, rejected, results = self_validate(ALL_CHECKS)
    for r in results:
        print(f"  [{'TRUST ' if r.passed else 'REJECT'}] {r.check_id}")
        for _ in r.missed_positives:
            print("           - missed a known positive (would be a FALSE NEGATIVE in prod)")
        for _ in r.false_fires:
            print("           - fired on a known negative (would be a FALSE POSITIVE in prod)")
    print(f"\n  {len(trusted)} trusted, {len(rejected)} rejected. "
          f"Rejected checks never run against real code.")

    print("\n[2] CORPUS EVALUATION  (measure the tool's OWN FP/FN on labelled code)\n")
    tp, fp, fn, fired = evaluate_corpus(trusted)
    print(f"  corpus: {len(corpus.VULNERABLE)} vulnerable + {len(corpus.CLEAN)} clean\n")
    print(f"  {'check':<20}{'TP':>4}{'FP':>4}{'FN':>4}   prec   recall")
    ttp = tfp = tfn = 0
    for c in trusted:
        t, p, n = tp[c.id], fp[c.id], fn[c.id]
        ttp += t; tfp += p; tfn += n
        prec = t / (t + p) if (t + p) else 1.0
        rec = t / (t + n) if (t + n) else 1.0
        note = "   <- FALSE POSITIVE: narrow before trusting" if p else ""
        print(f"  {c.id:<20}{t:>4}{p:>4}{n:>4}   {prec:>4.0%}   {rec:>4.0%}{note}")
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

    print("\n[4] WHAT THIS TOOL DOES NOT CLAIM\n")
    print("  Coverage is over the ENCODED classes only. A bug class nobody encoded")
    print("  scores NOTHING, not low — absent, not missed. Novel classes are the")
    print("  foreign-seat's job, by construction (Rice's theorem + distribution")
    print("  shift). Bar-raiser over a known past; never a sealer over the future.")
    print("  Green here means 'clean against what it knows', never 'clean'.")
    print("\n" + BAR)

    return 1 if rejected else 0


if __name__ == "__main__":
    sys.exit(main())
