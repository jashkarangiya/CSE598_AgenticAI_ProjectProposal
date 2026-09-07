#!/usr/bin/env python3
"""SlopGate demo: one command, no arguments, fixed output.

Runs the baseline over five reports covering every tier that matters, prints
the full evidence bundle for the flagship case, and asserts the verdict of
each. Exits non-zero if any of them moves.

    python3 demo.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))
sys.path.insert(0, os.path.join(HERE, "corpus"))

import build_corpus                              # noqa: E402
from slopgate.cli import analyze, render     # noqa: E402

REPO = os.path.join(HERE, "examples", "target_repo")

# (report, tier, expected verdict, what it demonstrates)
CASES = [
    ("examples/report_hallucinated.md", "T2", "HALLUCINATED",
     "symbol exists only inside a comment"),
    ("corpus/reports/t5_a.md", "T5", "HALLUCINATED",
     "real symbol, wrong real file (SlopForge)"),
    ("examples/report_deadcode.md", "T3", "UNVERIFIED",
     "real but unreachable - a finding, not slop"),
    ("examples/report_real.md", "T4", "UNVERIFIED",
     "genuine defect - the negative control"),
    ("examples/report_injection.md", "--", "UNVERIFIED",
     "attacks the triage system - forced to a human"),
]


def main():
    if not os.path.exists(os.path.join(HERE, "corpus", "reports", "t5_a.md")):
        build_corpus.main()

    results = [(c, analyze(os.path.join(HERE, c[0]), REPO)) for c in CASES]

    print("\nFull evidence bundle for the flagship case:")
    render(results[0][1])

    print("\n%-28s %-5s %-14s %-5s  %s"
          % ("REPORT", "TIER", "VERDICT", "CONF", "WHY IT IS HARD"))
    for (path, tier, _, why), r in results:
        print("%-28s %-5s %-14s %.2f  %s"
              % (os.path.basename(path), tier, r["verdict"], r["confidence"], why))

    bad = [(c[0], r["verdict"], c[2]) for c, r in results if r["verdict"] != c[2]]
    for path, got, want in bad:
        print("FAIL  %s: expected %s, got %s" % (path, want, got))
    print("\n%s  %d/%d verdicts as expected."
          % ("FAIL" if bad else "PASS", len(CASES) - len(bad), len(CASES)))
    print("Triage a queue:   python3 slopgate.py corpus/reports "
          "--repo examples/target_repo")
    print("Full evaluation:  python3 eval/run_eval.py")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
