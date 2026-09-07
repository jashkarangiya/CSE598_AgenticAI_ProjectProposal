#!/usr/bin/env python3
"""Confusion matrix + per-tier breakdown, SlopGate vs a naive grep incumbent.

Two rule-based systems, no models anywhere. The grep incumbent is the honest
null hypothesis: "does the claimed symbol appear anywhere in the tree?" It does
fine on T1 and falls over on T2, and that gap is the result.
"""
import argparse
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

from run_baseline import analyze  # noqa: E402

POS = "HALLUCINATED"


def grep_baseline(report_path, repo):
    """Naive incumbent: symbol absent from `grep -r` output => HALLUCINATED."""
    import re
    text = open(report_path, encoding="utf-8").read()
    m = re.search(r"\*\*Affected function:\*\*\s*([A-Za-z_]\w*)", text)
    if not m:
        return "NOT_HALLUCINATED"
    out = subprocess.run(["grep", "-rq", m.group(1), repo],
                         capture_output=True)
    return "NOT_HALLUCINATED" if out.returncode == 0 else POS


def confusion(rows, key):
    tp = sum(1 for r in rows if r[key] == POS and r["gold"] == POS)
    fp = sum(1 for r in rows if r[key] == POS and r["gold"] != POS)
    fn = sum(1 for r in rows if r[key] != POS and r["gold"] == POS)
    tn = sum(1 for r in rows if r[key] != POS and r["gold"] != POS)
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if prec == prec and rec == rec and prec + rec else float("nan")
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=prec, recall=rec, f1=f1,
                expected_cost=fp * 500.0 + fn * 1.0)


def fmt(m):
    return ("TP=%-3d FP=%-3d FN=%-3d TN=%-3d  P=%.2f R=%.2f F1=%.2f  cost=%.1f"
            % (m["tp"], m["fp"], m["fn"], m["tn"], m["precision"], m["recall"],
               m["f1"], m["expected_cost"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", default=os.path.join(ROOT, "corpus", "labels.json"))
    a = ap.parse_args()

    spec = json.load(open(a.labels))
    repo = os.path.join(ROOT, spec["target_repo"])
    rdir = os.path.join(os.path.dirname(a.labels), "reports")

    rows, t0 = [], time.time()
    for it in spec["items"]:
        p = os.path.join(rdir, it["file"])
        r = analyze(p, repo)
        rows.append({"file": it["file"], "tier": it["tier"], "gold": it["label"],
                     "slopgate": r["verdict"] if r["verdict"] == POS
                                 else "NOT_HALLUCINATED",
                     "raw": r["verdict"], "conf": r["confidence"],
                     "grep": grep_baseline(p, repo), "latency": r["latency_s"]})
    elapsed = time.time() - t0

    print("=" * 78)
    print("PER-ITEM")
    print("  %-10s %-5s %-18s %-18s %-18s" % ("FILE", "TIER", "GOLD", "SLOPGATE", "GREP"))
    for r in rows:
        mark = " " if r["slopgate"] == r["gold"] else "X"
        print("%s %-10s %-5s %-18s %-18s %-18s"
              % (mark, r["file"], r["tier"], r["gold"], r["raw"], r["grep"]))

    print("\nOVERALL  (positive class = %s)" % POS)
    sg, gp = confusion(rows, "slopgate"), confusion(rows, "grep")
    print("  SlopGate      %s" % fmt(sg))
    print("  grep baseline %s" % fmt(gp))

    print("\nPER TIER (accuracy)")
    print("  %-5s %-4s %-12s %-12s" % ("TIER", "N", "SLOPGATE", "GREP"))
    for tier in sorted({r["tier"] for r in rows}):
        sub = [r for r in rows if r["tier"] == tier]
        s = sum(1 for r in sub if r["slopgate"] == r["gold"]) / len(sub)
        g = sum(1 for r in sub if r["grep"] == r["gold"]) / len(sub)
        print("  %-5s %-4d %-12.2f %-12.2f" % (tier, len(sub), s, g))

    print("\nABSTENTION  %d/%d verdicts were UNVERIFIED"
          % (sum(1 for r in rows if r["raw"] == "UNVERIFIED"), len(rows)))
    print("LATENCY     %.3f s/report (mean), %.2f s total"
          % (sum(r["latency"] for r in rows) / len(rows), elapsed))
    print("COST        $0.00 (rule-based, no model calls)")
    print("=" * 78)

    os.makedirs(os.path.join(ROOT, "eval", "results"), exist_ok=True)
    out = os.path.join(ROOT, "eval", "results",
                       "eval_%s.json" % time.strftime("%Y%m%d"))
    json.dump({"method": "rule-based", "rows": rows, "slopgate": sg, "grep": gp},
              open(out, "w"), indent=2)
    print("wrote %s" % os.path.relpath(out, ROOT))

    bad = [r["file"] for r in rows if r["slopgate"] != r["gold"]]
    if bad:
        print("REGRESSION  %d item(s) disagree with gold: %s" % (len(bad), ", ".join(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
