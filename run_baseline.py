#!/usr/bin/env python3
"""SlopGate baseline - ground a vulnerability report in the code it describes.

Rule-based end to end. No model, no API key, no network, no dependencies
beyond the Python standard library and git.

    python3 run_baseline.py --report examples/report_hallucinated.md \
                            --repo examples/target_repo
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from slopgate import adjudicate as adj      # noqa: E402
from slopgate import extract, ground        # noqa: E402

BAR = "-" * 72


def analyze(report_path, repo):
    t0 = time.time()
    raw = open(report_path, encoding="utf-8").read()
    clean, injection = extract.sanitize(raw)
    claims = extract.extract_heuristic(clean)

    g = {"symbols": [], "paths": [], "reachability": []}
    for s in claims.get("symbols", []):
        rec = ground.find_symbol(repo, s)
        g["symbols"].append(rec)
        if rec["status"] == "DEFINED":
            g["reachability"].append(
                {"symbol": s, "result": ground.reachable_from_entry(repo, s, rec)})
    for p in claims.get("paths", []):
        g["paths"].append(ground.check_path(repo, p))
    g["version"] = ground.check_version(repo, claims.get("version"))

    primary = claims.get("primary_symbol")
    prec = next((r for r in g["symbols"] if r["symbol"] == primary), None)
    if prec:
        g["symbol_location"] = ground.check_symbol_location(
            repo, primary, prec, claims.get("primary_path"))

    if claims.get("line") and g["paths"]:
        # the line claim is about the report's *declared* file, not whichever
        # path sorted first
        pc = next((x for x in g["paths"] if x["path"] == claims.get("primary_path")),
                  g["paths"][0])
        g["line_check"] = {"claimed": claims["line"], "file_lines": pc["line_count"],
                           "in_range": bool(pc["exists"]
                                            and claims["line"] <= pc["line_count"])}

    out = adj.adjudicate(claims, g, injection)
    out.update({"report": os.path.basename(report_path),
                "method": "rule-based (no model call)",
                "latency_s": round(time.time() - t0, 3),
                "cost_usd": 0.0})
    return out


def render(r):
    print(BAR)
    print("SlopGate triage record: %s" % r["report"])
    print(BAR)
    print("VERDICT            %s   (confidence %.2f)" % (r["verdict"], r["confidence"]))
    print("RECOMMENDED ACTION %s" % r["recommended_action"])
    print("METHOD             %s   LATENCY %.3fs   COST $%.2f"
          % (r["method"], r["latency_s"], r["cost_usd"]))
    print()
    print("EVIDENCE")
    print("  %-13s %-32s %-13s %s" % ("TYPE", "VALUE", "STATUS", "DETAIL"))
    for c in r["claims"]:
        print("  %-13s %-32s %-13s %s"
              % (c["type"], str(c["value"])[:32], c["status"], c["evidence"][:70]))
    print()
    print("RATIONALE")
    for x in r["reasons"]:
        print("  - %s" % x)
    print(BAR)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--json", help="also write the record to this path")
    a = ap.parse_args()
    r = analyze(a.report, a.repo)
    render(r)
    if a.json:
        os.makedirs(os.path.dirname(a.json) or ".", exist_ok=True)
        json.dump(r, open(a.json, "w"), indent=2)
        print("wrote %s" % a.json)


if __name__ == "__main__":
    main()
