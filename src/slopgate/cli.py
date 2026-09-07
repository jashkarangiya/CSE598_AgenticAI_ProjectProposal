#!/usr/bin/env python3
"""SlopGate - ground vulnerability reports in the code they describe.

Rule-based end to end. No model, no API key, no network, no dependencies
beyond the Python standard library and git.

    python3 slopgate.py REPORT.md            # one report, full evidence bundle
    python3 slopgate.py inbox/               # a queue, ranked by what to read first

--repo defaults to the current directory, so pointing this at a checkout you
are standing in needs no flags.
"""
import argparse
import glob
import json
import os
import sys
import time

from . import adjudicate as adj
from . import extract, ground

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


# What to read first. A maintainer wants the reports most likely to be real at
# the top, so rank by verdict and then by how sure the verdict is: the least
# confident HALLUCINATED is the one most worth a second look.
RANK = {"REPRODUCIBLE": 0, "UNVERIFIED": 1, "HALLUCINATED": 2}


def triage(paths, repo):
    return sorted((analyze(p, repo) for p in paths),
                  key=lambda r: (RANK[r["verdict"]], r["confidence"]))


def render_queue(records, repo):
    hall = [r for r in records if r["verdict"] == "HALLUCINATED"]
    human = [r for r in records if r["verdict"] != "HALLUCINATED"]
    print(BAR)
    print("SlopGate queue: %d report(s) against %s" % (len(records), repo))
    print(BAR)
    print("  %-3s %-14s %-5s %-26s %s"
          % ("#", "VERDICT", "CONF", "REPORT", "TOP REASON"))
    for i, r in enumerate(records, 1):
        print("  %-3d %-14s %-5.2f %-26s %s"
              % (i, r["verdict"], r["confidence"], r["report"][:26],
                 (r["reasons"][0] if r["reasons"] else "")[:60]))
    print(BAR)
    print("READ FIRST   %d report(s) need a human" % len(human))
    print("DEPRIORITIZE %d report(s) contradict the tree, evidence attached"
          % len(hall))
    print("COST         $%.2f in %.2fs. Nothing was closed automatically."
          % (sum(r["cost_usd"] for r in records),
             sum(r["latency_s"] for r in records)))
    print(BAR)


def collect(target):
    """A file, a directory of reports, or a glob.

    A directory scan skips README.md: an inbox usually has one describing the
    inbox, and triaging it as a vulnerability report is noise. An explicit
    path or glob is honoured as given.
    """
    if os.path.isdir(target):
        return sorted(p for p in glob.glob(os.path.join(target, "*.md"))
                      if os.path.basename(p).lower() != "readme.md")
    hits = sorted(glob.glob(target))
    if not hits:
        sys.exit("no reports matched %r" % target)
    return hits


def main():
    ap = argparse.ArgumentParser(
        description="Ground vulnerability reports in the code they describe.")
    ap.add_argument("target", nargs="?",
                    help="report file, directory of reports, or glob")
    ap.add_argument("--report", help=argparse.SUPPRESS)   # older spelling
    ap.add_argument("--repo", default=".",
                    help="checkout the reports describe (default: .)")
    ap.add_argument("--json", help="also write the record(s) to this path")
    a = ap.parse_args()

    target = a.target or a.report
    if not target:
        ap.error("give a report file, a directory of reports, or a glob")

    paths = collect(target)
    if len(paths) == 1:
        out = analyze(paths[0], a.repo)
        render(out)
    else:
        out = triage(paths, a.repo)
        render_queue(out, a.repo)

    if a.json:
        os.makedirs(os.path.dirname(a.json) or ".", exist_ok=True)
        json.dump(out, open(a.json, "w"), indent=2)
        print("wrote %s" % a.json)


if __name__ == "__main__":
    main()
