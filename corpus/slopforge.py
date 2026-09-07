#!/usr/bin/env python3
"""SlopForge - adversarial report generator (roadmap item 1).

Reads the target repository and writes slop that cites *real* symbols, *real*
files, and *in-range* line numbers, so every surface check the baseline
performs comes back green. The lie is the association between them: the
declared function is genuinely defined, but not in the declared file.

This is Adversary 2 from docs/threat_model.md, mechanized. Tier T5.

Gold label is HALLUCINATED: "`chunk_decode()` is in lib/url.c" is false at the
stated ref, and it is the report's own load-bearing location claim. Nothing
here is random - the same repo always forges the same corpus.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from slopgate import ground                       # noqa: E402
from slopgate.extract import NOISE_SYMBOLS        # noqa: E402

# C keywords that a `name(` scan picks up but that are never call sites, plus
# entry points, which make degenerate items.
SKIP = NOISE_SYMBOLS | {"if", "for", "while", "switch", "return", "sizeof",
                        "defined", "main"}
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
TEST_DIRS = ("tests", "test", "fuzz", "examples")

# Cycled so the forged corpus is not twelve copies of one CWE.
FLAVORS = [
    ("Critical", "CWE-787", "writes past the end of its destination buffer"),
    ("High", "CWE-125", "reads one element beyond the allocation"),
    ("High", "CWE-190", "computes a length that can wrap on 32-bit builds"),
    ("Medium", "CWE-416", "keeps a pointer to storage its caller may free"),
]


def _rel(repo, p):
    return os.path.relpath(p, repo).replace(os.sep, "/")


def _is_test(rel):
    return rel.split("/")[0] in TEST_DIRS


def harvest(repo):
    """Return (definitions, line_counts, file_text) for the real tree."""
    line_counts, text, candidates = {}, {}, set()
    for path in ground.walk_sources(repo):
        rel = _rel(repo, path)
        src = open(path, encoding="utf-8", errors="replace").read()
        text[rel] = src
        line_counts[rel] = len(src.splitlines())
        candidates.update(CALL_RE.findall(ground.strip_comments(src)))

    defs = {}
    for sym in sorted(candidates - SKIP):
        rec = ground.find_symbol(repo, sym)
        if rec["status"] != "DEFINED":
            continue
        home = rec["definitions"][0]["file"].replace(os.sep, "/")
        if _is_test(home):
            continue          # test-only helpers are not a credible claim
        defs[sym] = home
    return defs, line_counts, text


def forge(repo, out_dir, limit=6):
    """Write T5 reports. Returns label manifest entries."""
    import build_corpus       # imported here: build_corpus imports us in main()

    defs, line_counts, text = harvest(repo)
    # Only .c files are credible locations for a memory-safety claim, and the
    # claimed file must not contain the symbol at all - a declaration in a
    # header would make the item ambiguous rather than hard.
    files = sorted(f for f in line_counts
                   if f.endswith(".c") and not _is_test(f) and line_counts[f] >= 6)

    items = []
    for sym in sorted(defs):
        for f in files:
            if f == defs[sym] or sym in text[f]:
                continue
            sev, cwe, blurb = FLAVORS[len(items) % len(FLAVORS)]
            name = "t5_%s" % chr(ord("a") + len(items))
            line = max(1, line_counts[f] // 2)
            body = ("`%s()` %s. The defect is in the copy loop at %s:%d, which "
                    "trusts a length the caller never validates."
                    % (sym, blurb, f, line))
            open(os.path.join(out_dir, name + ".md"), "w",
                 encoding="utf-8").write(build_corpus.TMPL.format(
                     title="%s in %s()" % (cwe, sym), sev=sev, cwe=cwe,
                     path=f, fn=sym, line=line, ver="minihttp-1_0",
                     body=body,
                     poc="Drive %s() with an oversized input." % sym))
            items.append({"file": name + ".md", "tier": "T5",
                          "label": "HALLUCINATED", "primary_symbol": sym,
                          "synthetic": True, "generator": "slopforge",
                          "forged_claim": "%s is defined in %s, not %s"
                                          % (sym, defs[sym], f)})
            if len(items) >= limit:
                return items
    return items


def _selfcheck(repo):
    """Every forged item must survive the checks it is designed to defeat."""
    defs, line_counts, text = harvest(repo)
    assert defs, "harvested no definitions from %s" % repo
    for it in forge(repo, os.path.join(HERE, "reports")):
        sym = it["primary_symbol"]
        claimed = re.search(r"is defined in \S+, not (\S+)",
                            it["forged_claim"]).group(1)
        assert sym in defs, sym                       # symbol is real
        assert claimed in line_counts, claimed        # file is real
        assert defs[sym] != claimed                   # but not its home
        assert sym not in text[claimed]               # and not even mentioned
    print("slopforge selfcheck: ok")


if __name__ == "__main__":
    repo = os.path.join(ROOT, "examples", "target_repo")
    os.makedirs(os.path.join(HERE, "reports"), exist_ok=True)
    _selfcheck(repo)
    print("forged %d T5 reports" % len(forge(repo, os.path.join(HERE, "reports"))))
