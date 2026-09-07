#!/usr/bin/env python3
"""Generate the labeled seed corpus.

Tiers, by how hard they are to ground:
  T1 symbol absent entirely            (grep catches this)
  T2 symbol appears only in a comment  (grep says "found it" - grep fails here)
  T3 symbol real but unreachable       (needs a call graph)
  T4 symbol real, reachable, real bug  (must NOT be called slop)
  T5 real symbol, real file, in-range line, but the symbol is not in that
     file - forged by corpus/slopforge.py from the tree itself

Labels are HALLUCINATED for T1/T2/T5 and NOT_HALLUCINATED for T3/T4.
T3 is deliberately labeled NOT_HALLUCINATED: dead code is a real code smell and
auto-closing it is the failure mode this project exists to avoid.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "reports")

TMPL = """# {title}

**Severity:** {sev}
**CWE:** {cwe}
**Affected file:** {path}
**Affected function:** {fn}
**Affected line:** {line}
**Version:** {ver}

## Summary

{body}

## Proof of concept

{poc}
"""

ITEMS = [
    # --- T1: symbol does not exist anywhere -------------------------------
    ("t1_a", "T1", "HALLUCINATED", dict(
        title="Heap overflow in curl_easy_parse_header()", sev="Critical",
        cwe="CWE-122", path="lib/http_chunks.c", fn="curl_easy_parse_header",
        line=214, ver="minihttp-1_0",
        body="`curl_easy_parse_header()` copies an attacker-controlled header "
             "into a fixed 256-byte stack buffer without bounds checking.",
        poc="Return a header longer than 256 bytes.")),
    ("t1_b", "T1", "HALLUCINATED", dict(
        title="Use-after-free in http_state_release()", sev="High",
        cwe="CWE-416", path="lib/http_chunks.c", fn="http_state_release",
        line=88, ver="minihttp-1_0",
        body="`http_state_release()` frees the chunk state and then reads "
             "`st->used` from the freed allocation.",
        poc="Trigger two consecutive releases.")),
    ("t1_c", "T1", "HALLUCINATED", dict(
        title="Integer overflow in url_normalize_percent()", sev="High",
        cwe="CWE-190", path="lib/url.c", fn="url_normalize_percent",
        line=140, ver="minihttp-1_0",
        body="`url_normalize_percent()` multiplies the escape count by 3 "
             "without an overflow guard.",
        poc="Supply 2^30 escape sequences.")),
    ("t1_d", "T1", "HALLUCINATED", dict(
        title="Format string bug in chunk_log_error()", sev="Medium",
        cwe="CWE-134", path="lib/http_chunks.c", fn="chunk_log_error",
        line=60, ver="minihttp-1_0",
        body="`chunk_log_error()` passes attacker data as the format argument.",
        poc="Send a chunk header containing %n.")),
    # --- T2: symbol appears only in a comment / changelog -----------------
    ("t2_a", "T2", "HALLUCINATED", dict(
        title="Stack overflow in curl_easy_parse_header()", sev="Critical",
        cwe="CWE-121", path="lib/http_chunks.c", fn="curl_easy_parse_header",
        line=12, ver="minihttp-1_0",
        body="The header helper `curl_easy_parse_header()` is reachable from "
             "`chunk_decode()` and writes past its destination.",
        poc="Oversized header value.")),
    ("t2_b", "T2", "HALLUCINATED", dict(
        title="Missing bounds check in curl_easy_parse_header()", sev="High",
        cwe="CWE-787", path="docs/history.md", fn="curl_easy_parse_header",
        line=2, ver="minihttp-1_0",
        body="Documentation confirms `curl_easy_parse_header()` ships in this "
             "release and it lacks a length check.",
        poc="See summary.")),
    # --- T3: real symbol, unreachable from any entry point ----------------
    ("t3_a", "T3", "NOT_HALLUCINATED", dict(
        title="Out-of-bounds read in url_legacy_unescape()", sev="High",
        cwe="CWE-125", path="lib/url.c", fn="url_legacy_unescape",
        line=25, ver="minihttp-1_0",
        body="`url_legacy_unescape()` advances the read pointer three bytes on "
             "`%` without checking that two bytes remain.",
        poc="Pass a string ending in a bare percent sign.")),
    ("t3_b", "T3", "NOT_HALLUCINATED", dict(
        title="Pointer arithmetic overflow in url_legacy_unescape()",
        sev="Medium", cwe="CWE-823", path="lib/url.c", fn="url_legacy_unescape",
        line=26, ver="minihttp-1_0",
        body="The write pointer can pass the read pointer for malformed input.",
        poc="Malformed escape sequence at end of string.")),
    # --- T4: real, reachable, genuine defect ------------------------------
    ("t4_a", "T4", "NOT_HALLUCINATED", dict(
        title="Length confusion in chunk_decode()", sev="High",
        cwe="CWE-787", path="lib/http_chunks.c", fn="chunk_decode", line=45,
        ver="minihttp-1_0",
        body="`chunk_decode()` copies the declared chunk length from the wire "
             "without comparing it against `len`, the bytes actually present.",
        poc='chunk_decode(&st, "ffff\\r\\nA", 7)')),
    ("t4_b", "T4", "NOT_HALLUCINATED", dict(
        title="Unbounded hex accumulation in chunk_read_size()", sev="Medium",
        cwe="CWE-190", path="lib/http_chunks.c", fn="chunk_read_size", line=20,
        ver="minihttp-1_0",
        body="`chunk_read_size()` accumulates into a size_t and only checks the "
             "bound after multiplication.",
        poc="Send a 32-digit hex chunk length.")),
    ("t4_c", "T4", "NOT_HALLUCINATED", dict(
        title="Truncation in url_parse_host()", sev="Low", cwe="CWE-197",
        path="lib/url.c", fn="url_parse_host", line=10, ver="minihttp-1_0",
        body="`url_parse_host()` rejects long hosts but callers may ignore the "
             "return value.",
        poc="Supply a 300-character host.")),
    ("t4_d", "T4", "NOT_HALLUCINATED", dict(
        title="Missing length guard in chunk_decode()", sev="High",
        cwe="CWE-120", path="lib/http_chunks.c", fn="chunk_decode", line=48,
        ver="minihttp-1_0",
        body="The memcpy in `chunk_decode()` is bounded by the attacker-declared "
             "size rather than the received size.",
        poc="Truncated chunk body.")),
    # Negative control for the T5 location rule: citing the header that only
    # *declares* the symbol is legitimate report-writing, not a forgery. If
    # this ever flips to HALLUCINATED the rule has started costing 500x.
    ("t4_e", "T4", "NOT_HALLUCINATED", dict(
        title="Bad API contract in chunk_decode()", sev="Medium",
        cwe="CWE-787", path="lib/http_chunks.h", fn="chunk_decode", line=10,
        ver="minihttp-1_0",
        body="The prototype for `chunk_decode()` takes a length the "
             "implementation ignores.",
        poc="See summary.")),
]


def main():
    os.makedirs(OUT, exist_ok=True)
    labels = []
    for name, tier, label, kw in ITEMS:
        fn = "%s.md" % name
        with open(os.path.join(OUT, fn), "w", encoding="utf-8") as f:
            f.write(TMPL.format(**kw))
        labels.append({"file": fn, "tier": tier, "label": label,
                       "primary_symbol": kw["fn"], "synthetic": True})

    import slopforge  # imported here so slopforge can reuse TMPL above
    labels += slopforge.forge(os.path.join(HERE, os.pardir,
                                           "examples", "target_repo"), OUT)
    with open(os.path.join(HERE, "labels.json"), "w") as f:
        json.dump({"target_repo": "examples/target_repo",
                   "labeling_protocol": "docs/labeling_protocol.md",
                   "items": labels}, f, indent=2)
    print("wrote %d reports to %s" % (len(labels), OUT))


if __name__ == "__main__":
    main()
