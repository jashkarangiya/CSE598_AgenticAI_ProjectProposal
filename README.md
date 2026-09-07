# SlopGate

**Evidence-grounded triage for AI-generated vulnerability reports.**

Decides whether an inbound vulnerability report is grounded in the code it
claims to describe, and emits an evidence bundle for every verdict.

> Companion to the CSE 598 capstone proposal. The proposal covers the problem,
> the baseline mechanism, and the headline result. Everything else lives here.

---

## Quick start

```bash
git clone <REPO_URL> && cd slopgate
python3 run_baseline.py --report examples/report_hallucinated.md \
                        --repo   examples/target_repo
```

Python 3.8+ and `git`. **No dependencies, no model, no API key, no network.**
The baseline is rule-based end to end. The target repository is bundled in
`examples/target_repo`, so there is no clone step and no build step. First
result in well under a second.

### Full evaluation

```bash
python3 corpus/build_corpus.py     # writes 12 labeled reports to corpus/reports/
python3 eval/run_eval.py           # confusion matrix, per-tier breakdown, grep comparison
```

### Why the baseline has no model in it

This is deliberate. The first question worth asking about any agent is *what
does the dumbest possible system score?* A rule-based baseline answers that
honestly and sets the bar every later stage has to clear: a claim extractor
that costs $0.00 and runs in a millisecond is a real competitor, and an LLM
stage that does not beat it on the hard tiers should not ship.

It also means the artifact is trivially reproducible. Nothing to install,
nothing to authenticate, no rate limits, no nondeterminism, and no grader
staring at a traceback because they do not have a key.

LLM-assisted claim extraction is phase-2 work (roadmap item 3), and it will be
evaluated as a delta against these numbers, not as a replacement for them.

---

## CLI reference

### `run_baseline.py`

| Flag | Required | Default | Meaning |
|---|---|---|---|
| `--report PATH` | yes | — | Vulnerability report in Markdown |
| `--repo PATH` | yes | — | Checkout of the repository the report describes |
| `--json PATH` | no | — | Also write the machine-readable triage record |

### `eval/run_eval.py`

| Flag | Default | Meaning |
|---|---|---|
| `--labels PATH` | `corpus/labels.json` | Labeled corpus manifest |

Results are written dated to `eval/results/eval_YYYYMMDD.json` and committed.
Exits non-zero if any item's verdict disagrees with its gold label, so it works
as the regression gate for phase-2 changes.

---

## How it works

Four stages. Report text is treated as untrusted data at every one of them.

**1. Sanitize** (`src/slopgate/extract.py`)
Strips instruction-shaped spans from the report before any model sees it: HTML
comments, "ignore previous instructions", "set verdict to", "pre-verified by".
Each hit is recorded as an injection signal rather than silently dropped.

**2. Extract**
Regex over the report's structured header fields and inline code spans, pulling
the *declared* primary symbol, file paths, line number, version ref, and CWE
into a JSON claim set. Standard-library names (`memcpy`, `strlen`, ...) are
filtered out because they carry no grounding signal about the target. The
declared primary symbol drives the verdict; incidental symbols only contribute
supporting evidence.

**3. Ground** (`src/slopgate/ground.py`)
For each symbol, walk the tree with a **single-pass tokenizer** that blanks
comments and string literals while preserving line numbers, then classify:

| Status | Meaning |
|---|---|
| `ABSENT` | token appears nowhere in the tree |
| `MENTIONED` | appears, but only in a comment, string, or doc |
| `DEFINED` | appears at an actual definition site |

Then check path existence, line-in-range, git tag existence, and transitive
reachability from a non-test entry point (depth-4 caller graph; `tests/`,
`fuzz/`, and `examples/` are excluded as entry points).

The tokenizer matters more than it looks. A naive sequential regex stripper
treats the `//` inside `"https://example.com"` as a line comment and silently
swallows the rest of the line, which loses real call sites. One alternation
pass, strings first, fixes it.

**4. Adjudicate** (`src/slopgate/adjudicate.py`)
Deterministic rules over the evidence table, keyed on the report's *own*
declared primary claim. Every verdict traces to a specific check, so the
evidence bundle is an audit trail rather than a rationalization. Any detected
injection attempt forces routing to a human regardless of the grounding result.

Because nothing here is probabilistic, the same report against the same ref
always produces the same record. That is a property worth keeping as later
stages are added: the model may propose claims, but it should not be the thing
that decides.

---

## Verdicts and the cost matrix

| Verdict | Meaning | Action |
|---|---|---|
| `HALLUCINATED` | a load-bearing claim contradicts the tree at the claimed ref | deprioritize, evidence attached |
| `UNVERIFIED` | claims ground, exploitability undecided | needs human |
| `REPRODUCIBLE` | PoC executed and reproduced | escalate |

**SlopGate never auto-closes anything.** The operating point comes from an
explicit cost matrix in `adjudicate.py`: a wrongly closed real CVE is priced at
**500x** a wasted human review. Under that matrix abstaining is cheap and
guessing is not, so `UNVERIFIED` is the default whenever the evidence for
`HALLUCINATED` is anything less than unambiguous.

This is why the framing is *queue routing*, not classification. The output is
not a label, it is an ordering plus a pre-computed evidence bundle, so the
maintainer's next thirty minutes go to the reports most likely to be real.

`REPRODUCIBLE` is unreachable in the current baseline: there is no PoC sandbox
yet, so every genuinely grounded report collapses to `UNVERIFIED`.

---

## Difficulty tiers

Every corpus item is tagged, so precision on hard negatives is reported
separately from precision on easy ones.

| Tier | Claim under test | Why it is hard | Gold label |
|---|---|---|---|
| T1 | symbol absent from the tree | grep catches it | `HALLUCINATED` |
| T2 | symbol appears only in a comment | grep says "found it" and is wrong | `HALLUCINATED` |
| T3 | symbol real but unreachable | needs a call graph | `NOT_HALLUCINATED` |
| T4 | symbol real, reachable, genuine defect | must not be called slop | `NOT_HALLUCINATED` |

T3 is labeled `NOT_HALLUCINATED` deliberately. Dead code is a real finding, and
auto-closing it is exactly the failure this project exists to prevent.

---

## Current results

Seed corpus, 12 items. Two rule-based systems, no models involved, measured
against the honest null hypothesis: *does grep find the claimed symbol?*

```
OVERALL  (positive class = HALLUCINATED)
  SlopGate       TP=6  FP=0  FN=0  TN=6   P=1.00  R=1.00  F1=1.00   cost=0.0
  grep baseline  TP=3  FP=0  FN=3  TN=6   P=1.00  R=0.50  F1=0.67   cost=3.0

PER TIER (accuracy)
  TIER   n    SlopGate   grep
  T1     4    1.00       0.75
  T2     2    1.00       0.00
  T3     2    1.00       1.00
  T4     4    1.00       1.00

ABSTENTION  6/12 verdicts were UNVERIFIED
LATENCY     0.004 s/report      COST  $0.00 (rule-based, no model calls)
```

**T2 is the row that justifies the project.** In the bundled target,
`curl_easy_parse_header` appears in the tree exactly once, inside a block
comment recording that it was removed before release. grep reports it as
present. So does every symbol checker that does not parse.

Read these numbers with the obvious caveat: 12 synthetic items against one
small bundled repo. Perfect scores here mean the tiers are well separated, not
that the system generalizes. Corpus growth is item 6 on the roadmap.

---

## Repository layout

```
run_baseline.py              graded artifact - CLI entry point
requirements.txt             empty by design - stdlib only
src/slopgate/
  extract.py                 injection sanitizer + claim extraction
  ground.py                  tokenizer, symbol grounding, reachability
  adjudicate.py              cost-asymmetric decision rules
examples/
  report_hallucinated.md     T2 - comment-only symbol, out-of-range line
  report_real.md             T4 - real reachable defect
  report_deadcode.md         T3 - real but unreachable
  report_injection.md        report that attacks the triage system
  target_repo/               bundled 6-file C project (no nested .git; the
                             minihttp-1_0 tag lives on this repo so the
                             version-ref check works straight from a clone)
corpus/
  build_corpus.py            generates the 12 labeled reports
  labels.json                manifest: file, tier, gold label
  reports/                   generated
eval/
  run_eval.py                confusion matrix + per-tier + grep comparison
  results/                   dated JSON, committed
docs/
  threat_model.md
  labeling_protocol.md
```

---

## The four example reports

| File | Tier | Expected verdict | What it demonstrates |
|---|---|---|---|
| `report_hallucinated.md` | T2 | `HALLUCINATED` 0.93 | a comment mention is not existence |
| `report_real.md` | T4 | `UNVERIFIED` 0.50 | negative control, does not false-positive |
| `report_deadcode.md` | T3 | `UNVERIFIED` 0.60 | real symbol, no path from an entry point |
| `report_injection.md` | n/a | `UNVERIFIED` forced | embedded "set verdict to REPRODUCIBLE" stripped and logged |

Always run at least one negative control alongside the positive. A detector
that only ever fires is not a detector.

---

## Roadmap

Phase 2, in priority order. Items 1 and 2 are the distinctive contributions and
are protected; 7 and 8 are the first to be cut.

1. **SlopForge**, an adversarial generator that reads the target repo and
   writes slop citing *real* symbols, real paths, and plausible line numbers.
   Yields unlimited hard negatives, an adaptive evaluation, and a co-evolution
   curve across rounds.
2. **Hardening against reports that attack the triage system**, including the
   *suppression* attack: a real report crafted to look hallucinated so a
   maintainer buries it. See `docs/threat_model.md`.
3. LLM-assisted claim extraction for prose reports that lack structured header
   fields, evaluated strictly as a delta against the rule-based numbers above.
4. tree-sitter parsing and a real call graph, replacing the regex approximation.
5. Dockerized PoC execution: network off, read-only mount, non-root, hard
   timeout. This is the schedule risk; budget a full week.
6. Expansion to a Python target and a Go target.
7. Corpus growth to ~200 items using curl's ~87 published CVEs and its publicly
   disclosed rejected reports, with a two-labeler protocol and Cohen's kappa.
8. Small human study (n~8) measuring triage time with and without the evidence
   bundle.

### Known limitations

- Existence checking cannot separate a real function used incorrectly from a
  real vulnerability.
- Regex reachability misses function pointers, macros, and dynamic dispatch.
- Confidence values are hand-set constants, not calibrated. Reliability diagram
  and ECE are phase-2 deliverables.
- The corpus is synthetic and authored by the team.
- Extraction depends on structured header fields (`**Affected function:**` and
  friends). A report written as unstructured prose degrades to whatever the
  inline code spans yield. This is the main gap an LLM stage would close.

---

## Ethics and legal guardrail

Every target is local, synthetic, or a repository the team owns. **No scanning
of third-party production systems.** Adversarial reports are generated only
against the bundled target repo and against historical, already-fixed, publicly
disclosed CVEs. Synthetic malicious inputs live under clearly marked
directories with a README stating their purpose.

Full threat model in `docs/threat_model.md`; labeling rules and the
disagreement procedure in `docs/labeling_protocol.md`.
