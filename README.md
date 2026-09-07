# SlopGate

Evidence-grounded triage for AI-generated vulnerability reports.

Maintainers are getting buried in plausible-looking security reports that
describe code that does not exist. SlopGate checks an inbound report against
the tree it claims to describe and returns a verdict with the evidence
attached. It never auto-closes anything; the output is a queue ordering, not a
classification.

Rule-based end to end. No model, no API key, no network, no dependencies
outside the standard library.

CSE 598 capstone. The proposal covers the problem and the headline result;
this repo is the artifact.

## Quickstart

Requires Python 3.8+ and `git`. There is no install step and no build step —
the target repository is bundled.

```bash
git clone https://github.com/jashkarangiya/CSE598_AgenticAI_ProjectProposal.git
cd CSE598_AgenticAI_ProjectProposal
python3 demo.py
```

`demo.py` takes no arguments, prints a fixed evidence bundle, and exits
non-zero if any verdict moves. Expect this:

```
REPORT                       TIER  VERDICT        CONF   WHY IT IS HARD
report_hallucinated.md       T2    HALLUCINATED   0.93  symbol exists only inside a comment
t5_a.md                      T5    HALLUCINATED   0.90  real symbol, wrong real file (SlopForge)
report_deadcode.md           T3    UNVERIFIED     0.60  real but unreachable - a finding, not slop
report_real.md               T4    UNVERIFIED     0.50  genuine defect - the negative control
report_injection.md          --    UNVERIFIED     0.50  attacks the triage system - forced to a human

PASS  5/5 verdicts as expected.
```

Then the full evaluation:

```bash
python3 corpus/build_corpus.py   # 13 authored + 6 forged reports
python3 eval/run_eval.py         # confusion matrix, per-tier, grep comparison
```

`run_eval.py` exits non-zero if any verdict disagrees with its gold label, so
it doubles as the regression gate.

One report at a time:

```bash
python3 run_baseline.py --report examples/report_real.md \
                        --repo examples/target_repo [--json out.json]
```

## Results

19 items: 13 hand-authored, 6 forged by SlopForge. Measured against the honest
null hypothesis — *does grep find the claimed symbol?*

```
OVERALL  (positive class = HALLUCINATED)
  SlopGate      TP=12  FP=0   FN=0   TN=7    P=1.00 R=1.00 F1=1.00  cost=0.0
  grep baseline TP=3   FP=0   FN=9   TN=7    P=1.00 R=0.25 F1=0.40  cost=9.0
```

| Tier | n | SlopGate | grep |
|---|---|---|---|
| T1 | 4 | 1.00 | 0.75 |
| T2 | 2 | 1.00 | 0.00 |
| T3 | 2 | 1.00 | 1.00 |
| T4 | 5 | 1.00 | 1.00 |
| T5 | 6 | 1.00 | 0.00 |

7/19 verdicts abstain. 0.011 s/report, $0.00.

T2 and T5 are the rows that justify the project. In the bundled target,
`curl_easy_parse_header` appears exactly once, inside a comment recording that
it was removed before release. grep reports it as present.

**Perfect scores on 19 synthetic items against one small repo mean the tiers
are well separated, not that the system generalizes.** Corpus growth is on the
roadmap.

### Co-evolution

SlopForge generates the T5 tier by reading the target tree. Round 1 is the
useful half:

| | F1 | recall | T5 |
|---|---|---|---|
| round 0 — seed corpus only | 1.00 | 1.00 | — |
| **round 1 — SlopForge attacks** | **0.67** | **0.50** | **0.00** |
| round 2 — location check added | 1.00 | 1.00 | 1.00 |

One generated tier erased a perfect score. Both rounds are separate commits, so
the curve is reproducible rather than asserted. grep scores 0.00 on T5 in both
rounds and cannot do better: substring matching has no way to know a symbol is
defined somewhere other than where the report says.

## Difficulty tiers

Every corpus item is tagged, so precision on hard negatives is reported apart
from precision on easy ones.

| Tier | Claim under test | Why it is hard | Gold |
|---|---|---|---|
| T1 | symbol absent from the tree | grep catches it | `HALLUCINATED` |
| T2 | symbol appears only in a comment | grep says "found it" and is wrong | `HALLUCINATED` |
| T3 | symbol real but unreachable | needs a call graph | `NOT_HALLUCINATED` |
| T4 | symbol real, reachable, genuine defect | must not be called slop | `NOT_HALLUCINATED` |
| T5 | symbol real, file real, line in range, but the symbol is not in that file | every check passes individually; only the association is false | `HALLUCINATED` |

T3 is `NOT_HALLUCINATED` on purpose. Dead code is a real finding, and
auto-closing it is the failure this project exists to prevent.

## How it works

Four stages. Report text is untrusted data at every one.

| Stage | Module | What it does |
|---|---|---|
| Sanitize | `extract.py` | strips instruction-shaped spans (`ignore previous instructions`, `set verdict to`, HTML comments) and records each as an injection signal |
| Extract | `extract.py` | regex over header fields and inline code spans → declared symbol, paths, line, version ref, CWE |
| Ground | `ground.py` | classifies each symbol `ABSENT` / `MENTIONED` / `DEFINED`, then checks path, line range, git tag, reachability, and symbol-to-file association |
| Adjudicate | `adjudicate.py` | deterministic rules over the evidence table; any injection signal forces a human |

Grounding uses a single-pass tokenizer that blanks comments and string literals
while preserving line numbers. A sequential regex stripper treats the `//` in
`"https://example.com"` as a line comment and swallows the rest of the line,
losing real call sites.

Nothing is probabilistic: the same report against the same ref always produces
the same record.

### Verdicts

| Verdict | Meaning | Action |
|---|---|---|
| `HALLUCINATED` | a load-bearing claim contradicts the tree at the claimed ref | deprioritize, evidence attached |
| `UNVERIFIED` | claims ground, exploitability undecided | needs human |
| `REPRODUCIBLE` | PoC executed and reproduced | escalate |

`adjudicate.py` prices a wrongly closed real CVE at **500x** a wasted human
review. Under that matrix abstaining is cheap and guessing is not, so
`UNVERIFIED` is the default whenever the evidence for `HALLUCINATED` is
anything less than unambiguous. `REPRODUCIBLE` is unreachable today — there is
no PoC sandbox, so every grounded report collapses to `UNVERIFIED`.

## Layout

```
demo.py                fixed-output entry point, self-checking
run_baseline.py        CLI for a single report
src/slopgate/
  extract.py           injection sanitizer + claim extraction
  ground.py            tokenizer, symbol grounding, reachability, location
  adjudicate.py        cost-asymmetric decision rules
corpus/
  build_corpus.py      13 hand-authored reports
  slopforge.py         adversarial generator, forges T5 from the tree
  labels.json          manifest: file, tier, gold label
eval/run_eval.py       confusion matrix, per-tier, grep comparison
examples/target_repo/  bundled 6-file C project, tagged minihttp-1_0
docs/                  threat model, labeling protocol
```

The `minihttp-1_0` tag lives on this repo, not on a nested one, so the
version-ref check works straight from a clone.

## Limitations

- Existence checking cannot separate a real function used incorrectly from a
  real vulnerability.
- Regex reachability misses function pointers, macros, and dynamic dispatch.
- Confidence values are hand-set constants, not calibrated.
- The corpus is synthetic: 13 authored by the team, 6 machine-forged against
  the same small tree.
- SlopForge has exactly one strategy, the location swap. Read T5 = 1.00 as
  "this attack is closed", not "T5 is solved".
- Extraction depends on structured header fields. A report written as prose
  degrades to whatever the inline code spans yield. This is the gap an LLM
  stage would close.

## Roadmap

1. **SlopForge** — round 1 shipped. Remaining: more forge strategies than the
   location swap, and rounds 3+ against them.
2. **Hardening against reports that attack the triage system**, including the
   *suppression* attack: a real report crafted to look hallucinated so a
   maintainer buries it. See [docs/threat_model.md](docs/threat_model.md).
3. LLM-assisted claim extraction for prose reports, evaluated as a delta
   against the rule-based numbers above.
4. tree-sitter parsing and a real call graph.
5. Dockerized PoC execution: network off, read-only mount, non-root, hard
   timeout. Budget a full week.
6. A Python target and a Go target.
7. Corpus growth to ~200 items from curl's published CVEs and its disclosed
   rejected reports, two labelers, Cohen's kappa.
8. Human study (n≈8) measuring triage time with and without the bundle.

Items 1 and 2 are the distinctive contributions. 7 and 8 are the first to cut.

## Ethics

Every target is local, synthetic, or owned by the team. No scanning of
third-party production systems. Adversarial reports are generated only against
the bundled target repo and against historical, already-fixed, publicly
disclosed CVEs.

Threat model: [docs/threat_model.md](docs/threat_model.md).
Labeling rules and the disagreement procedure:
[docs/labeling_protocol.md](docs/labeling_protocol.md).
