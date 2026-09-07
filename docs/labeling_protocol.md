# Labeling protocol

**Unit.** One (report, repository, ref) triple.

**Label space.** `HALLUCINATED` / `NOT_HALLUCINATED`, plus a `tier` field
recording why the item is hard.

**Rule.** A report is `HALLUCINATED` if at least one load-bearing claim is
false at the stated ref: the primary function has no definition, the file does
not exist, or the cited line lies outside the file. A report is
`NOT_HALLUCINATED` if every checkable claim holds, **even if the reported
behaviour turns out not to be exploitable.** Unreachable-but-real code (T3) is
labeled `NOT_HALLUCINATED` on purpose: auto-closing it is the failure mode this
project exists to prevent.

**Tiers.** T1 absent symbol, T2 comment-only symbol, T3 real but unreachable,
T4 real, reachable, genuine defect.

**Procedure.** Two labelers annotate independently against the checked-out ref.
Disagreements are resolved by a third labeler and recorded in
`corpus/disagreements.md`, which is a deliverable, not an appendix. Report
Cohen's kappa with the corpus.

**Provenance.** Seed corpus items are authored by the team as mutations of a
bundled target repo and are marked `synthetic: true`. Historical-CVE items
added in phase 2 are marked `synthetic: false` with the fixing commit recorded.
