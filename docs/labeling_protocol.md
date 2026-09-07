# Labeling protocol

**Unit.** One (report, repository, ref) triple.

**Label space.** `HALLUCINATED` / `NOT_HALLUCINATED`, plus a `tier` field
recording why the item is hard.

**Rule.** A report is `HALLUCINATED` if at least one load-bearing claim is
false at the stated ref: the primary function has no definition, the file does
not exist, the cited line lies outside the file, or **the primary function is
defined somewhere other than the claimed file and does not appear in the
claimed file at all**. That last clause was added with tier T5: "function F is
in file P" is a claim the report makes about the tree, and it can be false
while F, P and the line number are each individually real. A report is
`NOT_HALLUCINATED` if every checkable claim holds, **even if the reported
behaviour turns out not to be exploitable.** Unreachable-but-real code (T3) is
labeled `NOT_HALLUCINATED` on purpose: auto-closing it is the failure mode this
project exists to prevent.

**Tiers.** T1 absent symbol, T2 comment-only symbol, T3 real but unreachable,
T4 real, reachable, genuine defect, T5 real symbol attributed to the wrong
real file.

**A note on the T5 boundary.** Citing a header that *declares* the function is
not a T5 forgery, it is ordinary report-writing, and such an item is labeled
`NOT_HALLUCINATED` (see `t4_e`). Only total absence of the symbol from the
claimed file counts. This asymmetry follows the cost matrix, not convenience.

**Procedure.** Two labelers annotate independently against the checked-out ref.
Disagreements are resolved by a third labeler and recorded in
`corpus/disagreements.md`, which is a deliverable, not an appendix. Report
Cohen's kappa with the corpus.

**Provenance.** Seed corpus items are authored by the team as mutations of a
bundled target repo and are marked `synthetic: true`. T5 items are marked
`generator: "slopforge"` and carry a `forged_claim` field naming the exact
false association, so a labeler can audit the gold label without rereading the
tree. Historical-CVE items
added in phase 2 are marked `synthetic: false` with the fixing commit recorded.
