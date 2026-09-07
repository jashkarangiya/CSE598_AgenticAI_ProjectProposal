# Threat model

**Asset.** Maintainer attention, and the integrity of the triage queue.

**Adversary 1 - the low-effort reporter.** Generates plausible reports at near
zero cost to farm bounty payouts. Defeated by grounding.

**Adversary 2 - the adaptive reporter.** Reads the repository first and cites
real symbols, real paths, and plausible line numbers, so only reachability or
semantics separate the report from a real one. This is the adversary the T2/T3
tiers model and the one SlopForge generates as tier T5
(`corpus/slopforge.py`). Round 1 of that generator cut the baseline's recall
from 1.00 to 0.50 before the symbol-location check was added.

**Adversary 3 - the reporter who attacks the triage system.** The report is
untrusted text that SlopGate feeds to a model. Two attacks: *promotion* (steer
the agent to REPRODUCIBLE to jump the queue) and *suppression* (craft a real
report to look hallucinated so a maintainer buries it). Suppression is the more
dangerous of the two and is not, to our knowledge, described in the literature
on triage automation.

**Mitigations in the baseline.** Report text is sanitized for
instruction-shaped spans before any model sees it; the text is delimited and
declared as data; the model never sets the verdict, which is computed by
deterministic rules over the evidence table; a detected injection attempt
forces routing to a human regardless of grounding outcome.

**Out of scope.** Malicious maintainers, compromised repositories, and
attackers with write access to the target tree.

**Legal and ethical guardrail.** Every target is local, synthetic, or a
repository the team owns. No scanning of third-party production systems.
Adversarial reports are generated only against the bundled target repo and
against historical, already-fixed, publicly disclosed CVEs.
