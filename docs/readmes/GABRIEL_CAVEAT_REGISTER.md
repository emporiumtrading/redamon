# Gabriel caveat and acceptance register

This register distinguishes executable engineering work from product/review gates. An implementation or VM pass does not automatically close a release gate. Source-specific evidence belongs in the implementation ledger and PR. Production remains **BLOCKED** until the required integrated acceptance gates pass.

| ID | Caveat | Current resolution / next work | Acceptance evidence |
| --- | --- | --- | --- |
| CV-01 | Durable policy and human approval state absent | Increment 8 implements exact policy/approval for real local case closure; component verification pending | Real SQL authorization/drift/concurrency/failure tests and restart/restore; no legacy closure bypass |
| CV-02 | Independent trust-boundary review incomplete | Keep PRs draft; independent reviewer acceptance pending | Review findings resolved against exact source; no AI confidence score substitutes for sign-off |
| CV-03 | Operational/product UAT incomplete | Component VM regression/recovery runs exist; integrated staging and human UAT remain NOT_RUN | Full critical-path staging UAT/regression, artifact approval, then post-release UAT/regression and observation |
| CV-04 | Custody lacks external anchoring | Application append-only grants, hash checks and approval-bound prefixes exist; independently controlled anchor storage/signing still needed | Demonstrate privileged rewriting/valid-tail deletion detected against a trusted externally retained checkpoint; key/store authority separation |
| CV-05 | Retention, legal holds and deletion absent | Implement durable hold/policy state before destructive purge; no purge command currently exists | Holds survive recovery, racing purge denied, scheduled retention and object/database deletion reconcile without false success |
| CV-06 | Browser collection and source authenticity absent | Engineer-approved text remains explicitly unverified; implement pairing/scope/envelope and real browser lab next after prerequisites | Chrome/Brave scoped tab/page/account/task tests, incomplete-view reporting, manual login handoff, provenance/replay/denial tests |
| CV-07 | Full C04 action/external response state incomplete | Only transactional local closure admitted; external operations remain unavailable | Exact consent, target/policy revalidation, response connector lab effects, timeout-to-unknown reconciliation and independent verification |
| CV-08 | Evidence key rewrap/retirement absent | Separate purpose-marked keys; retain all referenced keys, never reuse IDs | Atomic rewrap, old-process downgrade denial, corruption/audit rollback and coherent restore before retirement |
| CV-09 | Entire inherited conversion baseline not accepted | Separate defensive image denies inherited tool names; full disposition inventory and stack review remain open | Every inherited capability/path disposition reviewed and required full-stack baseline passed |
| CV-10 | Models, specialists and autonomous hunting not accepted | Do not represent component foundations as an active defender | Real permitted tools, approved model routes, specialist/playbook evaluations, source-linked assessments and qualified escalation |

Order: verify CV-01 and resolve any observed defect; continue deterministic evidence retention/hold state and independently controlled anchoring; complete prerequisite review/integration gates before browser/product acceptance. Investigative access stays vendor agnostic and browser-first, with engineer-operated external authentication. API credentials are never a prerequisite for the browser workflows.
