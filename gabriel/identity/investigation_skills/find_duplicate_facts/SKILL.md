---
name: find-duplicate-facts
description: Identify repeated typed fact assertions without conflating them with independently verified duplicate security events.
version: 1.0.0
---
Use find_duplicate_facts to examine repeated case facts in Alert Triage, Incident Scoping or Identity/Access. It compares only exact type, source evidence ID/digest, entity grouping, event time and closed typed values, excluding the fact's own UUID.

Output: de-identified counts of identical same-source fact repeat candidates and unique signatures. The tool never deletes facts, adjusts incident severity or equates independently logged events with duplicates. Cross-source event identity and independent corroboration are unavailable.

Multiple distinct source records can describe one event, and a repeated record can be a legitimate retry. Do not use repeat-candidate counts as an attack verdict or evidence of deduplication. Preserve uncertainty and ask for analyst review.