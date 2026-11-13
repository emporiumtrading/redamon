---
name: audit-provenance
description: Verify grounded artifact assertions and custody limitations in case-bound DFIR investigations.
version: 1.0.0
---
Use audit_provenance only when a case contains verified-source-bound artifact facts for a DFIR investigation. The runtime already verifies stored bytes, ciphertext and custody links before running this skill and rechecks case authority before publishing.

Input: specialist-facts-v1 artifact facts with integrity and custody assertions. Output: de-identified counts of reported mismatches, custody gaps and repeated source assertions. Interpret reported integrity/custody values as supplied assertions, not independent evidence of authenticity.

Never identify original source authenticity, declare a chain of custody legally sufficient, reveal evidence IDs or digest material, fetch new evidence, or approve a response. If artifact facts are absent, explicitly report insufficient evidence. Analyst review is required.