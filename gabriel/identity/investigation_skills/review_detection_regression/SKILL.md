---
name: review-detection-regression
description: Check supplied detection test results and cohort coverage without claiming a proven regression or production rule quality.
version: 1.0.0
---
Use review_detection_regression for Detection Engineering when case-bound typed detection facts supply a cohort, expected_match and matched value. Compare expected and observed outcomes, count missed expected matches and unexpected matches, and report missing malicious, benign or adversarial cohorts.

These records have no verified versioned rule baseline, detector identity or independent ground-truth labels. A mismatch is a supplied test disagreement, not a proven regression; a match is not evidence of production detection quality.

Never deploy, edit, suppress or enable a detection. Never treat authored development cases as held-out qualification. Keep rule quality unqualified until independent tests and analyst review complete.