# Case ownership and investigation questions

Schema 13 adds append-only assignment events, investigation questions and evidence-linked analyst answers. The workbench case page and authenticated case CLI operate on these real PostgreSQL records. Assignment history uses a monotonic per-case sequence rather than wall-clock ordering. Owner/admin users can assign an active owner/admin/analyst or unassign; analysts can claim an unassigned case or retain their own assignment. Assignment changes never grant authority. Current assignee activity/role is rechecked when displaying the assignment.

Questions and answers are protected analyst comments. Viewers can inspect assignment metadata but cannot read question/answer text or mutate workflow. Each answer links an integrity-checked, available artifact in the same tenant and case. An answer is labelled `human_answer_supplied` with unverified source truth; it is not validated learned memory, automatic benign suppression, a confidence score or proof of attacker absence. Answers are immutable; record a new question when more investigation is needed. Existing evidence-bound local case closure retains unresolved questions and their history; it does not mark them answered, promote memory or dispatch external response. Closed-case workflow changes are denied.

## CLI

Use the existing case-data environment and private human token file:

```bash
python -m gabriel.identity.case_cli workflow-get --case-id CASE_UUID --token-file /operator/session
python -m gabriel.identity.case_cli assign --case-id CASE_UUID --request-id REQUEST_UUID --member-id MEMBER_UUID --token-file /operator/session
python -m gabriel.identity.case_cli question-add --case-id CASE_UUID --request-id REQUEST_UUID --question 'Investigation question' --token-file /operator/session
python -m gabriel.identity.case_cli question-answer --case-id CASE_UUID --question-id QUESTION_UUID --evidence-id EVIDENCE_UUID --answer 'Analyst interpretation' --token-file /operator/session
```

Omit `--member-id` to unassign as owner/admin. Assignment/question request UUIDs make same-actor identical retries idempotent; conflicting reuse is denied. Each question admits one immutable answer, whose identical replay is safe while current role/case/evidence admission remains valid. Bounds are 128 assignment events and 64 questions per case, 512 characters per question and 1,024 per answer; controls and invalid UTF-8 are rejected. The browser form envelope is bounded at 16 KiB to accommodate percent-encoded Unicode. Notes are sensitive case content; keep credentials out of them. Evidence metadata reports remain version 1 and do not include these comments; inspect/export through the workflow CLI until a separately accepted report-version change.

## Controls and UAT

| Control | Expected persisted result | Required denial |
| --- | --- | --- |
| Assignment select / Update | New actor/time/sequence record; live active assignee | Foreign/inactive/viewer assignee; analyst stealing another assignment; viewer mutation |
| Assign to me | Analyst claims an unassigned case | No privilege gain; current case/role checks still apply |
| Question / Add | One case-linked question per actor/request payload | Duplicate conflict, control/oversized text, closed/foreign case or quota |
| Evidence select / Record answer | Immutable analyst answer linked to verified stored bytes in the same case | Wrong case, missing/purged/corrupt evidence, changed answer, viewer or closed case |
| Assignment/questions view | Durable history with visible human-comment status | Viewer comment content excluded; revoked or foreign access denied |

## Loop record

Partial C06, GAB-003/005/006/022/024/025/031/032/040. Owner: implementation agent; independent reviewer and human UAT unassigned. Baseline: PR20 source `b6e3c4a4b9888d6d4e28bccde304235cacfc6e8d`, whose hosted gates are queued. This is independent preparation, not prerequisite or release acceptance.

Migration 13 preserves all earlier migration files/checksums, adds tenant/case composite foreign keys and indexes, and grants runtime SELECT/INSERT only. Organization/case lock ordering and mandatory transactional audit govern writes. Historical upgrade fixtures remove version 13 before earlier teardown; tests require real v12 upgrade and interrupted-DDL rollback, replay/concurrency, role/tenant/evidence denials, append-only privileges, audit rollback and closed-case behavior. Actual restart/dump-restore must retain assignment/question/answer identity and human-comment state. The Chrome for Testing/Brave lab now submits assignment, question and answer forms and checks their persisted records.

State: IMPLEMENTED_UNVERIFIED. No hosted result or human UAT is claimed until recorded at the exact source. PostgreSQL schema guidance informed composite foreign-key indexes and bounded access. Rollback restores the prior application image while retaining the additive tables; do not drop workflow history from a live database to roll back code. Dedicated deletion/retention of comment history, historical pagination, graph/entity correlation, independent review and full release acceptance remain open.
