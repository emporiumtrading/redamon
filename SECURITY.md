# Gabriel security reporting

Gabriel handles private evidence and scoped browser authority. Use a private reporting channel for vulnerabilities, credentials, customer data or exploitable technical details.

Use this repository's GitHub private vulnerability reporting flow when available. If no private reporting channel is configured, ask the repository maintainers to arrange one without including sensitive technical details in a public issue. Do not send Gabriel reports to an upstream project's contact address merely because inherited source retains its name.

Include the exact Gabriel source revision, affected component, sanitized reproduction steps, expected and observed behavior, and the tested environment. Generated fixtures are preferred. Do not include passwords, provider keys, cookies, access/pairing tickets or customer evidence.

Relevant boundaries include organization and role isolation, evidence encryption/custody, browser scope and revocation, credential storage, model admission and spending, dependency integrity, and backup/recovery. A passing automated check is not independent security approval.

Supported release scope and acceptance are recorded in the implementation and requirement registers. The present source is a controlled manual-test candidate; public hosting, native operating-system acceptance and production model qualification require their own evidence.

See [the operational notice](DISCLAIMER.md), [LICENSE](LICENSE) and [upstream notices](UPSTREAM-NOTICES.md).
