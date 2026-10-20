# Model route checkpoint — 20 October 2026

The dedicated OpenRouter key settings now pass preflight: nonzero $18 cap, monthly reset. A prior fixed Gemini/Vertex generation received HTTP 404; its outcome remains unvalidated and no zero-cost assertion is made. The public endpoint catalogs for Gemini 2.5 Flash Lite and Flash currently list AI Studio variants and no Vertex route. The repaired catalog check denies a missing approved route before a generation. This is a route-availability finding, not a model-quality result.

The production owner delegated model selection and approved continued engineering/evaluation within the existing $20 envelope. Add **GPT-4.1 mini through Azure on OpenRouter as a comparison candidate**, not an activated primary model or automatic fallback. Its public catalog lists Azure at $0.40/M input and $1.60/M output; those observations are not a billing guarantee. The request still enforces the existing $0.50/M input and $3/M output ceilings with zero per-request fee, required parameters, ZDR, denied data collection, Azure-only routing and no fallback. Unsupported/unavailable routes fail closed. Google remains an unqualified candidate; do not silently route Gemini requests to AI Studio.

The CI job explicitly selects a fixed, **one-call comparison schedule** with `--azure-comparison`. Its software gate runs first; only the existing same-repository `feature/gabriel-provider-probe` PR condition can access the dedicated secret. There are no extra live jobs, automatic retries or live probes from the confidential-input branch. Default manual probe invocation still describes the two fixed Gemini candidates. Arbitrary, repeated or combined schedules are refused before key metadata or generation requests. Both schedules use the same fixed generated development case, read-only key and endpoint checks, allowance, response contract, bounded payload/output and sanitized artifacts. Azure uses its declared `max_completion_tokens` parameter without an unsupported reasoning toggle.

One successful generated comparison is connectivity/contract evidence only, never defensive suitability, a production-primary selection, held-out quality evidence or authority. No production budget allowlist, specialist engine, database grant, vault configuration or dispatcher is changed. Actual release admission still needs the full expert-reviewed corpus, compression/redaction comparison, privacy/account policy checks and operational/human acceptance. The owner need not change the account again for this route investigation.

References retrieved 20 October 2026:
- https://openrouter.ai/api/v1/models/google/gemini-2.5-flash-lite/endpoints
- https://openrouter.ai/api/v1/models/google/gemini-2.5-flash/endpoints
- https://openrouter.ai/api/v1/models/openai/gpt-4.1-mini/endpoints
- https://openrouter.ai/docs/guides/features/zdr

Rollback restores the preceding probe/workflow source; it does not delete past generated probe receipts, settle unknown charges or change any production record. Matching-image software gates and real probe results must be recorded by exact source before claiming a pass.
