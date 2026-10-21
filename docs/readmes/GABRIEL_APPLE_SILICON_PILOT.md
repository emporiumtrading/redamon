# Apple Silicon pilot and restricted provider probe

Owner-supplied host: macOS, Apple Silicon, Docker Desktop installed, 18 GB unified memory. Use a lean core pilot: provisional Docker allocation 6 GB RAM and 4 CPUs, leaving memory for macOS and the browser. Use cloud inference, not a local model. Optional Wazuh/IR tools are separate profiles or separate lab hosts; do not start all ten on this machine. These are initial resource targets, not measured sizing guarantees. Watch memory pressure, swap, disk and latency during pilot UAT and tune from evidence.

Build/run Linux ARM64 containers natively. The ARM64 CI job first builds/import-checks the core image on a Linux ARM64 runner, then runs the matching-image PostgreSQL/restart/restore and runtime/foundation gates. Record exact-source results before accepting those later checks. Linux ARM64 tests do not accept macOS Docker Desktop pairing, certificate trust, volume permissions, startup or consumer Chrome/Brave. Actual Mac UAT and complete Docker onboarding remain release gates. No appliance or separate manually managed Ubuntu VM is required for the intended Desktop path.

## Saved OpenRouter key

The owner confirmed saving `OPENROUTER_API_KEY` as a GitHub Actions secret. Do not retrieve it into chat, code, build arguments, generic test logs or artifacts. Only the isolated live probe step receives it at runtime; software/ARM64 tests do not receive it. The probe image contains stdlib code and generated development data, no offensive runtime, database DSN, vault key, browser profile or production evidence. Production will use the encrypted backend vault and a restricted dispatcher, not this CI environment variable.

Workflow `gabriel-provider-probe.yml` serializes live probes for the dedicated key. Only a same-repository PR on `feature/gabriel-provider-probe` can reach the live job, after software tests pass. Fork PRs and ordinary feature branches cannot. Each invocation makes at most two calls, no retries/fallbacks/redirects, to the two Gemini candidates on Google Vertex through OpenRouter. Fixed-host TLS, data-collection denial, required ZDR, parameter support, price ceilings and bounded request/output sizes apply. If no compliant route exists, it fails rather than relaxes policy. No regional-residency promise is made for this synthetic-only global endpoint.

Before each call, the key metadata must show an inference-only key, monthly reset, a nonzero cap at most $18 and at least $0.02 remaining. Daily credit plus BYOK usage with the run allowance must stay below $0.50, and monthly usage plus allowance below $18. Missing/invalid billing metadata denies calls. Provider caps are at most $0.50/M input and $3/M output with no per-request fee; at most 8,000 input and 768 output tokens are admitted in returned usage, and measured cost must be at most $0.01 per call. Wire input is capped at 7,000 bytes; it is a conservative input-size bound, not a certified tokenizer bound. The account/key ceiling remains important. Other applications concurrently using the same key are outside the probe's serialization; use a dedicated key. No automatic top-up is performed.

The probe submits only the fixed authored development question and observations. Case/family/class IDs, acceptable labels and rationales are excluded from the request. It checks response model/provider, finish state, source references, actual usage/cost and the known development escalation expectation. Successful responses are genuine provider outputs, never canned answers. Software tests use explicit fake HTTP responses solely to verify protocol handling. A timeout/invalid response preserves incomplete status and possible unknown cost; no blind retry occurs. Retained outputs are generated-only, exclude credentials and always state `quality_qualified: false` and `production_admission: false`.

This is connection/contract evidence on one known example, not the 60-family expert-held-out evaluation, poisoning/privacy effectiveness proof, full coordinator or production worker. Actual model quality, qualified analyst adjudication, secure production transport, confidentiality policy admission and Mac pilot/release acceptance remain open. GitHub secret existence or successful model connectivity does not close those requirements.

References checked 20 October 2026: https://openrouter.ai/docs/guides/routing/provider-selection and https://openrouter.ai/docs/api/api-reference/api-keys/get-current-api-key .

## First verification outcome

Source `448a9d43cb52542bc6d827ccc237b08a86c781b7` passed thirteen container-isolated probe software tests and a real native Linux ARM64 core-image build/import check in workflow `39458006340`. ARM64 image: `sha256:4c2edf421bc2b988d3c2702003c8a842356949790df6a5242636d91edb44e772`. The live job reached authenticated key metadata and returned `key_requires_monthly_limit_at_most_18_usd`, with zero attempted/completed paid calls and no unknown cost. This means the cap and/or reset setting needs correction; it does not identify which setting is absent, and it does not qualify either Gemini model. Full regression/source artifacts remain subject to the ledger's recorded results. Once the existing key has a cap at most $18 and monthly reset, the failed live job can be rerun without replacing the secret if its value is unchanged.

## Current Mac component preflight

The current integrated code candidate is `b76e329c5019c0b22129fd81b814cffb01d2d297` on `feature/gabriel-model-v2-wider`. Source-specific hosted outcomes are recorded in the worker/comparison documents. A clean local checkout and generated-only checks can establish the Mac Docker path before any private account/console or production model activation. These commands run the implemented scripts; they do not deploy a persistent product or qualify a model.

Start Docker Desktop with the provisional 6 GB / 4 CPU allocation. Use a new checkout directory. Run the checks sequentially:

```bash
git clone https://github.com/emporiumtrading/redamon.git gabriel-local
cd gabriel-local
git fetch origin feature/gabriel-model-v2-wider
git switch --detach b76e329c5019c0b22129fd81b814cffb01d2d297
uname -m
docker version
docker compose version
gabriel_mac_evidence="$(mktemp -d "${TMPDIR:-/tmp}/gabriel-mac-evidence.XXXXXX")"
bash gabriel.sh identity-test "$gabriel_mac_evidence/identity"
bash gabriel.sh test "$gabriel_mac_evidence/runtime"
bash tooling/scripts/gabriel_foundation_check.sh "$gabriel_mac_evidence/foundation"
python3 tooling/scripts/gabriel_extension_package.py gabriel/browser_extension "$gabriel_mac_evidence/gabriel-browser-0.1.0.zip"
```

On Apple Silicon, record the observed architecture, macOS/Docker versions, exact checkout/image IDs, test counts and any failures. The identity script creates its own disposable project, generated credentials/keys and private checkpoint outside the evidence reports; its cleanup removes only that disposable database project/volume. Existing deployments are not selected by that unique project. The restart/restore rehearsal includes encrypted model answers and interrupted receipt recovery with fixture HTTP only. It requires no OpenRouter key and performs no paid model call. An unavailable Docker daemon blocks the check; do not substitute host pytest.

The extension package is the reviewed six-file MV3 artifact. Native Mac consumer Chrome and Brave still require actual human checks: install the unpacked source, inspect permissions, verify keyboard/focus/readable errors, then approved-scope pairing, exact preview/consent, Pause/Resume/Stop and receipt inspection against a generated console. Private TLS/operator workbench and browser gateway setup follow their existing operator guides; the component test script does not leave a persistent workbench running. Do not treat successful packaging or Linux browser CI as those human Mac passes. Record them as NOT_RUN until actually observed.

The development model preference is GPT-OSS-120B/Cerebras, with Nemotron 3 Super/Crusoe and Llama 3.3 70B/Cloudflare retained for comparison. All three matched eight distinct small v2 development examples; GPT-OSS had the lowest observed mean latency and validated-answer cost in those runs. No production configuration is admitted. The existing GitHub Actions key is not copied into a local application; later authorized local provider setup uses the encrypted backend vault. Real console adapters, independent suitability adjudication/sealed holdout, integrated product operation and release acceptance remain separate open gates.
