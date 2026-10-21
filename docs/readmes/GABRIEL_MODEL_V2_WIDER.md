# Wider v2 development comparison

The first v2 protocol evaluation at source 536d0ffea5b29f3589dd0e6798dcbf06356ae5b6 produced 3/3 matching known development decisions for GPT-4.1 mini/Azure, Nemotron 3 Super/Crusoe, GPT-OSS-120B/Cerebras and Llama 3.3 70B/Cloudflare. It made 14 calls, validated 12 answers and reported $0.005966117. Mistral returned an empty contradictions array (`missing_reasoning`); DeepSeek had a new unresolved transport outcome, causing an immediate stop with no retry. Qwen-122B was not attempted in that configuration. Generated artifact 12311618705 independently matched ZIP SHA256 1d220c6e9d92dfc29b1a31a4cc03faea549acbc48d0b75c9bdc7ce97b3b54ff6. These three examples do not qualify any model.

This new fixed schedule compares only those four contract-complete configurations, using the identical v2 prompt on five different authored development examples: persistence, exfiltration, authorized administration, prompt injection and clock skew. The corpus pin and original labels/validator remain unchanged. No held-out/validation partition, private evidence, arbitrary case/model selection, tools or external actions are accepted. Fixture replies are software checks only.

At most 20 serial calls reserve $0.12608. Two prior unresolved comparison calls retain $0.012608 and prior comparison reported costs retain $0.011676605. Their combined ceiling is $0.150364605 within the $0.16 comparison envelope, with the separate $0.01 historical Gemini hold also included in account headroom. Five calls per model reserve $0.03152, below the existing $0.05 investigation limit. The $18/month, $0.50/day, route price/privacy, one-call-at-a-time CI lock and no-retry/no-fallback policies remain. DeepSeek and Qwen-35B are excluded; neither uncertain request is resent. A new unknown stops the entire batch.

The dedicated same-repository branch can run one paid job on initial PR opening only, after its isolated Docker software gate passes. Later code/document pushes cannot repeat paid calls. The output records exact model/provider/prompt/configuration, decisions/references, usage/cost, bounded diagnostics and label matches. All quality/admission flags remain false. Three new behavior tests cover the exact 20-call schedule/carry holds, first-new-unknown stop and mixed-stage denial. Full inherited software/recovery regressions and actual wider outcomes are pending until exact-source evidence is recorded.

Development matches guide further evaluation, not model activation. Labels remain provisional, the author-seen corpus is not independently sealed holdout, and a qualified analyst must adjudicate claims and realistic workload. No model is admitted to production; durable storage is developed separately. Subsequent evaluation should be chosen from observed failures and measured cost, rather than assuming a more expensive model is better.


## Actual wider result

Comparison source `f34f2daf4fa6924c03b27fa532fba5a2e452befe`, tree `cba7bab8a30b514de658b0758a5e5664cb4f19ac`, passed the isolated 31-test software gate in run 39525445734. Actual live job 118979029086 made 18 calls and validated 17 answers for **$0.009227293** current reported cost, without any new unknown outcome. Prior unknowns remain held. It stopped GPT-4.1 mini's remaining examples when the authorized-administration answer omitted `requested_actions`, retaining the rejection and known charge rather than repairing the answer. Every contract-valid answer matched its provisional expected development decision.

| Model / provider | Wider contract-valid / planned | Wider decisions matched | Wider reported cost | Combined v2 decisions matched / tested | Combined v2 validated-answer cost | Mean observed v2 latency |
| --- | --- | --- | --- | --- | --- | --- |
| GPT-4.1 mini / Azure | 2/5 | 2/2 valid | $0.0014504 including rejected answer | 5/6 attempted; two later cases not sent | $0.0024648 valid answers only | 2,240 ms |
| Nemotron 3 Super / Crusoe | 5/5 | 5/5 | $0.0031185 | 8/8 | $0.0049413 | 1,346 ms |
| GPT-OSS-120B / Cerebras | 5/5 | 5/5 | $0.00220705 | 8/8 | $0.00347855 | 341 ms |
| Llama 3.3 70B / Cloudflare | 5/5 | 5/5 | $0.002451343 | 8/8 | $0.003741460 | 3,830 ms |

Combined configurations/prompt hashes were verified identical across the two v2 rounds for each model. The initial three cases and these five cases are distinct. GPT-OSS-120B/Cerebras is the leading development candidate based on these observed answers, latency and reported cost. Nemotron and Llama remain comparison candidates. This is a provisional engineering selection, not production admission, a population accuracy estimate, repeatability/SLA evidence or independent adjudication. Eight small authored examples remain insufficient for qualification.

The generated artifact 12313765881 was independently downloaded and its ZIP SHA256 verified as `e9a69a618552801df77abb404d9c9f812aecf728419fa3c712ccee209c1a2445`. Its complete journal is preserved as `testing/gabriel_model_lab/results/openrouter-v2-wider-20261021.jsonl`. Known reported comparison costs across all four batches total $0.020903898; this is not total account usage, authenticated provider billing or a statement that historical errors were free. The two comparison unknowns still reserve $0.012608, plus the separate $0.01 historical Gemini hold.

## Integrated worker candidate

The wider-comparison branch now incorporates the encrypted answer/recovery increment and the v2 evidence records. No subsequent push may repeat paid calls. Integrated x86/ARM64/restart/restore/browser/software acceptance must be recorded at the combined source, rather than inferring it from separate branch results. Model comparisons and recovery fixtures remain separate evidence. Production admission remains empty. Earlier source-specific results remain preserved.
