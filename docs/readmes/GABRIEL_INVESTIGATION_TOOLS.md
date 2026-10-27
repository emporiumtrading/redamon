# Gabriel investigation tools and skills

Gabriel's twelve designated specialists have a role-bound tool catalog and executable dispatch paths. The runtime loads each tool's packaged usage skill into the specialist prompt. Its manifest binds the skill text, implementation source and pinned engine versions into the exact model configuration digest. These are Gabriel runtime skills, not personal ChatGPT skills.

## Installed tools

| Tool | Implementation and license | What it actually does |
| --- | --- | --- |
| scan_artifacts | yara-python 4.5.4, Apache-2.0; bundled libyara, BSD-3-Clause | Scans supplied source-file bytes against three bundled behavioral text rules: encoded PowerShell, shadow-copy deletion and a credential-dumping command reference. Matches are hypotheses, not malware verdicts. |
| inspect_packets | dpkt 1.9.8, BSD-3-Clause | Reads supplied Ethernet PCAP/PCAPNG files and returns protocol, endpoint/flow-cardinality, SYN/reset and malformed-packet counts. No live capture or traffic generation. |
| inspect_logs | Python standard library, PSF-2.0 | Parses normalized JSONL exports and finds five failures within 300 seconds, including a subsequent success. Duplicate records are not deduplicated; this requires analyst review. |
| correlate_events | Gabriel, MIT | Groups relevant typed facts by entity and outcome. Explicitly preserves overlap and coverage uncertainty. |
| assess_exposure | Gabriel, MIT | Flags supplied reachable, unmitigated high/critical exposures for urgent review, without asserting exploitation. |
| inspect_toolkit | Gabriel, MIT | Checks private parser-service readiness, exact installed versions and implementation fingerprint. Reports missing or mismatched capabilities. |
| verify_sources | Gabriel, MIT | Checks encrypted stored-byte integrity/custody. Does not authenticate the original source. |
| review_rules | Gabriel, MIT | Applies existing role-specific rules to verified typed input. |
| inspect_timeline | Gabriel, MIT | Bounds supplied event times; does not verify source clocks. |
| review_memory | Gabriel, MIT | Checks human-approved local memory availability. Does not export its contents or train the model. |

Pinned upstream sources and full license texts are retained under `gabriel/toolbox/licenses/`. See [yara-python v4.5.4](https://github.com/VirusTotal/yara-python/tree/v4.5.4), [libyara v4.5.4](https://github.com/VirusTotal/yara/tree/v4.5.4), and [dpkt v1.9.8](https://github.com/kbandla/dpkt/tree/v1.9.8). Gabriel-authored rules, adapters and skills use the repository's MIT license. Python's standard-library license ships with the base runtime.

## Specialist assignments

All roles have source verification, role-rule review and toolkit inspection. All except Recovery also have supplied-timeline inspection; Recovery has reviewed-memory availability instead.

| Specialist | Additional tools |
| --- | --- |
| Telemetry health | Correlate typed events; inspect normalized logs |
| Alert triage | Inspect logs; correlate typed events; scan supplied files |
| Incident scoping | Correlate typed events; inspect logs and packet captures |
| Threat intelligence | Scan supplied files; inspect packet captures |
| Threat hunting | Inspect logs, supplied files and packet captures |
| DFIR evidence | Scan supplied files; inspect packet captures |
| Detection engineering | Scan supplied files; inspect normalized logs |
| Exposure and vulnerability | Assess exposure priorities |
| Identity and access | Inspect logs; correlate typed events |
| Cloud and supply chain | Scan supplied files; correlate typed events |
| Response and remediation | Assess exposure priorities; correlate typed events |
| Recovery and learning | Correlate typed events |

Each skill explains when to select its tool, accepted inputs, interpretation and limitations. The model requests a tool by its exact catalog name; the runtime supplies the job's authorized evidence. The model cannot supply file paths, commands, URLs, new rules or package names. Unknown tools and tools assigned to another role are rejected.

`inspect_toolkit` checks what is installed. Missing tools are acquired through a reviewed image update, with license, dependency and behavior checks; an agent does not download executable code from an investigation page. This release packages the tools above. Memory-image acquisition, arbitrary vendor-log parsing, live endpoint collection and general external threat-intelligence searches are not implemented by this catalog.

## Docker isolation

The installation starts `investigation-tools` from the same immutable image as Gabriel. The tool service has its own internal `toolbus` network, shared only with the workbench. It has no published port, database network, provider key, database credential, evidence-volume mount or outbound network. The normal workbench remains on private networks; the optional AI-egress overlay adds provider connectivity only to the workbench.

Only case-authorized, digest-verified source bytes are sent to that local service. Fixed subprocesses receive bounded stdin with a stripped environment, closed inherited file descriptors and CPU, memory, output and wall-time limits. They do not execute evidence or user-authored commands/rules. Provider-visible summaries accept only registered identifiers, counts and closed statuses: no file contents, packet payloads, addresses or raw log identities.

One request accepts at most 1 MiB of stored source content; a tool invocation covers at most eight selected sources and 4 MiB total. PCAP parsing is limited to 10,000 packets; normalized log parsing to 5,000 records. Oversized inputs require a narrower scope. Unsupported, malformed, missing or failed analyses remain visible; no-match and empty summaries never prove safety.

## Using tools locally

1. Rebuild the Docker installation from this source and open the workbench normally. The internal tool service starts as a dependency; AI egress is unnecessary for local tools.
2. Import source artifacts through the existing case-evidence intake. Supply a valid `specialist-facts-v1` document linking those artifacts and their stored digests.
3. Open the case's **Specialist AI agents** page. Select a specialist/tool and the typed-fact document under **Run local investigation tool**. Approve analysis of those linked sources.
4. Review the encrypted tool report and its status, evidence binding and limitations. Local execution does not call a model or require an AI key. CSRF, case authorization and source-byte checks still apply.

The text intake accepts ordinary UTF-8 source files directly. For binary files or captures, import a UTF-8 JSON envelope with exactly these fields:

```json
{"format":"gabriel-artifact-v1","kind":"pcap","encoding":"base64","data":"BASE64_OF_CAPTURE_BYTES"}
```

Use `kind: "file"` for other binary source files. The stored envelope itself must fit the 1 MiB limit. There is no file-path or URL dereference. `inspect_logs` accepts one JSON object per line with exactly `timestamp` (ISO8601 with timezone), `entity` (a local correlation identifier), and `outcome` (`failure`, `success`, `blocked` or `observed`). Convert vendor exports explicitly; do not assume field meanings.

## AI and qualification

When an admitted specialist configuration runs, it can request these tools and use their minimized results in later reasoning, within the existing three-round limit. Exposure/response agents automatically assess exposure priorities before reasoning when exposure facts are supplied. A model's benign disposition is rejected if that check found an urgent exposure; abstention does not erase the urgent local finding.

No production specialist configuration is admitted by adding these tools. The earlier 24-call development evaluation tested different prompt/tool hashes. The new tool/skill configurations require new live tool-loop, independent held-out and analyst-review evidence. No paid inference is triggered by this implementation or its Docker tests. Browser navigation retains its separate approved session and is not replaced by these offline tools.
