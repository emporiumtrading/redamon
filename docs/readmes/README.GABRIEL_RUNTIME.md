# Gabriel defensive runtime — increment 2

## Delivered scope

This is the local inspection portion of C02, with inventory tooling for C00. It runs independently of RedAmon's agent, MCP servers and Compose deployment. It exposes two real capabilities: `capabilities.list` describes the installed catalog and limits; `evidence.hash` computes a SHA-256 digest of supplied UTF-8 content. A digest verifies content equality, not the source's truth or completeness.

The package has one exact-name dispatch boundary and a closed capability catalog. Unknown operations and arguments are rejected. User-supplied approvals, tenant fields, commands, file paths and URLs cannot extend the catalog. No model output, environment mode or MCP manifest can add handlers. Invalid JSON, duplicate fields, nonfinite numbers, invalid UTF-8 and oversized requests have bounded error paths that do not echo the supplied content.

The production image copies only the three Gabriel package files. The separate test stage contains test dependencies and source-inventory tooling. `compose.gabriel.yml` defines one non-root, read-only service with no network, no published ports, no host mounts, dropped capabilities and a process/memory ceiling. There is no listening API or shared user state in this increment. Its declared profile is `local-inspection`; requesting any other profile fails closed.

## Run

```bash
bash gabriel.sh build
bash gabriel.sh describe
printf '%s\n' '{"schema_version":1,"operation":"evidence.hash","arguments":{"content":"authorized evidence"}}' | bash gabriel.sh run
bash gabriel.sh test /absolute/path/to/evidence
bash gabriel.sh inventory HEAD > /absolute/path/to/inventory.json
```

The runtime uses a JSON-lines interface on standard input/output. A denied or invalid request causes a nonzero process exit after all supplied lines are processed. Content hashing is bounded at 128 KiB of UTF-8 bytes; each input line is limited to 256 KiB. Only supplied text is processed; it never reads a named source file or fetches a URL.

The wrapper always selects the Gabriel Compose file explicitly. Do not combine it with the original RedAmon composition. The original application's defensive conversion is not established by running this package.

## Inventory and conversion review

`tooling/scripts/gabriel_inventory.py` resolves a commit, enumerates every tracked tree entry with its Git object ID, and discovers static registry/tool/route/Compose anchors. It reads committed objects without importing source, following symlinks or including dirty/untracked files. It records parse failures, dynamic registry behavior, gitlinks and lexical Compose limitations as review gaps.

Inherited files start with proposed disposition `isolate`; the new Gabriel package and its entry points are proposed `retain`. All start with review state `unreviewed`. These are proposals, not a completed human conversion review. The report remains `REVIEW_REQUIRED`. Static discovery cannot enumerate all runtime plugins, listeners, jobs, credentials or data-driven dispatch. The per-capability review, rendered deployment review, original stack baseline and C01 pilot decisions remain outstanding before C02 can be accepted for a customer product.

## Verification obligations

The matching image tests known hashes, Unicode/size boundaries, hostile supplied content, denied legacy tool names, malformed/ambiguous requests, untrusted authority fields, concurrent callers and unsupported profiles. Inventory tests cover static discovery, explicit gaps and committed-versus-dirty Git state.

The VM workflow renders the actual Compose file, builds both image targets, runs the strict image tests, sends all discovered registry/tool/server names through the packaged production gateway, inspects the shipped image for excluded code/dependencies, and repeats the existing foundation regression. It retains actual source/image IDs, inventory, rendered configuration, machine-readable counts and denial results. A workflow definition alone is not a test pass.

Local Docker/VM execution remains unavailable in the working environment. Product execution must stay in the matching Docker image; host pytest is not an accepted fallback. Isolated fixtures are test data only, never presented as live telemetry.

## Product boundaries and next work

GAB-001 inventory coverage and GAB-002 runtime closure are partially implemented here. No claim is made that all conversion decisions are reviewed or the full legacy gate has passed. This CLI does not implement browser sessions, authenticated multi-user operations, durable cases, incident detection, agent roles, continuous learning or response. Those capabilities must follow C03/C04 and their own acceptance requirements.

This runtime has no authority to act on systems. C03 must introduce real authenticated tenant/service identity before any network-facing or delegated workflow is admitted; C04 must establish durable evidence/action state. Authorization cannot be inferred from fields in a future request body. Browser work then integrates through the same reviewed admission principle with its own typed contracts.
