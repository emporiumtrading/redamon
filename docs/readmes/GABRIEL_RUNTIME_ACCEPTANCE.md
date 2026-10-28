# Native runtime acceptance evidence

The runtime collector verifies a running installation against its exact checkout and Docker image, inspects actual containers and network objects, and performs a trusted private-CA HTTPS request. It never authenticates to a dashboard, dispatches AI, changes services, or grants production admission. Keep its result private; runtime/image metadata and platform versions are operational information.

Run on the installation host after `gabriel_install.py open`, using the source that created or rebuilt that installation:

```bash
mkdir -m 700 "$HOME/gabriel-acceptance"
python3 tooling/scripts/gabriel_acceptance.py \
  --installation "$HOME/gabriel-private-test" \
  --output "$HOME/gabriel-acceptance/runtime.json"
```

An installation deliberately opened with `--ai-egress` also needs `--allow-provider-egress` for this collector. The flag only permits workbench egress in the assessment; Hermes, tools and the database must remain private. It does not qualify a route or authorize inference. Capture the actual egress policy with the release review.

The new result file has mode 0600 in an operator-owned 0700 directory. A successful command prints its SHA-256 digest, never Docker environment values, mounted file contents, credentials or account identifiers. A missing/unhealthy service, changed application image, published private port, public entry listener, privileged/host namespace, missing hardening/resource limits, privileged mount, persistent/secret mount on Hermes/tools/entry, or unexpected private-network egress fails collection. The installed source must match the checked-out commit. Existing outputs are never overwritten. The check may fail while healthchecks are starting; inspect service health before collecting again under a new filename.

The report distinguishes collector host OS/architecture from Docker engine OS/architecture. Docker Desktop's Linux VM is not macOS or Windows browser evidence. A collector executed inside WSL or an Ubuntu guest records that environment; it does not certify the Windows/macOS host. The Python installer/collector requires a POSIX installation host; Windows analysts may use the supported Linux guest/WSL installation path and must separately test their native browser.

Both architecture installation workflows execute this collector against the actual generated-data installation, retain `runtime-acceptance.json`, and run offline security fault-injection tests in the Docker image. These are Linux runtime checks, never a replacement for native UAT.

## Evidence still requiring the actual operator and reviewer

On Apple Silicon Docker Desktop, then each supported Windows/macOS/Linux Chrome and Brave combination, retain a dated record bound to the exact source, image, extension and runtime report digest. Exercise native certificate trust; manual login/MFA; pairing and multiple selected tabs; scope/privacy and excluded tabs; Stop, logout and revocation; stale/missing/partial pages and UI drift; spending exhaustion; restart and fresh login. Record actual expected/observed outcomes and original failed evidence. A reviewer other than the implementer must assess material results; this script cannot authenticate their identity or signoff.

Separately rehearse backup plus original-key recovery to a fresh host/project; measure elapsed recovery time and actual last recovered event against declared RTO/RPO. Retain failed attempts too. Same-source restore and forward migration do not establish safe database downgrade or signed release rollback. Retention/hold/purge policy, external key custody, workload sizing, vulnerability disposition, rollback, operator ownership and escalation contacts still require recorded release-owner acceptance. Do not replace these observations with checked boxes or a passing CI artifact. No model or external containment action is enabled by runtime acceptance.
