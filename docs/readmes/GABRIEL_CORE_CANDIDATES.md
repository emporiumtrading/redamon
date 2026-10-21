# Checked core Docker candidates

Requirement scope: GAB-008, GAB-019, GAB-040 and GAB-041. This is a distribution increment for testing, not production acceptance.

After the database, recovery, defensive runtime and foundation gates pass, each AMD64 and native ARM64 job exports its existing core, defensive boundary and offline checkpoint-signer images. The exporter does not rebuild them. It requires one fresh strict, nonempty report per gate at the checked-out source commit, with no failures, errors or skips. It checks recorded image IDs, Linux architecture, nonroot users, secret configuration exclusions, archive config digests and image tags, then loads the archive and verifies image IDs and the core's imports with no network.

The job retains gabriel-core-candidate-amd64 or gabriel-core-candidate-arm64 for fourteen days. Each contains images.tar.gz, manifest.json and four sanitized component reports. The manifest records source SHA, architecture, exact image IDs, archive SHA-256/size and test-report checksums. It explicitly records production_admitted=false. The source SHA is the actual CI checkout, which can be a pull-request merge commit.

## Initial testing

Download the candidate for the Docker host's Linux architecture from the successful CI job. Match the archive SHA-256 and size against manifest.json before loading. Keep the manifest and matching component/browser evidence with the candidate.

Run docker load --input images.tar.gz. Inspect each tag listed in the manifest and verify its image ID equals the recorded image_id. Use those exact image IDs for test execution. Do not substitute an unverified rebuild or a mutable development tag.

The core image contains the private account, case, workbench and gateway command modules. This bundle does not include PostgreSQL, persistent volumes, TLS certificates, customer credentials, deployment configuration or a ready-to-run production installation. Prepare those separately under the documented identity/evidence/provider-key procedures. Do not mount CI fixture secrets or real incident material into a test candidate.

The Chrome/Brave extension remains a separate packaged-browser artifact. Its source must match the candidate and its own browser checks must pass. A core image bundle alone does not establish browser acceptance. ARM64 Linux CI does not establish native macOS, Windows or Docker Desktop acceptance.

## Release boundary and recovery

No provider key or runtime database/evidence state is exported. Customers must supply their own OpenRouter or NVIDIA key; an image download grants no access to a developer key or an admitted model route.

An archive checksum detects mismatches against the retained manifest; this increment does not supply an independent signature, SBOM or release provenance attestation. Dependency/license/container scans, model quality qualification, real-console and OS UAT, declared workload/capacity, installation/upgrade/rollback and recovery procedures, release authorization and post-release observation remain required. Archive loading is not database rollback or reversal of an external action.

Failure of any component gate or export check prevents the candidate upload. Sanitized diagnostic evidence is retained separately. Old or mixed source reports, empty/skipped gates, wrong image IDs and missing archives must never be treated as an accepted candidate.
