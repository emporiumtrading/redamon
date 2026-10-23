# Private Docker test installation

This installs the existing defensive case workbench and encrypted evidence services for a local, operator-led test. It is not a complete production release or an autonomous SOC deployment. Production console adapters and model routes remain empty. Wazuh/DFIR-IRIS deployment and browser adapter acceptance are subsequent work; this command does not install those tools.

## Requirements and setup

Use a checked-out source revision, Python 3.9 or later on a POSIX host, Docker Engine/Desktop with Compose v2, and an operator-owned directory outside the source checkout. The controller uses POSIX ownership and file locking; native Windows execution is not supported by this increment. Linux x86/ARM CI coverage is recorded in the PR; macOS/Windows Docker Desktop and the 18 GB target host still require acceptance. Commands below use `$HOME/gabriel-private-test` as a new directory; do not put it inside Git or a shared/synced folder. Docker volumes retain database, encrypted evidence and private workbench session files. Do not run inherited offensive-stack installation commands.

```bash
python3 tooling/scripts/gabriel_install.py prepare "$HOME/gabriel-private-test"
python3 tooling/scripts/gabriel_install.py initialize "$HOME/gabriel-private-test" --organization 'My private lab' --username owner
python3 tooling/scripts/gabriel_install.py open "$HOME/gabriel-private-test"
```

`prepare` builds the defensive production image and binds the installation to that exact local image ID and source. It generates separate database credentials, provider-vault/evidence encryption keys and a localhost-only certificate. Nothing reads a developer provider key. For an already checked image, pass `prepare --image sha256:<exact-local-image-id>`; verify its provenance first. No image is pulled by an unqualified mutable application tag. PostgreSQL currently uses the existing `postgres:16-alpine` dependency and still needs release-level digest pinning/scanning.

`initialize` prompts privately for an owner password and stores only its Argon2 hash in PostgreSQL. Enrollment is single-use and refuses an existing organization; uncertain enrollment state is left for operator inspection. There is no default owner password. `open` asks for the same password, revokes the previous workbench's authority and prints a new access ticket. Open the displayed `https://localhost:8444/claim` promptly and enter that ticket. It is a secret: do not place it in a URL, logs, screenshots or tickets. The claim expires after 60 seconds and the workbench session after ten minutes. Re-run `open` for a fresh authenticated session; no automatic authority renewal or unattended continuous monitoring is provided. After 128 session directories, operator cleanup/review is required rather than unbounded enrollment storage.

Trust only this installation's `tls/ca.pem` in a dedicated local browser profile using the browser/OS certificate settings. Do not disable certificate checks or globally trust an unknown CA. This local CA's signing key is discarded and its server certificate lasts 30 days. Managed certificate renewal/public hosting is not implemented. The HTTPS port is published only on IPv4 loopback; PostgreSQL has no published port. The app runs as UID 10001, with read-only root filesystem, dropped capabilities and separate mounts from the migration owner's database credential.

The application and database stay on an internal Docker network with no admitted model/provider egress. A separate unprivileged entry container has no secrets or data volumes and forwards opaque TLS only to the fixed workbench service. Its only published listener is IPv4 loopback. It has a normal bridge attachment for Docker port publication; it never terminates TLS, accepts a caller-selected destination or grants application egress. Forwarding allows four connections, a 30-second forwarding window and 4 MiB per connection; individual socket I/O has a three-second timeout and may finish after that window. The UI can store customer keys in its encrypted vault, but live OpenRouter funding checks and inference require separately reviewed egress/route admission. NVIDIA entitlement validation remains pending. Adding credentials does not activate any model or real-console adapter.

```bash
python3 tooling/scripts/gabriel_install.py status "$HOME/gabriel-private-test"
python3 tooling/scripts/gabriel_install.py stop "$HOME/gabriel-private-test"
```

`status` reports Docker service state, not detection effectiveness or release acceptance. The healthcheck verifies trusted HTTPS rejects unauthenticated case access and that the saved operator identity remains valid; it does not claim a browser has connected or that the ten-minute workbench session is current. `stop` closes the interface, revokes the saved session and stops PostgreSQL; it retains volumes. Reopen with `open`. Unexpected process/database restarts require a fresh `open` if the single-use startup guard rejects reuse. Commands serialize with a nonblocking local operator lock. Partial failures retain state, refuse silent credential replacement and need inspection before retrying initialization/restoration.

## Quiesced backup and fresh-target restore

```bash
python3 tooling/scripts/gabriel_install.py backup "$HOME/gabriel-private-test" --backup "$HOME/gabriel-test-backup"
python3 tooling/scripts/gabriel_install.py prepare "$HOME/gabriel-restored-test" --port 8445 --image sha256:<same-image-id>
python3 tooling/scripts/gabriel_install.py restore "$HOME/gabriel-restored-test" --backup "$HOME/gabriel-test-backup" --keys-from "$HOME/gabriel-private-test"
python3 tooling/scripts/gabriel_install.py open "$HOME/gabriel-restored-test"
```

Backup stops the workbench and revokes its session before snapshotting PostgreSQL and encrypted objects. The backup manifest records file SHA-256 values, exact source/image, owner identifiers and encryption-key fingerprints. It contains no evidence/provider encryption keys or password. The database dump still contains sensitive account, case and encrypted-vault data; protect the whole directory and retain keys separately under operator access control. Local hashes detect accidental mismatch, not a malicious operator rewriting both manifest and files. No external writer/connector is admitted in this installation; future writers must participate in quiescence before this backup process can be accepted for them.

Restore requires a new prepared project with no existing containers or volumes, the identical source/image, matching original evidence/provider keyrings and verified backup files. It replaces only that new target's unused generated evidence/provider keys. It never overwrites an existing database or evidence volume. Database secrets and TLS remain new. Stored migrations are checked against the exact source; the owner is verified and a fresh login is required. Object archives reject traversal, links, unknown names, duplicate members and invalid sizes before publishing any objects. Current rehearsal limits are 128 MiB per backup input, 128 MiB expanded objects, 4,096 encrypted objects and the existing per-object bound. Larger installations need a streaming/scaled recovery implementation. A failed restore target remains isolated for inspection; do not promote it.

Back up original keys separately before any host loss. Losing encryption keys makes corresponding evidence/vault contents unrecoverable. This is a same-source restore rehearsal, not automated upgrade, database downgrade, signed release rollback, measured RPO/RTO or disaster-recovery acceptance. All remain release gates, together with security scans, real-console integration, model qualification, load testing and human UAT.
