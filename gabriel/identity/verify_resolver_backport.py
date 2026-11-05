"""Verify the resolver backport inside the candidate before issuing scan evidence."""

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import socket
import sys
import _socket


def verify():
    if platform.python_version() != "3.15.2":
        raise SystemExit("Resolver backport proof requires CPython 3.15.2.")
    flags = socket.AI_NUMERICHOST | socket.AI_NUMERICSERV
    for resolve in (socket.getaddrinfo, _socket.getaddrinfo):
        for host, port in (
            ("127.0.0.1\0", 80),
            (b"127.0.0.1\0", 80),
            ("127.0.0.1", "8\x000"),
            ("127.0.0.1", b"8\x000"),
        ):
            try:
                resolve(host, port, 0, 0, 0, flags)
            except ValueError:
                continue
            raise SystemExit("CVE-2026-116566 regression: embedded NUL was accepted.")
        if not resolve("127.0.0.1", "80", 0, 0, 0, flags):
            raise SystemExit("Normal numeric resolution failed.")


if __name__ == "__main__":
    verify()
    if len(sys.argv) > 1:
        image_id = sys.argv[1]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise SystemExit("An exact Docker image ID is required.")
        module_digest = sha256(Path(_socket.__file__).read_bytes()).hexdigest()
        print(json.dumps({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": f"urn:gabriel:resolver-backport:{image_id}",
            "author": "Gabriel candidate verification",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": 1,
            "statements": [{
                "vulnerability": {"name": "CVE-2026-116566"},
                "products": [{"@id": "pkg:generic/python@3.15.2"}],
                "status": "fixed",
                "status_notes": (
                    f"Image {image_id} passed both resolver entry points with "
                    f"upstream backport 131a3a66c5f400b588f9fd2732a5ed4e89623ee3. "
                    f"_socket SHA256: {module_digest}."
                ),
            }],
        }, indent=2))
