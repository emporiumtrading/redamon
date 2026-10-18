#!/usr/bin/env python3
"""Generate fresh deployment database secrets outside the source checkout."""
import argparse
import os
from pathlib import Path
import secrets


def prepare(directory):
    directory = directory.resolve()
    repo = Path(__file__).resolve().parents[2]
    if directory == repo or repo in directory.parents:
        raise ValueError('Secret directory must be outside the repository')
    if directory.exists() and (not directory.is_dir() or any(directory.iterdir())):
        raise ValueError('Use a new or empty secret directory; existing secrets are never replaced')
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.stat().st_uid != os.getuid():
        raise ValueError('Secret directory must be owned by the current operator')
    directory.chmod(0o700)
    owner, app = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
    files = {
        'db_password': owner,
        'owner_dsn': f'postgresql://postgres:{owner}@identity-db:5432/gabriel',
        'app_dsn': f'postgresql://gabriel_identity_app:{app}@identity-db:5432/gabriel',
        'role_init.sql': "CREATE ROLE gabriel_identity_app LOGIN PASSWORD '" + app + "' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;\n",
    }
    for name, value in files.items():
        path = directory / name
        with path.open('x') as stream:
            stream.write(value + ('\n' if not value.endswith('\n') else ''))
        # Parent 0700 protects host access; each container sees only its explicit mounts.
        path.chmod(0o444)
    return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    try:
        path = prepare(args.directory)
    except (ValueError, OSError) as exc:
        parser.exit(2, str(exc) + '\n')
    print(f'Prepared database secret files in {path}; no credentials printed.')


if __name__ == '__main__':
    main()
