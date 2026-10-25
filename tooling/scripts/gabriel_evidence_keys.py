#!/usr/bin/env python3
"""Prepare evidence-only keys separately from model-provider credentials."""
import argparse
from gabriel_provider_keys import prepare


def main():
    parser = argparse.ArgumentParser(description='Prepare external evidence encryption keys')
    parser.add_argument('directory')
    parser.add_argument('--from-file')
    args = parser.parse_args()
    try:
        prepare(args.directory,args.from_file,purpose='evidence-v1')
    except (OSError,ValueError,TypeError,UnicodeError,RecursionError):
        print('BLOCKED: evidence key preparation failed; existing files were not replaced.')
        return 2
    print('Evidence-only key directory created; no key material printed.')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
