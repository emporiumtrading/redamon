"""Bounded JSON-lines interface for the local inspection profile."""
import argparse
import json
import os
import sys

from gabriel.capabilities import CapabilityDenied, InvalidRequest, execute

MAX_REQUEST_BYTES = 256 * 1024


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidRequest("duplicate_json_key")
        result[key] = value
    return result


def _constant(value):
    raise InvalidRequest("nonfinite_json_number")


def process(raw):
    try:
        request = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        return {"status": "ok", "result": execute(request)}
    except CapabilityDenied as exc:
        return {"status": "denied", "code": str(exc)}
    except InvalidRequest as exc:
        return {"status": "invalid", "code": str(exc)}
    except (UnicodeError, ValueError, RecursionError):
        return {"status": "invalid", "code": "invalid_json"}


def _emit(result):
    print(json.dumps(result, ensure_ascii=True, allow_nan=False), flush=True)


def main():
    parser = argparse.ArgumentParser(description="Gabriel local inspection runtime")
    parser.add_argument("--describe", action="store_true")
    args = parser.parse_args()
    if os.environ.get("GABRIEL_PROFILE", "local-inspection") != "local-inspection":
        _emit({"status": "denied", "code": "unsupported_runtime_profile"})
        return 2
    if args.describe:
        _emit({"status": "ok", "result": execute({
            "schema_version": 1, "operation": "capabilities.list", "arguments": {}})})
        return 0
    failed = False
    while True:
        raw = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
        if not raw:
            break
        if len(raw) > MAX_REQUEST_BYTES:
            if not raw.endswith(b"\n"):
                while raw and not raw.endswith(b"\n"):
                    raw = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
            result = {"status": "invalid", "code": "request_limit_exceeded"}
        else:
            result = process(raw)
        _emit(result)
        failed = failed or result["status"] != "ok"
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
