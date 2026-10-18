"""Closed local capability catalog, independent of model and MCP output."""
from hashlib import sha256
from types import MappingProxyType

from gabriel import __version__

POLICY_VERSION = "local-inspection-v1"
MAX_CONTENT_BYTES = 128 * 1024


class CapabilityDenied(ValueError):
    pass


class InvalidRequest(ValueError):
    pass


def _describe(arguments):
    if arguments:
        raise InvalidRequest("unexpected_arguments")
    return {
        "product": "Gabriel — The Defender", "version": __version__,
        "profile": "local-inspection", "policy_version": POLICY_VERSION,
        "capabilities": [dict(name=name, **metadata) for name, metadata in _METADATA.items()],
        "external_access": False, "external_authentication": False, "response_execution": False,
        "authentication": "local_process_only", "production_ready": False,
    }


def _hash_content(arguments):
    if set(arguments) != {"content"} or not isinstance(arguments["content"], str):
        raise InvalidRequest("content_string_required")
    try:
        content = arguments["content"].encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise InvalidRequest("invalid_utf8_content") from exc
    if len(content) > MAX_CONTENT_BYTES:
        raise InvalidRequest("content_limit_exceeded")
    return {"algorithm": "sha256", "digest": sha256(content).hexdigest(),
            "byte_length": len(content), "source_verified": False,
            "scope": "supplied_utf8_content_only"}


_HANDLERS = MappingProxyType({"capabilities.list": _describe, "evidence.hash": _hash_content})
_METADATA = MappingProxyType({
    "capabilities.list": MappingProxyType({
        "purpose": "Inspect the fixed capabilities and limitations of this runtime.",
        "arguments": "empty object", "effect": "local_computation",
    }),
    "evidence.hash": MappingProxyType({
        "purpose": "Hash supplied UTF-8 content without reading files or fetching a source.",
        "arguments": "content: string, at most 128 KiB after UTF-8 encoding",
        "effect": "local_computation",
    }),
})


def execute(request):
    if not isinstance(request, dict) or set(request) != {"schema_version", "operation", "arguments"}:
        raise InvalidRequest("invalid_request_fields")
    if type(request["schema_version"]) is not int or request["schema_version"] != 1:
        raise InvalidRequest("unsupported_schema_version")
    operation = request["operation"]
    if not isinstance(operation, str) or operation not in _HANDLERS:
        raise CapabilityDenied("operation_not_allowed")
    if not isinstance(request["arguments"], dict):
        raise InvalidRequest("arguments_object_required")
    return _HANDLERS[operation](request["arguments"])
