"""Conservative, source-aware event normalization for evidence already authorized by a case.

Only the pinned Wazuh SSH-invalid-user adapter is implemented. This pure
module performs no network access, live collection, cross-tenant lookup or
incident classification. Its outputs are reported assertions, not attested
events or independent corroboration.
"""
from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
import re
from uuid import UUID

from gabriel.identity.evidence_store import canonical
from gabriel.identity.wazuh_events import (
    UnsupportedWazuhEvent, VERSION as WAZUH_ADAPTER, normalize as normalize_wazuh,
)

VERSION = 'gabriel-source-events-v1'
MAX_EVENTS = 128
TIMESTAMP = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z')
DIGEST = re.compile(r'[a-f0-9]{64}\Z')
EVENT_ID = re.compile(r'[0-9]{1,30}\.[0-9]{1,30}\Z')
FIELDS = frozenset({
    'schema_version', 'case_id', 'source_id', 'source_product',
    'source_product_version', 'adapter_version', 'native_event_id',
    'reported_event_time', 'observed_at', 'evidence_id', 'evidence_digest',
    'category', 'actor_alias', 'asset_alias', 'origin_alias',
    'source_authenticated', 'source_clock_verified', 'source_bytes_verified',
    'external_actions_authorized',
})


class UnsupportedSourceEvent(ValueError):
    """Unsupported, incomplete or conflicting claimed source semantics."""


def _require(condition):
    if not condition:
        raise UnsupportedSourceEvent('invalid_or_unsupported_source_event')


def _uuid(value):
    _require(type(value) is str)
    try:
        _require(str(UUID(value)) == value)
    except (ValueError, TypeError, AttributeError):
        raise UnsupportedSourceEvent('invalid_or_unsupported_source_event') from None
    return value


def _instant(value):
    _require(type(value) is str and TIMESTAMP.fullmatch(value) is not None)
    try:
        parsed = datetime.fromisoformat(value[:-1] + '+00:00')
        _require(1970 <= parsed.year <= 2100 and parsed.utcoffset().total_seconds() == 0)
    except (ValueError, TypeError, OverflowError, AttributeError):
        raise UnsupportedSourceEvent('invalid_or_unsupported_source_event') from None
    return parsed


def validate_event(event):
    """Validate de-identified output without upgrading its provenance claim."""
    _require(type(event) is dict and set(event) == FIELDS)
    _require(event['schema_version'] == VERSION)
    for key in ('case_id', 'source_id', 'evidence_id',
                'actor_alias', 'asset_alias', 'origin_alias'):
        _uuid(event[key])
    _require(type(event['evidence_digest']) is str and DIGEST.fullmatch(event['evidence_digest']) is not None)
    _require(event['source_product'] == 'wazuh')
    _require(event['source_product_version'] == '4.14.9')
    _require(event['adapter_version'] == WAZUH_ADAPTER)
    _require(type(event['native_event_id']) is str and EVENT_ID.fullmatch(event['native_event_id']) is not None)
    _require(event['category'] == 'authentication_failure_invalid_user')
    _instant(event['reported_event_time'])
    _instant(event['observed_at'])
    _require(event['source_authenticated'] is False
             and event['source_clock_verified'] is False
             and event['source_bytes_verified'] is False
             and event['external_actions_authorized'] is False)
    _require(len(canonical(event)) <= 4096)
    return event


def normalize_wazuh_invalid_user(record, *, case_id, source_id,
                                 evidence_id, evidence_digest, observed_at):
    """Project exactly one supported Wazuh event with explicit provenance limits.

    The caller MUST verify current organization/case authority and source bytes
    before presenting this output to a human. The pure normalizer cannot do it.
    """
    _uuid(case_id)
    _uuid(source_id)
    _uuid(evidence_id)
    _instant(observed_at)
    try:
        event, manifest = normalize_wazuh(record, source_id, evidence_id, evidence_digest)
    except UnsupportedWazuhEvent:
        raise UnsupportedSourceEvent('invalid_or_unsupported_source_event') from None
    projected = dict(
        schema_version=VERSION,
        case_id=case_id,
        source_id=event['source_id'],
        source_product='wazuh',
        source_product_version='4.14.9',
        adapter_version=manifest['normalizer_version'],
        native_event_id=event['event_id'],
        reported_event_time=event['event_time'],
        observed_at=observed_at,
        evidence_id=event['evidence_id'],
        evidence_digest=event['evidence_digest'],
        category='authentication_failure_invalid_user',
        actor_alias=event['actor_id'],
        asset_alias=event['asset_id'],
        origin_alias=event['source_asset_id'],
        source_authenticated=False,
        source_clock_verified=False,
        source_bytes_verified=False,
        external_actions_authorized=False,
    )
    return validate_event(projected)


def _semantic_digest(event):
    """Digest same-source event meaning, excluding evidence-copy metadata."""
    keys = ('case_id', 'source_id', 'source_product',
            'source_product_version', 'adapter_version', 'native_event_id',
            'reported_event_time', 'category', 'actor_alias', 'asset_alias',
            'origin_alias')
    return sha256(canonical({key: event[key] for key in keys})).hexdigest()


def review_source_events(events):
    """Report repeated IDs, contradictions and temporal co-occurrence only.

    Never delete repeated records, join identities across products, infer an
    attack or treat correlated timelines as independent corroboration.
    """
    _require(type(events) is list and 1 <= len(events) <= MAX_EVENTS)
    for event in events:
        validate_event(event)
    cases = {row['case_id'] for row in events}
    _require(len(cases) == 1)
    identities = defaultdict(list)
    for event in events:
        identities[(event['source_id'], event['native_event_id'])].append(_semantic_digest(event))
    repeats = sum(len(values) - len(set(values)) for values in identities.values())
    conflicts = sum(len(set(values)) > 1 for values in identities.values())
    ordered = [(row['source_id'], row['category'], _instant(row['reported_event_time']))
               for row in events]
    coincidences = sum(
        a_source != b_source and a_kind == b_kind and abs((a_time - b_time).total_seconds()) <= 300
        for i, (a_source, a_kind, a_time) in enumerate(ordered)
        for b_source, b_kind, b_time in ordered[i + 1:]
    )
    clock_ahead = sum(
        (_instant(row['reported_event_time']) - _instant(row['observed_at'])).total_seconds() > 300
        for row in events
    )
    return dict(
        schema_version=VERSION,
        status='review_required',
        event_count=len(events),
        source_count=len({row['source_id'] for row in events}),
        evidence_copy_count=len({row['evidence_id'] for row in events}),
        same_source_event_key_count=len(identities),
        same_source_repeat_candidates=repeats,
        same_source_identity_conflict_groups=conflicts,
        cross_source_300s_coincidence_pairs=coincidences,
        event_clocks_ahead_of_observation_count=clock_ahead,
        cross_source_identity_join_performed=False,
        cross_source_event_deduplication_performed=False,
        independent_corroboration_established=False,
        source_authenticated=False,
        source_clock_verified=False,
        attack_status='unknown',
        external_actions_authorized=False,
        model_used=False,
    )
