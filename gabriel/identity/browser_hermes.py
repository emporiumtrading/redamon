"""Receipt-only Hermes evidence for explicitly selected browser tabs."""
import re
from uuid import uuid5

from gabriel.identity.browser_navigation import BrowserNavigationService, context_of, pending_navigation
from gabriel.identity.cases import iso
from gabriel.identity.evidence_store import canonical
from gabriel.identity.service import AccessDenied, InvalidIdentityInput, _digest, connection, identifier
from gabriel.identity.specialist_analysis import validate_document
from gabriel.identity.specialist_contracts import digest

VERSION = 'browser-hermes-snapshot-v1'
SOURCE_LABEL = 'Browser scoped Hermes receipt facts'
ACCESS_WALL = re.compile(r'^\s*(?:sign in to continue|session expired|access denied|authentication required)\s*$', re.I | re.M)


def selection(value):
    if not isinstance(value, (list, tuple)) or len(value) > 8:
        raise InvalidIdentityInput('invalid_hermes_tab_selection')
    leases = [identifier(item) for item in value]
    if len(set(leases)) != len(leases):
        raise InvalidIdentityInput('invalid_hermes_tab_selection')
    return leases


def current_captures(service, conn, principal, token, case_id, leases, *, record_access=False):
    browser = BrowserNavigationService(service._dsn, service.store)
    session_digest = _digest(token)
    captures = []
    for lease_id in sorted(leases, key=str):
        lease = conn.execute('''SELECT * FROM gabriel_identity.browser_leases
            WHERE organization_id=%s AND id=%s''', (principal.organization_id, lease_id)).fetchone()
        if not lease or (lease['case_id'], lease['issued_by'], lease['human_session_digest']) != (
                case_id, principal.user_id, session_digest):
            raise AccessDenied('hermes_selected_tab_not_owned')
        status = browser._browser_lease_status(conn, principal, lease)
        if not (status['authorization_current'] and status['heartbeat_fresh']
                and lease['state'] == 'active' and lease['intake_enabled']):
            raise AccessDenied('hermes_selected_tab_not_current')
        if pending_navigation(conn, principal.organization_id, lease_id):
            raise AccessDenied('hermes_navigation_outcome_unresolved')
        observation = conn.execute('''SELECT o.*,r.created_at AS received_at,
                clock_timestamp()-o.observed_at AS age,clock_timestamp()-r.created_at AS capture_age
            FROM gabriel_identity.browser_observations o
            LEFT JOIN gabriel_identity.browser_observation_receipts r
                ON (r.organization_id,r.observation_id,r.evidence_id)=(o.organization_id,o.id,o.evidence_id)
            WHERE o.organization_id=%s AND o.lease_id=%s ORDER BY o.sequence DESC LIMIT 1''',
            (principal.organization_id, lease_id)).fetchone()
        if (not observation or observation['state'] != 'captured' or observation['received_at'] is None
                or not 0 <= observation['age'].total_seconds() <= 120
                or not 0 <= observation['capture_age'].total_seconds() <= 120):
            raise AccessDenied('hermes_fresh_tab_read_required')
        navigation = conn.execute('''SELECT c.created_at,r.context,r.context_digest
            FROM gabriel_identity.browser_navigation_commits c
            JOIN gabriel_identity.browser_navigation_receipts r USING(organization_id,intent_id)
            JOIN gabriel_identity.browser_navigation_intents i ON (i.organization_id,i.id)=(c.organization_id,c.intent_id)
            JOIN gabriel_identity.browser_navigation_grants g ON (g.organization_id,g.id)=(i.organization_id,i.grant_id)
            WHERE g.organization_id=%s AND g.lease_id=%s ORDER BY c.created_at DESC,c.intent_id DESC LIMIT 1''',
            (principal.organization_id, lease_id)).fetchone()
        if navigation and (observation['created_at'] <= navigation['created_at']
                or navigation['context'] != context_of(lease)
                or navigation['context_digest'] != digest(navigation['context'])):
            raise AccessDenied('hermes_post_navigation_capture_required')
        artifact = browser._captured_artifact(conn, principal, observation, lease)
        if artifact['id'] != observation['evidence_id']:
            raise AccessDenied('hermes_capture_binding_mismatch')
        try:
            content = service._verify(conn, artifact).decode('utf-8')
        except UnicodeError:
            raise AccessDenied('hermes_capture_binding_mismatch') from None
        if ACCESS_WALL.search(content):
            raise AccessDenied('hermes_dashboard_access_wall')
        if record_access:
            service._custody(conn, principal, artifact, 'accessed')
        captures.append(observation)
    return captures


def receipt_document(case_id, captures):
    """Only capture integrity and missing semantic visibility are asserted."""
    facts = []
    for observation in captures:
        receipt_time = iso(observation['received_at']).replace('+00:00', 'Z')
        common = dict(evidence_id=str(observation['evidence_id']), evidence_digest=observation['content_digest'],
                      entity_id=None, event_time=receipt_time)
        facts.extend((
            dict(common, id=str(uuid5(observation['id'], VERSION + '/integrity')),
                 type='artifact', data=dict(integrity='match', custody='unknown')),
            dict(common, id=str(uuid5(observation['id'], VERSION + '/coverage')),
                 type='coverage', data=dict(state='missing')),
        ))
    as_of = iso(max(observation['received_at'] for observation in captures)).replace('+00:00', 'Z')
    document = dict(version='specialist-facts-v1', case_id=str(case_id), as_of=as_of, facts=facts)
    return validate_document(document, case_id)


def prepare(service, token, case_id, lease_ids):
    leases = selection(lease_ids)
    if not leases:
        raise InvalidIdentityInput('hermes_selected_tabs_required')

    def snapshot(*, record_access=False):
        with connection(service._dsn) as conn:
            principal = service._human(conn, token, write=True, content=True)
            case = service._case(conn, principal, case_id, open_only=True)
            captures = current_captures(service, conn, principal, token, case['id'], leases, record_access=record_access)
            return receipt_document(case['id'], captures), captures

    case_id = identifier(case_id)
    document, captures = snapshot(record_access=True)
    request = uuid5(case_id, VERSION + '/' + digest([str(row['id']) for row in captures]))
    artifact = service.acquire(token, case_id, request, canonical(document).decode(), SOURCE_LABEL,
                               approved=True, parent_id=captures[0]['evidence_id'],
                               redaction_state='user_declared_redacted')
    if snapshot()[0] != document:
        raise AccessDenied('hermes_selected_capture_changed')
    return dict(facts_evidence_id=str(artifact['id']), selected_leases=sorted(map(str, leases)),
                coverage='partial', semantic_telemetry_parsed=False, visible_text_exported=False, model_calls=0)
