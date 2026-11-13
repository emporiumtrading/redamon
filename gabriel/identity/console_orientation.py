"""Vendor-neutral, evidence-bound browser-console orientation.

This local review consumes Gabriel's EXISTING visible-top-frame discovery result.
It does not identify a vendor, execute navigation, parse unknown event semantics,
grant browser permissions, authenticate the source, or qualify any AI model.
"""
from hashlib import sha256
import re
from urllib.parse import urlsplit, unquote, urlunsplit
from uuid import UUID

from gabriel.identity.evidence_store import canonical
from gabriel.identity.browser_navigation import readonly_page
from gabriel.identity.service import AccessDenied

VERSION = 'gabriel-console-orientation-v1'
DISCOVERY_KEYS = frozenset({'title','headings','links','identification','coverage'})
MAX_LINKS = 100
MAX_CANDIDATES = 20
UUID_ERROR = 'invalid_console_orientation_input'
SENSITIVE_ROUTE = re.compile(
    r'(?:^|[/?#._-])(?:login|signin|sign-in|logout|signout|oauth|sso|mfa|password|'
    r'token|secret|key|credential|delete|remove|disable|enable|execute|apply|save|'
    r'create|reset|reboot|shutdown|terminate|block|unblock|approve|revoke|edit|'
    r'settings|configuration)(?:$|[/?#._-])',
    re.I,
)


class InvalidConsoleOrientation(ValueError):
    pass


def require(ok):
    if not ok:
        raise InvalidConsoleOrientation(UUID_ERROR)


def valid_uuid(value):
    require(type(value) is str)
    try:
        require(str(UUID(value)) == value)
    except (ValueError, TypeError, AttributeError):
        raise InvalidConsoleOrientation(UUID_ERROR) from None
    return value


def strict_source(url):
    require(type(url) is str and 1 <= len(url) <= 1024)
    try:
        parsed = urlsplit(url)
        require(parsed.scheme == 'https' and parsed.hostname and not parsed.username
                and not parsed.password and not parsed.query and not parsed.fragment
                and not any(ord(c) < 33 or ord(c) == 127 for c in url))
        require(urlunsplit(parsed) == url)
        readonly_page(url)
    except (ValueError, AccessDenied, UnicodeError):
        raise InvalidConsoleOrientation(UUID_ERROR) from None
    return parsed


def candidate(url, origin):
    """Candidate for an operator; backend grant still determines navigation."""
    if type(url) is not str or len(url) > 1024:
        return False
    try:
        parsed = urlsplit(url)
        if (parsed.scheme, parsed.netloc) != origin or parsed.username or parsed.password:
            return False
        if parsed.query or parsed.fragment or urlunsplit(parsed) != url:
            return False
        route = url
        for _ in range(4):
            route = unquote(route)
        if SENSITIVE_ROUTE.search(route):
            return False
        if any(ord(c) < 33 or ord(c) == 127 for c in url):
            return False
        readonly_page(url)
        return True
    except (ValueError, AccessDenied, UnicodeError):
        return False


def orient(snapshot, *, case_id, evidence_id, evidence_digest, source_url):
    """Return a bounded list of possible read-only pages for analyst review.

    The caller must verify case/observation rights and evidence content/digest
    prior to this pure review and again before any actual browser grant.
    Headings and page text are NOT trusted instructions or source truth.
    """
    valid_uuid(case_id)
    valid_uuid(evidence_id)
    require(type(evidence_digest) is str and re.fullmatch(r'[0-9a-f]{64}',evidence_digest) is not None)
    page = strict_source(source_url)
    require(type(snapshot) is dict and set(snapshot) == DISCOVERY_KEYS)
    require(snapshot['identification'] == 'page-reported, unverified')
    require(snapshot['coverage'] == 'partial; visible top-frame links only')
    require(type(snapshot['title']) is str and len(snapshot['title']) <= 160)
    require(type(snapshot['headings']) is list and len(snapshot['headings']) <= 12)
    require(all(type(x) is str and len(x) <= 160 for x in snapshot['headings']))
    links=snapshot['links']
    require(type(links) is list and len(links) <= MAX_LINKS)
    require(all(type(x) is str and len(x) <= 1024 for x in links))
    require(len(canonical(snapshot)) <= 131072)
    origin=(page.scheme,page.netloc)
    admitted=[]
    for url in links:
        if url != source_url and candidate(url, origin) and url not in admitted:
            admitted.append(url)
    admitted=admitted[:MAX_CANDIDATES]
    return dict(
        version=VERSION,
        case_id=case_id,
        evidence_id=evidence_id,
        evidence_digest=evidence_digest,
        source_url=source_url,
        snapshot_sha256=sha256(canonical(snapshot)).hexdigest(),
        reported_heading_count=len(snapshot['headings']),
        observed_link_count=len(links),
        read_only_candidate_count=len(admitted),
        read_only_candidates=admitted,
        status='analyst_review_required' if admitted else 'no_supported_navigation_candidates',
        console_vendor='unknown',
        console_semantics='unverified',
        source_authenticity='unverified',
        account_identity='not_verified_by_this_review',
        coverage='visible_top_frame_only',
        frame_and_dynamic_controls='not_assessed',
        cross_origin_navigation_allowed=False,
        navigation_performed=False,
        navigation_granted=False,
        threat_detection_qualified=False,
        external_actions_authorized=False,
        model_used=False,
    )
