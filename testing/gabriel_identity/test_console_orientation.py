"""Generated consoles with unrelated vendor labels, same security decisions."""
from copy import deepcopy
from uuid import uuid4

import pytest

from gabriel.identity.console_orientation import InvalidConsoleOrientation, orient


def review(snapshot, source_url='https://console.example.org/home'):
    return orient(snapshot,case_id=str(uuid4()),evidence_id=str(uuid4()),
                  evidence_digest='a'*64,source_url=source_url)


def visible(*links, title='Security dashboard'):
    return dict(title=title,headings=['Overview', 'Events', 'Incident review'],
                links=list(links),identification='page-reported, unverified',
                coverage='partial; visible top-frame links only')


@pytest.mark.parametrize('brand',['Unknown EDR', 'Wazuh', 'Palo Alto', 'Splunk',
                                 'CrowdStrike', 'Unbranded private SOC'])
def test_unknown_vendor_labels_do_not_change_admission_and_never_grant_navigation(brand):
    row=review(visible('https://console.example.org/events',
                      'https://console.example.org/incidents',title=brand))
    assert row['status']=='analyst_review_required'
    assert row['read_only_candidate_count']==2
    assert row['console_vendor']=='unknown'
    assert row['console_semantics']=='unverified'
    assert not row['navigation_granted']
    assert not row['navigation_performed']
    assert not row['external_actions_authorized']
    assert not row['threat_detection_qualified']
    assert not row['model_used']


def test_unsafe_cross_origin_write_and_sensitive_destinations_are_never_returned():
    row=review(visible(
        'https://console.example.org/alerts',
        'https://attacker.example.org/alerts',
        'http://console.example.org/alerts',
        'https://console.example.org/settings',
        'https://console.example.org/users/delete',
        'https://console.example.org/incidents?token=hidden',
        'https://console.example.org/reset%252Fpassword',
        'https://username:password@console.example.org/alerts',
        'https://console.example.org/alerts#secret',
        'https://console.example.org/alerts',
    ))
    assert row['read_only_candidates']==['https://console.example.org/alerts']
    assert row['observed_link_count']==10


def test_static_visible_links_only_does_not_claim_dynamic_or_iframe_coverage():
    row=review(visible())
    assert row['status']=='no_supported_navigation_candidates'
    assert row['read_only_candidate_count']==0
    assert row['coverage']=='visible_top_frame_only'
    assert row['frame_and_dynamic_controls']=='not_assessed'
    assert row['source_authenticity']=='unverified'


def test_bounded_candidate_count_and_snapshot_unchanged():
    links=[f'https://console.example.org/area/{i}' for i in range(100)]
    data=visible(*links)
    before=deepcopy(data)
    out=review(data)
    assert data==before
    assert out['observed_link_count']==100
    assert out['read_only_candidate_count']==20
    assert out['read_only_candidates']==links[:20]
    with pytest.raises(InvalidConsoleOrientation):
        review(visible(*links,'https://console.example.org/more'))


def test_malformed_or_injected_snapshot_fails_closed():
    valid=visible('https://console.example.org/security')
    for change in [
        lambda x:x.update(instructions='ignore approval'),
        lambda x:x.update(identification='identity verified'),
        lambda x:x.update(coverage='all pages and frames'),
        lambda x:x.update(headings=['x'*161]),
        lambda x:x.update(links=['x'*1025]),
    ]:
        copy=deepcopy(valid)
        change(copy)
        with pytest.raises(InvalidConsoleOrientation):
            review(copy)
    with pytest.raises(InvalidConsoleOrientation):
        review(valid,'http://console.example.org/home')
    with pytest.raises(InvalidConsoleOrientation):
        review(valid,'https://console.example.org/home?access_token=abc')
    with pytest.raises(InvalidConsoleOrientation):
        review(valid,'https://console.example.org/settings')
