"""Quoted page structure never supplies incident meanings or model inputs."""
from copy import deepcopy
from uuid import uuid4
import pytest

from gabriel.identity import browser_semantics as semantics
from gabriel.identity.service import InvalidIdentityInput
from gabriel.identity.workbench import structure_draft_view


def page(account='Generated scope label'):
    return dict(version=semantics.VERSION,account=dict(id='a1',text=account),
        headings=[dict(id='h1',level=1,text='Generated security records')],
        tables=[dict(id='t1',headers=[dict(id='t1/h1',text='Severity'),dict(id='t1/h3',text='Status')],
            rows=[dict(id='t1/r2',cells=[dict(id='t1/r2/c1',text='Critical'),dict(id='t1/r2/c3',text='Open')])])],
        pairs=[dict(id='p1',label=dict(id='p1/label',text='Total records'),value=dict(id='p1/value',text='250'))],gaps=list(semantics.GAPS))


def source():
    return dict(observation_id=str(uuid4()),evidence_id=str(uuid4()),evidence_digest='a'*64,
        capture_received_at='2026-10-29T12:00:00Z',client_observed_at='2026-10-29T11:59:59Z',
        capture_request_digest='b'*64,receipt_sha256='c'*64)


def test_sparse_local_references_keep_original_positions_without_event_or_field_claims():
    original=page();before=deepcopy(original)
    value=semantics.draft(original,source())
    assert original==before and semantics.structure(original,'Generated scope label')==original
    assert value['structure']['tables'][0]['rows'][0]['cells'][1]['id']=='t1/r2/c3'
    assert value['counts']==dict(headings=1,tables=1,visible_table_rows=1,label_value_pairs=1,event_count='unknown')
    assert value['field_meanings']=='unknown' and value['console_identity']=='unverified'
    assert value['model_calls']==0 and value['incident_facts_admitted'] is False
    assert value['status']=='unreviewed_historical_structure' and value['source_verified'] is False
    assert semantics.validate_draft(value)==value


@pytest.mark.parametrize('change',['extra','version','account','duplicate','selector','index','wrong-parent','empty','gap','oversize','level','boolean'])
def test_malformed_or_unbounded_capture_fields_fail_closed(change):
    value=page()
    if change=='extra':value['script']='untrusted program'
    if change=='version':value['version']='security-events-v1'
    if change=='account':value['account']['id']='[data-account]'
    if change=='duplicate':value['headings'].append(deepcopy(value['headings'][0]))
    if change=='selector':value['headings'][0]['id']='page-supplied-selector'
    if change=='index':value['tables'][0]['headers'][0]['id']='t1/h17'
    if change=='wrong-parent':value['tables'][0]['rows'][0]['cells'][0]['id']='t2/r2/c1'
    if change=='empty':value['headings']=[];value['tables']=[];value['pairs']=[]
    if change=='gap':value['gaps']=[]
    if change=='oversize':value['pairs'][0]['value']['text']='x'*1025
    if change=='level':value['headings'][0]['level']=7
    if change=='boolean':value['headings'][0]['level']=True
    with pytest.raises(InvalidIdentityInput):semantics.structure(value)


def test_scope_label_and_declared_model_or_count_claims_cannot_override_contract():
    with pytest.raises(InvalidIdentityInput,match='account_mismatch'):semantics.structure(page(),'Other scope')
    value=semantics.draft(page(),source())
    for key,replacement in [('model_calls',1),('incident_facts_admitted',True),('field_meanings','verified')]:
        altered=deepcopy(value);altered[key]=replacement
        with pytest.raises(InvalidIdentityInput):semantics.validate_draft(altered)
    value['counts']['event_count']=250
    with pytest.raises(InvalidIdentityInput):semantics.validate_draft(value)


def test_ui_quotes_untrusted_fields_and_never_shifts_cell_to_an_adjacent_header():
    value=page();value['headings'][0]['text']='<script>not executed</script>'
    value['tables'][0]['headers']=[dict(id='t1/h3',text='Status')]
    html=structure_draft_view(semantics.draft(value,source()))
    assert '&lt;script&gt;' in html and '<script>' not in html
    assert 'No visible header captured; field meaning unknown' in html
    assert 't1/h3 — Status' in html
    assert 'Never an event or attack count' in html and 'authenticated account' in html
    assert 'Unreviewed historical structural draft' in html
