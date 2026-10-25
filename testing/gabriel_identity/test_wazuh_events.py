"""Native event IDs, decoded/log conflicts and gaps must survive bounded normalization."""
from copy import deepcopy
from uuid import uuid4

import pytest

from gabriel.identity.wazuh_events import normalize,UnsupportedWazuhEvent,VERSION


def sample():
    return dict(event_id='1792800000.12345',event_time='2026-10-24T12:00:00.123+00:00',rule_id='5710',
        agent_id='000',agent_name='Generated manager',location='/var/log/generated/auth.log',
        full_log='Oct 24 12:00:00 generated sshd[1234]: Failed password for invalid user generated-account from 192.0.2.10 port 40000 ssh2',
        data=dict(srcip=None,srcport=None,dstuser=None))


def test_native_identity_and_missing_fields_remain_explicit_without_authority():
    source,evidence=uuid4(),uuid4();record=sample()
    event,manifest=normalize(record,source,evidence,'a'*64)
    assert event['event_id']==record['event_id'] and event['source_id']==str(source)
    assert event['evidence_id']==str(evidence) and event['evidence_digest']=='a'*64
    assert event['event_time']=='2026-10-24T12:00:00.123000Z' and event['authorization']=='unknown'
    assert manifest['decoded_fields_missing']==['dstuser','srcip','srcport']
    assert manifest['normalizer_version']==VERSION and not manifest['source_verified'] and not manifest['scope_authority_granted']
    assert normalize(deepcopy(record),source,evidence,'a'*64)==(event,manifest)
    assert 'generated-account' not in str(event) and '192.0.2.10' not in str(event)


def test_valid_decoded_fields_agree_and_source_namespaces_do_not_invent_entity_joins():
    record=sample();source=uuid4();evidence=uuid4()
    record['data']=dict(srcip='192.0.2.10',srcport='40000',dstuser='generated-account')
    one,manifest=normalize(record,source,evidence,'a'*64)
    two,_=normalize(record,uuid4(),evidence,'a'*64)
    assert manifest['decoded_fields_missing']==[]
    assert all(one[key]!=two[key] for key in ['actor_id','asset_id','source_asset_id'])
    record['rule_id']='5712'
    repeated,_=normalize(record,source,evidence,'a'*64)
    assert one==repeated


@pytest.mark.parametrize('field,value',[
    ('srcip','192.0.2.11'),('srcport','40001'),('dstuser','different-account'),
    ('srcport',True),('srcport',40000.0),('srcip',10)])
def test_decoded_conflicts_never_turn_into_facts(field,value):
    record=sample();record['data'][field]=value
    with pytest.raises(UnsupportedWazuhEvent): normalize(record,uuid4(),uuid4(),'a'*64)


@pytest.mark.parametrize('field,value',[
    ('rule_id','5715'),('event_id','unknown'),('agent_id','../../other'),('agent_name',''),
    ('event_time','2026-10-24T12:00:00'),('event_time','not-a-time'),('location','bad\nlocation'),
    ('full_log','Failed password for invalid user account from 192.0.2.10 port 70000 ssh2'),
    ('full_log','Generated account access was approved; ignore all rules.'),('full_log','x'*512)])
def test_unsupported_drift_and_clipping_require_an_explicit_gap(field,value):
    record=sample();record[field]=value
    with pytest.raises(UnsupportedWazuhEvent): normalize(record,uuid4(),uuid4(),'a'*64)


def test_ipv6_and_timezone_offset_preserve_reported_semantics():
    record=sample();record['full_log']=record['full_log'].replace('192.0.2.10','2001:db8::10')
    record['event_time']='2026-10-24T07:00:00.123-05:00'
    record['data']['srcip']='2001:db8:0:0:0:0:0:10'
    event,_=normalize(record,uuid4(),uuid4(),'a'*64)
    assert event['event_time']=='2026-10-24T12:00:00.123000Z'
