"""Bounded native SSH-failure semantics; parsing never authenticates a source or grants scope."""
from datetime import datetime,timezone
import ipaddress
import re
from uuid import UUID,uuid5

VERSION='wazuh-4.14.9-ssh-invalid-user-v1'
FIELDS={'event_id','event_time','rule_id','agent_id','agent_name','full_log','location','data'}
LOG=re.compile(r'(?:^| )sshd\[[0-9]{1,10}\]: Failed password for invalid user ([^\s\x00-\x1f\x7f]{1,128}) from ([^\s]{1,64}) port ([0-9]{1,5}) ssh2$')


class UnsupportedWazuhEvent(ValueError):
    pass


def require(condition):
    if not condition: raise UnsupportedWazuhEvent('unsupported_or_conflicting_wazuh_event')


def normalize(record,source_id,evidence_id,evidence_digest):
    try:
        source=UUID(str(source_id));evidence=UUID(str(evidence_id))
        require(type(evidence_digest) is str and re.fullmatch('[a-f0-9]{64}',evidence_digest) is not None)
        require(type(record) is dict and set(record)==FIELDS and record['rule_id'] in {'5710','5712'})
        require(type(record['event_id']) is str and re.fullmatch(r'[0-9]{1,30}\.[0-9]{1,30}',record['event_id']) is not None)
        require(type(record['agent_id']) is str and re.fullmatch('[0-9]{3,8}',record['agent_id']) is not None)
        for name,maximum in [('agent_name',256),('location',512),('event_time',64)]:
            value=record[name]
            require(type(value) is str and 0<len(value)<=maximum and all(ord(c)>=32 and ord(c)!=127 for c in value))
        log=record['full_log']
        # A projection at its clipping boundary cannot establish complete log semantics.
        require(type(log) is str and 0<len(log)<512 and all(ord(c)>=32 and ord(c)!=127 for c in log))
        match=LOG.search(log);require(match is not None)
        actor,address,port=match.groups();address=str(ipaddress.ip_address(address));port=int(port)
        require(1<=port<=65535)
        decoded=record['data'];require(type(decoded) is dict and set(decoded)=={'srcip','srcport','dstuser'})
        if decoded['srcip'] is not None: require(type(decoded['srcip']) is str and str(ipaddress.ip_address(decoded['srcip']))==address)
        if decoded['srcport'] is not None:
            require(type(decoded['srcport']) in {str,int} and str(decoded['srcport'])==str(port))
        if decoded['dstuser'] is not None: require(type(decoded['dstuser']) is str and decoded['dstuser']==actor)
        when=datetime.fromisoformat(record['event_time'])
        require(when.tzinfo is not None and when.utcoffset() is not None)
        stamp=when.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
        event=dict(source_id=str(source),event_id=record['event_id'],evidence_id=str(evidence),evidence_digest=evidence_digest,
            event_time=stamp,kind='auth_failure',actor_id=str(uuid5(source,'actor/'+actor)),
            asset_id=str(uuid5(source,'agent/'+record['agent_id'])),source_asset_id=str(uuid5(source,'origin/'+address)),
            process_sha256=None,object_id=None,authorization='unknown')
        manifest=dict(normalizer_version=VERSION,native_rule_id=record['rule_id'],
            decoded_fields_missing=sorted(key for key,value in decoded.items() if value is None),
            entity_semantics='reported invalid-user identity and source address; no cross-source identity join',
            source_verified=False,scope_authority_granted=False)
        return event,manifest
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
        raise UnsupportedWazuhEvent('unsupported_or_conflicting_wazuh_event') from None
