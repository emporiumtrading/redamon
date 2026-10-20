"""Local typed telemetry projection; never a free-text redactor or egress grant.

Only a future authorized adapter may normalize source evidence into this schema.
The returned manifest contains private identifiers and must stay local. The wire
packet contains case-scoped pseudonyms, exact typed facts and opaque references.
"""
from datetime import datetime, timezone
from hashlib import sha256
import hmac
import ipaddress
import re
from uuid import UUID

from gabriel.identity.model_evaluation import canonical, digest

VERSION='typed-telemetry-minimization-v1'
KINDS={'authentication','process','network','file','alert','visibility'}
OUTCOMES={'success','failure','blocked','unknown','observed','missing'}
HEX=re.compile(r'[a-f0-9]{64}\Z')
FIELDS={'record_id','evidence_id','evidence_digest','event_time','kind','outcome',
        'actor','asset','address','count'}
LIMITS={'authentication':{'success','failure','blocked','unknown'},
        'process':{'observed','blocked','unknown'},'network':{'observed','blocked','unknown'},
        'file':{'observed','blocked','unknown'},'alert':{'observed','unknown'},
        'visibility':{'missing','unknown'}}


class ModelInputError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise ModelInputError(code)


def uid(value):
    try:
        require(type(value) is str and str(UUID(value))==value,'invalid_local_identifier')
    except (ValueError,AttributeError):
        raise ModelInputError('invalid_local_identifier') from None
    return value


def opaque(value):
    require(type(value) is str and 1<=len(value)<=512
            and all(32<=ord(c)!=127 for c in value),'invalid_identity_value')
    try:
        value.encode('utf-8')
    except UnicodeError:
        raise ModelInputError('invalid_identity_value') from None
    # Case and whitespace are significant; normalization could merge identities.
    return value


def event_time(value):
    require(type(value) is str and re.fullmatch(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z',value) is not None,
        'invalid_event_time')
    try:
        parsed=datetime.fromisoformat(value[:-1]+'+00:00')
    except ValueError:
        raise ModelInputError('invalid_event_time') from None
    return parsed.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')


def prepare(records, *, organization_id, case_id, pseudonym_key, max_wire_bytes=12000):
    """Project already-normalized rows without silently truncating observations.

    The byte cap is not a tokenizer estimate. A provider-specific token admission
    step is still required. This pure builder does not check current DB authority.
    """
    organization_id,case_id=uid(organization_id),uid(case_id)
    require(type(pseudonym_key) is bytes and len(pseudonym_key)==32,'case_pseudonym_key_required')
    require(type(max_wire_bytes) is int and 1024<=max_wire_bytes<=32768,'invalid_wire_limit')
    require(type(records) is list and 1<=len(records)<=64,'invalid_record_count')
    require(len(canonical(records))<=131072,'source_input_limit')
    scope=hmac.digest(pseudonym_key,canonical([VERSION,organization_id,case_id]),'sha256')
    identities={}

    def alias(kind, value):
        if value is None:
            return None
        value=opaque(value)
        tag=kind+'-'+hmac.new(scope,canonical([kind,value]),sha256).hexdigest()
        require(tag not in identities or identities[tag]==(kind,value),'pseudonym_collision')
        identities[tag]=(kind,value)
        return tag

    for row in records:
        require(type(row) is dict and set(row)==FIELDS,'unsupported_telemetry_fields')
        uid(row['record_id'])
    ordered=sorted(records,key=lambda row:row['record_id'])
    seen=set()
    grouped={}
    lineage={}
    for index,row in enumerate(ordered,1):
        require(type(row) is dict and set(row)==FIELDS,'unsupported_telemetry_fields')
        rid,eid=uid(row['record_id']),uid(row['evidence_id'])
        require(rid not in seen,'duplicate_local_record')
        seen.add(rid)
        require(type(row['evidence_digest']) is str and HEX.fullmatch(row['evidence_digest']) is not None,
                'invalid_evidence_digest')
        require(type(row['kind']) is str and row['kind'] in KINDS,'unsupported_event_kind')
        require(type(row['outcome']) is str and row['outcome'] in LIMITS[row['kind']],
                'unsupported_event_outcome')
        require(type(row['count']) is int and 1<=row['count']<=1000000,'invalid_event_count')
        address=row['address']
        if address is not None:
            try:
                require(type(address) is str and '%' not in address,'invalid_address')
                address=ipaddress.ip_address(address).compressed
            except ValueError:
                raise ModelInputError('invalid_address') from None
        event=dict(event_time=event_time(row['event_time']),kind=row['kind'],outcome=row['outcome'],
                   actor=alias('actor',row['actor']),asset=alias('asset',row['asset']),
                   address=alias('address',address),count=row['count'])
        ref='o'+str(index)
        signature=digest(event)
        if signature not in grouped:
            grouped[signature]=dict(event,references=[])
        grouped[signature]['references'].append(ref)
        lineage[ref]=dict(record_id=rid,evidence_id=eid,evidence_digest=row['evidence_digest'])
    events=[grouped[key] for key in sorted(grouped)]
    packet=dict(version=VERSION,events=events,source_count=len(records),event_count=len(events),
        scope='partial_observations_only',source_authenticity='unverified',
        independent_corroboration='not_established',actions_authorized=False,
        gaps=['unstructured_context_excluded','adapter_semantics_unverified',
              'source_visibility_not_established','pseudonymization_is_not_anonymity'])
    wire=canonical(packet)
    require(len(wire)<=max_wire_bytes,'wire_limit_requires_narrower_scope')
    manifest=dict(version=VERSION,organization_id=organization_id,case_id=case_id,
        source_digest=digest(records),wire_digest=sha256(wire).hexdigest(),lineage=lineage,
        identity_map={key:dict(kind=value[0],value=value[1]) for key,value in identities.items()},
        original_bytes=len(canonical(records)),wire_bytes=len(wire),
        egress_admitted=False,authority_checked=False,quality_qualified=False)
    manifest['binding_mac']=hmac.new(scope,canonical(manifest),sha256).hexdigest()
    return dict(packet=packet,local_manifest=manifest)


def resolve_references(prepared, references, *, organization_id, case_id, pseudonym_key):
    """Translate wire aliases locally only after caller rechecks current access."""
    require(type(prepared) is dict and set(prepared)=={'packet','local_manifest'},'invalid_prepared_input')
    manifest=prepared['local_manifest']
    organization_id,case_id=uid(organization_id),uid(case_id)
    require(type(pseudonym_key) is bytes and len(pseudonym_key)==32,'case_pseudonym_key_required')
    require(type(manifest) is dict and manifest.get('organization_id')==organization_id
            and manifest.get('case_id')==case_id,'manifest_scope_mismatch')
    scope=hmac.digest(pseudonym_key,canonical([VERSION,organization_id,case_id]),'sha256')
    unsigned={key:value for key,value in manifest.items() if key!='binding_mac'}
    require(type(manifest.get('binding_mac')) is str and hmac.compare_digest(
        manifest['binding_mac'],hmac.new(scope,canonical(unsigned),sha256).hexdigest()),'manifest_binding_mismatch')
    require(type(manifest) is dict and manifest.get('wire_digest')==digest(prepared['packet']),
            'wire_binding_mismatch')
    require(type(references) is list and 1<=len(references)<=64
            and all(type(ref) is str for ref in references)
            and len(set(references))==len(references),'invalid_model_references')
    lineage=manifest.get('lineage')
    require(type(lineage) is dict and all(ref in lineage for ref in references),'unknown_model_reference')
    return [dict(lineage[ref]) for ref in references]
