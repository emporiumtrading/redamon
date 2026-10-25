"""Evidence-bound candidate passages from unknown console text; never an incident verdict."""
import re
from uuid import uuid5

from gabriel.identity.evidence_store import canonical
from gabriel.identity.service import AccessDenied,_audit,connection,identifier

VERSION='console-text-candidates-v1'
RULES=(
    ('authentication',r'\b(?:failed (?:login|sign.?in|authentication)|authentication fail(?:ed|ure)|brute.?force|password spray(?:ing)?)\b'),
    ('malware',r'\b(?:malware detected|ransomware detected|ransom note|malicious (?:process|file)|quarantined threat)\b'),
    ('control_tampering',r'\b(?:protection disabled|tamper(?:ing)? detected|audit logging disabled|backup disabled)\b'),
    ('network_alert',r'\b(?:intrusion detected|command.and.control|data exfiltration|suspicious outbound|threat (?:detected|blocked))\b'),
)


def candidate_passages(content):
    findings=[];omitted=0;offset=0
    for line in content.splitlines(keepends=True):
        quote=line.rstrip('\r\n')
        for family,pattern in RULES:
            if not re.search(pattern,quote,re.I):continue
            # Zero/negated counts and documentation examples are not activity assertions.
            if re.search(r'\b(?:no|zero|0|not|example|documentation|tutorial)\b',quote,re.I):continue
            if len(quote)>512 or len(findings)>=16:omitted+=1;continue
            findings.append(dict(family=family,quote=quote,start=offset,end=offset+len(quote),
                assessment='candidate_passage_requires_review'))
        offset+=len(line)
    return dict(version=VERSION,findings=findings,omitted_matches=omitted,coverage='partial',
        source_verified=False,quality_qualified=False,incident_confirmed=False,model_used=False,
        limitation='Literal candidate passages; surrounding context, event semantics and source authenticity require review.')


def process(service,human,peer,context,observation_id):
    observation_id=identifier(observation_id)
    def bound(conn):
        p,lease,_=service._observer(conn,human,peer,context)
        if not lease['scheduled_review_enabled']:raise AccessDenied('scheduled_text_review_consent_required')
        return p,lease
    with connection(service._dsn) as conn:
        p,lease=bound(conn)
        observation=service._observation(conn,p,observation_id)
        if observation['lease_id']!=lease['id'] or observation['state']!='captured':raise AccessDenied('text_review_capture_required')
        artifact=service._captured_artifact(conn,p,observation,lease)
        content=service._verify(conn,artifact).decode('utf-8')
        service._custody(conn,p,artifact,'accessed')
        value=dict(candidate_passages(content),case_id=str(lease['case_id']),observation_id=str(observation_id),
            evidence_id=str(artifact['id']),evidence_digest=artifact['digest'])
        for row in value['findings']:
            if content[row['start']:row['end']]!=row['quote']:raise AccessDenied('text_review_source_mismatch')
        case_id=lease['case_id'];parent_id=artifact['id']
    with connection(service._dsn) as conn:bound(conn)
    holder=service.acquire(human,case_id,uuid5(observation_id,VERSION),canonical(value).decode(),
        'Browser text candidate passages - unqualified',approved=True,parent_id=parent_id,redaction_state='user_declared_redacted')
    with connection(service._dsn) as conn:
        p,_=bound(conn)
        _audit(conn,'browser.text_candidates_reviewed',p,observation_id)
    return dict(review_evidence_id=str(holder['id']),candidate_count=len(value['findings']),
        families=sorted({row['family'] for row in value['findings']}),omitted_matches=value['omitted_matches'],
        source_verified=False,quality_qualified=False,incident_confirmed=False,model_cost_usd='0')
