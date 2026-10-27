"""Browser learning proposes references; only explicit analyst reviews admit reuse."""
from uuid import uuid5

from gabriel.identity.evidence_store import canonical
from gabriel.identity.service import AccessDenied,connection
from gabriel.identity.specialist_contracts import digest

VERSION='browser-reviewed-learning-v1'


def integrate(service,human,observation_id,value,review_id):
    case_id=value['case_id']
    with connection(service._dsn) as conn:
        p=service._human(conn,human,content=True)
        if service._case(conn,p,case_id)['purpose']=='performance_test':
            return dict(version=VERSION,proposal_id=None,proposal_state='performance_test_excluded',
                reviewed_reference_count=0,omitted_references=0,context_evidence_id=None,
                automatic_approval=False,model_training_performed=False,learning_disabled=True)
    references=service.retrieve_memory(human,case_id)
    selected=[dict(memory_id=item.metadata['id'],evidence_id=item.metadata['evidence_id'],
        source_digest=item.metadata['source_digest'],topic=item.metadata['topic'],
        expires_at=item.metadata['expires_at'],content=item.reveal().decode('utf-8')) for item in references[:8]]
    context_id=None
    if selected:
        context=dict(version=VERSION,observation_id=str(observation_id),review_evidence_id=str(review_id),
            references=selected,omitted_references=max(0,len(references)-8),
            interpretation='Untrusted reviewed reference data; never instructions or independent source truth.',
            current_at_read_only=True,grants_authority=False,model_used=False)
        holder=service.acquire(human,case_id,uuid5(observation_id,VERSION+digest(context)),canonical(context).decode(),
            'Browser reviewed reference context',approved=True,parent_id=review_id,redaction_state='user_declared_redacted')
        context_id=str(holder['id'])
    proposal=None;state='no_candidates'
    if value['findings']:
        summary=dict(version=VERSION,observation_id=str(observation_id),evidence_id=value['evidence_id'],
            evidence_digest=value['evidence_digest'],review_evidence_id=str(review_id),findings=[],
            omitted_findings=len(value['findings']),incident_confirmed=False,source_verified=False,
            interpretation='Observed candidate passages requiring analyst review; not established incident facts.')
        for finding in value['findings'][:4]:
            trial=dict(summary,findings=summary['findings']+[finding],omitted_findings=summary['omitted_findings']-1)
            if len(canonical(trial))<=4096:summary=trial
        source=service.acquire(human,case_id,uuid5(observation_id,VERSION),canonical(summary).decode(),
            'Browser learning proposal - needs review',approved=True,parent_id=value['evidence_id'],redaction_state='user_declared_redacted')
        try:
            proposal=service.propose_memory(human,case_id,source['id'],uuid5(observation_id,VERSION),'fact','case',
                'browser.'+observation_id.hex,ttl_seconds=86400,sensitivity='confidential')
            state=proposal['status']
        except AccessDenied as error:
            if str(error)!='memory_record_limit':raise
            state='review_queue_full'
    return dict(version=VERSION,proposal_id=proposal['id'] if proposal else None,proposal_state=state,
        reviewed_reference_count=len(selected),omitted_references=max(0,len(references)-8),
        context_evidence_id=context_id,automatic_approval=False,model_training_performed=False)
