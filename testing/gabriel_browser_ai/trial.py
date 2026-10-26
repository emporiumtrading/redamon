"""Export authored synthetic request bodies offline; never grants model admission."""
from datetime import datetime,timezone
from hashlib import sha256
import json
from uuid import NAMESPACE_DNS,uuid5

from gabriel.identity.browser_ai import VERSION,PROMPT,configuration,project
from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_evaluation import digest

MODEL='openai/gpt-oss-120b'
SAMPLES=(
    ('candidate-auth','Failed login for GENERATED_USER\nFailed login for GENERATED_USER'),
    ('candidate-malware','Malware detected on GENERATED_ASSET'),
    ('candidate-controls','Audit logging disabled on GENERATED_ASSET'),
    ('candidate-network','Suspicious outbound traffic from GENERATED_ASSET'),
    ('candidate-mixed','Failed login for GENERATED_USER\nIntrusion detected on GENERATED_ASSET'),
)


def export():
    config=configuration(MODEL);requests=[]
    for name,content in SAMPLES:
        observation_id=uuid5(NAMESPACE_DNS,'gabriel-synthetic-'+name)
        artifact=dict(id=uuid5(observation_id,'source'),digest=sha256(content.encode()).hexdigest())
        prepared=project(content,observation_id,artifact,datetime(2026,10,25,12,tzinfo=timezone.utc))
        body=dict(model=MODEL,messages=[dict(role='system',content=PROMPT),
            dict(role='user',content=canonical(prepared['packet']).decode())],**config['parameters'])
        wire=canonical(body)
        assert len(wire)<=7000 and prepared['packet']['signals']
        assert all(private.encode() not in wire for private in ('GENERATED_USER','GENERATED_ASSET',content,str(artifact['id'])))
        requests.append(dict(case_id=name,body=body,body_sha256=sha256(wire).hexdigest(),
            source_classification='authored_synthetic_candidate_reports',independent_adjudication='pending'))
    no_signals=project('No failed login events visible',uuid5(NAMESPACE_DNS,'gabriel-negative'),
        dict(id=uuid5(NAMESPACE_DNS,'gabriel-negative-source'),digest='0'*64),datetime(2026,10,25,12,tzinfo=timezone.utc))
    assert no_signals['packet']['signals']==[]
    return dict(version='gabriel-browser-ai-trial-packet-v1',projection_version=VERSION,model=MODEL,
        configuration=config,configuration_digest=digest(config),requests=requests,request_count=len(requests),
        request_set_sha256=digest(requests),provider='OpenRouter / Cerebras',
        destination='https://openrouter.ai/api/v1/chat/completions',
        max_new_reservation_usd='0.031520',per_request_reservation_usd='0.006304',
        local_negative_control='abstain_without_provider_request',
        live_calls_made=0,quality_qualified=False,held_out=False,production_admission=False,
        evaluation_status='prepared_for_owner_payload_destination_and_spending_review')


if __name__=='__main__':
    print(json.dumps(export(),sort_keys=True,indent=2))
