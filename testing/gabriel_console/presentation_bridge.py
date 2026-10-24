"""Generated lab evidence to all twelve existing local rule kernels; no model or action dispatch."""
from hashlib import sha256
from datetime import datetime, timezone
import html
import json
import re
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from gabriel.identity.specialist_analysis import analyze, validate_document
from gabriel.identity.specialist_contracts import ROLES


def main():
    root=Path('/output')
    raw=(root/'browser.json').read_bytes();browser=json.loads(raw)
    check=browser['replay_event_query'];event=check['native_detail']
    assert browser['status']=='PASS' and check['empty_control_verified'] and check['marker_filtered_rows_rendered']
    assert check['marker'] in event['full_log'] and event['rule_id']=='5710'
    def uid(key): return str(uuid5(NAMESPACE_URL,check['marker']+'/'+key))
    actor=re.search(r'Failed password for invalid user (gabriel-lab-[a-f0-9]{12}) from ',event['full_log'])
    assert actor and actor[1]==check['marker']
    eid=uid('browser-evidence');digest=sha256(raw).hexdigest()
    when=datetime.fromisoformat(event['event_time']).astimezone(timezone.utc).isoformat().replace('+00:00','Z')
    def fact(kind,entity,data):
        return dict(id=uid(kind),type=kind,evidence_id=eid,evidence_digest=digest,
            entity_id=entity,event_time=when,data=data)
    document=dict(version='specialist-facts-v1',case_id=uid('case'),as_of=when,facts=[
        fact('activity',uid('agent/'+event['agent_id']),dict(category='authentication',outcome='failure',count=1)),
        fact('identity',uid('actor/'+actor[1]),dict(event='login_failure',authorized='unknown')),
        fact('coverage',None,dict(state='missing')),
        fact('artifact',None,dict(integrity='unknown',custody='unknown'))])
    validate_document(document,document['case_id'])
    results={role:analyze(role,document,'evidence/'+eid) for role in ROLES}
    assert len(results)==12 and all(r['confidence']=='unqualified' and not r['external_actions_authorized'] for r in results.values())
    report=dict(version='generated-console-specialist-demo-v1',production_ready=False,model_enabled=False,
        source_browser_sha256=digest,observed_event_count=1,synthetic_replay=True,
        database_persisted=False,gabriel_scoped_browser_capture=False,
        normalizer_scope='generated replay format only; actor reported by log text',facts=document,specialists=results)
    (root/'specialist-demo.json').write_text(json.dumps(report,sort_keys=True)+'\n')
    rows=''.join('<tr><td>'+html.escape(role.replace('_',' ').title())+'</td><td>'+html.escape(r['incident_assessment'])+'</td><td>'+html.escape(r['urgency'])+'</td></tr>' for role,r in results.items())
    page='<!doctype html><meta charset="utf-8"><title>Gabriel verified lab demonstration</title><style>body{font:18px system-ui;max-width:1100px;margin:48px auto;padding:24px;background:#111827;color:#e5e7eb}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px;border-bottom:1px solid #374151}aside{padding:20px;background:#273449;border-radius:12px}h1{color:#67e8f9}</style><h1>Gabriel: defensive investigation lab</h1><p>Real Wazuh browser event → typed evidence → twelve local specialist reviews.</p><aside>Engineering demonstration. Synthetic SSH log replay. Local rules; AI models are disabled and quality remains unqualified. One observed event; incomplete telemetry. No autonomous response or production-readiness claim.</aside><h2>Specialist results</h2><table><tr><th>Specialist</th><th>Assessment</th><th>Urgency</th></tr>'+rows+'</table><p>Security effectiveness: unassessed. Compliance coverage: unassessed.</p><p>Browser evidence SHA-256: <code>'+digest+'</code></p><p>These results are generated in an isolated test container. Database persistence and Gabriel’s scoped browser integration remain separate acceptance gates.</p>'
    (root/'presentation.html').write_text(page)
    print('PASS: generated browser evidence reviewed by twelve local specialist kernels; production and AI qualification remain open')


if __name__=='__main__': main()
