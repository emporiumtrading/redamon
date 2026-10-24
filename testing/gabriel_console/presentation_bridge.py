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
    def label(value): return html.escape(value.replace('_',' ').capitalize())
    rows=''.join('<tr><td>'+html.escape(role.replace('_',' ').title())+'</td><td>'+label(r['incident_assessment'])+'</td><td>'+label(r['urgency'])+'</td></tr>' for role,r in results.items())
    page='<!doctype html><meta charset="utf-8"><title>Gabriel verified lab demonstration</title><style>body{font:18px system-ui;max-width:1100px;margin:48px auto;padding:24px;background:#111827;color:#e5e7eb}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px;border-bottom:1px solid #374151}aside{padding:20px;background:#273449;border-radius:12px}h1{color:#67e8f9}</style><h1>Gabriel: defensive investigation lab</h1><p>Real Wazuh browser event → typed evidence → twelve local specialist reviews.</p><aside>Engineering demonstration. Synthetic SSH log replay. Local rules; AI models are disabled and quality remains unqualified. One observed event; incomplete telemetry. No autonomous response or production-readiness claim.</aside><h2>Specialist results</h2><table><tr><th>Specialist</th><th>Assessment</th><th>Urgency</th></tr>'+rows+'</table><p>Security effectiveness: unassessed. Compliance coverage: unassessed.</p><p>Browser evidence SHA-256: <code>'+digest+'</code></p><p>These results are generated in an isolated test container. Database persistence and Gabriel’s scoped browser integration remain separate acceptance gates.</p>'
    page+='<h2>Observed event</h2><p>Native event ID: <code>'+html.escape(event['event_id'])+'</code>. Rule: '+html.escape(event['rule_id'])+'. Source time: '+html.escape(when)+'.</p><p>One browser-visible synthetic authentication failure was normalized. This does not establish a brute-force attack, compromise, or attacker absence. Exact server-side event identity reconciliation remains open.</p><h2>Specialist findings and follow-up</h2>'
    for role,result in results.items():
        page+='<details><summary>'+html.escape(role.replace('_',' ').title())+' — '+label(result['incident_assessment'])+'</summary><h3>Reported observations</h3><ul>'
        page+=''.join('<li>'+html.escape(item['statement'])+'</li>' for item in result['observations'])+'</ul><h3>Suggested review steps</h3><ul>'
        page+=''.join('<li>'+label(item)+'</li>' for item in result['next_steps'])+'</ul><p>Attack status: unknown. Confidence: unqualified. These suggestions do not authorize external actions.</p></details>'
    page+='<h2>Presentation walkthrough</h2><ol><li>Explain the generated SSH log replay in a real Wazuh container.</li><li>Show the positive event search and the separate empty-search control.</li><li>Show how the native event becomes source-linked typed facts.</li><li>Expand a specialist review and an abstention; explain the missing evidence.</li><li>Use the persistence section only when it reports a successful database restart check.</li></ol><h2>Remaining release gates</h2><p>Qualified AI models and customer-key inference; scoped production browser adapters; labeled attack effectiveness and compliance acceptance; operational release hardening and user acceptance remain open.</p>'
    (root/'presentation.html').write_text(page)
    print('PASS: generated browser evidence reviewed by twelve local specialist kernels; production and AI qualification remain open')


if __name__=='__main__': main()
