"""Generated lab evidence to all twelve existing local rule kernels; no model or action dispatch."""
from hashlib import sha256
from datetime import datetime, timezone
import html
import json
import re
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from gabriel.identity.specialist_analysis import analyze, validate_document
from gabriel.identity.attack_patterns import investigate
from gabriel.identity.browser_specialists import project
from gabriel.identity.specialist_contracts import ROLES


def main():
    root=Path('/output')
    raw=(root/'browser.json').read_bytes();browser=json.loads(raw)
    reconciliation=json.loads((root/'native-reconciliation.json').read_text())
    assert reconciliation['status']=='PASS' and reconciliation['native_event_identity_verified']
    assert reconciliation['browser_sha256']==sha256(raw).hexdigest()
    check=browser['replay_event_query'];events=check['native_details']
    assert reconciliation['observed_event_count']==12 and reconciliation['emitted_record_coverage_verified']
    assert set(reconciliation['event_ids'])=={event['event_id'] for event in events}
    assert browser['status']=='PASS' and check['empty_control_verified'] and check['marker_filtered_rows_rendered']
    def uid(key): return str(uuid5(NAMESPACE_URL,check['marker']+'/'+key))
    eid=uid('browser-evidence');digest=sha256(raw).hexdigest();typed=[]
    for event in events:
        actor=re.search(r'Failed password for invalid user (gabriel-lab-[a-f0-9]{12}) from ',event['full_log'])
        assert actor and actor[1]==check['marker'] and event['rule_id'] in {'5710','5712'}
        when=datetime.fromisoformat(event['event_time']).astimezone(timezone.utc).isoformat().replace('+00:00','Z')
        typed.append(dict(source_id=uid('manager'),event_id=event['event_id'],evidence_id=eid,evidence_digest=digest,
            event_time=when,kind='auth_failure',actor_id=uid('actor/'+actor[1]),asset_id=uid('agent/'+event['agent_id']),
            source_asset_id=uid('source/'+event['data']['srcip']),process_sha256=None,object_id=None,authorization='unknown'))
    when=max(row['event_time'] for row in typed)
    security=dict(version='security-events-v1',case_id=uid('case'),as_of=when,
        missing_sources=['process','network','file','kernel','boot'],events=typed)
    attack=investigate(security,security['case_id'])
    assert len(typed)==12 and attack['unique_event_count']==12
    assert [r['family'] for r in attack['findings']]==['brute_force']
    assert attack['findings'][0]['observed_event_count']==12
    # Duplicating a captured record must never supply the tenth distinct event.
    negative=dict(security,events=typed[:9]+[typed[0]]*3)
    assert not investigate(negative,security['case_id'])['findings']
    document,_=project(security,uid('observation'))
    validate_document(document,document['case_id'])
    results={role:analyze(role,document,'evidence/'+eid) for role in ROLES}
    assert len(results)==12 and all(r['confidence']=='unqualified' and not r['external_actions_authorized'] for r in results.values())
    report=dict(version='generated-console-specialist-demo-v1',production_ready=False,model_enabled=False,
        source_browser_sha256=digest,observed_event_count=12,synthetic_replay=True,attack_review=attack,security_events=security,
        duplicate_inflation_control_verified=True,
        database_persisted=False,gabriel_scoped_browser_capture=False,native_event_reconciled=True,
        normalizer_scope='generated replay format only; actor reported by log text',facts=document,specialists=results)
    (root/'specialist-demo.json').write_text(json.dumps(report,sort_keys=True)+'\n')
    def label(value): return html.escape(value.replace('_',' ').capitalize())
    rows=''.join('<tr><td>'+html.escape(role.replace('_',' ').title())+'</td><td>'+label(r['incident_assessment'])+'</td><td>'+label(r['urgency'])+'</td></tr>' for role,r in results.items())
    page='<!doctype html><meta charset="utf-8"><title>Gabriel verified lab demonstration</title><style>body{font:18px system-ui;max-width:1100px;margin:48px auto;padding:24px;background:#111827;color:#e5e7eb}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px;border-bottom:1px solid #374151}aside{padding:20px;background:#273449;border-radius:12px}h1{color:#67e8f9}</style><h1>Gabriel: defensive investigation lab</h1><p>Real Wazuh browser event → typed evidence → twelve local specialist reviews.</p><aside>Engineering demonstration. Synthetic SSH log replay. Local rules; AI models are disabled and quality remains unqualified. Twelve observed authentication failures; other telemetry remains incomplete. No autonomous response or production-readiness claim.</aside><h2>Specialist results</h2><table><tr><th>Specialist</th><th>Assessment</th><th>Urgency</th></tr>'+rows+'</table><p>Security effectiveness: unassessed. Compliance coverage: unassessed.</p><p>Browser evidence SHA-256: <code>'+digest+'</code></p><p>These results are generated in an isolated test container. Database persistence and Gabriel’s scoped browser integration remain separate acceptance gates.</p>'
    page+='<h2>Observed event</h2><p>Native event IDs: <code>'+html.escape(', '.join(row['event_id'] for row in events))+'</code>. Rule: '+html.escape(', '.join(sorted({row['rule_id'] for row in events})))+'. Source time: '+html.escape(when)+'.</p><p>The browser-visible event exactly matched the generated Wazuh manager alert projection. All twelve synthetic authentication failures were normalized. The existing local rule flagged a repeated-failure candidate for analyst review, with benign alternatives retained. This does not establish a live brute-force attack, compromise, attacker absence, or source authenticity.</p><h2>Specialist findings and follow-up</h2>'
    for role,result in results.items():
        page+='<details><summary>'+html.escape(role.replace('_',' ').title())+' — '+label(result['incident_assessment'])+'</summary><h3>Reported observations</h3><ul>'
        page+=''.join('<li>'+html.escape(item['statement'])+'</li>' for item in result['observations'])+'</ul><h3>Suggested review steps</h3><ul>'
        page+=''.join('<li>'+label(item)+'</li>' for item in result['next_steps'])+'</ul><p>Attack status: unknown. Confidence: unqualified. These suggestions do not authorize external actions.</p></details>'
    page+='<h2>Repeated-failure candidate</h2><p>Twelve distinct native events matched the local threshold of ten failures within five minutes. Status: suspected, requires review. '+html.escape(attack['findings'][0]['alternative'])+'</p><p>A separate nine-event control with duplicate copies remained below threshold.</p>'
    page+='<h2>Presentation walkthrough</h2><ol><li>Explain the generated SSH log replay in a real Wazuh container.</li><li>Show the positive event search and the separate empty-search control.</li><li>Show how the native event becomes source-linked typed facts.</li><li>Expand a specialist review and an abstention; explain the missing evidence.</li><li>Use the persistence section only when it reports a successful database restart check.</li></ol><h2>Remaining release gates</h2><p>Qualified AI models and customer-key inference; scoped production browser adapters; labeled attack effectiveness and compliance acceptance; operational release hardening and user acceptance remain open.</p>'
    (root/'presentation.html').write_text(page)
    print('PASS: generated browser evidence reviewed by twelve local specialist kernels; production and AI qualification remain open')


if __name__=='__main__': main()
