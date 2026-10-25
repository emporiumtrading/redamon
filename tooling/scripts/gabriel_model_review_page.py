"""Create a local review worksheet; no reviewer verdict or model qualification is supplied."""
import argparse
from hashlib import sha256
import json
from pathlib import Path


def digest(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()


def render(packet):
    partition=packet.get('partition','development')
    expected={'development':24,'validation':10}.get(partition)
    if (expected is None or packet['purpose']!='pending-human-review-not-qualification' or packet['quality_qualified'] is not False
            or packet['production_admission'] is not False or len(packet['entries'])!=expected):
        raise ValueError('pending_authored_packet_required')
    seen=set()
    for entry in packet['entries']:
        run=entry['run'];source=entry['input']
        key=(entry['model'],run['case_id'])
        if (key in seen or digest(run)!=entry['run_sha256'] or digest(entry['configuration'])!=run['configuration_sha256']
                or digest({key:source[key] for key in ('question','observations')})!=run['input_sha256']
                or source['input_sha256']!=run['input_sha256'] or source['case_id']!=run['case_id']
                or run['origin']!='live_provider' or entry['review_status']!='pending'
                or any(value is not None for value in entry['adjudication'].values())):
            raise ValueError('review_packet_integrity_failed')
        seen.add(key)
    data=json.dumps(packet,ensure_ascii=False).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    return PAGE.replace('ANSWER_COUNT',str(expected)).replace('PARTITION_LABEL',partition).replace('PACKET_DIGEST',digest(packet)).replace('PACKET_DATA',data)


PAGE='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'">
<title>Gabriel model review worksheet</title><style>
body{font:16px system-ui;line-height:1.5;background:#101827;color:#e7edf6;max-width:1050px;margin:auto;padding:28px}
h1,h2{color:#7dd3fc}aside,article{padding:20px;background:#1e293b;border-radius:10px;margin:20px 0}
label{display:block;margin:12px 0}input,textarea,select,button{font:inherit;padding:9px;border:1px solid #94a3b8;border-radius:5px;max-width:100%;box-sizing:border-box}
textarea{width:100%;min-height:90px}button{cursor:pointer;background:#bae6fd;color:#102031}button:disabled{opacity:.45;cursor:default}
pre,code{white-space:pre-wrap;overflow-wrap:anywhere}summary{cursor:pointer;font-weight:bold}li{margin:9px 0}.status{color:#fcd34d}
</style><h1>Gabriel: model answer review</h1><aside>
<strong>ANSWER_COUNT authored PARTITION_LABEL answers. No model is qualified.</strong><p>Compare each claim with its cited observations, then assess the reasoning and decision. Reject unsupported claims. These are authored examples, not an independently sealed acceptance set. Reviewer entries are self-attested and need identity verification before use.</p>
<p>This page runs locally and sends nothing over the network. Export your work before closing; there is no automatic save. Exporting reviews cannot activate a model, authorize a response or approve a release.</p>
</aside><label>Accountable reviewer ID <input id="reviewer" autocomplete="off" required></label>
<p id="progress" role="status">0 of ANSWER_COUNT answers reviewed</p><button id="export">Export current reviews</button>
<button id="complete" disabled>Export completed review</button><main id="entries"></main>
<script type="application/json" id="packet">PACKET_DATA</script><script>
const packet=JSON.parse(document.getElementById('packet').textContent),reviews=new Map();
const el=(tag,text,parent)=>{const n=document.createElement(tag);if(text!==null)n.textContent=text;if(parent)parent.append(n);return n;};
function choice(label,parent){const wrap=el('label',label+' ',parent),select=el('select',null,wrap);
for(const [value,text] of [['','Choose a verdict'],['true','Supported / adequate'],['false','Unsupported / inadequate']]){const o=el('option',text,select);o.value=value;}return select;}
function update(){document.getElementById('progress').textContent=reviews.size+' of '+packet.entries.length+' answers reviewed';
document.getElementById('complete').disabled=reviews.size!==packet.entries.length||!document.getElementById('reviewer').value.trim();}
packet.entries.forEach((entry,index)=>{
const card=el('article',null,document.getElementById('entries')),details=el('details',null,card);
el('summary',(index+1)+'. '+entry.run.case_id+' — '+entry.model,details);el('p',entry.input.question,details);
el('h3','Source observations',details);const list=el('ul',null,details);
entry.input.observations.forEach(row=>el('li',row.id+' | '+row.source+' | '+row.event_time+' | '+row.content,list));
el('h3','Model decision: '+entry.run.decision.disposition,details);
const claims={};entry.run.decision.claims.forEach(claim=>{
el('p',claim.id+': '+claim.statement+' [references: '+claim.references.join(', ')+']',details);
claims[claim.id]=choice('Claim '+claim.id,details);});
const criteria={};for(const key of ['alternatives','contradictions','uncertainty']){
el('h3',key,details);const ul=el('ul',null,details);entry.run.decision[key].forEach(value=>el('li',value,ul));
criteria[key+'_adequate']=choice(key+' adequate?',details);}
criteria.decision_justified=choice('Decision justified by the observations?',details);
el('p','Reported gaps: '+entry.run.decision.reported_gaps.join(', '),details);
el('p','Requested actions: '+entry.run.decision.requested_actions.join(', '),details);
if(entry.machine_review_notes.length){const notes=el('details',null,details);el('summary','Provisional AI screening notes — not analyst verdicts',notes);
entry.machine_review_notes.forEach(value=>el('pre',typeof value==='string'?value:JSON.stringify(value,null,2),notes));}
const rationaleLabel=el('label','Reviewer rationale',details),rationale=el('textarea',null,rationaleLabel);
const status=el('p','Pending — no verdict supplied',details);status.className='status';const save=el('button','Record this review',details);
const controls=[...Object.values(claims),...Object.values(criteria),rationale];
controls.forEach(control=>control.addEventListener('input',()=>{reviews.delete(index);status.textContent='Pending — edited; record again';update();}));
save.onclick=()=>{if(!controls.every(control=>control.value.trim())){status.textContent='Complete every verdict and the rationale first.';return;}
const verdicts=Object.fromEntries(Object.entries(claims).map(([key,node])=>[key,node.value==='true']));
reviews.set(index,{case_id:entry.run.case_id,model:entry.model,run_sha256:entry.run_sha256,claim_verdicts:verdicts,
...Object.fromEntries(Object.entries(criteria).map(([key,node])=>[key,node.value==='true'])),rationale:rationale.value.trim(),reviewed_at:new Date().toISOString()});
status.textContent='Review recorded. Export before closing.';update();};
el('p','Exact run SHA-256: '+entry.run_sha256,details);
});
document.getElementById('reviewer').oninput=update;
function download(complete){const reviewer=document.getElementById('reviewer').value.trim();if(!reviewer){alert('Enter an accountable reviewer ID first.');return;}
if(complete&&reviews.size!==packet.entries.length)return;
const result={version:'gabriel-authored-review-export-v2',purpose:'authored-adjudication-not-qualification',
packet_sha256:'PACKET_DIGEST',reviewer_id:reviewer,reviewer_identity_verified:false,corpus_sha256:packet.corpus_sha256,
partition:packet.partition||'development',complete:reviews.size===packet.entries.length,quality_qualified:false,production_admission:false,
reviews:[...reviews.values()],pending_run_sha256:packet.entries.filter((entry,index)=>!reviews.has(index)).map(entry=>entry.run_sha256)};
const url=URL.createObjectURL(new Blob([JSON.stringify(result,null,2)],{type:'application/json'}));const a=document.createElement('a');
a.href=url;a.download='Gabriel_Authored_Reviews.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
document.getElementById('export').onclick=()=>download(false);document.getElementById('complete').onclick=()=>download(true);
</script></html>'''


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packet',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args()
    with args.output.open('x') as output: output.write(render(json.loads(args.packet.read_text())))

