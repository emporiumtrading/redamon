"""Candidate event correlations for analyst review, not a qualified live detector.

This pure kernel neither collects a page nor grants actions. Source verification,
current scope and normalization semantics remain responsibilities of its caller.
"""
from collections import defaultdict
import re

from gabriel.identity.evidence_store import canonical
from gabriel.identity.specialist_analysis import at,require,uid

VERSION='attack-pattern-candidates-v1'
KINDS={'auth_failure','auth_success','remote_execution','file_write','file_rename',
       'ransom_note','backup_disabled','kernel_integrity_violation','boot_integrity_violation'}
FIELDS={'source_id','event_id','evidence_id','evidence_digest','event_time','kind','actor_id',
        'asset_id','source_asset_id','process_sha256','object_id','authorization'}
ALTERNATIVES={
    'brute_force':'User mistakes, stale service credentials or an approved authentication test can cause failures.',
    'password_spray':'An authorized test or misconfigured shared service can affect several accounts.',
    'password_misuse':'Authorization records can be incomplete or a legitimate recovery can follow failed logins.',
    'worm_propagation':'Approved software distribution can propagate the same executable across hosts.',
    'ransomware':'Bulk maintenance or backup testing can resemble file-change and backup-interference patterns.',
    'lateral_movement':'Approved remote administration can connect the same account across hosts.',
    'possible_rootkit':'An approved kernel/boot update or sensor fault can produce integrity findings.',
}


def normalized(document,case_id):
    require(type(document) is dict and set(document)=={'version','case_id','as_of','missing_sources','events'}
            and document['version']=='security-events-v1','invalid_security_events')
    require(uid(document['case_id'])==str(case_id),'security_event_case_mismatch')
    end=at(document['as_of'])
    missing=document['missing_sources']
    require(type(missing) is list and len(missing)<=6 and all(type(item) is str and item in
        {'authentication','process','network','file','kernel','boot'} for item in missing)
        and len(set(missing))==len(missing),'invalid_security_source_gaps')
    rows=document['events']
    require(type(rows) is list and 1<=len(rows)<=256 and len(canonical(document))<=131072,'security_event_limit')
    grouped={}
    evidence_digests={}
    for row in rows:
        require(type(row) is dict and set(row)==FIELDS,'invalid_security_event')
        for key in ('source_id','evidence_id','asset_id'):
            uid(row[key])
        for key in ('actor_id','source_asset_id','object_id'):
            if row[key] is not None: uid(row[key])
        require(type(row['event_id']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}',row['event_id']) is not None,
                'invalid_security_event_id')
        require(type(row['evidence_digest']) is str and re.fullmatch('[a-f0-9]{64}',row['evidence_digest']) is not None,
                'invalid_security_event_digest')
        require(type(row['kind']) is str and row['kind'] in KINDS and type(row['authorization']) is str
                and row['authorization'] in {'approved','denied','unknown'},
                'invalid_security_event_kind_or_authorization')
        require(row['process_sha256'] is None or type(row['process_sha256']) is str and
                re.fullmatch('[a-f0-9]{64}',row['process_sha256']) is not None,'invalid_security_process_digest')
        require(at(row['event_time'])<=end,'security_event_after_snapshot')
        require(row['evidence_id'] not in evidence_digests or evidence_digests[row['evidence_id']]==row['evidence_digest'],
                'conflicting_security_evidence_digest')
        evidence_digests[row['evidence_id']]=row['evidence_digest']
        key=(row['source_id'],row['event_id'])
        semantic={k:v for k,v in row.items() if k not in {'evidence_id','evidence_digest'}}
        if key in grouped:
            require(grouped[key]['semantic']==semantic,'conflicting_security_event_identity')
        else:
            grouped[key]=dict(semantic=semantic,row=row,refs=set())
        grouped[key]['refs'].add('evidence/'+row['evidence_id'])
    return sorted([dict(item['row'],references=sorted(item['refs'])) for item in grouped.values()],
                  key=lambda row:(at(row['event_time']),row['source_id'],row['event_id']))


def windows(rows,seconds):
    rows=sorted(rows,key=lambda row:at(row['event_time']))
    start=0
    for stop,row in enumerate(rows):
        while (at(row['event_time'])-at(rows[start]['event_time'])).total_seconds()>seconds:
            start+=1
        yield rows[start:stop+1]


def investigate(document,case_id):
    events=normalized(document,case_id)
    # A page's assertion of approval is unverified context, never suppression.
    candidate_events=events
    findings=[]

    def add(rule,family,rows):
        if not rows: return
        # A rule can match overlapping windows. Keep the largest observed scope
        # for this rule/group rather than generating one alarm per observation.
        unique={(r['source_id'],r['event_id']):r for r in rows}
        rows=sorted(unique.values(),key=lambda r:at(r['event_time']))
        assets={r['asset_id'] for r in rows}
        findings.append(dict(rule_id=rule,family=family,status='suspected_requires_review',priority='urgent_review',
            affected_asset_count=len(assets),observed_event_count=len(rows),
            first_event_time=rows[0]['event_time'],last_event_time=rows[-1]['event_time'],
            references=sorted({ref for r in rows for ref in r['references']}),
            reported_approved_event_count=sum(r['authorization']=='approved' for r in rows),
            alternative=ALTERNATIVES[family],source_verified=False,confidence='unqualified'))

    def groups(rows,key):
        result=defaultdict(list)
        for row in rows:
            value=key(row)
            if value is not None: result[value].append(row)
        return result.values()

    def best(candidates):
        return max(candidates,key=lambda rows:(len({r['asset_id'] for r in rows}),len(rows)),default=[])

    failures=[r for r in candidate_events if r['kind']=='auth_failure']
    successes=[r for r in candidate_events if r['kind']=='auth_success']
    for rows in groups(failures,lambda r:r['actor_id']):
        add('repeated-account-failures-10-in-300s','brute_force',best(w for w in windows(rows,300) if len(w)>=10))
    for rows in groups(failures,lambda r:r['source_asset_id']):
        add('multi-account-failures-10-accounts-5-in-300s','password_spray',best(w for w in windows(rows,300)
            if len(w)>=10 and len({r['actor_id'] for r in w if r['actor_id'] is not None})>=5))
    for success in successes:
        if success['authorization']=='denied':
            add('reported-unauthorized-authentication','password_misuse',[success])
        if success['actor_id'] is not None:
            prior=[r for r in failures if (r['actor_id'],r['asset_id'])==(success['actor_id'],success['asset_id'])
                   and 0<=(at(success['event_time'])-at(r['event_time'])).total_seconds()<=300]
            if len(prior)>=10:
                add('success-after-repeated-failures','password_misuse',prior+[success])

    remote=[r for r in candidate_events if r['kind']=='remote_execution' and r['source_asset_id'] is not None
            and r['source_asset_id']!=r['asset_id']]
    for rows in groups(remote,lambda r:r['actor_id']):
        def chained(window):
            supported=[r for r in window if any(a['actor_id']==r['actor_id'] and a['asset_id']==r['asset_id']
                       and a['source_asset_id']==r['source_asset_id'] and
                       0<=(at(r['event_time'])-at(a['event_time'])).total_seconds()<=60 for a in successes)]
            return supported if any(a['asset_id']==b['source_asset_id'] and a['asset_id']!=b['asset_id']
                                    and at(a['event_time'])<at(b['event_time']) for a in supported for b in supported) else []
        add('authenticated-remote-execution-chain-in-300s','lateral_movement',best(chained(w) for w in windows(rows,300)))
    for rows in groups(remote,lambda r:r['process_sha256']):
        add('same-process-multisource-spread-in-300s','worm_propagation',best(w for w in windows(rows,300)
            if len({r['asset_id'] for r in w})>=3 and len({r['source_asset_id'] for r in w})>=2
            and any(a['asset_id']==b['source_asset_id'] and at(a['event_time'])<at(b['event_time']) for a in w for b in w)))
    files=[r for r in candidate_events if r['kind'] in {'file_write','file_rename'} and r['object_id'] is not None]
    for rows in groups(files,lambda r:r['asset_id']):
        candidates=[]
        for window in windows(rows,60):
            if len({r['object_id'] for r in window})<20: continue
            markers=[r for r in candidate_events if r['asset_id']==window[0]['asset_id'] and
                     r['kind'] in {'ransom_note','backup_disabled'} and
                     -300<=(at(r['event_time'])-at(window[-1]['event_time'])).total_seconds()<=60]
            if markers: candidates.append(window+markers)
        add('bulk-file-change-with-ransom-or-backup-indicator','ransomware',best(candidates))
    for rows in groups([r for r in candidate_events if r['kind'] in {'kernel_integrity_violation','boot_integrity_violation'}],lambda r:r['asset_id']):
        add('reported-kernel-or-boot-integrity-violation','possible_rootkit',rows)
    require(len(findings)<=128,'security_finding_limit_requires_narrower_scope')
    return dict(version=VERSION,findings=findings,unique_event_count=len(events),
        forwarded_duplicate_count=len(document['events'])-len(events),coverage='partial',
        missing_sources=list(document['missing_sources']),source_authenticity='unverified',
        quality_qualified=False,live_detection_accepted=False,external_actions_authorized=False,
        limitations=['Candidate thresholds require independent evaluation; unmatched activity is not a benign verdict.',
                     'Only supplied typed events are examined; collection, normalization and current visibility are unverified.',
                     'No console observation, model invocation, page navigation or response execution occurs in this kernel.'])
