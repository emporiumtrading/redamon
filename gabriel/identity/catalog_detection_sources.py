"""Local bounded parsers for synthetic canonical events and YARA syntax."""
import json
import re
import subprocess
import sys
from datetime import datetime

FORMAT_NAMES = {
    'validate_sigma_subset': 'sigma', 'compile_yara_rule': 'yara',
    'validate_kql_subset': 'kql', 'validate_spl_subset': 'spl',
    'validate_eql_subset': 'eql', 'evaluate_behavioral_rule': 'behavioral',
    'evaluate_correlation_rule': 'correlation',
}
TYPES = {'authentication', 'process', 'network', 'file'}
OUTCOMES = {'success', 'failure', 'blocked', 'observed'}


def _fields(values):
    return (type(values) is dict and set(values) == {'event_type', 'outcome'}
            and type(values['event_type']) is str and type(values['outcome']) is str
            and values['event_type'] in TYPES and values['outcome'] in OUTCOMES)


def _sigma(source):
    lines = source.rstrip('\n').split('\n')
    if (len(lines) != 8 or not re.fullmatch(r'title: [A-Za-z0-9 _-]{1,80}', lines[0])
            or lines[1:5] != ['logsource:', '  category: canonical_event', 'detection:', '  selection:']
            or lines[7] != '  condition: selection'):
        return None
    fields = {}
    for line in lines[5:7]:
        match = re.fullmatch(r'    (event_type|outcome): ([a-z]+)', line)
        if not match or match[1] in fields: return None
        fields[match[1]] = match[2]
    return fields if _fields(fields) else None


def _query(fmt, source):
    if fmt == 'sigma': return _sigma(source)
    prefix = {'kql': 'Events | where ', 'spl': 'search ', 'eql': 'any where '}.get(fmt)
    if prefix:
        if not source.startswith(prefix): return None
        parts = source[len(prefix):].split(' ' if fmt == 'spl' else ' and ')
        pattern = r'(event_type|outcome)=([a-z]+)' if fmt == 'spl' else r'(event_type|outcome) == "([a-z]+)"'
        fields = {}
        for part in parts:
            match = re.fullmatch(pattern, part)
            if not match or match[1] in fields: return None
            fields[match[1]] = match[2]
        return fields if _fields(fields) else None
    if fmt == 'behavioral':
        try: data = json.loads(source)
        except ValueError: return None
        if (type(data) is dict and set(data) == {'event_type','outcome','minimum_count'}
                and type(data['minimum_count']) is int and 1 <= data['minimum_count'] <= 1000000
                and _fields({k:data[k] for k in ('event_type','outcome')})):
            return data
    return None


def _correlation(source):
    try: data = json.loads(source)
    except ValueError: return None
    if (type(data) is not dict or set(data) != {'first','then','within_seconds'}
            or type(data['within_seconds']) is not int or not 1 <= data['within_seconds'] <= 3600
            or not _fields(data['first']) or not _fields(data['then'])):
        return None
    return data


def _compile_yara(source):
    if len(source) > 2048 or re.search(r'(?m)^\s*(?:import|include)\b', source):
        return 'unsupported_source'
    runner = '''import resource, sys
resource.setrlimit(resource.RLIMIT_AS, (256*1024*1024, 256*1024*1024))
resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
try:
    import yara
except ImportError:
    sys.exit(3)
try:
    yara.compile(source=sys.stdin.read(2049), includes=False, error_on_warning=True)
except (yara.SyntaxError, yara.Error, ValueError):
    sys.exit(2)
'''
    try:
        child = subprocess.run([sys.executable, '-I', '-c', runner], input=source,
                               capture_output=True, text=True, timeout=3, check=False,
                               close_fds=True, env={'PATH':'/usr/local/bin:/usr/bin:/bin'}, cwd='/')
    except subprocess.TimeoutExpired: return 'compiler_timeout'
    except OSError: return 'compiler_unavailable'
    return {0:'syntax_validated',2:'invalid_rule',3:'compiler_unavailable'}.get(child.returncode,'compiler_failure')


def evaluate(name, document):
    if name not in FORMAT_NAMES: raise ValueError('unknown_detection_source_skill')
    fmt = FORMAT_NAMES[name]
    sources = [f['data']['source'] for f in document['facts'] if f['type']=='detection_source'
               and f['data']['format']==fmt]
    events = [f for f in document['facts'] if f['type']=='detection_event']
    valid=invalid=unavailable=unsupported=timed_out=failed=matched=0
    for source in sources:
        if fmt == 'yara':
            status = _compile_yara(source)
            valid += status == 'syntax_validated'; invalid += status == 'invalid_rule'
            unavailable += status == 'compiler_unavailable'; unsupported += status == 'unsupported_source'
            timed_out += status == 'compiler_timeout'; failed += status == 'compiler_failure'
            continue
        rule = _correlation(source) if fmt == 'correlation' else _query(fmt,source)
        valid += rule is not None; unsupported += rule is None
        if rule is None: continue
        if fmt == 'correlation':
            selected=[f for f in events if f['entity_id'] is not None]
            for later in selected:
                if any(later['data'][k]!=v for k,v in rule['then'].items()): continue
                end=datetime.fromisoformat(later['event_time'].replace('Z','+00:00'))
                for earlier in selected:
                    if earlier['id']==later['id'] or earlier['entity_id']!=later['entity_id']: continue
                    if any(earlier['data'][k]!=v for k,v in rule['first'].items()): continue
                    start=datetime.fromisoformat(earlier['event_time'].replace('Z','+00:00'))
                    if 0 <= (end-start).total_seconds() <= rule['within_seconds']:
                        matched += 1; break
        else:
            matched += sum(f['data']['event_type']==rule['event_type']
                           and f['data']['outcome']==rule['outcome']
                           and (fmt!='behavioral' or f['data']['count']>=rule['minimum_count']) for f in events)
    return dict(status='review_required' if invalid or unsupported or timed_out or failed
                else 'compiler_unavailable' if unavailable else 'analyzed' if sources else 'no_matching_detection_source',
                format=fmt, source_count=len(sources), accepted_subset_count=valid,
                rejected_or_unsupported_count=unsupported, invalid_rule_count=invalid,
                compiler_unavailable_count=unavailable, compiler_timeout_count=timed_out,
                compiler_failure_count=failed, reported_matching_event_count=matched,
                canonical_event_count=len(events), counts_may_overlap=True,
                dialect_scope='yara_compiler_syntax_only' if fmt=='yara' else 'documented_canonical_subset',
                source_authenticity='unverified', source_clocks_verified=False,
                entity_aliases_independently_resolved=False, correlation_causality_established=False,
                live_engine_replay_verified=False, mapping_accuracy_verified=False,
                incident_status='unknown', confidence='unqualified', external_actions_authorized=False,
                model_used=False, requires_analyst_review=True, deployment_performed=False)
