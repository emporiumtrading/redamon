"""Fixed offline parsers. Never execute evidence, user rules, URLs or commands."""
import base64
from collections import Counter,defaultdict
from datetime import datetime
import io
import json
import resource
import sys

MAX_BYTES=1048576
MAX_PACKETS=10000
MAX_RECORDS=5000
VERSIONS={'yara-python':'4.5.5','dpkt':'1.9.8'}
RULES='''
rule powershell_encoded_command {
 strings: $p="powershell" nocase $e="-encodedcommand" nocase
 condition: $p and $e
}
rule windows_shadow_copy_deletion {
 strings: $v="vssadmin" nocase $d="delete shadows" nocase
 condition: $v and $d
}
rule credential_dump_reference {
 strings: $m="sekurlsa::logonpasswords" nocase
 condition: $m
}
'''


def artifact(raw):
    if not 1<=len(raw)<=MAX_BYTES:raise ValueError('artifact_size_limit')
    # Binary evidence uses an explicit envelope because the existing intake is UTF-8.
    try:doc=json.loads(raw)
    except (ValueError,UnicodeError):return raw,None
    if type(doc) is dict and doc.get('format')=='gabriel-artifact-v1':
        if set(doc)!={'format','kind','encoding','data'} or doc['encoding']!='base64' or doc['kind'] not in {'file','pcap'}:
            raise ValueError('invalid_artifact_envelope')
        data=base64.b64decode(doc['data'],validate=True)
        if not 1<=len(data)<=MAX_BYTES:raise ValueError('artifact_size_limit')
        return data,doc['kind']
    return raw,None


def scan_artifacts(raw):
    import yara
    data,kind=artifact(raw)
    rules=yara.compile(source=RULES,includes=False,error_on_warning=True)
    matches=rules.match(data=data,timeout=2)
    return dict(status='analyzed',engine='yara-python',version=yara.__version__,
        matched_rule_ids=sorted(m.rule for m in matches),rules_evaluated=3,
        rule_scope='three_behavioral_text_patterns_not_comprehensive_malware_detection',
        maliciousness='unqualified',source_authenticity='unverified')


def inspect_packets(raw):
    import dpkt
    data,kind=artifact(raw)
    if kind!='pcap':return dict(status='unsupported_format',required='gabriel-artifact-v1_pcap_base64')
    reader=dpkt.pcap.UniversalReader(io.BytesIO(data))
    if reader.datalink()!=dpkt.pcap.DLT_EN10MB:
        return dict(status='unsupported_link_type',required='ethernet')
    counts=Counter();peers=set();flows=set();timestamps=[];packets=0;malformed=0
    for ts,buf in reader:
        packets+=1
        if packets>MAX_PACKETS:raise ValueError('packet_count_limit')
        timestamps.append(float(ts))
        try:
            ip=dpkt.ethernet.Ethernet(buf).data
            if not isinstance(ip,(dpkt.ip.IP,dpkt.ip6.IP6)):
                counts['non_ip']+=1;continue
            peers.update((ip.src,ip.dst));transport=ip.data
            protocol='tcp' if isinstance(transport,dpkt.tcp.TCP) else 'udp' if isinstance(transport,dpkt.udp.UDP) else 'other_ip'
            counts[protocol]+=1
            if protocol=='tcp':
                if transport.flags & dpkt.tcp.TH_SYN and not transport.flags & dpkt.tcp.TH_ACK:counts['tcp_syn_without_ack']+=1
                if transport.flags & dpkt.tcp.TH_RST:counts['tcp_reset']+=1
            flows.add((ip.src,ip.dst,protocol,getattr(transport,'sport',None),getattr(transport,'dport',None)))
        except (dpkt.UnpackError,ValueError,TypeError):malformed+=1
    return dict(status='analyzed',engine='dpkt',version=dpkt.__version__,packet_count=packets,
        protocol_counts=dict(counts),unique_endpoints=len(peers),directed_flow_count=len(flows),
        supplied_duration_seconds=round(max(timestamps)-min(timestamps),6) if timestamps else 0,
        malformed_packets=malformed,payloads_exported=False,addresses_exported=False,
        coverage='supplied_capture_only',attack_status='unknown')


def inspect_logs(raw):
    """Parse normalized JSONL exports; never guess vendor field semantics."""
    lines=raw.decode('utf-8').splitlines()
    if not 1<=len(lines)<=MAX_RECORDS:raise ValueError('log_record_limit')
    records=[]
    for line in lines:
        row=json.loads(line)
        if (type(row) is not dict or set(row)!={'timestamp','entity','outcome'}
                or type(row['entity']) is not str or not 1<=len(row['entity'])<=128
                or row['outcome'] not in {'failure','success','blocked','observed'}):
            raise ValueError('normalized_log_schema_required')
        instant=datetime.fromisoformat(row['timestamp'].replace('Z','+00:00'))
        if instant.utcoffset() is None:raise ValueError('log_timezone_required')
        records.append((instant.timestamp(),row['entity'],row['outcome']))
    records.sort();groups=defaultdict(list);bursts=set();sequences=set()
    for instant,entity,outcome in records:
        failures=groups[entity]
        failures[:]=[t for t in failures if 0<=instant-t<=300]
        if outcome=='failure':failures.append(instant)
        if len(failures)>=5:
            bursts.add(entity)
            if outcome=='success':sequences.add(entity)
    return dict(status='analyzed',engine='python-json-datetime',record_count=len(records),
        outcome_counts=dict(Counter(r[2] for r in records)),unique_entities=len(groups),
        five_failures_in_300s_groups=len(bursts),failure_burst_then_success_groups=len(sequences),
        duplicates_deduplicated=False,clock_verified=False,attack_status='hypothesis_requires_review')


TOOLS={'scan_artifacts':scan_artifacts,'inspect_packets':inspect_packets,'inspect_logs':inspect_logs}


def main():
    resource.setrlimit(resource.RLIMIT_CPU,(3,3))
    resource.setrlimit(resource.RLIMIT_AS,(192*1024*1024,192*1024*1024))
    resource.setrlimit(resource.RLIMIT_FSIZE,(0,0))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    try:
        if len(sys.argv)!=2 or sys.argv[1] not in TOOLS:raise ValueError('tool_not_allowed')
        raw=sys.stdin.buffer.read(MAX_BYTES+1)
        if not 1<=len(raw)<=MAX_BYTES:raise ValueError('artifact_size_limit')
        result=TOOLS[sys.argv[1]](raw)
        encoded=json.dumps(result,sort_keys=True,allow_nan=False).encode()
        if len(encoded)>8192:raise ValueError('tool_output_limit')
        sys.stdout.buffer.write(encoded)
        return 0
    except Exception:
        sys.stdout.write('{"status":"analysis_failed","source_authenticity":"unverified"}')
        return 2


if __name__=='__main__':raise SystemExit(main())
