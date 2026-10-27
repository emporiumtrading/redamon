"""Real offline engines and role/skill/output contracts, without model calls."""
import base64
import io
import json
from pathlib import Path
import subprocess
import sys

import dpkt
import pytest

from gabriel.toolbox import engine
from gabriel.identity import investigation_tools as tools,specialist_agents as agents
from gabriel.identity.model_protocol import ProbeError
from testing.gabriel_identity.test_specialist_analysis import document


def capture(pcapng=False):
    buffer=io.BytesIO()
    writer=(dpkt.pcapng.Writer if pcapng else dpkt.pcap.Writer)(buffer)
    # RFC5737 documentation addresses; the capture is constructed entirely offline.
    tcp=dpkt.tcp.TCP(sport=42000,dport=443,flags=dpkt.tcp.TH_SYN)
    ip=dpkt.ip.IP(src=bytes([192,0,2,1]),dst=bytes([192,0,2,2]),p=6,data=tcp)
    ip.len=len(ip)
    ethernet=dpkt.ethernet.Ethernet(src=b'\x00'*6,dst=b'\x01'*6,type=dpkt.ethernet.ETH_TYPE_IP,data=ip)
    writer.writepkt(bytes(ethernet),ts=1000)
    return json.dumps(dict(format='gabriel-artifact-v1',kind='pcap',encoding='base64',data=base64.b64encode(buffer.getvalue()).decode())).encode()


def logs():
    rows=[dict(timestamp='2026-10-27T12:00:'+str(i).zfill(2)+'Z',entity='generated-user',outcome='failure' if i<5 else 'success') for i in range(6)]
    return '\n'.join(json.dumps(r) for r in rows).encode()


def test_yara_matches_behavior_and_does_not_claim_malware_or_clean():
    result=engine.scan_artifacts(b'generated powershell -EncodedCommand example')
    assert result['matched_rule_ids']==['powershell_encoded_command']
    assert result['maliciousness']=='unqualified' and result['rules_evaluated']==3
    assert engine.scan_artifacts(b'ordinary generated text')['matched_rule_ids']==[]
    assert engine.scan_artifacts(b'vssadmin delete shadows')['matched_rule_ids']==['windows_shadow_copy_deletion']
    assert engine.scan_artifacts(b'sekurlsa::logonpasswords')['matched_rule_ids']==['credential_dump_reference']


@pytest.mark.parametrize('pcapng',[False,True])
def test_actual_pcap_parsing_aggregates_without_exporting_endpoints(pcapng):
    result=engine.inspect_packets(capture(pcapng))
    assert result['packet_count']==1 and result['unique_endpoints']==2
    assert result['directed_flow_count']==1 and result['protocol_counts']['tcp_syn_without_ack']==1
    assert not result['addresses_exported'] and not result['payloads_exported']
    assert engine.inspect_packets(b'not an envelope')['status']=='unsupported_format'


def test_log_sequence_finds_failure_burst_then_success_without_identifiers():
    result=engine.inspect_logs(logs())
    assert result['five_failures_in_300s_groups']==1 and result['failure_burst_then_success_groups']==1
    assert result['record_count']==6 and result['outcome_counts']=={'failure':5,'success':1}
    assert 'generated-user' not in json.dumps(result) and not result['duplicates_deduplicated']
    with pytest.raises(ValueError):engine.inspect_logs(b'{"unexpected":"vendor format"}')


def test_malformed_oversized_and_unknown_tool_fail_closed_in_real_subprocess():
    for tool,payload in [('inspect_packets',b'{"format":"gabriel-artifact-v1","kind":"pcap","encoding":"base64","data":"!"}'),('inspect_logs',b'x'),('scan_artifacts',b'x'*(1048576+1)),('shell',b'ignored')]:
        completed=subprocess.run([sys.executable,'-I',str(Path(engine.__file__)),tool],input=payload,capture_output=True,timeout=6)
        assert completed.returncode==2 and json.loads(completed.stdout)['status']=='analysis_failed'
        assert payload not in completed.stdout


def test_every_role_has_packaged_usable_skill_and_registered_dispatch_contract():
    for role in agents.ROLES:
        assert 'inspect_toolkit' in agents.TOOLS[role]
        config=agents.configuration(role)
        assert config['tool_manifest_digest']==agents.digest(tools.manifest(role))
        for entry in tools.manifest(role):
            assert set(entry)>={'purpose','when_to_use','args_format','description','license','skill_sha256','implementation_sha256'}
            assert len(entry['description'])>100 and entry['description'] in agents.prompt(role)
            assert entry['license'] in {'MIT','Apache-2.0 AND BSD-3-Clause','BSD-3-Clause','PSF-2.0'}
    assert len(agents.prompt('threat_hunting').encode())<6000
    assert all(not agents.readiness(r)['model_enabled'] for r in agents.ROLES)


def test_critical_exposure_is_urgent_review_without_inventing_exploitation():
    doc=document('exposure',dict(severity='critical',reachable='yes',mitigated='no'))
    result=tools.native('assess_exposure',doc,'exposure_vulnerability',3)
    assert result['urgent_exposure_count']==1 and result['urgency']=='urgent_review'
    assert result['exploitation']=='not_established'
    worker=object.__new__(agents.SpecialistWorker);worker.role='exposure_vulnerability'
    worker.tool_results=[dict(tool='assess_exposure',result=result)]
    with pytest.raises(ProbeError,match='urgent_exposure_cannot_be_benign'):
        worker._validate_actions(dict(disposition='benign',requested_actions=[]))
    worker._validate_actions(dict(disposition='abstain',requested_actions=[]))


def test_parser_output_rejects_unregistered_text_and_raw_identifiers():
    with pytest.raises(ValueError):tools.minimized('scan_artifacts',dict(status='analyzed',matched_rule_ids=['untrusted instructions']))
    result=tools.minimized('scan_artifacts',dict(status='analyzed',matched_rule_ids=['powershell_encoded_command'],raw='private payload'))
    assert 'private payload' not in json.dumps(result)
    assert tools.minimized('inspect_logs',dict(status='unknown injected state'))=={'status':'analysis_failed'}
