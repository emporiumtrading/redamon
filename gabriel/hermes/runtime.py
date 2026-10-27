"""Run one genuine Hermes turn using a single supplied, credential-free reply."""
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import sys
import traceback

UPSTREAM='bf0203a794a07aac3ff764972ab9087baa4e4f4e'
VERSION='gabriel-hermes-bridge-v1'
STAGE='start'
NATIVE_REQUESTS=[]
POLICY_ERROR=''
REQUEST_METADATA={}
SYSTEM_DIFF=[]


class BoundaryViolation(RuntimeError):
    pass


def execute(packet):
    global STAGE,NATIVE_REQUESTS,POLICY_ERROR,REQUEST_METADATA,SYSTEM_DIFF
    if type(packet) is not dict or set(packet)!={'model','messages','answer'}:
        raise ValueError('invalid_hermes_packet')
    if packet['model']!='openai/gpt-oss-120b':raise ValueError('unsupported_hermes_model')
    messages=packet['messages']
    if (type(messages) is not list or len(messages)!=2 or
            [m.get('role') for m in messages]!=['system','user'] or
            any(set(m)!={'role','content'} or type(m['content']) is not str for m in messages) or
            len(json.dumps(messages).encode())>7000 or type(packet['answer']) is not str or len(packet['answer'].encode())>16384):
        raise ValueError('invalid_hermes_context')
    provenance=json.loads(Path('/etc/hermes/image-provenance.json').read_text())
    if provenance.get('revision')!=UPSTREAM or json.loads(Path('/opt/hermes/install-stamp.json').read_text()).get('commit')!=UPSTREAM:
        raise ValueError('unexpected_hermes_source')
    # Pin a conservative local working window; isolated turns must never probe
    # provider metadata or silently infer a context window from the network.
    Path(os.environ['HERMES_HOME'],'config.yaml').write_text(json.dumps(dict(model=dict(
        default=packet['model'],provider='custom',base_url='http://127.0.0.1:9/v1',context_length=65536))))
    sys.path.insert(0,'/opt/hermes')
    STAGE='imports'
    import httpx
    from openai.types.chat import ChatCompletion,ChatCompletionChunk
    from run_agent import AIAgent
    import agent.conversation_loop as native_loop
    def fail_without_retry(agent,api_error):
        raise BoundaryViolation('hermes_replay_api_error') from api_error
    native_loop.handle_api_error=fail_without_retry
    calls=[]
    NATIVE_REQUESTS=calls
    class ReplayStream:
        def __init__(self,chunks):
            self.chunks=chunks
            self.response=httpx.Response(200,request=httpx.Request('POST','http://127.0.0.1:9/internal-replay'))
        def __iter__(self):return iter(self.chunks)
        def __enter__(self):return self
        def __exit__(self,*args):self.close()
        def close(self):pass
    def completion(**body):
        global POLICY_ERROR,REQUEST_METADATA,SYSTEM_DIFF
        def reject(code):
            global POLICY_ERROR
            if not POLICY_ERROR:POLICY_ERROR=code
            raise BoundaryViolation(code)
        if calls:reject('hermes_single_turn_limit')
        calls.append(dict(body,messages=json.loads(json.dumps(body.get('messages')))))
        outgoing=body.get('messages')
        REQUEST_METADATA=dict(expected_count=len(messages),actual_count=len(outgoing) if type(outgoing) is list else None,
            actual_roles=[m.get('role') for m in outgoing if type(m) is dict] if type(outgoing) is list else [],
            message_keys=[sorted(m) for m in outgoing if type(m) is dict] if type(outgoing) is list else [],
            content_equal=[m.get('content')==messages[i]['content'] for i,m in enumerate(outgoing[:2]) if type(m) is dict] if type(outgoing) is list else [],
            tools_present=bool(body.get('tools')),model_matches=body.get('model')==packet['model'])
        if outgoing!=messages or body.get('tools') or body.get('model')!=packet['model']:
            if os.environ.get('GABRIEL_HERMES_TEST_DIAGNOSTICS')=='1' and type(outgoing) is list and outgoing and type(outgoing[0].get('content')) is str:
                import difflib
                SYSTEM_DIFF=list(difflib.unified_diff(messages[0]['content'].splitlines(),outgoing[0]['content'].splitlines()))[:40]
            reject('hermes_request_binding_failed')
        # Replay bookkeeping is internal and synthetic; Gabriel separately
        # verifies and records the actual provider's usage and cost receipt.
        usage=dict(prompt_tokens=100,completion_tokens=50,total_tokens=150)
        if not body.get('stream'):
            return ChatCompletion.model_validate(dict(id='gabriel-replay',object='chat.completion',created=1,model=packet['model'],
                choices=[dict(index=0,finish_reason='stop',message=dict(role='assistant',content=packet['answer']))],usage=usage))
        first=ChatCompletionChunk.model_validate(dict(id='gabriel-replay',object='chat.completion.chunk',created=1,model=packet['model'],
            choices=[dict(index=0,finish_reason=None,delta=dict(role='assistant',content=packet['answer']))]))
        last=ChatCompletionChunk.model_validate(dict(id='gabriel-replay',object='chat.completion.chunk',created=1,model=packet['model'],
            choices=[dict(index=0,finish_reason='stop',delta={})],usage=usage))
        return ReplayStream([first,last])
    class ReplayClient:
        def __init__(self):
            from types import SimpleNamespace
            self.chat=SimpleNamespace(completions=SimpleNamespace(create=completion))
        def with_options(self,**kwargs):return self
        def copy(self,**kwargs):return self
        def close(self):pass
        def is_closed(self):return False
    class ControlledHermes(AIAgent):
        def _create_openai_client(self,*args,**kwargs):return ReplayClient()
    STAGE='initialization'
    agent=ControlledHermes(base_url='http://127.0.0.1:9/v1',api_key='gabriel-internal-replay-no-provider-credential',provider='custom',
        api_mode='chat_completions',model=packet['model'],max_iterations=1,max_tokens=768,enabled_toolsets=[],
        save_trajectories=False,quiet_mode=True,verbose_logging=False,skip_context_files=True,load_soul_identity=False,
        skip_memory=True,skip_background_review=True,checkpoints_enabled=False,run_budget_seconds=20,platform='gabriel',
        request_overrides=dict(stream=False,temperature=0,response_format=dict(type='json_object')))
    try:
        agent.client=ReplayClient()
        agent._create_openai_client=lambda *args,**kwargs:ReplayClient()
        agent.tools=[];agent.valid_tool_names=set();agent._persist_disabled=True
        from agent.agent_init import set_config_context_length
        set_config_context_length(agent,65536)
        agent.context_compressor.context_length=65536
        agent._build_system_prompt=lambda *args,**kwargs:messages[0]['content']
        agent._cached_system_prompt=messages[0]['content'];agent._cached_system_prompt_static=messages[0]['content']
        STAGE='conversation'
        result=agent.run_conversation(messages[1]['content'],system_message=messages[0]['content'])
        STAGE='result_binding'
        if len(calls)!=1 or result.get('final_response')!=packet['answer']:
            raise ValueError('hermes_response_binding_failed')
        return dict(version=VERSION,upstream=UPSTREAM,messages=calls[0]['messages'],answer=result['final_response'],native_turns=1)
    finally:
        if hasattr(agent,'close'):agent.close()


def main():
    def expired(*args):raise TimeoutError('hermes_turn_deadline')
    signal.signal(signal.SIGALRM,expired);signal.alarm(30)
    raw=sys.stdin.buffer.read(32769)
    if len(raw)>32768:raise ValueError('hermes_packet_limit')
    # Framework diagnostics may include supplied content; never forward them.
    with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
        result=execute(json.loads(raw))
    print(json.dumps(result,separators=(',',':'),sort_keys=True))


if __name__=='__main__':
    try:main()
    except (Exception,BoundaryViolation) as error:
        code=POLICY_ERROR or (str(error) if str(error) in {'hermes_single_turn_limit','hermes_request_binding_failed','hermes_response_binding_failed','hermes_turn_deadline','unexpected_hermes_source','hermes_replay_api_error'} else 'details_withheld')
        root=error;seen=set()
        while id(root) not in seen:
            seen.add(id(root));cause=root.__cause__ or root.__context__
            if cause is None or id(cause) in seen:break
            root=cause
        frames=[dict(file=Path(f.filename).name,line=f.lineno,function=f.name) for f in traceback.extract_tb(root.__traceback__)[-12:]]
        print(json.dumps(dict(error='hermes_turn_failed',stage=STAGE,error_type=type(root).__name__,code=code,frames=frames,system_diff=SYSTEM_DIFF,request_metadata=REQUEST_METADATA,native_calls=len(NATIVE_REQUESTS),stream=NATIVE_REQUESTS[0].get('stream') if NATIVE_REQUESTS else None)))
        raise SystemExit(2)
