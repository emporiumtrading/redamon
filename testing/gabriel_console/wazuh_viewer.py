"""Operator-only setup/denial tests inside a fresh generated Wazuh manager container."""
import base64
import http.client
import json
from pathlib import Path
import ssl
import sys

phase='configuration'


def main():
    global phase
    config=json.load(sys.stdin)
    user,password=config['username'],config['password']
    def basic(name,secret): return 'Basic '+base64.b64encode((name+':'+secret).encode()).decode()
    index_context=ssl.create_default_context(cafile='/etc/ssl/root-ca.pem')
    api_context=ssl.create_default_context(cafile='/var/ossec/api/configuration/ssl/server.crt')
    # This pinned generated API certificate serves the fixed loopback endpoint.
    api_context.check_hostname=False
    def request(host,port,context,method,path,auth,payload=None,expected=200,raw=False):
        conn=http.client.HTTPSConnection(host,port,context=context,timeout=30)
        try:
            conn.request(method,path,body=json.dumps(payload) if payload is not None else None,
                headers={'Authorization':auth,'Content-Type':'application/json'})
            response=conn.getresponse();body=response.read(1048576)
            if response.status!=expected:
                print('Expected HTTP '+str(expected)+' observed '+str(response.status),file=sys.stderr)
                # Numeric vendor error identifiers diagnose auth without exposing tokens or bodies.
                try:
                    error=json.loads(body).get('error')
                    if type(error) is int: print('Wazuh error code '+str(error),file=sys.stderr)
                except (ValueError,AttributeError): pass
                raise ValueError('permission_or_setup_check_failed')
            return None if method=='HEAD' else body.decode() if raw else json.loads(body)
        finally: conn.close()
    owner=basic(config['indexer_username'],config['indexer_password'])
    def index(method,path,auth=owner,payload=None,expected=200):
        return request('wazuh.indexer',9200,index_context,method,path,auth,payload,expected)
    phase='indexer_role'
    role='gabriel_lab_viewer'
    index('PUT','/_plugins/_security/api/roles/'+role,payload=dict(cluster_permissions=['cluster_composite_ops_ro'],
        index_permissions=[dict(index_patterns=['*'],allowed_actions=['read'])],
        tenant_permissions=[dict(tenant_patterns=['global_tenant'],allowed_actions=['kibana_all_read'])]),expected=201)
    index('PUT','/_plugins/_security/api/internalusers/'+user,payload=dict(password=password,backend_roles=[]),expected=201)
    index('PUT','/_plugins/_security/api/rolesmapping/'+role,payload=dict(users=[user],backend_roles=[],hosts=[]),expected=201)
    viewer=basic(user,password)
    phase='indexer_denials'
    index('GET','/wazuh-alerts-*/_search?size=0&ignore_unavailable=true&allow_no_indices=true',auth=viewer)
    denied_index='gabriel-denied-'+user.rsplit('-',1)[-1]
    index('PUT','/'+denied_index,auth=viewer,payload={},expected=403)
    index('GET','/_plugins/_security/api/internalusers',auth=viewer,expected=403)
    index('HEAD','/'+denied_index,expected=404)
    phase='server_role_mapping'
    operator=request('localhost',55000,api_context,'POST','/security/user/authenticate?raw=true',
        basic(config['api_username'],config['api_password']),raw=True)
    def api(method,path,payload=None,token=operator,expected=200,raw=False):
        return request('localhost',55000,api_context,method,path,'Bearer '+token,payload,expected,raw)
    roles=api('GET','/security/roles')['data']['affected_items']
    matches=[row for row in roles if row['name']=='readonly']
    if len(matches)!=1: raise ValueError('readonly_role_missing')
    rule=api('POST','/security/rules',dict(name=user,rule={'FIND':{'user_name':user}}))['data']['affected_items']
    if len(rule)!=1: raise ValueError('viewer_rule_missing')
    api('POST','/security/roles/'+str(matches[0]['id'])+'/rules?rule_ids='+str(rule[0]['id']))
    viewer_token=request('localhost',55000,api_context,'POST','/security/user/authenticate/run_as?raw=true',
        basic(config['api_username'],config['api_password']),dict(name=user,auth=dict(user_name=user)),raw=True)
    phase='server_agents_read'
    api('GET','/agents?limit=1',token=viewer_token)
    phase='server_groups_before'
    before=api('GET','/groups')['data']['affected_items']
    denied_group='gabriel-denied-'+user.rsplit('-',1)[-1]
    phase='server_group_write_denial'
    api('POST','/groups',dict(group_id=denied_group),token=viewer_token,expected=403)
    phase='server_security_read_denial'
    api('GET','/security/users',token=viewer_token,expected=403)
    phase='server_groups_after'
    after=api('GET','/groups')['data']['affected_items']
    if before!=after or any(row['name']==denied_group for row in after): raise ValueError('denied_group_write_changed_state')
    print(json.dumps(dict(status='PASS',username=user,index_search_http=200,index_write_http=403,
        index_security_read_http=403,denied_index_absent=True,server_agents_read_http=200,
        server_group_write_http=403,server_security_read_http=403,groups_unchanged=True,
        index_scope='all indexes in this isolated generated lab; not customer scope',
        server_role='readonly',browser_session_verified=False,gabriel_adapter_admitted=False)))


if __name__=='__main__':
    try: main()
    except Exception as error:
        print('Generated Wazuh viewer check failed at '+phase+' ('+type(error).__name__+')',file=sys.stderr)
        raise SystemExit(1)
