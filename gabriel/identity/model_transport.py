"""Single-attempt OpenRouter transport; no arbitrary hosts, redirects or tools."""
import http.client
import ssl

from gabriel.identity.model_evaluation import canonical
from gabriel.identity.model_protocol import ProbeError,decode


class OpenRouterTransport:
    def __init__(self,credential):
        secret=credential.reveal()
        if not isinstance(secret,str) or not 20<=len(secret)<=512 or not secret.isascii() or any(c.isspace() for c in secret):
            raise ProbeError('provider_credential_invalid')
        self._secret=secret

    def __repr__(self): return '<OpenRouterTransport credential=redacted>'

    def request(self,method,path,payload=None):
        if (method,path) not in {('GET','/api/v1/key'),('GET','/api/v1/endpoints/zdr'),('POST','/api/v1/chat/completions')}:
            raise ProbeError('model_transport_endpoint_denied')
        if (method=='POST')!=(payload is not None): raise ProbeError('model_transport_payload_denied')
        body=canonical(payload) if payload is not None else None
        if body is not None and len(body)>7000: raise ProbeError('model_transport_input_limit')
        client=http.client.HTTPSConnection('openrouter.ai',443,timeout=30,context=ssl.create_default_context())
        headers={'Content-Type':'application/json','Accept':'application/json','X-OpenRouter-Title':'Gabriel bounded model evaluation'}
        if path!='/api/v1/endpoints/zdr': headers['Authorization']='Bearer '+self._secret
        try:
            client.request(method,path,body=body,headers=headers)
            response=client.getresponse()
            if response.status!=200: raise ProbeError('provider_http_'+str(response.status))
            if 'application/json' not in response.getheader('Content-Type','').lower():
                raise ProbeError('provider_content_type_invalid')
            limit=4*1024*1024 if path=='/api/v1/endpoints/zdr' else 131072
            raw=response.read(limit+1)
            if len(raw)>limit or self._secret.encode() in raw: raise ProbeError('provider_response_rejected')
            return decode(raw)
        except ProbeError: raise
        except (OSError,http.client.HTTPException,ValueError,RecursionError):
            raise ProbeError('provider_transport_unresolved') from None
        finally: client.close()
