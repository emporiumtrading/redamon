"""Comparison candidates; registry membership never admits production inference."""
from decimal import Decimal, InvalidOperation

from gabriel.identity.model_evaluation import digest

VERSION='openrouter-candidate-routes-v1'
ROUTES={
    'openai/gpt-4.1-mini':('Azure','azure','max_completion_tokens',None),
    'qwen/qwen3.5-35b-a3b':('DeepInfra','deepinfra/fp8','max_tokens','disabled'),
    'mistralai/mistral-small-3.2-24b-instruct':('DeepInfra','deepinfra/fp8','max_tokens',None),
    'nvidia/nemotron-3-super-120b-a12b':('DeepInfra','deepinfra/bf16','max_tokens','disabled'),
    'openai/gpt-oss-120b':('DeepInfra','deepinfra/bf16','max_tokens','low'),
    'meta-llama/llama-3.3-70b-instruct':('DeepInfra','deepinfra/turbo','max_tokens',None),
    'deepseek/deepseek-v3.2':('DeepInfra','deepinfra/fp4','max_tokens','disabled'),
    'qwen/qwen3.5-122b-a10b':('SiliconFlow','siliconflow/fp8','max_tokens','disabled'),
}
# Only a reviewed release can populate exact configuration digests. An account
# balance, cheap route, registry entry or operator quote cannot supply admission.
PRODUCTION_CONFIGURATIONS=frozenset()


class RouteError(ValueError):
    pass


def price(value):
    try:
        if type(value) not in {str,int,float}: raise ValueError
        result=Decimal(str(value))
        if not result.is_finite() or result<0: raise ValueError
        return result
    except (ValueError,InvalidOperation):
        raise RouteError('invalid_route_price') from None


def eligible(catalog,model):
    if model not in ROUTES: raise RouteError('unknown_candidate_route')
    data=catalog.get('data') if isinstance(catalog,dict) else None
    if not isinstance(data,list) or len(data)>10000: raise RouteError('invalid_zdr_catalog')
    provider,tag,token_parameter,reasoning=ROUTES[model]
    matches=[r for r in data if isinstance(r,dict) and r.get('model_id')==model
             and r.get('provider_name')==provider and r.get('tag')==tag
             and type(r.get('status')) is int and r['status']==0]
    if len(matches)!=1: raise RouteError('candidate_zdr_route_unavailable')
    row=matches[0]
    supported=row.get('supported_parameters')
    required={'temperature','response_format',token_parameter}|({'reasoning'} if reasoning else set())
    if not isinstance(supported,list) or not required<=set(supported):
        raise RouteError('candidate_parameters_unavailable')
    pricing=row.get('pricing')
    if not isinstance(pricing,dict): raise RouteError('invalid_route_price')
    incoming,outgoing=price(pricing.get('prompt')),price(pricing.get('completion'))
    if incoming>Decimal('0.0000005') or outgoing>Decimal('0.000003') or price(pricing.get('request',0))!=0:
        raise RouteError('candidate_price_exceeds_limit')
    return dict(model=model,provider=provider,tag=tag,input_usd_per_token=str(incoming),
                output_usd_per_token=str(outgoing),catalog_digest=digest(row),
                catalog_classification='openrouter_reported_zdr_not_independent_attestation',
                quality_qualified=False,production_admission=False)


def parameters(model):
    if model not in ROUTES: raise RouteError('unknown_candidate_route')
    _,tag,token_parameter,reasoning=ROUTES[model]
    result=dict(temperature=0,stream=False,response_format={'type':'json_object'},
                provider=dict(only=[tag],allow_fallbacks=False,require_parameters=True,
                              data_collection='deny',zdr=True,
                              max_price=dict(prompt=0.5,completion=3,request=0)))
    result[token_parameter]=768
    if reasoning: result['reasoning']={'enabled':False} if reasoning=='disabled' else {'effort':'low'}
    return result
