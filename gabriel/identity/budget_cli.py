"""Authenticated local budget operator; no provider credentials or network calls."""
import argparse
import json
import os

from gabriel.identity.cli import read_secret
from gabriel.identity.model_budget import ModelBudgetService
from gabriel.identity.service import IdentityError


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--token-file',required=True)
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('status')
    policy=sub.add_parser('configure')
    policy.add_argument('--pause',action='store_true')
    for name in ('month-microusd','day-microusd','investigation-microusd'):
        policy.add_argument('--'+name,type=int)
    quote=sub.add_parser('quote')
    for name in ('provider','model','configuration-digest'):
        quote.add_argument('--'+name,required=True)
    for name in ('input-microusd-per-million','output-microusd-per-million'):
        quote.add_argument('--'+name,type=int,required=True)
    quote.add_argument('--ttl-seconds',type=int,default=900)
    begin=sub.add_parser('begin')
    for name in ('case-id','request-id'):
        begin.add_argument('--'+name,required=True)
    reserve=sub.add_parser('reserve')
    for name in ('investigation-id','request-id','quote-id','input-digest'):
        reserve.add_argument('--'+name,required=True)
    reserve.add_argument('--max-input-tokens',type=int,default=8000)
    reserve.add_argument('--max-output-tokens',type=int,default=1500)
    claim=sub.add_parser('claim')
    claim.add_argument('--reservation-id',required=True)
    settle=sub.add_parser('settle')
    settle.add_argument('--reservation-id',required=True)
    settle.add_argument('--actual-microusd',type=int,required=True)
    settle.add_argument('--receipt-digest',required=True)
    stop=sub.add_parser('stop')
    stop.add_argument('--investigation-id',required=True)
    args=vars(parser.parse_args(argv))
    command=args.pop('command')
    try:
        token=read_secret(args.pop('token_file'),128)
        service=ModelBudgetService(read_secret(os.environ['GABRIEL_IDENTITY_DSN_FILE']))
        if command=='configure':
            args['enabled']=not args.pop('pause')
            args={key:value for key,value in args.items() if value is not None}
        result=getattr(service,command)(token,**args)
        print(json.dumps(dict(status='ok',result=result),default=str))
        return 0
    except (IdentityError,OSError,ValueError,TypeError,KeyError):
        print(json.dumps(dict(status='denied',code='model_budget_operation_denied')))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
