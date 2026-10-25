"""Generated localhost contract admission confined to the disposable browser test image."""
import sys
import time
from urllib.parse import urlsplit

from gabriel.identity.browser_navigation import CONTRACTS
from gabriel.identity.checkpoints import read_document
from gabriel.identity.gateway_cli import main
from gabriel.identity.browser_sessions import BrowserSessionService


if __name__=='__main__':
    try:
        configuration=sys.argv[sys.argv.index('--configuration')+1]
        context=read_document(configuration,private=True)['context']
        if urlsplit(context['page_url']).hostname!='localhost':
            raise ValueError('generated_localhost_required')
        if CONTRACTS: raise ValueError('test_catalog_must_start_empty')
        CONTRACTS['generated-console-v1']={'/security','/traffic','/threats'}
        original_disconnect=BrowserSessionService.disconnect_browser
        def delayed_disconnect(service,token):
            print('LAB: disconnect-request',flush=True)
            time.sleep(.5)
            return original_disconnect(service,token)
        BrowserSessionService.disconnect_browser=delayed_disconnect
    except (KeyError,ValueError,IndexError,OSError):
        print('Generated gateway configuration denied.')
        raise SystemExit(1)
    raise SystemExit(main())
