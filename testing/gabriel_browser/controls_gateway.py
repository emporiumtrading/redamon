"""Hold a generated prepared response so Stop can race actual extension dispatch."""
import time
from gabriel.identity import browser_gateway
from gabriel.identity import gateway_cli


class DelayedGateway(browser_gateway.BrowserGateway):
    def dispatch(self,operation,body,authorization):
        result=super().dispatch(operation,body,authorization)
        if operation=='controls-prepare':
            print('CONTROL_PREPARED_DELAY',flush=True)
            time.sleep(2)
        return result


if __name__=='__main__':
    browser_gateway.BrowserGateway=DelayedGateway
    gateway_cli.main()
