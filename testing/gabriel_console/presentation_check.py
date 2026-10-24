"""Render only the sanitized offline report in the existing isolated browser image."""
import base64
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from browser import CDP, wait


def main():
    root=Path('/output')
    process=subprocess.Popen(['/usr/bin/chromium','--headless=new','--no-sandbox','--no-first-run',
        '--disable-background-networking','--disable-dev-shm-usage','--remote-debugging-port=19222',
        '--user-data-dir=/tmp/report-profile','--proxy-server=http://127.0.0.1:9','about:blank'],
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    cdp=None
    try:
        cdp=CDP()
        target=cdp.send('Target.createTarget',{'url':'file:///output/presentation.html'})['targetId']
        session=cdp.send('Target.attachToTarget',{'targetId':target,'flatten':True})['sessionId']
        cdp.send('Emulation.setDeviceMetricsOverride',dict(width=1366,height=900,deviceScaleFactor=1,mobile=False),session)
        wait(lambda:cdp.evaluate(session,'document.title')=='Gabriel verified lab demonstration')
        result=cdp.evaluate(session,"""(()=>{
          const d=[...document.querySelectorAll('details')];
          if(d.length)d[0].open=true;
          return {specialists:d.length,tableRows:document.querySelectorAll('tr').length,
            persistenceVisible:document.body.innerText.includes('Persistence check: passed'),
            reconciliationVisible:document.body.innerText.includes('exactly matched the generated Wazuh manager'),
            repeatedFailureVisible:document.body.innerText.includes('Twelve distinct native events'),
            limitsVisible:document.body.innerText.includes('AI models are disabled'),
            disclosureOpened:d.length>0&&d[0].open&&d[0].querySelector('li').getClientRects().length>0,
            horizontalOverflow:document.documentElement.scrollWidth>innerWidth};
        })()""")
        assert result['specialists']==12 and result['tableRows']==13
        assert all(result[k] for k in ('persistenceVisible','reconciliationVisible','repeatedFailureVisible','limitsVisible','disclosureOpened'))
        assert not result['horizontalOverflow']
        screenshot=base64.b64decode(cdp.send('Page.captureScreenshot',{'format':'png'},session)['data'])
        (root/'presentation-preview.png').write_bytes(screenshot)
        result.update(status='PASS',scope='sanitized offline report; isolated Chromium with sandbox disabled',
            report_sha256=sha256((root/'presentation.html').read_bytes()).hexdigest(),
            screenshot_sha256=sha256(screenshot).hexdigest())
        (root/'presentation-check.json').write_text(json.dumps(result,sort_keys=True)+'\n')
        print('PASS: report renders twelve specialists, opens findings, shows persistence and limits, and fits desktop viewport')
    finally:
        if cdp: cdp.ws.close()
        process.terminate();process.wait(timeout=10)


if __name__=='__main__': main()
