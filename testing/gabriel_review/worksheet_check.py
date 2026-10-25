"""Real-browser worksheet checks do not produce analyst adjudication or model answers."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from browser import CDP,wait
from review_generator import render


def main():
    packet=json.loads(Path('/packet.json').read_text())
    expected=len(packet['entries'])
    for field in ('run_sha256','configuration','input'):
        altered=deepcopy(packet)
        if field=='run_sha256': altered['entries'][0][field]='0'*64
        elif field=='configuration': altered['entries'][0][field]['model']='altered'
        else: altered['entries'][0][field]['observations'][0]['content']='altered'
        try: render(altered)
        except ValueError: pass
        else: raise AssertionError('altered_packet_accepted')
    for field in ('partition','adjudication'):
        altered=deepcopy(packet)
        if field=='partition': altered['partition']='sealed_holdout'
        else: altered['entries'][0]['adjudication']['decision_justified']=True
        try: render(altered)
        except ValueError: pass
        else: raise AssertionError('unadmitted_or_prefilled_review_accepted')
    root=Path('/output');page=root/'Gabriel_Model_Review.html'
    page.write_text(render(packet))
    process=subprocess.Popen(['/usr/bin/chromium','--headless=new','--no-sandbox','--no-first-run',
        '--disable-background-networking','--disable-dev-shm-usage','--remote-debugging-port=19222',
        '--user-data-dir=/tmp/review-profile','--proxy-server=http://127.0.0.1:9','about:blank'],
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    cdp=None
    try:
        cdp=CDP();target=cdp.send('Target.createTarget',{'url':'file:///output/Gabriel_Model_Review.html'})['targetId']
        session=cdp.send('Target.attachToTarget',{'targetId':target,'flatten':True})['sessionId']
        cdp.send('Emulation.setDeviceMetricsOverride',dict(width=1366,height=900,deviceScaleFactor=1,mobile=False),session)
        wait(lambda:cdp.evaluate(session,"document.querySelectorAll('article').length") == expected)
        assert cdp.evaluate(session,"document.getElementById('complete').disabled&&[...document.querySelectorAll('select')].every(e=>e.value==='')")
        assert cdp.evaluate(session,"(()=>{const d=document.querySelector('article>details');d.open=true;return d.innerText.includes('Source observations')&&d.querySelector('li').getClientRects().length>0;})()")
        assert cdp.evaluate(session,"document.documentElement.scrollWidth<=innerWidth")
        cdp.evaluate(session,"document.querySelector('article button').click();true")
        assert cdp.evaluate(session,"document.querySelector('article .status').textContent.includes('Complete every verdict')")
        cdp.evaluate(session,"(()=>{const a=document.querySelector('article');a.querySelectorAll('select').forEach(e=>{e.value='false';});a.querySelector('textarea').value='GENERATED UI TEST ONLY; NOT AN ANALYST REVIEW';a.querySelector('button').click();return true;})()")
        assert cdp.evaluate(session,"document.getElementById('progress').textContent.startsWith('1 of '+packet.entries.length)&&document.getElementById('complete').disabled")
        cdp.evaluate(session,"document.querySelector('article textarea').dispatchEvent(new Event('input'));true")
        assert cdp.evaluate(session,"document.getElementById('progress').textContent.startsWith('0 of '+packet.entries.length)")
        report=dict(status='PASS',entries=expected,blank_verdicts_verified=True,incomplete_denied=True,
            edits_invalidate_review=True,packet_corruption_rejected=True,quality_qualified=False,
            production_admission=False,human_reviews_produced=0,html_sha256=sha256(page.read_bytes()).hexdigest())
        (root/'review-page-check.json').write_text(json.dumps(report,sort_keys=True)+'\n')
        print('PASS: review worksheet renders; blank, incomplete, edited and corrupt inputs cannot become completed adjudication')
    finally:
        if cdp: cdp.ws.close()
        process.terminate();process.wait(timeout=10)


if __name__=='__main__': main()

