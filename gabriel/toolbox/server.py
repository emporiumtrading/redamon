"""Private-network toolbox: bounded stdin, fixed subprocess, no secrets or mounts."""
import base64
from hashlib import sha256
from http.server import BaseHTTPRequestHandler,HTTPServer
from importlib.metadata import version
import json
from pathlib import Path
import subprocess
import sys

MAX_WIRE=1500000
TOOLS={'scan_artifacts','inspect_packets','inspect_logs'}
ENGINE=Path(__file__).with_name('engine.py')


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass

    def reply(self,status,body):
        raw=json.dumps(body,sort_keys=True).encode()
        self.send_response(status);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)

    def do_GET(self):
        if self.path!='/health':return self.reply(404,dict(status='not_found'))
        return self.reply(200,dict(status='ready',packages={p:version(p) for p in ('yara-python','dpkt')},
            tools=sorted(TOOLS),engine_sha256=sha256(ENGINE.read_bytes()).hexdigest(),credential_access=False,network_actions=False))

    def do_POST(self):
        try:
            self.connection.settimeout(5)
            size=int(self.headers.get('Content-Length','0'))
            if self.path!='/analyze' or not 1<=size<=MAX_WIRE:raise ValueError
            if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type')!='application/json':raise ValueError
            doc=json.loads(self.rfile.read(size))
            if type(doc) is not dict or set(doc)!={'tool','data'} or doc['tool'] not in TOOLS:raise ValueError
            data=base64.b64decode(doc['data'],validate=True)
            if not 1<=len(data)<=1048576:raise ValueError
            completed=subprocess.run([sys.executable,'-I',str(ENGINE),doc['tool']],input=data,
                capture_output=True,timeout=5,check=False,close_fds=True,
                env={'PYTHONDONTWRITEBYTECODE':'1'},cwd='/tmp')
            if len(completed.stdout)>8192 or completed.returncode not in {0,2}:raise ValueError
            result=json.loads(completed.stdout)
            self.reply(200,result)
        except Exception:self.reply(422,dict(status='analysis_failed'))


def main():
    HTTPServer(('0.0.0.0',8450),Handler).serve_forever()


if __name__=='__main__':main()
