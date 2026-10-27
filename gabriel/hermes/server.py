"""Private bounded gateway; no credentials, database, evidence mounts or egress."""
from hashlib import sha256
from http.server import BaseHTTPRequestHandler,HTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile

from runtime import VERSION,UPSTREAM


def fingerprint():
    return sha256(b''.join((Path('/opt/gabriel-hermes')/name).read_bytes() for name in ('runtime.py','server.py'))).hexdigest()


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self,*args):pass

    def reply(self,status,body):
        data=json.dumps(body,separators=(',',':')).encode()
        self.send_response(status);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)

    def do_GET(self):
        if self.path!='/health':return self.reply(404,{'error':'not_found'})
        try:
            p=json.loads(Path('/etc/hermes/image-provenance.json').read_text())
            if p.get('revision')!=UPSTREAM or json.loads(Path('/opt/hermes/install-stamp.json').read_text()).get('commit')!=UPSTREAM:raise ValueError
            self.reply(200,dict(version=VERSION,upstream=UPSTREAM,runtime_digest=fingerprint()))
        except Exception:self.reply(503,{'error':'hermes_source_unavailable'})

    def do_POST(self):
        if self.path!='/turn':return self.reply(404,{'error':'not_found'})
        try:
            n=int(self.headers.get('Content-Length','0'))
            if not 0<n<=32768 or self.headers.get('Content-Type')!='application/json':raise ValueError
            raw=self.rfile.read(n)
            if len(raw)!=n:raise ValueError
            # Each turn gets an empty home. Upstream skills, sessions and memory
            # cannot leak from one analyst's investigation into another's.
            with tempfile.TemporaryDirectory(prefix='hermes-') as home:
                env=dict(PATH='/opt/hermes/.venv/bin:/usr/bin:/bin',HOME=home,HERMES_HOME=home,
                    PYTHONDONTWRITEBYTECODE='1',PYTHONUNBUFFERED='1')
                result=subprocess.run(['/opt/hermes/.venv/bin/python','/opt/gabriel-hermes/runtime.py'],input=raw,
                    stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env,cwd=home,timeout=35,close_fds=True)
            if result.returncode or len(result.stdout)>32768:raise ValueError
            body=json.loads(result.stdout)
            if body.get('version')!=VERSION:raise ValueError
            self.reply(200,body)
        except Exception:self.reply(503,{'error':'hermes_turn_unavailable'})


if __name__=='__main__':
    server=HTTPServer(('0.0.0.0',8451),Handler)
    server.timeout=40
    server.serve_forever()
