"""Private, short-lived browser setup for the local Docker installation."""
from hashlib import sha256
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic
from urllib.parse import parse_qs
import webbrowser

SETUP_SECONDS = 900
FORM_LIMIT = 16384
SCRIPT = """
const form = document.querySelector('form');
const action = document.querySelector('#action');
const organization = document.querySelector('#organization');
const password = document.querySelector('#password');
if (location.hash) {
  form.elements.setup_key.value = location.hash.slice(1);
  history.replaceState(null, '', '/');
}
function updateFields() {
  const creating = action.value === 'create';
  organization.required = creating;
  password.minLength = creating ? 16 : 1;
  password.autocomplete = creating ? 'new-password' : 'current-password';
}
action.addEventListener('change', updateFields);
updateFields();
form.addEventListener('submit', () => {
  form.querySelector('button').disabled = true;
  document.querySelector('#progress').textContent =
    'Starting Gabriel in Docker. The first launch may take several minutes.';
});
"""
STYLE = """
* { box-sizing: border-box }
body { margin: 0; background: #0d1421; color: #e6edf6; font: 1rem/1.5 system-ui, sans-serif }
main { max-width: 40rem; margin: 5vh auto; padding: 2rem; background: #162338;
       border: 1px solid #405470; border-radius: 1rem }
small { color: #98d8fb; font-weight: 700 }
h1 { line-height: 1.15 }
a { color: #98d8fb }
code { overflow-wrap: anywhere }
label { display: block; margin: 1rem 0 .3rem }
input, select, button { font: inherit; padding: .65rem; border-radius: .4rem }
input, select { width: 100%; background: #0d1421; color: inherit; border: 1px solid #748ba7 }
button { margin-top: 1.2rem; background: #98d8fb; color: #091523; border: 0; font-weight: 700 }
button:disabled { opacity: .65 }
[role="alert"] { border-left: .2rem solid #ffca8c; padding-left: .8rem }
"""


def page(title, body):
    return f"""<!doctype html>
<html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{escape(title)} | Gabriel</title><style>{STYLE}</style>
<main><small>GABRIEL — THE DEFENDER</small><h1>{escape(title)}</h1>
{body}
</main></html>"""


def form(key="", *, message="", opening=False, username="owner"):
    alert = f'<p role="alert">{escape(message)}</p>' if message else ""
    selected = " selected" if opening else ""
    return page("Set up your private lab", f"""
<p>Choose how to start your local Gabriel workbench.</p>
{alert}
<form method="post" action="/start">
<input type="hidden" name="setup_key" value="{escape(key)}">
<label for="action">Setup action</label>
<select name="action" id="action">
  <option value="create">Create the first owner</option>
  <option value="open"{selected}>Open an existing workbench</option>
</select>
<label for="organization">Organization name (first setup only)</label>
<input id="organization" name="organization" maxlength="100" value="Gabriel private lab">
<label for="username">Username</label>
<input id="username" name="username" maxlength="254" value="{escape(username)}" required
 autocomplete="username" autocapitalize="none" spellcheck="false">
<label for="password">Password</label>
<input id="password" type="password" name="password" maxlength="1024" required
 autocomplete="new-password" aria-describedby="password-help">
<p id="password-help">Use at least 16 characters when creating an owner.</p>
<button type="submit">Start Gabriel</button>
<p id="progress" role="status"></p>
</form>
<noscript><p>Enable JavaScript for this local page to use your private setup link.</p></noscript>
<script src="/setup.js"></script>""")


class SetupHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body="", content_type="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "
                         "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(data)

    def local_request(self):
        return self.headers.get_all("Host") == [self.server.authority]

    def do_GET(self):
        if not self.local_request():
            self.reply(403)
        elif self.path == "/":
            self.reply(200, form())
        elif self.path == "/setup.js":
            self.reply(200, SCRIPT, "application/javascript; charset=utf-8")
        else:
            self.reply(404)

    def do_POST(self):
        setup = self.server
        if (self.path != "/start" or not self.local_request() or setup.finished
                or monotonic() >= setup.deadline
                or self.headers.get_all("Origin") != [setup.origin]):
            self.reply(403)
            return
        sizes = self.headers.get_all("Content-Length", [])
        if (self.headers.get_all("Content-Type") != ["application/x-www-form-urlencoded"]
                or self.headers.get("Transfer-Encoding") is not None or len(sizes) != 1
                or re.fullmatch(r"[0-9]{1,5}", sizes[0]) is None
                or not 0 < int(sizes[0]) <= FORM_LIMIT):
            self.reply(400)
            return
        try:
            raw = self.rfile.read(int(sizes[0]))
            if len(raw) != int(sizes[0]):
                raise ValueError("incomplete form")
            fields = parse_qs(raw.decode("ascii"),
                              keep_blank_values=True, strict_parsing=True,
                              errors="strict", max_num_fields=5)
            if (set(fields) != {"setup_key", "action", "organization", "username", "password"}
                    or any(len(values) != 1 for values in fields.values())):
                raise ValueError("invalid form")
            key, action, organization, username, password = (
                fields[name][0] for name in ("setup_key", "action", "organization", "username", "password")
            )
        except (UnicodeError, ValueError):
            self.reply(400)
            return
        if not key.isascii() or not secrets.compare_digest(key, setup.key) or monotonic() >= setup.deadline:
            self.reply(403, page("Setup link required", "<p>Return to the private welcome page and reopen setup.</p>"))
            return
        if (action not in {"create", "open"} or not 0 < len(password.encode("utf-8")) <= 1024
                or re.fullmatch(r"[a-z0-9][a-z0-9._@+\-]{2,253}", username.strip().lower()) is None):
            self.reply(400, form(key, message="Enter a valid username and password.", opening=action == "open"))
            return
        if action == "create":
            if setup.owner_created:
                self.reply(409, form(key, message="The owner is saved. Open the existing workbench.", opening=True, username=username))
                return
            if (not 1 <= len(organization.strip()) <= 100 or len(password) < 16
                    or any(ord(char) < 32 for char in organization)):
                self.reply(400, form(key, message="Enter an organization name and a password of at least 16 characters."))
                return
        try:
            if action == "create":
                setup.installation.start_db()
                setup.installation.check_network()
                setup.installation.operator("initialize", {
                    "organization": organization, "username": username, "password": password,
                })
                setup.owner_created = True
            result = setup.installation.open(password, username=username)
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
            message = setup.installation.setup_failure(exc)
            if setup.owner_created:
                message += " Your owner was saved. Choose Open an existing workbench to retry."
            self.reply(409, form(key, message=message, opening=setup.owner_created or action == "open",
                                 username=username))
            return
        setup.finished = True
        endpoint = escape(f"https://localhost:{setup.installation.config['port']}/claim")
        ticket = escape(result["ticket"])
        self.reply(200, page("Gabriel is ready", f"""
<p>Copy this one-time ticket, then open the workbench and paste it into the claim form promptly.</p>
<label for="ticket">Workbench ticket</label>
<input id="ticket" value="{ticket}" readonly autocomplete="off" spellcheck="false">
<p><a href="{endpoint}" target="_blank" rel="noopener noreferrer">Open Gabriel workbench</a></p>
<p>The ticket stays on this page. Keep it private.</p>"""))


class SetupServer(HTTPServer):
    def __init__(self, installation):
        tls = installation.root / "tls"
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(tls / "server.pem", tls / "server.key")
        self.installation = installation
        self.owner_created = False
        self.finished = False
        self.key = secrets.token_urlsafe(32)
        super().__init__(("127.0.0.1", 0), SetupHandler)
        self.authority = f"127.0.0.1:{self.server_port}"
        self.origin = f"https://{self.authority}"
        self.deadline = monotonic() + SETUP_SECONDS

    def get_request(self):
        client, address = super().get_request()
        try:
            client.settimeout(5)
            return self.context.wrap_socket(client, server_side=True), address
        except (OSError, ValueError):
            client.close()
            raise

    def handle_error(self, request, client_address):
        # Request traces can contain local setup authority.
        pass

    def run(self):
        while not self.finished:
            remaining = self.deadline - monotonic()
            if remaining <= 0:
                break
            self.timeout = min(remaining, 1)
            self.handle_request()


def launch(installation):
    certificate = installation.root / "tls" / "ca.pem"
    fingerprint = sha256(ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))).hexdigest().upper()
    fingerprint = ":".join(re.findall("..", fingerprint))
    with SetupServer(installation) as server, TemporaryDirectory(prefix="gabriel-setup-") as directory:
        welcome = Path(directory) / "Gabriel-Setup.html"
        welcome.write_text(page("Welcome to Gabriel Setup", f"""
<p>Your private Docker lab is prepared. Use the browser to create your owner and start Gabriel.</p>
<ol>
<li>On first use, open Keychain Access on Mac or your browser’s certificate settings.
 Import <a href="{escape(certificate.as_uri())}">this lab’s public certificate</a>
 from <code>{escape(str(certificate))}</code>.</li>
<li>Compare its SHA-256 fingerprint and approve trust for this certificate in your test environment.
 <p><code>{fingerprint}</code></p></li>
<li><a href="{server.origin}/#{server.key}">Continue to secure setup</a></li>
</ol>
<p>Enter your password only after the browser accepts the local certificate. This private setup link expires after 15 minutes.</p>
"""), encoding="utf-8")
        print(f"Opening Gabriel Setup. If needed, open {welcome} in your browser.", file=sys.stderr, flush=True)
        webbrowser.open(welcome.as_uri())
        server.run()
        return {"workbench_opened": server.finished, "production_admitted": False}
