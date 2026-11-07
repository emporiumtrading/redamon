"""Private, short-lived browser setup for the local Docker installation."""
from hashlib import sha256
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from urllib.parse import parse_qs
from uuid import UUID
import webbrowser

from gabriel_provider_keys import unique

SETUP_SECONDS = 900
FORM_LIMIT = 16384
# Same-origin form posts need a usable Origin header for the setup check.
REFERRER_POLICY = "same-origin"
TRUST_REQUIRED = "<p>Return to Gabriel Setup and verify this lab’s certificate in Keychain Access.</p>"
OPERATION_ERRORS = (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError)
SCRIPT = """
const form = document.querySelector('#start-form');
const action = document.querySelector('#action');
const organization = document.querySelector('#organization');
const password = document.querySelector('#password');
if (location.hash) {
  for (const field of document.querySelectorAll('input[name="setup_key"]')) {
    field.value = location.hash.slice(1);
  }
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
small { color: #e7c88a; font-weight: 700 }
h1 { line-height: 1.15 }
a { color: #b7d5fa }
code { overflow-wrap: anywhere }
label { display: block; margin: 1rem 0 .3rem }
input, select, textarea, button { font: inherit; padding: .65rem; border-radius: .4rem }
input, select, textarea { width: 100%; background: #0d1421; color: inherit; border: 1px solid #748ba7 }
button { margin-top: 1.2rem; background: #e7c88a; color: #292011; border: 0; font-weight: 700 }
button:disabled { opacity: .65 }
textarea { min-height: 8rem; resize: vertical }
input[type="checkbox"] { width: auto }
li { margin-bottom: .6rem }
nav { display: flex; flex-wrap: wrap; gap: .7rem }
[role="alert"] { border-left: .2rem solid #ffca8c; padding-left: .8rem }
"""


def page(title, body):
    return f"""<!doctype html>
<html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="{REFERRER_POLICY}">
<title>{escape(title)} | Gabriel</title><style>{STYLE}</style>
<main><small>GABRIEL — THE DEFENDER</small><h1>{escape(title)}</h1>
{body}
</main></html>"""


def mac_tls_trusted(certificate):
    # Use Keychain trust for both loopback names without supplying our own trust anchor.
    try:
        return all(subprocess.run(
            ["/usr/bin/security", "verify-cert", "-L", "-q", "-p", "ssl", "-n", host, "-c", str(certificate)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False,
        ).returncode == 0 for host in ("127.0.0.1", "localhost"))
    except (OSError, subprocess.TimeoutExpired):
        return False


def setup_key(key):
    return f'<input type="hidden" name="setup_key" value="{escape(key)}">'


def navigation(key, *, pair=False):
    options = {'/pairing': 'Connect Chrome or Brave'} if pair else {'/': 'Back to setup'}
    options['/finish'] = 'Finish setup'
    return '<nav aria-label="Setup actions">' + ''.join(
        f'<form method="post" action="{path}">{setup_key(key)}<button type="submit">{label}</button></form>'
        for path, label in options.items()
    ) + '</nav>'


def form(key="", *, message="", opening=False, username="owner"):
    alert = f'<p role="alert">{escape(message)}</p>' if message else ""
    selected = " selected" if opening else ""
    return page("Set up your private lab", f"""
<p>Choose how to start your local Gabriel workbench.</p>
{alert}
<form id="start-form" method="post" action="/start">
{setup_key(key)}
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
<details>
<summary>Optional AI connection</summary>
<label><input type="checkbox" name="ai_egress" value="yes">Allow access to Gabriel’s configured AI provider</label>
<p>AI investigations also require an approved model, your own provider key and spending controls.</p>
</details>
<button type="submit">Start Gabriel</button>
<p id="progress" role="status"></p>
</form>
{navigation(key, pair=True)}
<noscript><p>Enable JavaScript for this local page to use your private setup link.</p></noscript>
<script src="/setup.js"></script>""")


def browser_form(key, *, message=""):
    alert = f'<p role="alert">{escape(message)}</p>' if message else ""
    return page("Connect Chrome or Brave", f"""
{alert}
<ol>
<li>Open a case in your active Gabriel workbench. Copy the case ID from its address.</li>
<li>In your dedicated Chrome or Brave profile, open the browser’s Extensions page, enable Developer mode,
 and choose <strong>Load unpacked</strong>. Select <code>gabriel/browser_extension</code> in your Gabriel checkout.</li>
<li>Open the approved console tab and sign in yourself. Open the Gabriel extension, select the browser
 and current tab, and copy its extension origin and generated context.</li>
</ol>
<form method="post" action="/pair">
{setup_key(key)}
<label for="case">Case ID</label>
<input id="case" name="case_id" required maxlength="36" spellcheck="false">
<label for="extension">Extension origin</label>
<input id="extension" name="extension_origin" required maxlength="51" placeholder="chrome-extension://…"
 autocomplete="off" spellcheck="false">
<label for="context">Generated tab context (JSON)</label>
<textarea id="context" name="context" required maxlength="4096" spellcheck="false"></textarea>
<label><input type="checkbox" name="share" value="yes">Allow reviewed observations to be shared with this case</label>
<p>Pairing is limited to the selected tab and expires after at most five minutes.
 Starting a new connection replaces the previous one. You approve the Gabriel site permission in the extension.</p>
<button type="submit">Generate pairing ticket</button>
</form>
{navigation(key)}""")


class SetupHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body="", content_type="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", REFERRER_POLICY)
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
            if self.server.trust_ready():
                self.reply(200, form())
            else:
                self.reply(403, page("Certificate trust required", TRUST_REQUIRED))
        elif self.path == "/setup.js":
            self.reply(200, SCRIPT, "application/javascript; charset=utf-8")
        else:
            self.reply(404)

    def do_POST(self):
        setup = self.server
        required = {
            "/": {"setup_key"},
            "/finish": {"setup_key"},
            "/pairing": {"setup_key"},
            "/pair": {"setup_key", "case_id", "extension_origin", "context"},
            "/start": {"setup_key", "action", "organization", "username", "password"},
        }.get(self.path)
        if (required is None or not self.local_request() or setup.finished
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
                              errors="strict", max_num_fields=6)
            optional = {"/pair": "share", "/start": "ai_egress"}.get(self.path)
            allowed = (required, required | {optional}) if optional else (required,)
            if set(fields) not in allowed or any(len(values) != 1 for values in fields.values()):
                raise ValueError("invalid form")
            fields = {name: values[0] for name, values in fields.items()}
        except (UnicodeError, ValueError):
            self.reply(400)
            return
        key = fields["setup_key"]
        if not key.isascii() or not secrets.compare_digest(key, setup.key) or monotonic() >= setup.deadline:
            self.reply(403, page("Setup link required", "<p>Return to the private welcome page and reopen setup.</p>"))
            return
        if self.path != "/finish" and not setup.trust_ready():
            self.reply(403, page("Certificate trust required", TRUST_REQUIRED))
            return
        if self.path == "/":
            self.reply(200, form(key, opening=setup.workbench_opened or setup.owner_created))
        elif self.path == "/finish":
            setup.finished = True
            self.reply(200, page("Setup complete", "<p>You can close this tab. Open the Gabriel launcher again to return.</p>"))
        elif self.path == "/pairing":
            self.reply(200, browser_form(key))
        elif self.path == "/pair":
            self.pair_browser(fields)
        else:
            self.start_workbench(fields)

    def pair_browser(self, fields):
        setup = self.server
        key = fields["setup_key"]
        try:
            case_id = str(UUID(fields["case_id"].strip()))
            origin = fields["extension_origin"].strip()
            share = fields.get("share", "")
            context = json.loads(fields["context"], object_pairs_hook=unique)
            if (not re.fullmatch(r"chrome-extension://[a-p]{32}", origin) or share not in {"", "yes"}
                    or not isinstance(context, dict) or len(fields["context"]) > 4096 or set(context) != {
                        "browser", "extension_version", "installation_id", "tab_id", "document_id",
                        "page_url", "account_label",
                    } or context["browser"] not in ("chrome", "brave")
                    or type(context["tab_id"]) is not int
                    or any(not isinstance(context[name], str) for name in context if name != "tab_id")):
                raise ValueError("invalid browser pairing form")
        except (ValueError, RecursionError):
            self.reply(400, browser_form(key, message="Check the case ID, extension origin and generated tab context."))
            return
        try:
            port = 8445 if setup.installation.config["port"] == 8443 else 8443
            with setup.installation.operation():
                result = setup.installation.browser_open(case_id, context, origin, port=port,
                                                         share_observations=share == "yes")
        except OPERATION_ERRORS as exc:
            message = setup.installation.setup_failure(exc)
            self.reply(409, browser_form(key, message=message + " Open the workbench again if your session has expired."))
            return
        setup.finished = True
        ticket = escape(result["ticket"])
        endpoint = escape(result["endpoint"])
        self.reply(200, page("Finish pairing in your browser", f"""
<p>In the Gabriel extension, enter the endpoint, approve its site permission and claim with the ticket promptly.</p>
<label for="endpoint">Gabriel endpoint</label>
<input id="endpoint" value="{endpoint}" readonly spellcheck="false">
<label for="ticket">Browser pairing ticket</label>
<input id="ticket" value="{ticket}" readonly autocomplete="off" spellcheck="false">
<p>Preview the selected page before sharing. Return to <strong>Browser health</strong> in your workbench to confirm the connection.</p>
<p>Use Pause or Stop in the extension to control sharing.</p>"""))

    def start_workbench(self, fields):
        setup = self.server
        key, action, organization, username, password = (
            fields[name] for name in ("setup_key", "action", "organization", "username", "password")
        )
        ai_egress = fields.get("ai_egress", "")
        if (action not in {"create", "open"} or ai_egress not in {"", "yes"}
                or not 0 < len(password.encode("utf-8")) <= 1024
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
            with setup.installation.operation():
                setup.installation.require_transport()
                if action == "create":
                    setup.installation.start_db()
                    setup.installation.check_network()
                    setup.installation.operator("initialize", {
                        "organization": organization, "username": username, "password": password,
                    })
                    setup.owner_created = True
                result = setup.installation.open(password, username=username, ai_egress=ai_egress == "yes")
        except OPERATION_ERRORS as exc:
            message = setup.installation.setup_failure(exc)
            if setup.owner_created:
                message += " Your owner was saved. Choose Open an existing workbench to retry."
            self.reply(409, form(key, message=message, opening=setup.owner_created or action == "open",
                                 username=username))
            return
        setup.workbench_opened = True
        endpoint = escape(f"https://localhost:{setup.installation.config['port']}/claim")
        ticket = escape(result["ticket"])
        self.reply(200, page("Gabriel is ready", f"""
<p>Copy this one-time ticket, then open the workbench and paste it into the claim form promptly.</p>
<label for="ticket">Workbench ticket</label>
<input id="ticket" value="{ticket}" readonly autocomplete="off" spellcheck="false">
<p><a href="{endpoint}" target="_blank" rel="noopener noreferrer">Open Gabriel workbench</a></p>
<p>If the link is denied, paste <code>{endpoint}</code> into a new tab. Keep the ticket private.</p>
<p>Create a case in the workbench, then return here to connect your browser. If you only need local tools, choose Finish setup.</p>
{navigation(key, pair=True)}"""))


class SetupServer(HTTPServer):
    def __init__(self, installation):
        tls = installation.root / "tls"
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.certificate = tls / "server.pem"
        self.certificate_digest = sha256(self.certificate.read_bytes()).digest()
        self.context.load_cert_chain(self.certificate, tls / "server.key")
        self.requires_system_trust = sys.platform == "darwin"
        self.installation = installation
        self.owner_created = False
        self.workbench_opened = False
        self.finished = False
        self.key = secrets.token_urlsafe(32)
        super().__init__(("127.0.0.1", 0), SetupHandler)
        self.authority = f"127.0.0.1:{self.server_port}"
        self.origin = f"https://{self.authority}"
        self.deadline = monotonic() + SETUP_SECONDS

    def trust_ready(self):
        if not self.requires_system_trust:
            return True
        try:
            # A certificate rotation requires a fresh listener and setup link.
            return (sha256(self.certificate.read_bytes()).digest() == self.certificate_digest
                    and mac_tls_trusted(self.certificate))
        except OSError:
            return False

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


def open_local_page(path, title, body):
    path.write_text(page(title, body), encoding="utf-8")
    print(f"Opening {title}. If needed, open {path} in your browser.", file=sys.stderr, flush=True)
    webbrowser.open(path.as_uri())


def launch(installation):
    installation.require_transport()
    certificate = installation.root / "tls" / "ca.pem"
    fingerprint = sha256(ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))).hexdigest().upper()
    fingerprint = ":".join(re.findall("..", fingerprint))
    public_ca = f'<a href="{escape(certificate.as_uri())}">this lab’s public CA certificate</a>'
    ca_path = escape(str(certificate))
    with TemporaryDirectory(prefix="gabriel-setup-") as directory:
        guide = Path(directory)
        if sys.platform == "darwin":
            leaf = certificate.with_name("server.pem")
            if not mac_tls_trusted(leaf):
                open_local_page(guide / "Gabriel-Trust.html", "Trust your Gabriel certificate", f"""
<p>Gabriel is waiting for macOS to verify HTTPS for this installation.</p>
<ol>
<li>Open <strong>Keychain Access</strong> and select the <strong>login</strong> keychain.
 Use <strong>File → Import Items</strong> to import {public_ca} from <code>{ca_path}</code>.</li>
<li>Open the imported <strong>Gabriel private test installation CA</strong>.
 Confirm its SHA-256 fingerprint matches <code>{fingerprint}</code>.</li>
<li>Under <strong>Trust</strong>, set <strong>Secure Sockets Layer (SSL)</strong> to <strong>Always Trust</strong>.
 Close the certificate details and approve the macOS prompt if it appears.</li>
</ol>
<p>Gabriel opens the next page once macOS confirms trust. Keep the launcher open while you finish this step.</p>
""")
                deadline = monotonic() + SETUP_SECONDS
                while monotonic() < deadline and not mac_tls_trusted(leaf):
                    sleep(2)
                if monotonic() >= deadline:
                    print("Certificate trust was not confirmed. Open Gabriel Setup again to retry.", file=sys.stderr)
                    return {"workbench_opened": False, "certificate_trust_confirmed": False,
                            "production_admitted": False}
            guidance = "<p>macOS verified the certificate for this local installation.</p>"
        else:
            guidance = f"""
<p>On first use, use the certificate settings for your test browser to trust {public_ca}
 at <code>{ca_path}</code>. Verify its SHA-256 fingerprint matches <code>{fingerprint}</code>.</p>
"""
        with SetupServer(installation) as server:
            open_local_page(guide / "Gabriel-Setup.html", "Welcome to Gabriel Setup", f"""
<p>Your private Docker lab is prepared. Use the browser to create your owner and start Gabriel.</p>
{guidance}
<p><a href="{server.origin}/#{server.key}">Continue to secure setup</a></p>
<p>Enter your password only when the browser accepts the certificate. This private setup link expires after 15 minutes.</p>
""")
            server.run()
            return {"workbench_opened": server.workbench_opened, "production_admitted": False}
