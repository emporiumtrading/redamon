"""Human-approved browser pairing contracts; no external authentication, navigation or page collection."""
from dataclasses import dataclass,field
from hashlib import sha256
import re
import secrets
from urllib.parse import urlsplit,urlunsplit,unquote
from uuid import uuid4

from gabriel.identity.evidence_keys import EvidenceKeyService
from gabriel.identity.service import (AccessDenied,AuthenticationDenied,InvalidIdentityInput,Principal,
    _audit,_digest,connection,identifier)
from gabriel.identity.tasks import task_record,available

VERSION = '0.4.0'
SUPPORTED_VERSIONS = frozenset({'0.1.0','0.2.0','0.3.0',VERSION})
CONTEXT_FIELDS = {'browser','extension_version','installation_id','tab_id','document_id','page_url','account_label'}


@dataclass(frozen=True)
class BrowserCredential:
    id: object
    token: str = field(repr=False)
    expires_at: object


def browser_digest(token):
    if not isinstance(token,str) or not re.fullmatch(r'gbp1_[A-Za-z0-9_-]{43}',token):
        raise AuthenticationDenied('invalid_browser_credential')
    return sha256(('gabriel-browser-v1|'+token).encode()).hexdigest()


def approved_context(value):
    try:
        if (not isinstance(value,dict) or set(value)!=CONTEXT_FIELDS or value['browser'] not in {'chrome','brave'}
                or value['extension_version'] not in SUPPORTED_VERSIONS or type(value['tab_id']) is not int
                or not 0<=value['tab_id']<=2147483647 or not isinstance(value['page_url'],str)
                or not 9<=len(value['page_url'])<=2048 or not isinstance(value['account_label'],str)
                or not 1<=len(value['account_label'])<=64 or any(ord(c)<32 or ord(c)==127 for c in value['account_label'])):
            raise ValueError
        result = dict(value)
        for key in ('installation_id','document_id'):
            result[key]=str(identifier(value[key]))
        url = urlsplit(value['page_url'])
        decoded = value['page_url']
        for _ in range(4):
            following = unquote(decoded,errors='strict')
            if following==decoded:
                break
            decoded = following
        if unquote(decoded,errors='strict')!=decoded:
            raise ValueError
        if (url.scheme!='https' or not url.hostname or url.username is not None or url.password is not None
                or url.query or '?' in decoded or '\\' in decoded
                or any(c in unquote(url.fragment,errors='strict') for c in ('=','&'))
                or ('#' in decoded and any(c in decoded.split('#',1)[1] for c in ('=','&')))
                or any(ord(c)<33 or ord(c)==127 for c in decoded)):
            raise ValueError
        url.port
        expected = urlunsplit(('https',url.netloc.lower(),url.path or '/','',url.fragment))
        if expected!=value['page_url'] or any(x in decoded.lower() for x in ('/login','/signin','/sign-in','/oauth','/sso','/mfa','/password','/authorize')):
            raise ValueError
        return result
    except (ValueError,TypeError,KeyError,AttributeError):
        raise InvalidIdentityInput('invalid_browser_context') from None


def lease_metadata(row):
    return {k:v for k,v in row.items() if k not in {'token_digest','human_session_digest','role'}}


class BrowserSessionService(EvidenceKeyService):
    def create_browser_task(self,token,name,ttl_seconds=900,max_steps=20):
        if (not isinstance(name,str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._ -]{0,79}',name)
                or type(ttl_seconds) is not int or not 60<=ttl_seconds<=3600
                or type(max_steps) is not int or not 1<=max_steps<=1000):
            raise InvalidIdentityInput('invalid_browser_task')
        with connection(self._dsn) as conn:
            p = self._human(conn,token,write=True)
            if conn.execute("SELECT count(*) AS n FROM gabriel_identity.investigation_tasks WHERE organization_id=%s AND state='active' AND expires_at>clock_timestamp()",
                    (p.organization_id,)).fetchone()['n']>=100:
                raise AccessDenied('active_task_limit')
            row = conn.execute('''INSERT INTO gabriel_identity.investigation_tasks
                (organization_id,id,created_by,name,resource,operations,max_steps,created_at,expires_at)
                SELECT %s,%s,%s,%s,'browser-observation-v1',ARRAY['browser.observe'],%s,t,t+%s*interval '1 second'
                FROM (SELECT clock_timestamp() AS t) admitted RETURNING *''',
                (p.organization_id,uuid4(),p.user_id,name,max_steps,ttl_seconds)).fetchone()
            _audit(conn,'browser.task_created',p,row['id'])
            return row

    def issue_browser_lease(self,token,task_id,case_id,context,ttl_seconds=300,*,share_observations=False,monitoring_approved=False):
        context = approved_context(context)
        if (type(ttl_seconds) is not int or type(monitoring_approved) is not bool
                or not 60<=ttl_seconds<=(3600 if monitoring_approved else 300) or type(share_observations) is not bool
                or monitoring_approved and not share_observations):
            raise InvalidIdentityInput('invalid_browser_lifetime')
        secret = 'gbp1_'+secrets.token_urlsafe(32)
        with connection(self._dsn) as conn:
            p = self._human(conn,token,write=True)
            case = self._case(conn,p,case_id,open_only=True)
            task = task_record(conn,p.organization_id,task_id)
            available(task)
            if task['resource']!='browser-observation-v1' or task['operations']!=['browser.observe']:
                raise AccessDenied('browser_task_required')
            if conn.execute("SELECT count(*) AS n FROM gabriel_identity.browser_leases WHERE organization_id=%s AND state<>'disconnected' AND expires_at>clock_timestamp()",
                    (p.organization_id,)).fetchone()['n']>=32:
                raise AccessDenied('browser_lease_limit')
            self._principal(conn,token,lock=True)
            session = conn.execute('SELECT expires_at FROM gabriel_identity.sessions WHERE token_digest=%s',(_digest(token),)).fetchone()
            row = conn.execute('''INSERT INTO gabriel_identity.browser_leases
                (organization_id,id,token_digest,issued_by,human_session_digest,task_id,case_id,browser,extension_version,
                 installation_id,tab_id,document_id,page_url,account_label,intake_enabled,scheduled_review_enabled,created_at,expires_at)
                SELECT %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,t,LEAST(t+%s*interval '1 second',%s,%s)
                FROM (SELECT clock_timestamp() AS t) admitted RETURNING *''',
                (p.organization_id,uuid4(),browser_digest(secret),p.user_id,_digest(token),task['id'],case['id'],context['browser'],
                 context['extension_version'],context['installation_id'],context['tab_id'],context['document_id'],context['page_url'],
                 context['account_label'],share_observations,monitoring_approved,ttl_seconds,task['expires_at'],session['expires_at'])).fetchone()
            conn.execute('INSERT INTO gabriel_identity.case_tasks VALUES (%s,%s,%s) ON CONFLICT DO NOTHING',(p.organization_id,case['id'],task['id']))
            _audit(conn,'browser.lease_issued',p,row['id'])
            return BrowserCredential(row['id'],secret,row['expires_at'])

    def _browser(self,conn,token,*,pending=False):
        hashed = browser_digest(token)
        org = conn.execute('SELECT organization_id FROM gabriel_identity.browser_leases WHERE token_digest=%s',(hashed,)).fetchone()
        if not org:
            raise AuthenticationDenied('invalid_browser_credential')
        conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,73582302))',(str(org['organization_id']),))
        row = conn.execute('''SELECT l.*,m.role FROM gabriel_identity.browser_leases l
            JOIN gabriel_identity.sessions s ON s.token_digest=l.human_session_digest AND s.organization_id=l.organization_id AND s.user_id=l.issued_by
            JOIN gabriel_identity.memberships m ON (m.organization_id,m.user_id)=(s.organization_id,s.user_id)
            JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
            WHERE l.token_digest=%s AND l.state<>'disconnected' AND l.expires_at>clock_timestamp()
                AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.active AND u.active
                AND m.role IN ('owner','admin','analyst') FOR UPDATE OF l,s,m,u''',(hashed,)).fetchone()
        if not row or (not pending and row['state']!='active'):
            raise AuthenticationDenied('invalid_browser_credential')
        p = Principal(row['organization_id'],row['issued_by'],row['role'])
        task = task_record(conn,p.organization_id,row['task_id'])
        available(task,replay=True)
        if task['resource']!='browser-observation-v1' or task['operations']!=['browser.observe']:
            raise AccessDenied('browser_task_required')
        self._case(conn,p,row['case_id'],open_only=True)
        return p,row

    def _browser_context(self,row,context):
        context = approved_context(context)
        if any(str(row[k])!=str(v) for k,v in context.items()):
            raise AccessDenied('browser_context_changed')

    def connect_browser(self,token,context):
        with connection(self._dsn) as conn:
            p,row = self._browser(conn,token,pending=True)
            self._browser_context(row,context)
            if row['state']=='active':
                now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
                if not row['last_seen'] or not 0<=(now-row['last_seen']).total_seconds()<=45:
                    raise AccessDenied('browser_heartbeat_gap_repair_required')
            else:
                conn.execute("UPDATE gabriel_identity.browser_leases SET state='active',last_seen=clock_timestamp() WHERE organization_id=%s AND id=%s",(p.organization_id,row['id']))
            _audit(conn,'browser.paired',p,row['id'])
            return {'lease_id':str(row['id']),'paired':True,'expires_at':row['expires_at'],
                'scheduled_review_enabled':row['scheduled_review_enabled'],'capabilities':['session.heartbeat','session.disconnect'],'page_content_received':False}

    def heartbeat_browser(self,token,context):
        with connection(self._dsn) as conn:
            p,row = self._browser(conn,token)
            self._browser_context(row,context)
            now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
            if not row['last_seen'] or not 0<=(now-row['last_seen']).total_seconds()<=45:
                raise AccessDenied('browser_heartbeat_gap_repair_required')
            conn.execute('UPDATE gabriel_identity.browser_leases SET last_seen=%s WHERE organization_id=%s AND id=%s',(now,p.organization_id,row['id']))
            _audit(conn,'browser.heartbeat',p,row['id'])
            return {'lease_id':str(row['id']),'heartbeat_at':now,'page_content_received':False}

    def disconnect_browser(self,token):
        with connection(self._dsn) as conn:
            p,row = self._browser(conn,token,pending=True)
            conn.execute("UPDATE gabriel_identity.browser_leases SET state='disconnected' WHERE organization_id=%s AND id=%s",(p.organization_id,row['id']))
            _audit(conn,'browser.disconnected',p,row['id'])

    def revoke_browser_lease(self,token,lease_id):
        with connection(self._dsn) as conn:
            p = self._human(conn,token,write=True)
            row = conn.execute('SELECT * FROM gabriel_identity.browser_leases WHERE organization_id=%s AND id=%s FOR UPDATE',
                (p.organization_id,identifier(lease_id))).fetchone()
            if not row or p.role not in {'owner','admin'} and p.user_id!=row['issued_by']:
                raise AccessDenied('browser_lease_not_accessible')
            if row['state']!='disconnected':
                conn.execute("UPDATE gabriel_identity.browser_leases SET state='disconnected' WHERE organization_id=%s AND id=%s",(p.organization_id,row['id']))
            _audit(conn,'browser.revoked',p,row['id'])

    def get_browser_lease(self,token,lease_id):
        with connection(self._dsn) as conn:
            p = self._human(conn,token)
            row = conn.execute('SELECT * FROM gabriel_identity.browser_leases WHERE organization_id=%s AND id=%s',
                (p.organization_id,identifier(lease_id))).fetchone()
            if not row:
                raise AccessDenied('browser_lease_not_accessible')
            session = conn.execute('''SELECT 1 FROM gabriel_identity.sessions s
                JOIN gabriel_identity.memberships m USING (organization_id,user_id)
                JOIN gabriel_identity.users u ON (u.organization_id,u.id)=(m.organization_id,m.user_id)
                WHERE s.organization_id=%s AND s.user_id=%s AND s.token_digest=%s AND s.revoked_at IS NULL
                    AND s.expires_at>clock_timestamp() AND m.active AND u.active AND m.role IN ('owner','admin','analyst')''',
                (p.organization_id,row['issued_by'],row['human_session_digest'])).fetchone()
            task = task_record(conn,p.organization_id,row['task_id'])
            case = self._case(conn,p,row['case_id'])
            now = conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
            result = lease_metadata(row)
            result['authorization_current'] = bool(session and row['expires_at']>now and row['state']!='disconnected'
                and task['creator_authorized'] and not task['expired'] and task['state'] in {'active','exhausted'} and case['state']=='open'
                and task['resource']=='browser-observation-v1' and task['operations']==['browser.observe'])
            result['heartbeat_fresh'] = bool(row['last_seen'] and 0<=(now-row['last_seen']).total_seconds()<=45)
            result['page_content_received'] = False
            return result
