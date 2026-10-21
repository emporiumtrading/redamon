"""Backend transition protocol; no console contract is production-admitted.

A separate explicit navigation grant adds bounded navigation authority to the
paired observation task. This service never drives a browser or authenticates
to an external system; completion is an unverified browser context claim.
"""
from urllib.parse import urlsplit
from uuid import uuid4

from psycopg.types.json import Jsonb

from gabriel.identity.browser_observations import BrowserObservationService
from gabriel.identity.browser_sessions import CONTEXT_FIELDS,approved_context
from gabriel.identity.cases import iso
from gabriel.identity.service import AccessDenied,InvalidIdentityInput,_audit,_digest,connection,identifier
from gabriel.identity.specialist_contracts import digest
from gabriel.identity.tasks import task_record,available

CONTRACTS={}


def context_of(row):
    return approved_context({key:str(row[key]) if key in {'document_id','installation_id'} else row[key] for key in CONTEXT_FIELDS})


def pending_navigation(conn,organization_id,lease_id):
    return conn.execute('''SELECT i.id FROM gabriel_identity.browser_navigation_intents i
        JOIN gabriel_identity.browser_navigation_grants g ON (g.organization_id,g.id)=(i.organization_id,i.grant_id)
        WHERE g.organization_id=%s AND g.lease_id=%s AND NOT EXISTS
        (SELECT 1 FROM gabriel_identity.browser_navigation_commits c
         WHERE (c.organization_id,c.intent_id)=(i.organization_id,i.id)) LIMIT 1''',(organization_id,lease_id)).fetchone()


def contract(version,urls,context):
    if not isinstance(version,str) or version not in CONTRACTS:
        raise AccessDenied('navigation_contract_not_admitted')
    if type(urls) is not list or not 1<=len(urls)<=20 or any(type(url) is not str for url in urls) or len(set(urls))!=len(urls):
        raise InvalidIdentityInput('invalid_navigation_destinations')
    original=urlsplit(context['page_url'])
    for url in urls:
        approved_context(dict(context,page_url=url))
        parsed=urlsplit(url)
        path=parsed.path+('#'+parsed.fragment if parsed.fragment else '')
        if (parsed.scheme,parsed.netloc)!=(original.scheme,original.netloc) or path not in CONTRACTS[version]:
            raise AccessDenied('navigation_destination_not_admitted')
    return urls


def public_intent(row,committed=False):
    return dict(id=str(row['id']),grant_id=str(row['grant_id']),sequence=row['sequence'],
        destination_url=row['destination_url'],source_context=row['source_context'],expires_at=iso(row['expires_at']),
        state='completed' if committed else 'prepared',dispatch_performed=False,source_verified=False)


class BrowserNavigationService(BrowserObservationService):
    def _actor(self,conn,human,peer):
        preliminary=self._principal(conn,human)
        from gabriel.identity.browser_sessions import browser_digest
        hint=conn.execute('SELECT organization_id,issued_by,human_session_digest FROM gabriel_identity.browser_leases WHERE token_digest=%s',
                          (browser_digest(peer),)).fetchone()
        if not hint or (hint['organization_id'],hint['issued_by'],hint['human_session_digest'])!=(preliminary.organization_id,preliminary.user_id,_digest(human)):
            raise AccessDenied('navigation_original_operator_required')
        p=self._human(conn,human,write=True)
        _,lease=self._browser(conn,peer)
        if lease['organization_id']!=p.organization_id or lease['issued_by']!=p.user_id or lease['human_session_digest']!=_digest(human):
            raise AccessDenied('navigation_original_operator_required')
        return p,lease

    def _grant(self,conn,p,lease):
        grant=conn.execute('SELECT * FROM gabriel_identity.browser_navigation_grants WHERE organization_id=%s AND lease_id=%s',
            (p.organization_id,lease['id'])).fetchone()
        at=conn.execute('SELECT clock_timestamp() AS t').fetchone()['t']
        if not grant or grant['expires_at']<=at or conn.execute('SELECT 1 FROM gabriel_identity.browser_navigation_stops WHERE organization_id=%s AND grant_id=%s',
                                                             (p.organization_id,grant['id'])).fetchone():
            raise AccessDenied('navigation_grant_not_active')
        contract(grant['contract_version'],grant['destinations'],context_of(lease))
        return grant,at

    def grant_navigation(self,human,peer,request_id,version,destinations,*,max_moves=10):
        request_id=identifier(request_id)
        if type(max_moves) is not int or not 1<=max_moves<=20: raise InvalidIdentityInput('invalid_navigation_limit')
        with connection(self._dsn) as conn:
            p,lease=self._actor(conn,human,peer)
            task=task_record(conn,p.organization_id,lease['task_id']);available(task)
            contract(version,destinations,context_of(lease))
            old=conn.execute('SELECT * FROM gabriel_identity.browser_navigation_grants WHERE organization_id=%s AND lease_id=%s',
                (p.organization_id,lease['id'])).fetchone()
            if old:
                if (old['request_id'],old['contract_version'],old['destinations'],old['max_moves'])!=(request_id,version,destinations,max_moves):
                    raise AccessDenied('navigation_grant_conflict')
                _audit(conn,'browser.navigation_grant_replayed',p,old['id'])
                return dict(id=str(old['id']),max_moves=old['max_moves'],expires_at=iso(old['expires_at']))
            row=conn.execute('''INSERT INTO gabriel_identity.browser_navigation_grants
                (organization_id,id,lease_id,request_id,created_by,contract_version,destinations,initial_context_digest,max_moves,expires_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''',
                (p.organization_id,uuid4(),lease['id'],request_id,p.user_id,version,Jsonb(destinations),digest(context_of(lease)),max_moves,lease['expires_at'])).fetchone()
            _audit(conn,'browser.navigation_granted',p,row['id'])
            return dict(id=str(row['id']),max_moves=max_moves,expires_at=iso(row['expires_at']))

    def prepare_navigation(self,human,peer,request_id,destination_url):
        request_id=identifier(request_id)
        with connection(self._dsn) as conn:
            p,lease=self._actor(conn,human,peer)
            grant,at=self._grant(conn,p,lease)
            if destination_url not in grant['destinations']: raise AccessDenied('navigation_destination_not_granted')
            old=conn.execute('SELECT * FROM gabriel_identity.browser_navigation_intents WHERE organization_id=%s AND grant_id=%s AND request_id=%s',
                (p.organization_id,grant['id'],request_id)).fetchone()
            if old:
                if old['requested_by']!=p.user_id or old['destination_url']!=destination_url: raise AccessDenied('navigation_request_conflict')
                committed=conn.execute('SELECT 1 FROM gabriel_identity.browser_navigation_commits WHERE organization_id=%s AND intent_id=%s',
                    (p.organization_id,old['id'])).fetchone()
                _audit(conn,'browser.navigation_intent_replayed',p,old['id'])
                return public_intent(old,bool(committed))
            available(task_record(conn,p.organization_id,lease['task_id']))
            if pending_navigation(conn,p.organization_id,lease['id']): raise AccessDenied('navigation_outcome_unresolved')
            if not lease['last_seen'] or not 0<=(at-lease['last_seen']).total_seconds()<=45:
                raise AccessDenied('browser_heartbeat_gap_repair_required')
            if destination_url==lease['page_url']: raise AccessDenied('navigation_already_at_destination')
            count=conn.execute('SELECT count(*) AS n FROM gabriel_identity.browser_navigation_intents WHERE organization_id=%s AND grant_id=%s',
                (p.organization_id,grant['id'])).fetchone()['n']
            if count>=grant['max_moves']: raise AccessDenied('navigation_move_limit')
            row=conn.execute('''INSERT INTO gabriel_identity.browser_navigation_intents
                (organization_id,id,grant_id,request_id,requested_by,sequence,source_context,destination_url,expires_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,LEAST(%s,%s+interval '30 seconds')) RETURNING *''',
                (p.organization_id,uuid4(),grant['id'],request_id,p.user_id,count+1,Jsonb(context_of(lease)),destination_url,grant['expires_at'],at)).fetchone()
            _audit(conn,'browser.navigation_prepared',p,row['id'])
            return public_intent(row)

    def complete_navigation(self,human,peer,intent_id,context):
        intent_id=identifier(intent_id);context=approved_context(context)
        with connection(self._dsn) as conn:
            p,lease=self._actor(conn,human,peer)
            grant,at=self._grant(conn,p,lease)
            intent=conn.execute('SELECT * FROM gabriel_identity.browser_navigation_intents WHERE organization_id=%s AND grant_id=%s AND id=%s',
                (p.organization_id,grant['id'],intent_id)).fetchone()
            if not intent: raise AccessDenied('navigation_intent_not_accessible')
            expected=dict(intent['source_context'],page_url=intent['destination_url'],document_id=context['document_id'])
            if context!=expected: raise AccessDenied('navigation_result_scope_mismatch')
            old=conn.execute('SELECT * FROM gabriel_identity.browser_navigation_receipts WHERE organization_id=%s AND intent_id=%s',
                (p.organization_id,intent_id)).fetchone()
            if old:
                if old['context']!=context or old['context_digest']!=digest(context): raise AccessDenied('navigation_receipt_conflict')
                if not conn.execute('SELECT 1 FROM gabriel_identity.browser_navigation_commits WHERE organization_id=%s AND intent_id=%s',
                                    (p.organization_id,intent_id)).fetchone():
                    raise AccessDenied('navigation_receipt_not_committed')
                _audit(conn,'browser.navigation_receipt_replayed',p,intent_id)
                return dict(intent_id=str(intent_id),context=context,current=context==context_of(lease),replayed=True,source_verified=False)
            if intent['expires_at']<=at or intent['source_context']!=context_of(lease): raise AccessDenied('navigation_intent_not_current')
            conn.execute('''INSERT INTO gabriel_identity.browser_navigation_receipts
                (organization_id,intent_id,context,context_digest,completed_by) VALUES (%s,%s,%s,%s,%s)''',
                (p.organization_id,intent_id,Jsonb(context),digest(context),p.user_id))
            conn.execute('SELECT gabriel_identity.apply_browser_navigation(%s,%s)',(p.organization_id,intent_id))
            _audit(conn,'browser.navigation_completed',p,intent_id)
            return dict(intent_id=str(intent_id),context=context,current=True,replayed=False,source_verified=False)

    def stop_navigation(self,human,peer):
        with connection(self._dsn) as conn:
            p,lease=self._actor(conn,human,peer)
            grant,_=self._grant(conn,p,lease)
            conn.execute('INSERT INTO gabriel_identity.browser_navigation_stops (organization_id,grant_id,stopped_by) VALUES (%s,%s,%s)',
                (p.organization_id,grant['id'],p.user_id))
            conn.execute("UPDATE gabriel_identity.browser_leases SET state='disconnected' WHERE organization_id=%s AND id=%s",(p.organization_id,lease['id']))
            _audit(conn,'browser.navigation_stopped',p,grant['id'])
            return dict(stopped=True)
