"""Personal provider credentials are resolved only for their current human owner."""
from uuid import uuid4

from gabriel.identity.provider_onboarding import funding
from gabriel.identity.model_transport import OpenRouterTransport
from gabriel.identity.service import AccessDenied,_audit,connection
from gabriel.identity.vault import ProviderVault,ProviderCredential,_secret


class PersonalProviders:
    def __init__(self,vault):
        if not isinstance(vault,ProviderVault):raise ValueError('provider_vault_required')
        self.vault=vault

    def principal(self,conn,token):
        p=self.vault._principal(conn,token,lock=True)
        if p.role not in {'owner','admin','analyst'}:raise AccessDenied('personal_provider_writer_required')
        self.vault._active(conn,p)
        return p

    def configure(self,token,provider,value):
        if provider!='openrouter':raise AccessDenied('personal_provider_not_supported')
        value=_secret(value)
        with connection(self.vault._dsn) as conn:
            p=self.principal(conn,token)
            _audit(conn,'personal_provider.validation_started',p)
        client=OpenRouterTransport(ProviderCredential(value))
        funding(client.request('GET','/api/v1/key'),client.request('GET','/api/v1/credits'))
        with connection(self.vault._dsn) as conn:
            p=self.principal(conn,token)
            row=conn.execute('''SELECT * FROM gabriel_identity.personal_provider_secrets
                WHERE organization_id=%s AND user_id=%s AND provider=%s FOR UPDATE''',
                (p.organization_id,p.user_id,provider)).fetchone()
            row=dict(row) if row else dict(organization_id=p.organization_id,id=uuid4(),provider=provider,revision=0)
            row['revision']+=1
            kid,nonce,cipher=self.vault._encrypt(conn,row,value)
            conn.execute('''INSERT INTO gabriel_identity.personal_provider_secrets
                (organization_id,user_id,id,provider,revision,key_id,nonce,ciphertext,checked)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,true)
                ON CONFLICT (organization_id,user_id,provider) DO UPDATE SET
                revision=EXCLUDED.revision,key_id=EXCLUDED.key_id,nonce=EXCLUDED.nonce,
                ciphertext=EXCLUDED.ciphertext,checked=true,revoked_at=NULL,updated_at=clock_timestamp()''',
                (p.organization_id,p.user_id,row['id'],provider,row['revision'],kid,nonce,cipher))
            _audit(conn,'personal_provider.stored',p,row['id'])
            return dict(provider=provider,revision=row['revision'],status='funding_verified',scope='personal')

    def checked(self,conn,p,*,expected=None):
        row=conn.execute('''SELECT * FROM gabriel_identity.personal_provider_secrets
            WHERE organization_id=%s AND user_id=%s AND provider='openrouter'
            AND checked AND revoked_at IS NULL''',(p.organization_id,p.user_id)).fetchone()
        if not row or expected is not None and (row['id'],row['revision'])!=expected:
            raise AccessDenied('personal_provider_current_checked_key_required')
        return row

    def resolve(self,token):
        with connection(self.vault._dsn) as conn:
            p=self.principal(conn,token)
            row=self.checked(conn,p)
            value=ProviderCredential(self.vault._decrypt(conn,row))
            _audit(conn,'personal_provider.resolved',p,row['id'])
            return value,(row['id'],row['revision'])

    def status(self,token):
        with connection(self.vault._dsn) as conn:
            p=self.principal(conn,token)
            rows=conn.execute('''SELECT provider,revision,checked,revoked_at FROM gabriel_identity.personal_provider_secrets
                WHERE organization_id=%s AND user_id=%s''',(p.organization_id,p.user_id)).fetchall()
            _audit(conn,'personal_provider.status_read',p)
            return [dict(provider=r['provider'],revision=r['revision'],scope='personal',
                status='revoked' if r['revoked_at'] else 'funding_verified' if r['checked'] else 'validation_pending') for r in rows]

    def revoke(self,token,provider='openrouter'):
        if provider!='openrouter':raise AccessDenied('personal_provider_not_supported')
        with connection(self.vault._dsn) as conn:
            p=self.principal(conn,token)
            conn.execute('''UPDATE gabriel_identity.personal_provider_secrets SET checked=false,
                revoked_at=clock_timestamp(),nonce=NULL,ciphertext=NULL
                WHERE organization_id=%s AND user_id=%s AND provider=%s''',(p.organization_id,p.user_id,provider))
            _audit(conn,'personal_provider.revoked',p)
