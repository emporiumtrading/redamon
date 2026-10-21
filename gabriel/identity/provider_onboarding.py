"""Tenant-owned credentials and read-only funding checks; no inference or fallback."""
from decimal import Decimal, InvalidOperation
from uuid import uuid4

from gabriel.identity.model_protocol import ProbeError
from gabriel.identity.model_transport import OpenRouterTransport
from gabriel.identity.service import AccessDenied, InvalidIdentityInput, _audit, connection
from gabriel.identity.vault import ProviderCredential, ProviderVault, _secret

PROVIDERS = {'openrouter', 'nvidia'}
MINIMUM_MICROUSD = 18000000


def amount(value):
    try:
        if type(value) not in {str, int, float}:
            raise ValueError
        parsed = Decimal(str(value))
        if not parsed.is_finite() or not 0 <= parsed <= 1000000000000:
            raise ValueError
        return parsed
    except (ValueError, InvalidOperation):
        raise ProbeError('provider_funding_metadata_invalid') from None


def funding(key_reply, credits_reply):
    """Account balance and remaining key allowance are separate constraints."""
    key = key_reply.get('data') if isinstance(key_reply, dict) else None
    credits = credits_reply.get('data') if isinstance(credits_reply, dict) else None
    if not isinstance(key, dict) or not isinstance(credits, dict):
        raise ProbeError('provider_funding_metadata_missing')
    if key.get('is_management_key') is not False or key.get('is_provisioning_key') is not False:
        raise ProbeError('inference_only_key_required')
    if key.get('limit_reset') != 'monthly' or amount(key.get('limit')) != 18:
        raise ProbeError('customer_key_requires_18_usd_monthly_cap')
    balance = amount(credits.get('total_credits')) - amount(credits.get('total_usage'))
    remaining = amount(key.get('limit_remaining'))
    if balance < 18 or remaining < 18:
        raise ProbeError('customer_requires_18_usd_available')
    return dict(account_available_microusd=int(balance * 1000000),
                key_available_microusd=int(remaining * 1000000))


def dispatch_credit(credits_reply, required_microusd):
    data=credits_reply.get('data') if isinstance(credits_reply,dict) else None
    if not isinstance(data,dict) or type(required_microusd) is not int or required_microusd<=0:
        raise ProbeError('provider_funding_metadata_missing')
    balance=amount(data.get('total_credits'))-amount(data.get('total_usage'))
    if balance*1000000<required_microusd:
        raise ProbeError('customer_provider_credit_unavailable')


def require_checked(conn, principal, provider, *, expected=None):
    row = conn.execute('''SELECT s.id,s.revision FROM gabriel_identity.provider_secrets s
        WHERE s.organization_id=%s AND s.provider=%s AND s.revoked_at IS NULL
        AND EXISTS (SELECT 1 FROM gabriel_identity.provider_onboarding_checks c
          WHERE (c.organization_id,c.secret_id,c.secret_revision)=(s.organization_id,s.id,s.revision)
          AND c.provider=s.provider AND c.status='funding_verified')''', (principal.organization_id, provider)).fetchone()
    if not row or provider != 'openrouter' or (expected is not None and (row['id'], row['revision']) != expected):
        raise AccessDenied('customer_provider_onboarding_required')
    return row


class CustomerProviders:
    def __init__(self, vault):
        if not isinstance(vault, ProviderVault):
            raise ValueError('provider_vault_required')
        self.vault = vault

    def configure(self, token, provider, value):
        if type(provider) is not str or provider not in PROVIDERS:
            raise InvalidIdentityInput('unsupported_customer_provider')
        value = _secret(value)
        with connection(self.vault._dsn) as conn:
            p = self.vault._admin(conn, token)
            _audit(conn, 'provider.onboarding_started', p)
        details = dict(account_available_microusd=None, key_available_microusd=None)
        status = 'validation_pending'
        if provider == 'openrouter':
            client = OpenRouterTransport(ProviderCredential(value))
            details = funding(client.request('GET', '/api/v1/key'), client.request('GET', '/api/v1/credits'))
            status = 'funding_verified'
        # NVIDIA account/catalog visibility does not establish entitlement,
        # production terms or a dollar balance. Store privately, leave disabled.
        stored = self.vault.put(token, provider, value)
        with connection(self.vault._dsn) as conn:
            p = self.vault._admin(conn, token)
            current = conn.execute('''SELECT id,revision FROM gabriel_identity.provider_secrets
                WHERE organization_id=%s AND provider=%s AND revoked_at IS NULL''',
                (p.organization_id, provider)).fetchone()
            if not current or str(current['id']) != stored['id'] or current['revision'] != stored['revision']:
                raise AccessDenied('provider_changed_during_onboarding')
            conn.execute('''INSERT INTO gabriel_identity.provider_onboarding_checks
                (organization_id,id,secret_id,secret_revision,provider,status,account_available_microusd,key_available_microusd,checked_by)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (p.organization_id, uuid4(), current['id'], current['revision'], provider, status,
                 details['account_available_microusd'], details['key_available_microusd'], p.user_id))
            _audit(conn, 'provider.onboarding_recorded', p, current['id'])
        return dict(provider=provider, revision=stored['revision'], status=status,
                    minimum_setup_microusd=MINIMUM_MICROUSD if provider == 'openrouter' else None,
                    model_enabled=False, inference_performed=False)

    def status(self, token):
        with connection(self.vault._dsn) as conn:
            p = self.vault._admin(conn, token)
            rows = conn.execute('''SELECT s.provider,s.revision,s.revoked_at,c.status,c.checked_at,
                c.account_available_microusd,c.key_available_microusd
                FROM gabriel_identity.provider_secrets s
                LEFT JOIN LATERAL (SELECT * FROM gabriel_identity.provider_onboarding_checks c
                    WHERE (c.organization_id,c.secret_id,c.secret_revision)=(s.organization_id,s.id,s.revision)
                    ORDER BY c.checked_at DESC,c.id DESC LIMIT 1) c ON true
                WHERE s.organization_id=%s AND s.provider IN ('openrouter','nvidia') ORDER BY s.provider''',
                (p.organization_id,)).fetchall()
            _audit(conn, 'provider.onboarding_read', p)
            return [dict(provider=r['provider'], revision=r['revision'],
                         status='revoked' if r['revoked_at'] else r['status'] or 'setup_required',
                         checked_at=r['checked_at'].isoformat() if r['checked_at'] else None,
                         account_available_microusd=r['account_available_microusd'],
                         key_available_microusd=r['key_available_microusd'],
                         balance_is_historical=True, model_enabled=False) for r in rows]

    def resolve(self, token, provider):
        with connection(self.vault._dsn) as conn:
            p = self.vault._admin(conn, token)
            self.vault._active(conn, p)
            checked = require_checked(conn, p, provider)
            row = conn.execute('''SELECT * FROM gabriel_identity.provider_secrets
                WHERE organization_id=%s AND id=%s AND revoked_at IS NULL''',
                (p.organization_id, checked['id'])).fetchone()
            credential = ProviderCredential(self.vault._decrypt(conn, row))
            _audit(conn, 'provider.customer_credential_resolved', p, row['id'])
            return credential, (row['id'], row['revision'])
