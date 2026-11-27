"""Storage mapping: the :class:`EncryptionScope` of every persisted ciphertext.

Writers, readers and the rotator all derive a value's context here, from the
record that stores it, so the three always agree. Owner ids are opaque record
ids (never secrets). Field names are the column or payload key that holds the
ciphertext.

Every row below is ``purpose`` → owner type and id.

- Bearer, API key, Basic and SigV4 secrets: ``credential.secret`` → ``credential``.
- ``oauth_tokens`` access and refresh tokens: ``credential.oauth_token`` → ``credential``.
- ``oauth_client_credentials`` client secret: ``oauth.client_secret`` → ``credential``.
- App registration client secret: ``oauth.client_secret`` → ``oauth_app_registration``.
- ``device_authorization_credentials`` device code: ``connect.device_code`` → ``credential``.
- Runtime provider config secret: ``oauth.client_secret`` → ``provider_config``, provider name.
- Held payload and async-job cookie: ``transient`` → ``execution`` id, else ``job`` id.
- MCP request state: ``mcp.request_state`` → ``agent``, agent id.
"""

from __future__ import annotations

from typing import Final

from jentic_one.shared.crypto.service import EncryptionContext, EncryptionScope, Purpose

OWNER_CREDENTIAL: Final = "credential"
OWNER_OAUTH_APP_REGISTRATION: Final = "oauth_app_registration"
OWNER_PROVIDER_CONFIG: Final = "provider_config"
OWNER_EXECUTION: Final = "execution"
OWNER_JOB: Final = "job"
OWNER_AGENT: Final = "agent"

# Column names of the stored ciphertexts, used as context fields.
FIELD_TOKEN_VALUE: Final = "encrypted_token_value"
FIELD_API_KEY: Final = "encrypted_key"
FIELD_PASSWORD: Final = "encrypted_password"
FIELD_SECRET_ACCESS_KEY: Final = "encrypted_secret_access_key"
FIELD_SESSION_TOKEN: Final = "encrypted_session_token"
FIELD_ACCESS_TOKEN: Final = "encrypted_access_token"
FIELD_REFRESH_TOKEN: Final = "encrypted_refresh_token"
FIELD_CLIENT_SECRET: Final = "encrypted_client_secret"
FIELD_DEVICE_CODE: Final = "encrypted_device_code"
FIELD_PROVIDER_CLIENT_SECRET: Final = "client_secret"
FIELD_HELD_PAYLOAD: Final = "encrypted_payload"
FIELD_COOKIE: Final = "cookie"
FIELD_MCP_REQUEST_STATE: Final = "request_state"


def credential_secret_scope(credential_id: str) -> EncryptionScope:
    """Scope of a static credential secret (bearer, API key, Basic, SigV4)."""
    return EncryptionScope(Purpose.CREDENTIAL_SECRET, OWNER_CREDENTIAL, credential_id)


def credential_secret_context(credential_id: str, field: str) -> EncryptionContext:
    """Context of one static secret column of *credential_id*."""
    return credential_secret_scope(credential_id).field(field)


def oauth_token_scope(credential_id: str) -> EncryptionScope:
    """Scope of the OAuth access and refresh tokens stored for *credential_id*."""
    return EncryptionScope(Purpose.OAUTH_TOKEN, OWNER_CREDENTIAL, credential_id)


def oauth_access_token_context(credential_id: str) -> EncryptionContext:
    """Context of the stored OAuth access token of *credential_id*."""
    return oauth_token_scope(credential_id).field(FIELD_ACCESS_TOKEN)


def oauth_refresh_token_context(credential_id: str) -> EncryptionContext:
    """Context of the stored OAuth refresh token of *credential_id*."""
    return oauth_token_scope(credential_id).field(FIELD_REFRESH_TOKEN)


def credential_client_secret_context(credential_id: str) -> EncryptionContext:
    """Context of an ``oauth_client_credentials`` client secret (shared credential PK)."""
    return EncryptionScope(Purpose.OAUTH_CLIENT_SECRET, OWNER_CREDENTIAL, credential_id).field(
        FIELD_CLIENT_SECRET
    )


def app_registration_client_secret_context(registration_id: str) -> EncryptionContext:
    """Context of an OAuth app registration's client secret."""
    return EncryptionScope(
        Purpose.OAUTH_CLIENT_SECRET, OWNER_OAUTH_APP_REGISTRATION, registration_id
    ).field(FIELD_CLIENT_SECRET)


def device_code_context(credential_id: str) -> EncryptionContext:
    """Context of a device-authorization device code (shared credential PK)."""
    return EncryptionScope(Purpose.DEVICE_CODE, OWNER_CREDENTIAL, credential_id).field(
        FIELD_DEVICE_CODE
    )


def provider_config_secret_context(provider: str, field: str) -> EncryptionContext:
    """Context of a secret field in a runtime provider config, keyed by provider name."""
    return EncryptionScope(Purpose.OAUTH_CLIENT_SECRET, OWNER_PROVIDER_CONFIG, provider).field(
        field
    )


def transient_scope(*, execution_id: str | None, job_id: str | None = None) -> EncryptionScope:
    """Scope of a held payload or async-job cookie.

    Prefer the execution id persisted with the job. Rows written before that
    id existed use the job id.

    Raises:
        ValueError: Neither id is given.
    """
    if execution_id:
        return EncryptionScope(Purpose.TRANSIENT, OWNER_EXECUTION, execution_id)
    if job_id:
        return EncryptionScope(Purpose.TRANSIENT, OWNER_JOB, job_id)
    raise ValueError("transient_scope needs an execution_id or a job_id")


def held_payload_context(
    *, execution_id: str | None, job_id: str | None = None
) -> EncryptionContext:
    """Context of a held execution's encrypted outer payload."""
    return transient_scope(execution_id=execution_id, job_id=job_id).field(FIELD_HELD_PAYLOAD)


def cookie_context(*, execution_id: str | None, job_id: str | None = None) -> EncryptionContext:
    """Context of an encrypted forwarded cookie (held or queued execution)."""
    return transient_scope(execution_id=execution_id, job_id=job_id).field(FIELD_COOKIE)


def mcp_request_state_context(agent_id: str) -> EncryptionContext:
    """Context of sealed MCP retry state handed to *agent_id*."""
    return EncryptionScope(Purpose.MCP_REQUEST_STATE, OWNER_AGENT, agent_id).field(
        FIELD_MCP_REQUEST_STATE
    )
