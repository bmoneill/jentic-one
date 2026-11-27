"""Typed-secret row writers for static credential types.

Each helper seals the secret material with a :class:`PreparedWrite` for the
credential's secret scope and inserts the per-type secret row
(``token_value_credentials``, ``customer_api_keys``, ``basic_credentials``,
``sigv4_credentials``) for an existing ``credentials`` row, inside the
caller's session. The caller owns the transaction: the helpers only flush,
so the parent credential row and its secret row commit (or roll back)
together. The caller prepares the write *before* opening the transaction, so
any encryption backend I/O never holds a connection; sealing is local.
``session`` is typed ``Any`` because control services must not
import ``sqlalchemy`` (``tests/arch/test_no_direct_db.py``); the repositories
it is passed to type it as ``AsyncSession``.

Secret inputs are ``SecretStr`` so they stay masked in reprs, tracebacks and
structured logs; plaintext is unwrapped only at the encrypt/preview call and
in the returned one-time echo model, which callers must never log.
"""

from __future__ import annotations

from typing import Any

from pydantic import SecretStr

from jentic_one.control.repos import (
    BasicCredentialRepository,
    CustomerAPIKeyRepository,
    Sigv4CredentialRepository,
    TokenValueCredentialRepository,
)
from jentic_one.control.services.credentials.schemas.credentials import (
    ApiKeyFull,
    BasicAuthFull,
    BearerTokenFull,
    Sigv4Full,
)
from jentic_one.shared.crypto import PreparedWrite
from jentic_one.shared.crypto.contexts import (
    FIELD_API_KEY,
    FIELD_PASSWORD,
    FIELD_SECRET_ACCESS_KEY,
    FIELD_SESSION_TOKEN,
    FIELD_TOKEN_VALUE,
    credential_secret_scope,
)
from jentic_one.shared.redaction import secret_preview


def _check_scope(sealer: PreparedWrite, credential_id: str) -> None:
    if sealer.scope != credential_secret_scope(credential_id):
        raise ValueError("prepared write does not belong to this credential's secret scope")


async def write_bearer_token_secret(
    session: Any,
    sealer: PreparedWrite,
    *,
    credential_id: str,
    token: SecretStr,
    created_by: str,
) -> BearerTokenFull:
    """Write the encrypted bearer token row for ``credential_id``."""
    _check_scope(sealer, credential_id)
    plaintext = token.get_secret_value()
    await TokenValueCredentialRepository.create(
        session,
        credential_id=credential_id,
        encrypted_token_value=sealer.seal(plaintext, field=FIELD_TOKEN_VALUE),
        token_preview=secret_preview(plaintext),
        created_by=created_by,
    )
    return BearerTokenFull(token=plaintext)


async def write_api_key_secret(
    session: Any,
    sealer: PreparedWrite,
    *,
    credential_id: str,
    key: SecretStr,
    location: str,
    field_name: str,
    created_by: str,
) -> ApiKeyFull:
    """Write the encrypted API key row (with its injection point) for ``credential_id``."""
    _check_scope(sealer, credential_id)
    plaintext = key.get_secret_value()
    await CustomerAPIKeyRepository.create(
        session,
        credential_id=credential_id,
        encrypted_key=sealer.seal(plaintext, field=FIELD_API_KEY),
        key_preview=secret_preview(plaintext),
        location=location,
        field_name=field_name,
        created_by=created_by,
    )
    return ApiKeyFull(key=plaintext, location=location, field_name=field_name)


async def write_basic_secret(
    session: Any,
    sealer: PreparedWrite,
    *,
    credential_id: str,
    username: str,
    password: SecretStr,
    created_by: str,
) -> BasicAuthFull:
    """Write the basic-auth row (plain username, encrypted password) for ``credential_id``."""
    _check_scope(sealer, credential_id)
    plaintext = password.get_secret_value()
    await BasicCredentialRepository.create(
        session,
        credential_id=credential_id,
        username=username,
        encrypted_password=sealer.seal(plaintext, field=FIELD_PASSWORD),
        created_by=created_by,
    )
    return BasicAuthFull(username=username, password=plaintext)


async def write_sigv4_secret(
    session: Any,
    sealer: PreparedWrite,
    *,
    credential_id: str,
    access_key_id: str,
    secret_access_key: SecretStr,
    session_token: SecretStr | None,
    region: str,
    service: str,
    created_by: str,
) -> Sigv4Full:
    """Write the SigV4 keypair row for ``credential_id``.

    An empty ``session_token`` stores no encrypted token, the same as ``None``.
    """
    _check_scope(sealer, credential_id)
    secret_plaintext = secret_access_key.get_secret_value()
    session_plaintext = session_token.get_secret_value() if session_token is not None else None
    encrypted_secret = sealer.seal(secret_plaintext, field=FIELD_SECRET_ACCESS_KEY)
    encrypted_session = (
        sealer.seal(session_plaintext, field=FIELD_SESSION_TOKEN) if session_plaintext else None
    )
    await Sigv4CredentialRepository.create(
        session,
        credential_id=credential_id,
        access_key_id=access_key_id,
        encrypted_secret_access_key=encrypted_secret,
        secret_preview=secret_preview(secret_plaintext),
        encrypted_session_token=encrypted_session,
        region=region,
        service=service,
        created_by=created_by,
    )
    return Sigv4Full(
        access_key_id=access_key_id,
        secret_access_key=secret_plaintext,
        session_token=session_plaintext,
        aws_region=region,
        aws_service=service,
    )
