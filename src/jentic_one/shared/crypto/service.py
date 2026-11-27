"""The encryption contract every credential encryption backend implements.

:class:`EncryptionService` is a Protocol. The built-in ``local`` backend
(:class:`~jentic_one.shared.crypto.encryption.LocalEncryptionService`) encrypts
with the AES-256-GCM keyset in ``credentials.encryption``. Extension packages
register other backends with
:func:`~jentic_one.shared.crypto.backends.register_encryption_backend` and
select them with ``credentials.encryption.backend``.

Every operation names what it protects through an :class:`EncryptionContext`
(purpose, owner and field), built from the storage mapping in
:mod:`jentic_one.shared.crypto.contexts`. A backend may bind that context to
the ciphertext, log it, or ignore it; the ``local`` backend ignores it except
for MCP request state, so its ciphertext is unchanged.

Wire-format rules every backend follows (checked by
``jentic_one.testing.BaseEncryptionServiceContract``):

1. A blob is ``<key_id>:<payload>``: ASCII, with ``key_id`` matching
   ``[a-zA-Z0-9_-]+`` and listed in :attr:`EncryptionService.key_ids`.
2. Every :meth:`EncryptionService.encrypt` returns a fresh ciphertext.
3. A backend that binds the context fails :meth:`EncryptionService.decrypt`
   with :exc:`DecryptionError` when given a different context.
4. Exceptions, logs and metrics never carry plaintext, key material or ciphertext.

This module never imports ``cryptography``.
"""

from __future__ import annotations

import struct
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

_CONTEXT_AAD_VERSION = b"jentic/encryption-context/v1"
_U16 = struct.Struct(">H")


class Purpose(StrEnum):
    """What a stored ciphertext protects. Stable strings: backends may persist or log them."""

    CREDENTIAL_SECRET = "credential.secret"  # pragma: allowlist secret
    """Static credential secrets: bearer tokens, API keys, Basic passwords, SigV4 keys."""
    OAUTH_TOKEN = "credential.oauth_token"
    """OAuth access and refresh tokens."""
    OAUTH_CLIENT_SECRET = "oauth.client_secret"  # pragma: allowlist secret
    """OAuth client secrets: client-credentials grants, app registrations, provider configs."""
    DEVICE_CODE = "connect.device_code"
    """Device-authorization device codes held while a connect flow polls."""
    TRANSIENT = "transient"
    """Short-lived payloads: held execution payloads and async-job cookies."""
    MCP_REQUEST_STATE = "mcp.request_state"
    """Sealed MCP retry state handed to an agent."""


@dataclass(frozen=True, slots=True)
class EncryptionScope:
    """Who a set of ciphertexts belongs to.

    Attributes:
        purpose: What the values protect.
        owner_type: Stable namespace of the owning record (for example ``credential``).
        owner_id: Opaque identifier of the owning record, or a fixed key such as a
            provider name. Never a secret.
    """

    purpose: Purpose
    owner_type: str
    owner_id: str

    def __post_init__(self) -> None:
        if not self.owner_type:
            raise ValueError("EncryptionScope.owner_type must not be empty")
        if not self.owner_id:
            raise ValueError("EncryptionScope.owner_id must not be empty")

    def field(self, field: str) -> EncryptionContext:
        """Return the context for one *field* of this scope."""
        return EncryptionContext(scope=self, field=field)


@dataclass(frozen=True, slots=True)
class EncryptionContext:
    """One encrypted value: its :class:`EncryptionScope` plus the column or payload key."""

    scope: EncryptionScope
    field: str

    def __post_init__(self) -> None:
        if not self.field:
            raise ValueError("EncryptionContext.field must not be empty")

    @property
    def purpose(self) -> Purpose:
        """Shortcut for ``scope.purpose``."""
        return self.scope.purpose

    def aad(self) -> bytes:
        """Canonical, versioned encoding of the context for use as AEAD associated data.

        Each component is length-prefixed, so no two distinct contexts encode
        to the same bytes.
        """
        parts = [
            _CONTEXT_AAD_VERSION,
            self.scope.purpose.value.encode(),
            self.scope.owner_type.encode(),
            self.scope.owner_id.encode(),
            self.field.encode(),
        ]
        out = bytearray()
        for part in parts:
            if len(part) > 0xFFFF:
                raise ValueError("encryption context component is too long")
            out += _U16.pack(len(part))
            out += part
        return bytes(out)


class PreparedWrite(Protocol):
    """A write key acquired for one :class:`EncryptionScope`.

    Obtained from :meth:`EncryptionService.prepare_write`. Sealing is local
    work only: any network I/O happened when the write was prepared, so a
    caller can prepare before an irreversible step (for example an OAuth token
    exchange) and seal its result afterwards.
    """

    @property
    def scope(self) -> EncryptionScope:
        """The scope every sealed field belongs to."""
        ...

    def seal(self, plaintext: str, *, field: str) -> str:
        """Encrypt one *field* of the scope. Every call returns a fresh ciphertext."""
        ...


@runtime_checkable
class EncryptionService(Protocol):
    """Credential encryption backend contract.

    Construction and teardown belong to :class:`~jentic_one.shared.context.Context`;
    callers obtain the service from ``ctx.encryption``.
    """

    @property
    def active_key_id(self) -> str:
        """Primary key id for new durable writes."""
        ...

    @property
    def key_ids(self) -> tuple[str, ...]:
        """Every key id this service can decrypt."""
        ...

    @property
    def write_key_ids(self) -> tuple[str, ...]:
        """Every key id this service currently writes with (across purposes)."""
        ...

    def key_id_of(self, blob: str) -> str:
        """Return the key id prefix of *blob*. Parsing only; raises :exc:`DecryptionError`."""
        ...

    def write_key_id(self, context: EncryptionContext) -> str:
        """Key id a new write for *context* would carry."""
        ...

    def needs_reencryption(self, blob: str, *, context: EncryptionContext) -> bool:
        """Whether *blob* differs from the current write target for *context*.

        Metadata only; does not authenticate the blob.
        """
        ...

    def prepare_write(self, scope: EncryptionScope) -> AbstractAsyncContextManager[PreparedWrite]:
        """Acquire a write key for *scope*; may perform network I/O on entry."""
        ...

    async def encrypt(self, plaintext: str, *, context: EncryptionContext) -> str:
        """Encrypt *plaintext* for *context*. Returns a fresh blob every call."""
        ...

    async def decrypt(self, blob: str, *, context: EncryptionContext) -> str:
        """Decrypt *blob* written for *context*.

        Raises:
            DecryptionError: The blob will never decrypt.
            EncryptionUnavailableError: Transient backend failure.
            EncryptionAccessDeniedError: The backend refused the operation.
        """
        ...

    async def reencrypt(self, blob: str, *, context: EncryptionContext) -> tuple[str, bool]:
        """Authenticate *blob* and rewrite it to the current write target if needed.

        Returns ``(blob_or_replacement, rewritten)``.
        """
        ...

    async def check(self) -> None:
        """Validate configuration and initialize backend health. Called once at startup."""
        ...

    async def aclose(self) -> None:
        """Release backend resources. Idempotent."""
        ...


def backend_name(service: object) -> str:
    """The registered name of an encryption backend, for errors and logs.

    Not part of the :class:`EncryptionService` contract: a backend that does not
    expose ``backend`` is reported as ``unknown``.
    """
    return str(getattr(service, "backend", "unknown"))
