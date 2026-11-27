"""The built-in ``local`` encryption backend: an AES-256-GCM keyset from config.

Keys come from ``credentials.encryption.entries``; ``active_id`` selects the
key for new writes and every entry can decrypt. Blobs use the legacy format
``<key_id>:<b64(nonce‖ct‖tag)>`` (see :mod:`jentic_one.shared.crypto.blob`).

The backend honours :class:`~jentic_one.shared.crypto.service.EncryptionContext`
exactly as the keyset always has: MCP request state is sealed with the AAD
``jentic/mcp/request-state/v1`` and every other value with no AAD, so existing
ciphertext keeps decrypting and new ciphertext is byte-compatible.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Final

from jentic_one.shared.config import ConfigError, EncryptionConfig
from jentic_one.shared.crypto import blob as blob_codec
from jentic_one.shared.crypto.aead import KEY_BYTES, AeadKey
from jentic_one.shared.crypto.errors import DecryptionError
from jentic_one.shared.crypto.service import (
    EncryptionContext,
    EncryptionScope,
    PreparedWrite,
    Purpose,
)

LOCAL_BACKEND: Final = "local"

#: AAD the local backend has always used for sealed MCP request state.
MCP_REQUEST_STATE_AAD: Final = b"jentic/mcp/request-state/v1"


def _local_aad(context: EncryptionContext) -> bytes | None:
    if context.purpose is Purpose.MCP_REQUEST_STATE:
        return MCP_REQUEST_STATE_AAD
    return None


class _LocalPreparedWrite:
    """Prepared write for the local backend: the active key, bound to one scope."""

    __slots__ = ("_key", "_key_id", "_scope")

    def __init__(self, key_id: str, key: AeadKey, scope: EncryptionScope) -> None:
        self._key_id = key_id
        self._key: AeadKey | None = key
        self._scope = scope

    @property
    def scope(self) -> EncryptionScope:
        return self._scope

    def close(self) -> None:
        self._key = None

    def seal(self, plaintext: str, *, field: str) -> str:
        if self._key is None:
            raise RuntimeError("Prepared write has closed")
        aad = _local_aad(self._scope.field(field))
        return blob_codec.encode(self._key_id, self._key.seal(plaintext.encode(), aad=aad))


class LocalEncryptionService:
    """AES-256-GCM keyset encryption with versioned key selection.

    Construct it through :class:`~jentic_one.shared.context.Context` (or
    :func:`~jentic_one.shared.crypto.backends.build_local_encryption_service`);
    other backends may wrap one to read values written under the keyset.
    """

    def __init__(self, cfg: EncryptionConfig, *, active_key_id: str | None = None) -> None:
        if not cfg.entries:
            raise ConfigError("EncryptionConfig.entries must not be empty")

        self._keys: dict[str, AeadKey] = {}
        for entry in cfg.entries:
            if entry.id in self._keys:
                raise ConfigError(f"Duplicate encryption key id: '{entry.id}'")
            try:
                raw = base64.b64decode(entry.resolved_material.get_secret_value())
            except (binascii.Error, ValueError) as exc:
                raise ConfigError(f"Encryption key '{entry.id}' is not valid base64") from exc
            if len(raw) != KEY_BYTES:
                raise ConfigError(
                    f"Encryption key '{entry.id}' must be {KEY_BYTES} bytes, got {len(raw)}"
                )
            self._keys[entry.id] = AeadKey(raw)

        self._current_key_id = active_key_id if active_key_id is not None else cfg.active_id
        if self._current_key_id not in self._keys:
            raise ConfigError(
                f"EncryptionConfig.active_id '{self._current_key_id}' not found in entries"
            )

    @property
    def backend(self) -> str:
        return LOCAL_BACKEND

    @property
    def active_key_id(self) -> str:
        """Identifier of the key used for new encryptions."""
        return self._current_key_id

    @property
    def key_ids(self) -> tuple[str, ...]:
        """All key identifiers configured on this service."""
        return tuple(self._keys)

    @property
    def write_key_ids(self) -> tuple[str, ...]:
        return (self._current_key_id,)

    def key_id_of(self, blob: str) -> str:
        """Extract the key identifier prefix from an encrypted blob."""
        return blob_codec.key_id_of(blob)

    def write_key_id(self, context: EncryptionContext) -> str:
        return self._current_key_id

    def needs_reencryption(self, blob: str, *, context: EncryptionContext) -> bool:
        """True when *blob* is not a legacy blob under :attr:`active_key_id`."""
        if blob_codec.key_id_of(blob) != self._current_key_id:
            return True
        return blob_codec.format_of(blob) is not blob_codec.BlobFormat.LEGACY

    def prepare_write(self, scope: EncryptionScope) -> AbstractAsyncContextManager[PreparedWrite]:
        return self._prepare_write(scope)

    @asynccontextmanager
    async def _prepare_write(self, scope: EncryptionScope) -> AsyncIterator[PreparedWrite]:
        write = _LocalPreparedWrite(self._current_key_id, self._keys[self._current_key_id], scope)
        try:
            yield write
        finally:
            write.close()

    async def encrypt(self, plaintext: str, *, context: EncryptionContext) -> str:
        async with self.prepare_write(context.scope) as write:
            return write.seal(plaintext, field=context.field)

    async def decrypt(self, blob: str, *, context: EncryptionContext) -> str:
        decoded = blob_codec.decode(blob)
        if decoded.fmt is not blob_codec.BlobFormat.LEGACY:
            raise DecryptionError("Blob format is not supported by the local backend")
        key = self._keys.get(decoded.key_id)
        if key is None:
            raise DecryptionError("Unknown key_id")
        plaintext = key.open(decoded.payload, aad=_local_aad(context))
        try:
            return plaintext.decode()
        except UnicodeDecodeError:
            raise DecryptionError("Decrypted payload is not UTF-8") from None

    async def reencrypt(self, blob: str, *, context: EncryptionContext) -> tuple[str, bool]:
        """Authenticate *blob* and re-encrypt it under :attr:`active_key_id` if needed."""
        plaintext = await self.decrypt(blob, context=context)
        if not self.needs_reencryption(blob, context=context):
            return blob, False
        return await self.encrypt(plaintext, context=context), True

    async def check(self) -> None:
        """Nothing to probe: the keyset is validated at construction."""

    async def aclose(self) -> None:
        """Nothing to release."""
