"""Contract tests and a fake backend for credential encryption backends.

:class:`BaseEncryptionServiceContract` proves a backend registered with
:func:`~jentic_one.shared.crypto.register_encryption_backend` follows the
:class:`~jentic_one.shared.crypto.EncryptionService` contract: method
signatures, the blob prefix rules, fresh ciphertext per write, prepared
writes, context binding (when the backend claims it), legacy decrypt of the
``local`` keyset (when the backend claims it), and idempotent ``aclose``. The
``local`` backend passes the same suite.

:class:`FakeEncryptionBackend` wraps a ``local`` service and adds injectable
latency and failures, for unit tests and perf runs that need a slow or failing
backend without a network dependency.

Like the other bases, names start with ``Base`` so pytest does not collect them
directly. Tests are ``async def``: run the subclass under pytest-asyncio in
``auto`` mode, or mark it with ``pytestmark = pytest.mark.asyncio``.
"""

from __future__ import annotations

import asyncio
import base64
import os
import re
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Final

from pydantic import SecretStr

from jentic_one.shared.config import EncryptionConfig, EncryptionKey
from jentic_one.shared.crypto import (
    DecryptionError,
    EncryptionBuildContext,
    EncryptionContext,
    EncryptionScope,
    EncryptionService,
    LocalEncryptionService,
    PreparedWrite,
    Purpose,
    register_encryption_backend,
)
from jentic_one.testing.compliance import assert_signature_matches

#: Backend name :func:`register_fake_encryption_backend` registers.
FAKE_BACKEND: Final = "test-fake"

_BLOB_PREFIX_RE: Final = re.compile(r"^([a-zA-Z0-9_-]+):")

#: Every method of the EncryptionService protocol (properties are checked by name).
_PROTOCOL_METHODS: Final = (
    "key_id_of",
    "write_key_id",
    "needs_reencryption",
    "prepare_write",
    "encrypt",
    "decrypt",
    "reencrypt",
    "check",
    "aclose",
)
_PROTOCOL_PROPERTIES: Final = ("active_key_id", "key_ids", "write_key_ids")


def keyset_config(*key_ids: str, active_id: str | None = None) -> EncryptionConfig:
    """Return an :class:`EncryptionConfig` with a fresh random key per id (default ``v1``)."""
    ids = key_ids or ("v1",)
    return EncryptionConfig(
        active_id=active_id or ids[0],
        entries=[
            EncryptionKey(id=key_id, material=SecretStr(base64.b64encode(os.urandom(32)).decode()))
            for key_id in ids
        ],
    )


def sample_context(
    purpose: Purpose = Purpose.CREDENTIAL_SECRET,
    *,
    owner_id: str = "cred_contract",
    field: str = "encrypted_token_value",
) -> EncryptionContext:
    """An arbitrary context for tests that do not care which value they protect."""
    return EncryptionScope(purpose, "credential", owner_id).field(field)


class BaseEncryptionServiceContract:
    """Subclass and override :meth:`service_factory` to prove a backend follows the contract.

    ``service_factory`` returns a fresh, ready service; each test closes it::

        class TestMyBackendContract(BaseEncryptionServiceContract):
            binds_context = True

            async def service_factory(self) -> EncryptionService:
                return await build_my_backend(...)

    Set :attr:`binds_context` when the backend rejects a blob opened under a
    different context. Override :meth:`legacy_service_factory` to return the
    ``local`` service whose blobs the backend must still decrypt.
    """

    #: The backend fails decrypt with DecryptionError under a different context.
    binds_context: bool = False

    async def service_factory(self) -> EncryptionService:
        raise NotImplementedError("Subclass must override service_factory()")

    def legacy_service_factory(self) -> LocalEncryptionService | None:
        """The ``local`` service whose blobs this backend must decrypt, or None."""
        return None

    @asynccontextmanager
    async def _service(self) -> AsyncIterator[EncryptionService]:
        service = await self.service_factory()
        try:
            yield service
        finally:
            await service.aclose()

    async def test_implements_protocol(self) -> None:
        async with self._service() as service:
            assert isinstance(service, EncryptionService)
            for name in _PROTOCOL_PROPERTIES:
                assert hasattr(service, name), f"missing property {name}"
            for method in _PROTOCOL_METHODS:
                assert_signature_matches(type(service), EncryptionService, method)

    async def test_round_trip(self) -> None:
        context = sample_context()
        async with self._service() as service:
            blob = await service.encrypt("s3cret-value", context=context)
            assert await service.decrypt(blob, context=context) == "s3cret-value"

    async def test_round_trip_every_purpose(self) -> None:
        async with self._service() as service:
            for purpose in Purpose:
                context = sample_context(purpose, owner_id=f"owner-{purpose.value}")
                blob = await service.encrypt("value", context=context)
                assert service.key_id_of(blob) == service.write_key_id(context)
                assert service.key_id_of(blob) in service.write_key_ids
                assert await service.decrypt(blob, context=context) == "value"

    async def test_blob_is_prefixed_ascii(self) -> None:
        context = sample_context()
        async with self._service() as service:
            blob = await service.encrypt("ünïcode ✓", context=context)
            assert blob.isascii()
            match = _BLOB_PREFIX_RE.match(blob)
            assert match is not None, "blob must start with '<key_id>:'"
            assert service.key_id_of(blob) == match.group(1)
            assert match.group(1) in service.key_ids
            assert service.write_key_id(context) == match.group(1)
            assert match.group(1) in service.write_key_ids
            assert not service.needs_reencryption(blob, context=context)

    async def test_every_encrypt_is_fresh(self) -> None:
        context = sample_context()
        async with self._service() as service:
            first = await service.encrypt("same", context=context)
            second = await service.encrypt("same", context=context)
            assert first != second

    async def test_prepared_write_seals_many_fields(self) -> None:
        scope = EncryptionScope(Purpose.OAUTH_TOKEN, "credential", "cred_prepared")
        async with self._service() as service:
            prepared: AbstractAsyncContextManager[PreparedWrite] = service.prepare_write(scope)
            async with prepared as write:
                assert write.scope == scope
                access = write.seal("access", field="encrypted_access_token")
                refresh = write.seal("refresh", field="encrypted_refresh_token")
                again = write.seal("access", field="encrypted_access_token")
            assert access != again
            assert (
                await service.decrypt(access, context=scope.field("encrypted_access_token"))
                == "access"
            )
            assert (
                await service.decrypt(refresh, context=scope.field("encrypted_refresh_token"))
                == "refresh"
            )

    async def test_reencrypt_current_blob_is_unchanged(self) -> None:
        context = sample_context()
        async with self._service() as service:
            blob = await service.encrypt("value", context=context)
            assert await service.reencrypt(blob, context=context) == (blob, False)

    async def test_malformed_blob_raises_decryption_error(self) -> None:
        context = sample_context()
        async with self._service() as service:
            for bad in ("", "no-separator", ":empty-key-id", "unknown-key:AAAA"):
                try:
                    await service.decrypt(bad, context=context)
                except DecryptionError as exc:
                    assert bad not in str(exc) or not bad
                else:
                    raise AssertionError(f"decrypt({bad!r}) did not raise DecryptionError")

    async def test_tampered_blob_raises_decryption_error(self) -> None:
        context = sample_context()
        async with self._service() as service:
            blob = await service.encrypt("value", context=context)
            mid = blob.rindex(":") + 1 + (len(blob) - blob.rindex(":")) // 2
            tampered = blob[:mid] + ("A" if blob[mid] != "A" else "B") + blob[mid + 1 :]
            try:
                await service.decrypt(tampered, context=context)
            except DecryptionError:
                pass
            else:
                raise AssertionError("tampered blob decrypted")

    async def test_context_binding(self) -> None:
        if not self.binds_context:
            return
        context = sample_context()
        scope = context.scope
        alternatives = (
            sample_context(owner_id="cred_other"),
            scope.field("another_field"),
            EncryptionScope(scope.purpose, "another_owner_type", scope.owner_id).field(
                context.field
            ),
            EncryptionScope(Purpose.OAUTH_TOKEN, scope.owner_type, scope.owner_id).field(
                context.field
            ),
        )
        async with self._service() as service:
            blob = await service.encrypt("value", context=context)
            for other in alternatives:
                try:
                    await service.decrypt(blob, context=other)
                except DecryptionError:
                    continue
                raise AssertionError("blob decrypted under a different context")

    async def test_mcp_request_state_is_domain_separated(self) -> None:
        state = sample_context(Purpose.MCP_REQUEST_STATE, field="request_state")
        stored = sample_context(Purpose.CREDENTIAL_SECRET, field="request_state")
        async with self._service() as service:
            blob = await service.encrypt("value", context=state)
            try:
                await service.decrypt(blob, context=stored)
            except DecryptionError:
                pass
            else:
                raise AssertionError("MCP request state opened as a stored secret")

    async def test_legacy_decrypt(self) -> None:
        legacy = self.legacy_service_factory()
        if legacy is None:
            return
        context = sample_context()
        blob = await legacy.encrypt("legacy-value", context=context)
        async with self._service() as service:
            assert await service.decrypt(blob, context=context) == "legacy-value"

    async def test_check_and_aclose_are_idempotent(self) -> None:
        service = await self.service_factory()
        await service.check()
        await service.aclose()
        await service.aclose()


@dataclass
class FakeBackendBehaviour:
    """Knobs for :class:`FakeEncryptionBackend`; mutate between calls to change behaviour.

    Attributes:
        latency_s: Delay added before every encrypt, decrypt, reencrypt and prepare.
        fail_with: Exception factory raised by the next ``fail_times`` operations.
        fail_times: How many operations raise; ``None`` means every operation.
        calls: Names of operations performed, in order.
    """

    latency_s: float = 0.0
    fail_with: Callable[[], Exception] | None = None
    fail_times: int | None = None
    calls: list[str] = field(default_factory=list)


class FakeEncryptionBackend:
    """A ``local`` service with injectable latency and failures. For tests and perf only."""

    def __init__(
        self,
        inner: LocalEncryptionService,
        behaviour: FakeBackendBehaviour | None = None,
        *,
        name: str = FAKE_BACKEND,
    ) -> None:
        self._inner = inner
        self.behaviour = behaviour or FakeBackendBehaviour()
        self._name = name
        self.closed = False

    async def _before(self, op: str) -> None:
        self.behaviour.calls.append(op)
        if self.behaviour.latency_s:
            await asyncio.sleep(self.behaviour.latency_s)
        factory = self.behaviour.fail_with
        if factory is None:
            return
        remaining = self.behaviour.fail_times
        if remaining is not None:
            if remaining <= 0:
                return
            self.behaviour.fail_times = remaining - 1
        raise factory()

    @property
    def backend(self) -> str:
        return self._name

    @property
    def active_key_id(self) -> str:
        return self._inner.active_key_id

    @property
    def key_ids(self) -> tuple[str, ...]:
        return self._inner.key_ids

    @property
    def write_key_ids(self) -> tuple[str, ...]:
        return self._inner.write_key_ids

    def key_id_of(self, blob: str) -> str:
        return self._inner.key_id_of(blob)

    def write_key_id(self, context: EncryptionContext) -> str:
        return self._inner.write_key_id(context)

    def needs_reencryption(self, blob: str, *, context: EncryptionContext) -> bool:
        return self._inner.needs_reencryption(blob, context=context)

    def prepare_write(self, scope: EncryptionScope) -> AbstractAsyncContextManager[PreparedWrite]:
        return self._prepare_write(scope)

    @asynccontextmanager
    async def _prepare_write(self, scope: EncryptionScope) -> AsyncIterator[PreparedWrite]:
        await self._before("prepare_write")
        async with self._inner.prepare_write(scope) as prepared:
            yield prepared

    async def encrypt(self, plaintext: str, *, context: EncryptionContext) -> str:
        await self._before("encrypt")
        return await self._inner.encrypt(plaintext, context=context)

    async def decrypt(self, blob: str, *, context: EncryptionContext) -> str:
        await self._before("decrypt")
        return await self._inner.decrypt(blob, context=context)

    async def reencrypt(self, blob: str, *, context: EncryptionContext) -> tuple[str, bool]:
        await self._before("reencrypt")
        return await self._inner.reencrypt(blob, context=context)

    async def check(self) -> None:
        await self._before("check")

    async def aclose(self) -> None:
        self.closed = True


def register_fake_encryption_backend(
    behaviour: FakeBackendBehaviour | None = None, *, name: str = FAKE_BACKEND
) -> list[FakeEncryptionBackend]:
    """Register a builder for :class:`FakeEncryptionBackend` under *name*.

    Select it with ``credentials.encryption.backend: <name>``. The builder wraps
    a local service over the configured keyset. Returns a list that collects
    every instance the builder creates, so a test can reach the live backend.
    Unregister with ``unregister_encryption_backend(name)`` when done.
    """
    built: list[FakeEncryptionBackend] = []
    shared = behaviour or FakeBackendBehaviour()

    async def build(ctx: EncryptionBuildContext) -> EncryptionService:
        backend = FakeEncryptionBackend(ctx.build_local(), shared, name=name)
        built.append(backend)
        return backend

    register_encryption_backend(name, build)
    return built
