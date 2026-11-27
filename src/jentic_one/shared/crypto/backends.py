"""Selecting and building the credential encryption backend.

``credentials.encryption.backend`` names a backend; ``local`` (the AES-256-GCM
keyset in ``credentials.encryption``) is built in and the default. Extension
packages register other backends at import time::

    from jentic_one.shared.crypto.backends import register_encryption_backend

    async def build(ctx: EncryptionBuildContext) -> EncryptionService:
        settings = ctx.app_config.extension("my_backend")  # the backend's own section
        return MyBackend(settings, legacy=ctx.build_local())

    register_encryption_backend("my-backend", build)

OSS config carries nothing backend-specific: a backend keeps its settings in
its own top-level config section (registered with ``register_config``) and
reads it from :attr:`EncryptionBuildContext.app_config`.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol

from jentic_one.shared.config import ConfigError, EncryptionConfig
from jentic_one.shared.crypto.encryption import LOCAL_BACKEND, LocalEncryptionService
from jentic_one.shared.crypto.service import EncryptionService

if TYPE_CHECKING:
    from jentic_one.shared.config import AppConfig

_BACKEND_NAME_RE: Final = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


class BuildLocalEncryptionService(Protocol):
    """Builds a :class:`LocalEncryptionService` over the configured keyset."""

    def __call__(self, *, active_key_id: str | None = None) -> LocalEncryptionService: ...


@dataclass(frozen=True, slots=True)
class EncryptionBuildContext:
    """What a backend builder receives.

    Attributes:
        config: The ``credentials.encryption`` section (backend, active_id, entries).
        app_config: The whole resolved config, so a backend can read its own section.
        surfaces: The surfaces this process serves (for example ``{"broker"}``).
        build_local: Builds a local keyset service over ``config.entries``, with an
            optional write-key override, for reading values written by ``local``.
    """

    config: EncryptionConfig
    app_config: AppConfig
    surfaces: frozenset[str]
    build_local: BuildLocalEncryptionService


EncryptionBackendBuilder = Callable[[EncryptionBuildContext], Awaitable[EncryptionService]]

_REGISTRY: dict[str, EncryptionBackendBuilder] = {}
_REGISTRY_LOCK = threading.Lock()


def register_encryption_backend(name: str, builder: EncryptionBackendBuilder) -> None:
    """Register an encryption backend selectable as ``credentials.encryption.backend: <name>``.

    Call at import time (for example in an extension package's ``__init__``),
    before config is loaded. Idempotent for the same ``(name, builder)``.

    The builder is awaited during :meth:`Context.startup`. It validates its
    configuration and constructs the backend; ``Context`` then awaits the
    backend's :meth:`~EncryptionService.check`.

    Raises:
        ValueError: *name* is not lowercase letters, digits, ``-`` and ``_``
            (starting with a letter or digit), is ``local``, or is already
            registered to a different builder.
    """
    if not _BACKEND_NAME_RE.fullmatch(name):
        raise ValueError(
            f"invalid encryption backend name {name!r}: use lowercase letters, digits, "
            "'-' and '_', starting with a letter or digit"
        )
    if name == LOCAL_BACKEND:
        raise ValueError(f"encryption backend {name!r} is built in and cannot be re-registered")
    with _REGISTRY_LOCK:
        existing = _REGISTRY.get(name)
        if existing is not None and existing is not builder:
            raise ValueError(f"encryption backend {name!r} is already registered to {existing!r}")
        _REGISTRY[name] = builder


def registered_encryption_backends() -> tuple[str, ...]:
    """The names ``credentials.encryption.backend`` may take, sorted."""
    with _REGISTRY_LOCK:
        return tuple(sorted({LOCAL_BACKEND, *_REGISTRY}))


def unregister_encryption_backend(name: str) -> None:
    """Remove a registered (non-built-in) backend. For tests only."""
    if name == LOCAL_BACKEND:
        raise ValueError(f"encryption backend {name!r} is built in and cannot be unregistered")
    with _REGISTRY_LOCK:
        _REGISTRY.pop(name, None)


def build_local_encryption_service(
    cfg: EncryptionConfig, *, active_key_id: str | None = None
) -> LocalEncryptionService:
    """Build the local keyset service. Raises :exc:`ConfigError` on an invalid keyset."""
    return LocalEncryptionService(cfg, active_key_id=active_key_id)


async def build_encryption_service(
    app_config: AppConfig, *, surfaces: frozenset[str]
) -> EncryptionService:
    """Build the backend ``credentials.encryption.backend`` names.

    Raises:
        ConfigError: The backend is not registered, or the keyset is invalid.
        TypeError: The builder returned an object that is not an EncryptionService.
    """
    cfg = app_config.credentials.encryption
    if cfg.backend == LOCAL_BACKEND:
        return build_local_encryption_service(cfg)
    with _REGISTRY_LOCK:
        builder = _REGISTRY.get(cfg.backend)
    if builder is None:
        raise ConfigError(
            f"credentials.encryption.backend {cfg.backend!r} is not registered; "
            f"registered backends: {', '.join(registered_encryption_backends())}"
        )

    # Validate configured legacy keys even if the extension never delegates to local.
    local = build_local_encryption_service(cfg) if cfg.entries else None

    def build_local(*, active_key_id: str | None = None) -> LocalEncryptionService:
        if local is not None and active_key_id in (None, local.active_key_id):
            return local
        return build_local_encryption_service(cfg, active_key_id=active_key_id)

    service = await builder(
        EncryptionBuildContext(
            config=cfg, app_config=app_config, surfaces=surfaces, build_local=build_local
        )
    )
    if not isinstance(service, EncryptionService):
        raise TypeError(
            f"encryption backend {cfg.backend!r} builder returned {type(service).__name__}, "
            "which does not implement EncryptionService"
        )
    return service
