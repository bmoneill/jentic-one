"""Backend registry, the encryption contract suite, and the Context encryption lifecycle."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from jentic_one.shared.config import AppConfig, ConfigError, load_config
from jentic_one.shared.context import Context
from jentic_one.shared.crypto import (
    EncryptionAccessDeniedError,
    EncryptionBuildContext,
    EncryptionService,
    EncryptionUnavailableError,
    LocalEncryptionService,
    build_encryption_service,
    register_encryption_backend,
    registered_encryption_backends,
)
from jentic_one.shared.crypto.backends import unregister_encryption_backend
from jentic_one.testing import (
    BaseEncryptionServiceContract,
    FakeBackendBehaviour,
    FakeEncryptionBackend,
    register_fake_encryption_backend,
)
from jentic_one.testing.encryption import FAKE_BACKEND, keyset_config, sample_context

_KEY = "vF7VWq2NJLr+uGDBFy9boIXfSJJIzqnTSF7iDDMKR5U="  # pragma: allowlist secret


class _LocalContract(BaseEncryptionServiceContract):
    async def service_factory(self) -> EncryptionService:
        return LocalEncryptionService(keyset_config("v1", "v2", active_id="v2"))


class _FakeContract(BaseEncryptionServiceContract):
    _legacy = LocalEncryptionService(keyset_config("v1"))

    async def service_factory(self) -> EncryptionService:
        return FakeEncryptionBackend(self._legacy)

    def legacy_service_factory(self) -> LocalEncryptionService | None:
        return self._legacy


@pytest.mark.parametrize("contract", [_LocalContract, _FakeContract], ids=["local", "fake"])
@pytest.mark.parametrize(
    "case",
    [
        name
        for name, _ in inspect.getmembers(BaseEncryptionServiceContract, inspect.isfunction)
        if name.startswith("test_")
    ],
)
async def test_backend_contract(contract: type[BaseEncryptionServiceContract], case: str) -> None:
    await getattr(contract(), case)()


@pytest.fixture
def fake_backend() -> Iterator[tuple[list[FakeEncryptionBackend], FakeBackendBehaviour]]:
    behaviour = FakeBackendBehaviour()
    built = register_fake_encryption_backend(behaviour)
    try:
        yield built, behaviour
    finally:
        unregister_encryption_backend(FAKE_BACKEND)


def _config(
    tmp_path: Path, base: dict[str, Any], *, backend: str = "local", keyset: bool = True
) -> AppConfig:
    cfg = dict(base)
    cfg["credentials"] = {
        **cfg.get("credentials", {}),
        "encryption": {
            "backend": backend,
            "active_id": "v1",
            "entries": [{"id": "v1", "material": _KEY}] if keyset else [],
        },
    }
    path = tmp_path / "cfg.yaml"
    path.write_text(yaml.dump(cfg))
    return load_config(path)


# --- Registry ---


def test_local_is_always_registered() -> None:
    assert "local" in registered_encryption_backends()


async def _noop_builder(ctx: EncryptionBuildContext) -> EncryptionService:
    return ctx.build_local()


def test_register_rules() -> None:
    with pytest.raises(ValueError, match="built in"):
        register_encryption_backend("local", _noop_builder)
    with pytest.raises(ValueError, match="invalid"):
        register_encryption_backend("Bad Name", _noop_builder)
    register_encryption_backend("test-noop", _noop_builder)
    try:
        register_encryption_backend("test-noop", _noop_builder)  # idempotent

        async def other(ctx: EncryptionBuildContext) -> EncryptionService:
            return ctx.build_local()

        with pytest.raises(ValueError, match="already registered"):
            register_encryption_backend("test-noop", other)
        assert "test-noop" in registered_encryption_backends()
    finally:
        unregister_encryption_backend("test-noop")
    assert "test-noop" not in registered_encryption_backends()


async def test_unknown_backend_lists_registered_names(
    tmp_path: Path, sample_config_dict: dict[str, Any]
) -> None:
    config = _config(tmp_path, sample_config_dict, backend="nope")
    with pytest.raises(ConfigError, match="registered backends: local"):
        await build_encryption_service(config, surfaces=frozenset())


async def test_builder_must_return_an_encryption_service(
    tmp_path: Path, sample_config_dict: dict[str, Any]
) -> None:
    async def wrong(ctx: EncryptionBuildContext) -> EncryptionService:
        return object()  # type: ignore[return-value]

    register_encryption_backend("test-wrong", wrong)
    try:
        config = _config(tmp_path, sample_config_dict, backend="test-wrong")
        with pytest.raises(TypeError, match="does not implement EncryptionService"):
            await build_encryption_service(config, surfaces=frozenset())
    finally:
        unregister_encryption_backend("test-wrong")


async def test_builder_receives_surfaces_and_local_factory(
    tmp_path: Path, sample_config_dict: dict[str, Any]
) -> None:
    seen: list[EncryptionBuildContext] = []

    async def capture(ctx: EncryptionBuildContext) -> EncryptionService:
        seen.append(ctx)
        return ctx.build_local()

    register_encryption_backend("test-capture", capture)
    try:
        config = _config(tmp_path, sample_config_dict, backend="test-capture")
        async with Context(config, allowed_dbs=set(), surfaces=frozenset({"broker"})) as context:
            service = context.encryption
    finally:
        unregister_encryption_backend("test-capture")
    assert seen[0].surfaces == frozenset({"broker"})
    assert seen[0].app_config is config
    assert isinstance(service, LocalEncryptionService)


# --- Context lifecycle ---


async def test_local_backend_is_lazy_and_byte_identical(
    tmp_path: Path, sample_config_dict: dict[str, Any]
) -> None:
    ctx = Context(_config(tmp_path, sample_config_dict), allowed_dbs=set())
    assert ctx.encryption_enabled is True
    assert isinstance(ctx.encryption, LocalEncryptionService)


async def test_local_without_keyset_boots_and_reports_disabled(
    tmp_path: Path, sample_config_dict: dict[str, Any]
) -> None:
    async with Context(
        _config(tmp_path, sample_config_dict, keyset=False), allowed_dbs=set()
    ) as ctx:
        assert ctx.encryption_enabled is False
        with pytest.raises(ConfigError):
            _ = ctx.encryption


async def test_registered_backend_is_built_checked_and_closed(
    tmp_path: Path,
    sample_config_dict: dict[str, Any],
    fake_backend: tuple[list[FakeEncryptionBackend], FakeBackendBehaviour],
) -> None:
    built, behaviour = fake_backend
    ctx = Context(_config(tmp_path, sample_config_dict, backend=FAKE_BACKEND), allowed_dbs=set())
    assert ctx.encryption_enabled is True
    with pytest.raises(RuntimeError, match=r"built by Context\.startup"):
        _ = ctx.encryption

    async with ctx:
        assert ctx.encryption is built[0]
        assert behaviour.calls == ["check"]
        context = sample_context()
        blob = await ctx.encryption.encrypt("v", context=context)
        assert await ctx.encryption.decrypt(blob, context=context) == "v"
    assert built[0].closed is True


async def test_extension_can_serve_without_a_local_keyset(
    tmp_path: Path, sample_config_dict: dict[str, Any]
) -> None:
    # This backend supplies its own key material, as an external key store would.
    async def build(ctx: EncryptionBuildContext) -> EncryptionService:
        assert not ctx.config.entries
        return LocalEncryptionService(keyset_config("extension-key"))

    register_encryption_backend("test-independent", build)
    try:
        config = _config(tmp_path, sample_config_dict, backend="test-independent", keyset=False)
        async with Context(config, allowed_dbs=set()) as ctx:
            assert ctx.encryption_enabled
            context = sample_context()
            blob = await ctx.encryption.encrypt("secret", context=context)
            assert ctx.encryption.key_id_of(blob) == "extension-key"
            assert await ctx.encryption.decrypt(blob, context=context) == "secret"
    finally:
        unregister_encryption_backend("test-independent")


@pytest.mark.parametrize(
    "error",
    [
        lambda: EncryptionUnavailableError("down", backend=FAKE_BACKEND),
        lambda: EncryptionAccessDeniedError("denied", backend=FAKE_BACKEND),
        asyncio.CancelledError,
    ],
)
async def test_failed_check_fails_startup_and_closes_backend(
    tmp_path: Path,
    sample_config_dict: dict[str, Any],
    fake_backend: tuple[list[FakeEncryptionBackend], FakeBackendBehaviour],
    error: Any,
) -> None:
    built, behaviour = fake_backend
    behaviour.fail_with = error
    behaviour.fail_times = 1
    ctx = Context(_config(tmp_path, sample_config_dict, backend=FAKE_BACKEND), allowed_dbs=set())
    with pytest.raises(type(error())):
        await ctx.startup()
    assert built[0].closed is True
    with pytest.raises(RuntimeError):
        _ = ctx.encryption


async def test_db_only_context_never_builds_the_backend(
    tmp_path: Path,
    sample_config_dict: dict[str, Any],
    fake_backend: tuple[list[FakeEncryptionBackend], FakeBackendBehaviour],
) -> None:
    built, behaviour = fake_backend
    behaviour.fail_with = lambda: EncryptionUnavailableError("down", backend=FAKE_BACKEND)
    config = _config(tmp_path, sample_config_dict, backend=FAKE_BACKEND)
    async with Context(config, allowed_dbs=set(), start_encryption=False) as ctx:
        with pytest.raises(RuntimeError, match="DB-only"):
            _ = ctx.encryption
    assert built == []


async def test_db_only_context_refuses_local_encryption(
    tmp_path: Path, sample_config_dict: dict[str, Any]
) -> None:
    async with Context(
        _config(tmp_path, sample_config_dict), allowed_dbs=set(), start_encryption=False
    ) as ctx:
        with pytest.raises(RuntimeError, match="DB-only"):
            _ = ctx.encryption


async def test_invalid_local_keyset_fails_startup(
    tmp_path: Path, sample_config_dict: dict[str, Any]
) -> None:
    cfg = dict(sample_config_dict)
    cfg["credentials"] = {
        **cfg.get("credentials", {}),
        "encryption": {"active_id": "missing", "entries": [{"id": "v1", "material": _KEY}]},
    }
    path = tmp_path / "cfg.yaml"
    path.write_text(yaml.dump(cfg))
    with pytest.raises(ConfigError, match="not found in entries"):
        await Context(load_config(path), allowed_dbs=set()).startup()
