"""Unit and real-SQLite tests for the local encryption backend and persisted key rotation."""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError
from sqlalchemy import Table, text
from sqlalchemy.engine import Connection
from sqlalchemy.schema import CreateTable

import jentic_one.admin.core.schema
import jentic_one.control.core.schema  # noqa: F401
from jentic_one.admin.core.schema.held_executions import HeldExecution
from jentic_one.admin.core.schema.jobs import Job
from jentic_one.admin.core.schema.provider_configs import ProviderConfigRecord
from jentic_one.control.core.schema.authorization_code_app_registration_details import (
    AuthorizationCodeAppRegistrationDetails,
)
from jentic_one.control.core.schema.basic_credentials import BasicCredential
from jentic_one.control.core.schema.credentials import Credential
from jentic_one.control.core.schema.customer_api_keys import CustomerAPIKey
from jentic_one.control.core.schema.device_authorization_credentials import (
    DeviceAuthorizationCredential,
)
from jentic_one.control.core.schema.oauth_app_registrations import OAuthAppRegistration
from jentic_one.control.core.schema.oauth_client_credentials import OAuthClientCredential
from jentic_one.control.core.schema.oauth_tokens import OAuthToken
from jentic_one.control.core.schema.sigv4_credentials import Sigv4Credential
from jentic_one.control.core.schema.token_value_credentials import TokenValueCredential
from jentic_one.shared.config import ConfigError, DatabaseConfig, EncryptionConfig, EncryptionKey
from jentic_one.shared.crypto import (
    DecryptionError,
    EncryptedStorageRotator,
    EncryptionContext,
    KeyRetirementError,
    KeyRotationReport,
    LocalEncryptionService,
    RotationFailure,
    aead,
    app_registration_client_secret_context,
    assert_only_active_key,
    cookie_context,
    credential_client_secret_context,
    credential_secret_context,
    device_code_context,
    held_payload_context,
    mcp_request_state_context,
    oauth_access_token_context,
    oauth_refresh_token_context,
    provider_config_secret_context,
    rotate_encrypted_storage,
    verify_key_retired,
)
from jentic_one.shared.crypto import blob as blob_codec
from jentic_one.shared.crypto.encryption import MCP_REQUEST_STATE_AAD
from jentic_one.shared.db import AdminBase, ControlBase, DatabaseSession
from jentic_one.testing.encryption import (
    FakeBackendBehaviour,
    FakeEncryptionBackend,
    sample_context,
)

CTX = sample_context()


def _make_key(key_id: str = "v1") -> EncryptionKey:
    material = base64.b64encode(os.urandom(32)).decode()
    return EncryptionKey(id=key_id, material=SecretStr(material))


def _make_config(key_id: str = "v1", keys: list[EncryptionKey] | None = None) -> EncryptionConfig:
    if keys is None:
        keys = [_make_key(key_id)]
    return EncryptionConfig(active_id=key_id, entries=keys)


# --- Round-trip ---


async def test_encrypt_decrypt_roundtrip():
    svc = LocalEncryptionService(_make_config())
    plaintext = "super-secret-token-value"
    blob = await svc.encrypt(plaintext, context=CTX)
    assert await svc.decrypt(blob, context=CTX) == plaintext


async def test_roundtrip_unicode():
    svc = LocalEncryptionService(_make_config())
    plaintext = "пароль-密码-🔑"
    assert await svc.decrypt(await svc.encrypt(plaintext, context=CTX), context=CTX) == plaintext


async def test_roundtrip_empty_string():
    svc = LocalEncryptionService(_make_config())
    assert await svc.decrypt(await svc.encrypt("", context=CTX), context=CTX) == ""


async def test_local_ignores_context_for_stored_values():
    """Stored secrets keep the legacy no-AAD format, so any context opens them."""
    svc = LocalEncryptionService(_make_config())
    blob = await svc.encrypt("secret", context=credential_secret_context("cred_a", "f"))
    other = oauth_access_token_context("cred_b")
    assert await svc.decrypt(blob, context=other) == "secret"


async def test_mcp_request_state_uses_the_historical_aad():
    """MCP state is sealed with the AAD the keyset always used, so old tokens still open."""
    key = _make_key()
    svc = LocalEncryptionService(_make_config(keys=[key]))
    state = mcp_request_state_context("agt_1")

    blob = await svc.encrypt("state", context=state)
    with pytest.raises(DecryptionError):
        await svc.decrypt(blob, context=CTX)
    with pytest.raises(DecryptionError):
        await svc.decrypt(await svc.encrypt("stored", context=CTX), context=state)

    # A token sealed directly with the historical AAD opens under the context.

    raw = base64.b64decode(key.resolved_material.get_secret_value())
    historical = blob_codec.encode("v1", aead.seal(raw, b"state", aad=MCP_REQUEST_STATE_AAD))
    assert await svc.decrypt(historical, context=mcp_request_state_context("agt_2")) == "state"


async def test_existing_legacy_blob_decrypts():
    """A blob in the pre-contract wire format decrypts unchanged."""
    key = _make_key()
    svc = LocalEncryptionService(_make_config(keys=[key]))

    raw = base64.b64decode(key.resolved_material.get_secret_value())
    legacy = "v1:" + base64.b64encode(aead.seal(raw, b"legacy", aad=None)).decode()
    assert await svc.decrypt(legacy, context=CTX) == "legacy"


# --- Blob format ---


async def test_blob_has_key_id_prefix():
    svc = LocalEncryptionService(_make_config(key_id="v2", keys=[_make_key("v2")]))
    blob = await svc.encrypt("hello", context=CTX)
    assert blob.startswith("v2:")
    assert blob.count(":") == 1


async def test_blob_is_nondeterministic():
    svc = LocalEncryptionService(_make_config())
    blob1 = await svc.encrypt("same", context=CTX)
    blob2 = await svc.encrypt("same", context=CTX)
    assert blob1 != blob2


async def test_prepared_write_matches_encrypt_format():
    svc = LocalEncryptionService(_make_config())
    scope = credential_secret_context("cred_1", "f").scope
    async with svc.prepare_write(scope) as write:
        blob = write.seal("value", field="f")
    assert blob.startswith("v1:")
    assert await svc.decrypt(blob, context=scope.field("f")) == "value"
    with pytest.raises(RuntimeError, match="closed"):
        write.seal("late", field="f")


# --- Decryption errors ---


async def test_tampered_blob_raises():
    svc = LocalEncryptionService(_make_config())
    blob = await svc.encrypt("secret", context=CTX)
    parts = blob.split(":", 1)
    payload = list(parts[1])
    payload[5] = "A" if payload[5] != "A" else "B"
    tampered = parts[0] + ":" + "".join(payload)
    with pytest.raises(DecryptionError):
        await svc.decrypt(tampered, context=CTX)


async def test_unknown_key_id_raises():
    svc = LocalEncryptionService(_make_config())
    with pytest.raises(DecryptionError, match="Unknown key_id"):
        await svc.decrypt("nonexistent_key:AAAA", context=CTX)


async def test_missing_separator_raises():
    svc = LocalEncryptionService(_make_config())
    with pytest.raises(DecryptionError, match="missing key_id separator"):
        await svc.decrypt("nocolonhere", context=CTX)


async def test_short_payload_raises():
    svc = LocalEncryptionService(_make_config())
    short = base64.b64encode(b"short").decode()
    with pytest.raises(DecryptionError):
        await svc.decrypt(f"v1:{short}", context=CTX)


async def test_envelope_format_is_rejected_by_local():
    svc = LocalEncryptionService(_make_config())
    envelope = "v1:3:" + base64.b64encode(b"\x00\x01x" + b"0" * 40).decode()
    with pytest.raises(DecryptionError, match="not supported"):
        await svc.decrypt(envelope, context=CTX)


# --- Multi-key rotation & LocalEncryptionService helpers ---


async def test_old_key_blobs_still_decrypt():
    old_key = _make_key("v1")
    new_key = _make_key("v2")

    old_svc = LocalEncryptionService(EncryptionConfig(active_id="v1", entries=[old_key]))
    old_blob = await old_svc.encrypt("legacy-secret", context=CTX)

    rotated_svc = LocalEncryptionService(
        EncryptionConfig(active_id="v2", entries=[old_key, new_key])
    )
    assert await rotated_svc.decrypt(old_blob, context=CTX) == "legacy-secret"


async def test_new_writes_use_current_key():
    old_key = _make_key("v1")
    new_key = _make_key("v2")

    svc = LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[old_key, new_key]))
    blob = await svc.encrypt("new-secret", context=CTX)
    assert blob.startswith("v2:")


async def test_active_key_override():
    old_key = _make_key("v1")
    new_key = _make_key("v2")
    svc = LocalEncryptionService(
        EncryptionConfig(active_id="v2", entries=[old_key, new_key]), active_key_id="v1"
    )
    assert svc.active_key_id == "v1"
    assert (await svc.encrypt("x", context=CTX)).startswith("v1:")


async def test_key_id_of_and_key_metadata():
    old_key = _make_key("v1")
    new_key = _make_key("v2")
    svc = LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[old_key, new_key]))
    assert svc.backend == "local"
    assert svc.active_key_id == "v2"
    assert svc.key_ids == ("v1", "v2")
    assert svc.write_key_ids == ("v2",)
    assert svc.write_key_id(CTX) == "v2"

    blob = await svc.encrypt("secret", context=CTX)
    assert svc.key_id_of(blob) == "v2"

    with pytest.raises(DecryptionError, match="missing key_id separator"):
        svc.key_id_of("malformed")
    with pytest.raises(DecryptionError, match="empty key_id"):
        svc.key_id_of(":payload")


async def test_needs_reencryption_and_reencrypt():
    old_key = _make_key("v1")
    new_key = _make_key("v2")

    v1_svc = LocalEncryptionService(EncryptionConfig(active_id="v1", entries=[old_key]))
    v1_blob = await v1_svc.encrypt("rotate-me", context=CTX)

    v2_svc = LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[old_key, new_key]))
    assert v2_svc.needs_reencryption(v1_blob, context=CTX) is True

    rotated_blob, changed = await v2_svc.reencrypt(v1_blob, context=CTX)
    assert changed is True
    assert rotated_blob.startswith("v2:")
    assert v2_svc.needs_reencryption(rotated_blob, context=CTX) is False
    assert await v2_svc.decrypt(rotated_blob, context=CTX) == "rotate-me"

    # Re-encrypting an already-current ciphertext is a no-op that still validates auth tag.
    noop_blob, changed_again = await v2_svc.reencrypt(rotated_blob, context=CTX)
    assert changed_again is False
    assert noop_blob == rotated_blob

    # Tampered active-key blob still fails closed during reencrypt.
    parts = rotated_blob.split(":", 1)
    tampered = parts[0] + ":" + ("A" if parts[1][0] != "A" else "B") + parts[1][1:]
    with pytest.raises(DecryptionError):
        await v2_svc.reencrypt(tampered, context=CTX)


async def test_reencrypt_preserves_mcp_request_state_aad():
    state = mcp_request_state_context("agt_1")
    old_key = _make_key("v1")
    new_key = _make_key("v2")
    v1_svc = LocalEncryptionService(EncryptionConfig(active_id="v1", entries=[old_key]))
    v2_svc = LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[old_key, new_key]))
    v1_blob = await v1_svc.encrypt("state", context=state)

    rotated_blob, changed = await v2_svc.reencrypt(v1_blob, context=state)

    assert changed is True
    assert await v2_svc.decrypt(rotated_blob, context=state) == "state"
    with pytest.raises(DecryptionError):
        await v2_svc.decrypt(rotated_blob, context=CTX)
    with pytest.raises(DecryptionError):
        await v2_svc.reencrypt(v1_blob, context=CTX)


# --- Boot validation ---


def test_empty_entries_raises():
    cfg = EncryptionConfig(active_id="v1", entries=[])
    with pytest.raises(ConfigError, match="must not be empty"):
        LocalEncryptionService(cfg)


def test_active_id_not_in_entries_raises():
    cfg = EncryptionConfig(active_id="missing", entries=[_make_key("v1")])
    with pytest.raises(ConfigError, match="not found in entries"):
        LocalEncryptionService(cfg)


def test_short_key_material_raises():
    short_material = base64.b64encode(b"tooshort").decode()
    entry = EncryptionKey(id="v1", material=SecretStr(short_material))
    cfg = EncryptionConfig(active_id="v1", entries=[entry])
    with pytest.raises(ConfigError, match="must be 32 bytes"):
        LocalEncryptionService(cfg)


def test_duplicate_key_id_raises():
    key1 = _make_key("v1")
    key2 = _make_key("v1")
    cfg = EncryptionConfig(active_id="v1", entries=[key1, key2])
    with pytest.raises(ConfigError, match="Duplicate encryption key id"):
        LocalEncryptionService(cfg)


def test_key_id_with_colon_rejected():
    with pytest.raises(ValidationError, match="key id must match"):
        EncryptionKey(id="aws:v1", material=SecretStr("dummy"))


def test_key_id_with_space_rejected():
    with pytest.raises(ValidationError, match="key id must match"):
        EncryptionKey(id="key 1", material=SecretStr("dummy"))


def test_backend_name_is_validated():
    assert EncryptionConfig().backend == "local"
    with pytest.raises(ValidationError):
        EncryptionConfig(backend="Not Valid")


# --- Real-SQLite storage rotation & key retirement verification ---


def _create_sqlite_tables(sync_conn: Connection, *tables: Table) -> None:
    """Create ORM tables on SQLite, temporarily stripping Postgres-only server defaults."""
    for table in tables:
        saved = {col: col.server_default for col in table.columns}
        for col in table.columns:
            col.server_default = None
        try:
            sync_conn.execute(CreateTable(table, if_not_exists=True))
        finally:
            for col, default in saved.items():
                col.server_default = default


async def _make_sqlite_dbs(tmp_path: Path) -> tuple[DatabaseSession, DatabaseSession]:
    control_db = DatabaseSession(
        DatabaseConfig(backend="sqlite", path=str(tmp_path / "control.db"))
    )
    admin_db = DatabaseSession(DatabaseConfig(backend="sqlite", path=str(tmp_path / "admin.db")))
    await control_db.connect()
    await admin_db.connect()
    async with control_db.engine.begin() as conn:
        await conn.run_sync(_create_sqlite_tables, *ControlBase.metadata.sorted_tables)
    async with admin_db.engine.begin() as conn:
        await conn.run_sync(_create_sqlite_tables, *AdminBase.metadata.sorted_tables)
    return control_db, admin_db


async def _seed_all_encrypted_families(
    control_db: DatabaseSession,
    admin_db: DatabaseSession,
    v1_svc: LocalEncryptionService,
) -> None:
    def _sigv4_ctx(field: str) -> EncryptionContext:
        return credential_secret_context("cred_sigv4", field)

    async with control_db.transaction() as session:
        # 1. customer_api_keys
        c_apikey = Credential(id="cred_apikey", type="api_key", name="k1", api_vendor="acme")
        session.add(c_apikey)
        session.add(
            CustomerAPIKey(
                id="cak_1",
                credential_id=c_apikey.id,
                encrypted_key=await v1_svc.encrypt(
                    "apikey-secret-1",
                    context=credential_secret_context(c_apikey.id, "encrypted_key"),
                ),
            )
        )

        # 2. token_value_credentials
        c_bearer = Credential(id="cred_bearer", type="bearer", name="k2", api_vendor="acme")
        session.add(c_bearer)
        session.add(
            TokenValueCredential(
                credential_id=c_bearer.id,
                encrypted_token_value=await v1_svc.encrypt(
                    "bearer-secret-1",
                    context=credential_secret_context(c_bearer.id, "encrypted_token_value"),
                ),
            )
        )

        # 3. basic_credentials
        c_basic = Credential(id="cred_basic", type="basic", name="k3", api_vendor="acme")
        session.add(c_basic)
        session.add(
            BasicCredential(
                credential_id=c_basic.id,
                username="alice",
                encrypted_password=await v1_svc.encrypt(
                    "basic-password-1",
                    context=credential_secret_context(c_basic.id, "encrypted_password"),
                ),
            )
        )

        # 4. sigv4_credentials (2 encrypted columns)
        c_sigv4 = Credential(id="cred_sigv4", type="sigv4", name="k4", api_vendor="aws")
        session.add(c_sigv4)
        session.add(
            Sigv4Credential(
                id="sigv4_1",
                credential_id=c_sigv4.id,
                access_key_id="AKIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret
                encrypted_secret_access_key=await v1_svc.encrypt(
                    "sigv4-secret-key", context=_sigv4_ctx("encrypted_secret_access_key")
                ),
                encrypted_session_token=await v1_svc.encrypt(
                    "sigv4-session-token", context=_sigv4_ctx("encrypted_session_token")
                ),
                region="us-east-1",
                service="s3",
            )
        )

        # 5. device_authorization_credentials
        c_device = Credential(id="cred_device", type="device", name="k5", api_vendor="github")
        session.add(c_device)
        session.add(
            DeviceAuthorizationCredential(
                id=c_device.id,
                client_id="dev-client",
                token_url="https://example.com/token",
                authorization_endpoint="https://example.com/device",
                encrypted_device_code=await v1_svc.encrypt(
                    "device-code-secret", context=device_code_context(c_device.id)
                ),
            )
        )

        # 6. oauth_client_credentials
        c_oauth_client = Credential(
            id="cred_oauth_client", type="oauth2", name="k6", api_vendor="slack"
        )
        session.add(c_oauth_client)
        session.add(
            OAuthClientCredential(
                id=c_oauth_client.id,
                token_url="https://example.com/oauth/token",
                client_id="oauth-client",
                encrypted_client_secret=await v1_svc.encrypt(
                    "oauth-client-secret",
                    context=credential_client_secret_context(c_oauth_client.id),
                ),
            )
        )

        # 7. authorization_code_app_registration_details
        reg = OAuthAppRegistration(
            id="oar_1",
            name="Acme OAuth App",
            api_vendor="acme",
            flow_kind="authorization_code",
            client_id="reg-client-id",
            catalog_api_id="acme/core",
            display_name="Acme",
        )
        session.add(reg)
        session.add(
            AuthorizationCodeAppRegistrationDetails(
                id=reg.id,
                encrypted_client_secret=await v1_svc.encrypt(
                    "app-reg-client-secret", context=app_registration_client_secret_context(reg.id)
                ),
                authorize_url="https://example.com/authorize",
                token_url="https://example.com/token",
            )
        )

        # 8. oauth_tokens (2 encrypted columns)
        c_oauth_tok = Credential(id="cred_oauth_tok", type="oauth2", name="k8", api_vendor="acme")
        session.add(c_oauth_tok)
        session.add(
            OAuthToken(
                id="oat_1",
                credential_id=c_oauth_tok.id,
                encrypted_access_token=await v1_svc.encrypt(
                    "oauth-access-token", context=oauth_access_token_context(c_oauth_tok.id)
                ),
                encrypted_refresh_token=await v1_svc.encrypt(
                    "oauth-refresh-token", context=oauth_refresh_token_context(c_oauth_tok.id)
                ),
            )
        )

    async with admin_db.transaction() as session:
        # 9. provider_configs
        session.add(
            ProviderConfigRecord(
                id="pcfg_1",
                name="auth0-prod",
                config_json={
                    "issuer": "https://auth.example.com",
                    "client_secret": await v1_svc.encrypt(
                        "provider-client-secret",
                        context=provider_config_secret_context("auth0-prod", "client_secret"),
                    ),
                },
            )
        )

        # 10. jobs (async execution job with encrypted inbound cookie)
        session.add(
            Job(
                id="job_async_1",
                kind="execution",
                status="queued",
                actor_type="agent",
                attempts=0,
                payload={
                    "operation_id": "op_1",
                    "inbound_cookie_enc": await v1_svc.encrypt(
                        "async-job-cookie",
                        context=cookie_context(execution_id=None, job_id="job_async_1"),
                    ),
                },
            )
        )

        # 11. held_executions (held job with _enc envelope + nested inbound_cookie_enc)
        held_inner = {
            "method": "POST",
            "path": "/v1/Charges",
            "inbound_cookie_enc": await v1_svc.encrypt(
                "held-nested-cookie", context=cookie_context(execution_id=None, job_id="job_held_1")
            ),
        }
        held_job = Job(
            id="job_held_1",
            kind="execution",
            status="held",
            actor_type="agent",
            attempts=0,
            payload={
                "_enc": await v1_svc.encrypt(
                    json.dumps(held_inner),
                    context=held_payload_context(execution_id=None, job_id="job_held_1"),
                )
            },
        )
        session.add(held_job)
        await session.flush()
        session.add(
            HeldExecution(
                id="held_1",
                job_id=held_job.id,
                agent_id="agt_1",
                credential_id="cred_apikey",
                api_vendor="acme",
                api_name="payments",
                api_version="v1",
                method="POST",
                path="/v1/Charges",
                request_fingerprint="fp_1",
                state="pending",
                expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(hours=1),
            )
        )


async def test_rotate_encrypted_storage_all_families_dry_run_resume_and_retire(
    tmp_path: Path,
) -> None:
    old_key = _make_key("v1")
    new_key = _make_key("v2")
    v1_svc = LocalEncryptionService(EncryptionConfig(active_id="v1", entries=[old_key]))
    v2_svc = LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[old_key, new_key]))
    v2_only_svc = LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[new_key]))

    control_db, admin_db = await _make_sqlite_dbs(tmp_path)
    try:
        await _seed_all_encrypted_families(control_db, admin_db, v1_svc)

        # 1. Dry-run inventories all 11 families: 14 encrypted values across 11 rows
        #    (a held job counts its payload and its nested cookie separately)
        dry_report = await rotate_encrypted_storage(
            v2_svc,
            control_db=control_db,
            admin_db=admin_db,
            dry_run=True,
            batch_size=2,
        )
        assert isinstance(dry_report, KeyRotationReport)
        assert dry_report.dry_run is True
        assert dry_report.batches_executed == 0
        assert dry_report.scanned_rows == 11
        assert dry_report.scanned_values == 14
        assert dry_report.rotated_rows == 0
        assert dry_report.rotated_values == 0
        assert dry_report.needs_rotation_values == 14
        assert dry_report.remaining_non_active_values == 14
        assert dry_report.counts_by_key_before == {"v1": 14}
        assert dry_report.counts_by_key_after == {"v1": 14}
        assert dry_report.completed is False

        # All table and family aliases resolve in by_family and by_table
        for family_or_table, expected_values in (
            ("customer_api_keys", 1),
            ("token_value_credentials", 1),
            ("bearer_token_credentials", 1),
            ("basic_credentials", 1),
            ("basic_auth_credentials", 1),
            ("sigv4_credentials", 2),
            ("device_authorization_credentials", 1),
            ("oauth_client_credentials", 1),
            ("authorization_code_app_registration_details", 1),
            ("oauth_app_registrations", 1),
            ("oauth_tokens", 2),
            ("provider_configs", 1),
            ("jobs", 1),
            ("held_executions", 2),
        ):
            assert dry_report.by_family[family_or_table].scanned_values == expected_values
            assert dry_report.by_table[family_or_table].needs_rotation_values == expected_values

        # 2. verify_key_retired and assert_only_active_key fail closed while v1 ciphertexts remain
        with pytest.raises(KeyRetirementError) as exc_info:
            await verify_key_retired(
                v2_svc,
                "v1",
                control_db=control_db,
                admin_db=admin_db,
            )
        assert exc_info.value.remaining_by_key == {"v1": 14}
        assert len(exc_info.value.remaining_by_family) == 11

        with pytest.raises(KeyRetirementError):
            await assert_only_active_key(
                v2_svc,
                control_db=control_db,
                admin_db=admin_db,
            )

        # Retiring the currently active key also fails closed
        with pytest.raises(KeyRetirementError, match="still the active encryption key"):
            dry_report.verify_key_retired("v2")

        # 3. Partial run with max_batches=4 rotates only 4 rows and leaves 7 rows for resume
        partial_report = await rotate_encrypted_storage(
            v2_svc,
            control_db=control_db,
            admin_db=admin_db,
            dry_run=False,
            batch_size=1,
            max_batches=4,
        )
        assert partial_report.batches_executed == 4
        assert partial_report.rotated_rows == 4
        assert partial_report.rotated_values == 5  # includes sigv4's 2 columns
        assert partial_report.remaining_non_active_values == 9
        assert partial_report.completed is False

        with pytest.raises(KeyRetirementError) as partial_exc:
            await verify_key_retired(
                v2_svc,
                "v1",
                control_db=control_db,
                admin_db=admin_db,
            )
        assert partial_exc.value.remaining_by_key == {"v1": 9}

        # 4. Resume rotation to completion using EncryptedStorageRotator
        rotator = EncryptedStorageRotator(
            v2_svc,
            control_db=control_db,
            admin_db=admin_db,
            batch_size=2,
        )
        resumed_report = await rotator.rotate(dry_run=False)
        assert resumed_report.completed is True
        assert resumed_report.rotated_rows == 7
        assert resumed_report.rotated_values == 9
        assert resumed_report.remaining_non_active_values == 0
        assert resumed_report.counts_by_key_before == {"v2": 5, "v1": 9}
        assert resumed_report.counts_by_key_after == {"v2": 14}

        # 5. Retirement checks now pass and v2_only_svc (without v1) decrypts every stored secret
        retired_report = await rotator.verify_key_retired("v1")
        assert retired_report.completed is True
        active_only_report = await rotator.assert_only_active_key()
        assert active_only_report.counts_by_key == {"v2": 14}

        # Verify v2_only_svc (old key removed from entries) passes assert_only_active_key
        final_check = await assert_only_active_key(
            v2_only_svc,
            control_db=control_db,
            admin_db=admin_db,
        )
        assert final_check.completed is True
        assert final_check.failures == []

        # Verify nested held_executions payload decrypts cleanly with v2_only_svc
        async with admin_db.session() as session:
            held_payload_raw = (
                await session.execute(text("SELECT payload FROM jobs WHERE id = 'job_held_1'"))
            ).scalar_one()
            held_payload = (
                json.loads(held_payload_raw)
                if isinstance(held_payload_raw, str)
                else held_payload_raw
            )
            inner_decrypted = json.loads(
                await v2_only_svc.decrypt(
                    held_payload["_enc"],
                    context=held_payload_context(execution_id=None, job_id="job_held_1"),
                )
            )
            assert await v2_only_svc.decrypt(
                inner_decrypted["inbound_cookie_enc"],
                context=cookie_context(execution_id=None, job_id="job_held_1"),
            ) == ("held-nested-cookie")
    finally:
        await control_db.close()
        await admin_db.close()


async def test_verify_key_retired_fails_closed_on_corrupted_ciphertext(
    tmp_path: Path,
) -> None:
    key_v1 = _make_key("v1")
    svc = LocalEncryptionService(EncryptionConfig(active_id="v1", entries=[key_v1]))

    control_db, admin_db = await _make_sqlite_dbs(tmp_path)
    try:
        async with control_db.transaction() as session:
            cred = Credential(id="cred_bad", type="api_key", name="bad", api_vendor="acme")
            session.add(cred)
            session.add(
                CustomerAPIKey(
                    id="cak_bad",
                    credential_id=cred.id,
                    encrypted_key="v1:not-valid-ciphertext",
                )
            )

        with pytest.raises(KeyRetirementError) as exc_info:
            await assert_only_active_key(svc, control_db=control_db, admin_db=admin_db)

        assert len(exc_info.value.failures) == 1
        failure = exc_info.value.failures[0]
        assert isinstance(failure, RotationFailure)
        assert failure.family == "customer_api_keys"
        assert failure.column == "encrypted_key"
    finally:
        await control_db.close()
        await admin_db.close()


def _held_job(job_id: str, outer_blob: str) -> Job:
    return Job(
        id=job_id,
        kind="execution",
        status="held",
        actor_type="agent",
        attempts=0,
        payload={"_enc": outer_blob},
    )


async def _seed_held_job_with_distinct_keys(
    admin_db: DatabaseSession,
    *,
    outer_svc: LocalEncryptionService,
    cookie_svc: LocalEncryptionService,
) -> None:
    """A held job whose outer payload and nested cookie use different (retired) keys."""
    job_id = "job_held_layers"
    inner = {
        "method": "POST",
        "inbound_cookie_enc": await cookie_svc.encrypt(
            "cookie", context=cookie_context(execution_id=None, job_id=job_id)
        ),
    }
    outer = await outer_svc.encrypt(
        json.dumps(inner), context=held_payload_context(execution_id=None, job_id=job_id)
    )
    async with admin_db.transaction() as session:
        session.add(_held_job(job_id, outer))


async def test_held_job_layers_are_counted_independently(tmp_path: Path) -> None:
    k1, k2, k3 = _make_key("v1"), _make_key("v2"), _make_key("v3")
    v1_svc = LocalEncryptionService(EncryptionConfig(active_id="v1", entries=[k1]))
    v2_svc = LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[k1, k2]))
    v3_svc = LocalEncryptionService(EncryptionConfig(active_id="v3", entries=[k1, k2, k3]))

    control_db, admin_db = await _make_sqlite_dbs(tmp_path)
    try:
        # Outer payload under v2, nested cookie under v1: two retired keys in one row.
        await _seed_held_job_with_distinct_keys(admin_db, outer_svc=v2_svc, cookie_svc=v1_svc)

        report = await rotate_encrypted_storage(
            v3_svc, control_db=control_db, admin_db=admin_db, dry_run=True
        )
        assert report.by_family["held_executions"].scanned_values == 2
        assert report.counts_by_key_after == {"v2": 1, "v1": 1}

        # Each retired key blocks its own retirement while its ciphertext remains.
        for retired in ("v1", "v2"):
            with pytest.raises(KeyRetirementError):
                await verify_key_retired(v3_svc, retired, control_db=control_db, admin_db=admin_db)

        # One row update rewrites both layers; afterwards both keys can retire.
        rotated = await rotate_encrypted_storage(v3_svc, control_db=control_db, admin_db=admin_db)
        assert rotated.rotated_rows == 1
        assert rotated.rotated_values == 2
        for retired in ("v1", "v2"):
            await verify_key_retired(v3_svc, retired, control_db=control_db, admin_db=admin_db)
    finally:
        await control_db.close()
        await admin_db.close()


class _TwoWriteTargetsBackend(FakeEncryptionBackend):
    """Writes with the active key and a second, dedicated key."""

    @property
    def write_key_ids(self) -> tuple[str, ...]:
        return (self.active_key_id, "v1")


async def test_verify_key_retired_refuses_a_current_write_target_with_zero_references(
    tmp_path: Path,
) -> None:
    k1, k2 = _make_key("v1"), _make_key("v2")
    inner = LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[k1, k2]))
    backend = _TwoWriteTargetsBackend(inner)

    control_db, admin_db = await _make_sqlite_dbs(tmp_path)
    try:
        # Empty database: no ciphertext references v1, but v1 is still written with.
        with pytest.raises(KeyRetirementError, match="current write key"):
            await verify_key_retired(backend, "v1", control_db=control_db, admin_db=admin_db)
    finally:
        await control_db.close()
        await admin_db.close()


async def test_inspection_requests_no_replacement_keys_and_writes_nothing(
    tmp_path: Path,
) -> None:
    k1, k2 = _make_key("v1"), _make_key("v2")
    v1_svc = LocalEncryptionService(EncryptionConfig(active_id="v1", entries=[k1]))
    behaviour = FakeBackendBehaviour()
    backend = FakeEncryptionBackend(
        LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[k1, k2])), behaviour
    )

    control_db, admin_db = await _make_sqlite_dbs(tmp_path)
    try:
        await _seed_all_encrypted_families(control_db, admin_db, v1_svc)

        async def _snapshot() -> tuple[object, ...]:
            async with admin_db.session() as session:
                jobs = (await session.execute(text("SELECT id, payload FROM jobs"))).all()
                providers = (
                    await session.execute(text("SELECT id, config_json FROM provider_configs"))
                ).all()
            async with control_db.session() as session:
                keys = (
                    await session.execute(text("SELECT id, encrypted_key FROM customer_api_keys"))
                ).all()
            return (tuple(map(tuple, jobs)), tuple(map(tuple, providers)), tuple(map(tuple, keys)))

        before = await _snapshot()

        report = await rotate_encrypted_storage(
            backend, control_db=control_db, admin_db=admin_db, dry_run=True
        )
        with pytest.raises(KeyRetirementError):
            await verify_key_retired(backend, "v1", control_db=control_db, admin_db=admin_db)

        assert report.needs_rotation_values == 14
        assert report.rotated_rows == 0
        forbidden = {"prepare_write", "encrypt", "reencrypt"}
        assert forbidden.isdisjoint(behaviour.calls), behaviour.calls
        assert "decrypt" in behaviour.calls
        assert await _snapshot() == before
    finally:
        await control_db.close()
        await admin_db.close()


async def _seed_one_held_job_cookie_on_v1(
    admin_db: DatabaseSession, v1_svc: LocalEncryptionService
) -> None:
    """A held job whose nested cookie (and outer payload) still use the retired key v1."""
    await _seed_held_job_with_distinct_keys(admin_db, outer_svc=v1_svc, cookie_svc=v1_svc)


async def test_retirement_is_refused_when_a_database_was_not_scanned(tmp_path: Path) -> None:
    k1, k2 = _make_key("v1"), _make_key("v2")
    v1_svc = LocalEncryptionService(EncryptionConfig(active_id="v1", entries=[k1]))
    v2_svc = LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[k1, k2]))

    control_db, admin_db = await _make_sqlite_dbs(tmp_path)
    try:
        await _seed_one_held_job_cookie_on_v1(admin_db, v1_svc)

        # Control-only: nothing is scanned, yet it must not certify retirement.
        with pytest.raises(KeyRetirementError, match="admin"):
            await verify_key_retired(v2_svc, "v1", control_db=control_db)
        with pytest.raises(KeyRetirementError, match="admin"):
            await assert_only_active_key(v2_svc, control_db=control_db)
        # Admin-only: the other direction.
        with pytest.raises(KeyRetirementError, match="control"):
            await verify_key_retired(v2_svc, "v1", admin_db=admin_db)

        # Partial scans stay available for inspection and rotation.
        partial = await rotate_encrypted_storage(v2_svc, control_db=control_db, dry_run=True)
        assert partial.covered_databases == {"control"}
        with pytest.raises(KeyRetirementError, match="admin"):
            partial.verify_key_retired("v1")

        # Both databases: the held cookie is found and retirement is refused for the real reason.
        with pytest.raises(KeyRetirementError) as full:
            await verify_key_retired(v2_svc, "v1", control_db=control_db, admin_db=admin_db)
        assert full.value.remaining_by_key == {"v1": 2}
    finally:
        await control_db.close()
        await admin_db.close()


@pytest.mark.parametrize("bad_envelope", ["", None, 123, ["x"]], ids=repr)
async def test_a_present_but_unreadable_held_envelope_blocks_retirement(
    tmp_path: Path, bad_envelope: object
) -> None:
    k1 = _make_key("v1")
    svc = LocalEncryptionService(EncryptionConfig(active_id="v1", entries=[k1]))

    control_db, admin_db = await _make_sqlite_dbs(tmp_path)
    try:
        async with admin_db.transaction() as session:
            session.add(
                Job(
                    id="job_bad_env",
                    kind="execution",
                    status="held",
                    actor_type="agent",
                    attempts=0,
                    payload={"_enc": bad_envelope},
                )
            )
            # A legacy held payload that omits the marker is still supported.
            session.add(
                Job(
                    id="job_legacy",
                    kind="execution",
                    status="held",
                    actor_type="agent",
                    attempts=0,
                    payload={"method": "GET"},
                )
            )

        with pytest.raises(KeyRetirementError) as exc:
            await assert_only_active_key(svc, control_db=control_db, admin_db=admin_db)
        failures = exc.value.failures
        assert [f.row_id for f in failures] == ["job_bad_env"]
        assert failures[0].column == "payload._enc"
    finally:
        await control_db.close()
        await admin_db.close()


async def test_bounded_rotation_requests_no_write_key_for_rows_past_the_cap(
    tmp_path: Path,
) -> None:
    k1, k2 = _make_key("v1"), _make_key("v2")
    v1_svc = LocalEncryptionService(EncryptionConfig(active_id="v1", entries=[k1]))
    behaviour = FakeBackendBehaviour()
    backend = FakeEncryptionBackend(
        LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[k1, k2])), behaviour
    )

    control_db, admin_db = await _make_sqlite_dbs(tmp_path)
    try:
        await _seed_all_encrypted_families(control_db, admin_db, v1_svc)

        report = await rotate_encrypted_storage(
            backend, control_db=control_db, admin_db=admin_db, batch_size=1, max_batches=1
        )

        assert report.batches_executed == 1
        assert report.rotated_rows == 1
        assert behaviour.calls.count("prepare_write") == 1
        # The skipped rows are still authenticated and counted.
        assert report.scanned_values == 14
        assert report.remaining_non_active_values == 14 - report.rotated_values
    finally:
        await control_db.close()
        await admin_db.close()


class _PurposeTargetBackend(FakeEncryptionBackend):
    """Writes one purpose under ``target_key`` and everything else under the active key."""

    def __init__(self, inner: LocalEncryptionService, *, purpose: str, target_key: str) -> None:
        super().__init__(inner)
        self._purpose = purpose
        self._target_key = target_key

    @property
    def write_key_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((self.active_key_id, self._target_key)))

    def write_key_id(self, context: EncryptionContext) -> str:
        if context.purpose.value == self._purpose:
            return self._target_key
        return super().write_key_id(context)

    def needs_reencryption(self, blob: str, *, context: EncryptionContext) -> bool:
        return self.key_id_of(blob) != self.write_key_id(context)


async def _seed_provider_config(
    admin_db: DatabaseSession, svc: LocalEncryptionService, secret: str = "s"
) -> None:
    async with admin_db.transaction() as session:
        session.add(
            ProviderConfigRecord(
                id="pcfg_x",
                name="idp",
                config_json={
                    "client_secret": await svc.encrypt(
                        secret, context=provider_config_secret_context("idp", "client_secret")
                    )
                },
            )
        )


async def test_all_keys_check_accepts_a_secondary_key_at_its_purpose_write_target(
    tmp_path: Path,
) -> None:
    k1, k2 = _make_key("v1"), _make_key("v2")
    v1_svc = LocalEncryptionService(EncryptionConfig(active_id="v1", entries=[k1]))
    inner = LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[k1, k2]))
    backend = _PurposeTargetBackend(inner, purpose="oauth.client_secret", target_key="v1")

    control_db, admin_db = await _make_sqlite_dbs(tmp_path)
    try:
        await _seed_provider_config(admin_db, v1_svc)  # v1 is correct for this purpose
        report = await assert_only_active_key(backend, control_db=control_db, admin_db=admin_db)
        assert report.counts_by_key_after == {"v1": 1}
    finally:
        await control_db.close()
        await admin_db.close()


async def test_all_keys_check_rejects_a_primary_key_value_under_the_wrong_purpose(
    tmp_path: Path,
) -> None:
    k1, k2 = _make_key("v1"), _make_key("v2")
    v2_svc = LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[k1, k2]))
    backend = _PurposeTargetBackend(v2_svc, purpose="oauth.client_secret", target_key="v1")

    control_db, admin_db = await _make_sqlite_dbs(tmp_path)
    try:
        # Stored under the primary key v2, but this purpose now writes with v1.
        await _seed_provider_config(admin_db, v2_svc)
        with pytest.raises(KeyRetirementError) as exc:
            await assert_only_active_key(backend, control_db=control_db, admin_db=admin_db)
        assert exc.value.remaining_by_key == {"<needs-rewrite>": 1}
    finally:
        await control_db.close()
        await admin_db.close()


async def test_a_legacy_held_jobs_top_level_cookie_blocks_retirement(tmp_path: Path) -> None:
    """A held job without an envelope keeps its cookie at the top level; the worker reads it."""
    k1, k2 = _make_key("v1"), _make_key("v2")
    v1_svc = LocalEncryptionService(EncryptionConfig(active_id="v1", entries=[k1]))
    v2_svc = LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[k1, k2]))
    v2_only = LocalEncryptionService(EncryptionConfig(active_id="v2", entries=[k2]))

    control_db, admin_db = await _make_sqlite_dbs(tmp_path)
    try:
        async with admin_db.transaction() as session:
            session.add(
                Job(
                    id="job_legacy_cookie",
                    kind="execution",
                    status="held",
                    actor_type="agent",
                    attempts=0,
                    payload={
                        "method": "GET",
                        "inbound_cookie_enc": await v1_svc.encrypt(
                            "session=abc",
                            context=cookie_context(execution_id=None, job_id="job_legacy_cookie"),
                        ),
                    },
                )
            )
            # A legacy held job with no cookie at all is still accepted.
            session.add(
                Job(
                    id="job_legacy_plain",
                    kind="execution",
                    status="held",
                    actor_type="agent",
                    attempts=0,
                    payload={"method": "GET"},
                )
            )

        report = await rotate_encrypted_storage(
            v2_svc, control_db=control_db, admin_db=admin_db, dry_run=True
        )
        assert report.by_family["held_executions"].scanned_values == 1
        with pytest.raises(KeyRetirementError):
            await verify_key_retired(v2_svc, "v1", control_db=control_db, admin_db=admin_db)

        rotated = await rotate_encrypted_storage(v2_svc, control_db=control_db, admin_db=admin_db)
        assert rotated.rotated_values == 1
        await verify_key_retired(v2_svc, "v1", control_db=control_db, admin_db=admin_db)

        async with admin_db.session() as session:
            job = await session.get(Job, "job_legacy_cookie")
        assert job is not None
        payload = job.payload
        assert isinstance(payload, dict)
        assert (
            await v2_only.decrypt(
                payload["inbound_cookie_enc"],
                context=cookie_context(execution_id=None, job_id="job_legacy_cookie"),
            )
            == "session=abc"
        )
    finally:
        await control_db.close()
        await admin_db.close()
