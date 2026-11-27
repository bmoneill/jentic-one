"""Encryption backend failures answer 503 Problem Details on the control-plane apps."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from jentic_one.control.web.app import create_app as create_control_app
from jentic_one.shared.config import AppConfig
from jentic_one.shared.context import Context
from jentic_one.shared.crypto.errors import (
    EncryptionAccessDeniedError,
    EncryptionUnavailableError,
)
from jentic_one.shared.web.app_factory import create_combined_app

_KEY_MATERIAL = "k3y-m4t3r14l"
_CIPHERTEXT = "v1:c1ph3rt3xt"


def _combined(config: dict[str, Any]) -> FastAPI:
    return create_combined_app(Context(AppConfig.model_validate(config)), ["control", "admin"])


def _standalone(config: dict[str, Any]) -> FastAPI:
    return create_control_app(Context(AppConfig.model_validate(config)))


def _raise_on(app: FastAPI, exc: Exception) -> TestClient:
    @app.get("/boom")
    def boom() -> None:
        raise exc

    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("build", [_combined, _standalone])
def test_unavailable_maps_to_503_with_retry_after(
    sample_config_dict: dict[str, Any], build: Any
) -> None:
    exc = EncryptionUnavailableError(
        f"throttled with {_KEY_MATERIAL} on {_CIPHERTEXT}",
        backend="example-kms",
        key_id="key-1",
        retry_after_s=2.5,
    )
    resp = _raise_on(build(sample_config_dict), exc).get("/boom")

    assert resp.status_code == 503
    assert resp.headers["content-type"] == "application/problem+json"
    assert resp.headers["Retry-After"] == "3"
    body = resp.json()
    assert body["type"] == "encryption_unavailable"
    assert body["status"] == 503
    assert body["instance"] == "/boom"
    assert "example-kms" in body["detail"]
    assert _KEY_MATERIAL not in resp.text
    assert _CIPHERTEXT not in resp.text


def test_unavailable_without_retry_hint_omits_retry_after(
    sample_config_dict: dict[str, Any],
) -> None:
    exc = EncryptionUnavailableError("timed out", backend="example-kms")
    resp = _raise_on(_combined(sample_config_dict), exc).get("/boom")

    assert resp.status_code == 503
    assert resp.json()["type"] == "encryption_unavailable"
    assert "Retry-After" not in resp.headers


@pytest.mark.parametrize("build", [_combined, _standalone])
def test_access_denied_maps_to_503(sample_config_dict: dict[str, Any], build: Any) -> None:
    exc = EncryptionAccessDeniedError(
        f"key {_KEY_MATERIAL} disabled", backend="example-kms", key_id="key-1"
    )
    resp = _raise_on(build(sample_config_dict), exc).get("/boom")

    assert resp.status_code == 503
    assert resp.headers["content-type"] == "application/problem+json"
    assert "Retry-After" not in resp.headers
    body = resp.json()
    assert body["type"] == "encryption_access_denied"
    assert "example-kms" in body["detail"]
    assert _KEY_MATERIAL not in resp.text
