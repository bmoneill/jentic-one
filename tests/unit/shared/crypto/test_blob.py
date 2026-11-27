"""Blob codec, AEAD primitives and encryption-context encoding."""

from __future__ import annotations

import base64

import pytest

from jentic_one.shared.crypto import EncryptionScope, Purpose, aead
from jentic_one.shared.crypto import blob as blob_codec
from jentic_one.shared.crypto.blob import BlobFormat
from jentic_one.shared.crypto.errors import DecryptionError


def test_legacy_round_trip() -> None:
    encoded = blob_codec.encode("v1", b"payload")
    assert encoded == "v1:" + base64.b64encode(b"payload").decode()
    decoded = blob_codec.decode(encoded)
    assert (decoded.key_id, decoded.fmt, decoded.payload) == ("v1", BlobFormat.LEGACY, b"payload")


@pytest.mark.parametrize("fmt", [BlobFormat.CONTEXT_BOUND, BlobFormat.ENVELOPE])
def test_tagged_formats_round_trip(fmt: BlobFormat) -> None:
    encoded = blob_codec.encode("kms-1", b"payload", fmt=fmt)
    assert encoded.startswith(f"kms-1:{fmt.value}:")
    assert blob_codec.key_id_of(encoded) == "kms-1"
    assert blob_codec.format_of(encoded) is fmt
    assert blob_codec.decode(encoded).payload == b"payload"


@pytest.mark.parametrize(
    ("blob", "message"),
    [
        ("no-separator", "missing key_id separator"),
        (":payload", "empty key_id"),
        ("v1:9:AAAA", "unknown format tag"),
    ],
)
def test_malformed_blobs(blob: str, message: str) -> None:
    with pytest.raises(DecryptionError, match=message):
        blob_codec.decode(blob)


def test_encode_rejects_invalid_key_id() -> None:
    with pytest.raises(ValueError, match="key id"):
        blob_codec.encode("bad:id", b"x")


def test_envelope_round_trip() -> None:
    packed = blob_codec.pack_envelope(b"wrapped-key", b"sealed-bytes")
    assert blob_codec.unpack_envelope(packed) == (b"wrapped-key", b"sealed-bytes")


@pytest.mark.parametrize("payload", [b"", b"\x00", b"\x00\x05abc", b"\x00\x00rest"])
def test_truncated_envelopes_raise(payload: bytes) -> None:
    with pytest.raises(DecryptionError):
        blob_codec.unpack_envelope(payload)


def test_pack_envelope_rejects_empty_wrapped_key() -> None:
    with pytest.raises(ValueError):
        blob_codec.pack_envelope(b"", b"sealed")


def test_aead_round_trip_and_fresh_nonce() -> None:
    key = aead.generate_key()
    assert len(key) == aead.KEY_BYTES
    first = aead.seal(key, b"plain", aad=b"ctx")
    second = aead.seal(key, b"plain", aad=b"ctx")
    assert first != second
    assert aead.open_sealed(key, first, aad=b"ctx") == b"plain"


def test_aead_rejects_wrong_aad_and_short_input() -> None:
    key = aead.generate_key()
    sealed = aead.seal(key, b"plain", aad=b"ctx")
    with pytest.raises(DecryptionError):
        aead.open_sealed(key, sealed, aad=b"other")
    with pytest.raises(DecryptionError):
        aead.open_sealed(key, sealed, aad=None)
    with pytest.raises(DecryptionError, match="too short"):
        aead.open_sealed(key, b"short", aad=None)


def test_aead_rejects_wrong_key_length() -> None:
    with pytest.raises(ValueError):
        aead.seal(b"short", b"plain", aad=None)


def test_context_aad_is_canonical_and_unambiguous() -> None:
    scope = EncryptionScope(Purpose.CREDENTIAL_SECRET, "credential", "cred_1")
    assert scope.field("a").aad() == scope.field("a").aad()
    # Moving a separator between components must change the encoding.
    left = EncryptionScope(Purpose.CREDENTIAL_SECRET, "credential", "ab").field("c")
    right = EncryptionScope(Purpose.CREDENTIAL_SECRET, "credential", "a").field("bc")
    assert left.aad() != right.aad()
    other_purpose = EncryptionScope(Purpose.OAUTH_TOKEN, "credential", "cred_1").field("a")
    assert other_purpose.aad() != scope.field("a").aad()


def test_context_rejects_empty_components() -> None:
    with pytest.raises(ValueError):
        EncryptionScope(Purpose.TRANSIENT, "", "x")
    with pytest.raises(ValueError):
        EncryptionScope(Purpose.TRANSIENT, "execution", "")
    with pytest.raises(ValueError):
        EncryptionScope(Purpose.TRANSIENT, "execution", "x").field("")


def test_legacy_payloads_decode_leniently_as_before() -> None:
    """Stray characters outside the base64 alphabet are ignored, as the keyset always did."""
    clean = blob_codec.encode("v1", b"payload")
    assert blob_codec.decode(clean + "\n").payload == b"payload"
    assert blob_codec.decode(clean.replace(":", ": ", 1)).payload == b"payload"


def test_a_key_id_accepted_by_config_can_write_and_read() -> None:
    """Key ids use ``match``, like config validation, so a trailing newline is accepted."""
    encoded = blob_codec.encode("v1\n", b"payload")
    assert blob_codec.decode(encoded).payload == b"payload"
