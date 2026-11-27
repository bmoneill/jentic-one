"""AES-256-GCM primitives shared by every encryption backend.

This is one of the few modules permitted to import ``cryptography`` (see
``tests/arch/test_encryption_facade.py``). Backends build on these helpers
instead of importing ``cryptography`` themselves, so there is one AES-GCM
code path in the codebase.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from jentic_one.shared.crypto.errors import DecryptionError

KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16


def generate_key() -> bytes:
    """Return 32 fresh random bytes suitable as an AES-256 key."""
    return os.urandom(KEY_BYTES)


def _cipher(key: bytes) -> AESGCM:
    if len(key) != KEY_BYTES:
        raise ValueError(f"AES-256-GCM key must be {KEY_BYTES} bytes, got {len(key)}")
    return AESGCM(key)


class AeadKey:
    """A validated AES-256-GCM key, reusable across many seal/open calls."""

    __slots__ = ("_cipher",)

    def __init__(self, key: bytes) -> None:
        self._cipher = _cipher(key)

    def seal(self, plaintext: bytes, *, aad: bytes | None) -> bytes:
        """Encrypt with a fresh 12-byte nonce. Returns ``nonce ‖ ciphertext ‖ tag``."""
        nonce = os.urandom(NONCE_BYTES)
        return nonce + self._cipher.encrypt(nonce, plaintext, aad)

    def open(self, sealed: bytes, *, aad: bytes | None) -> bytes:
        """Decrypt ``nonce ‖ ciphertext ‖ tag``. Raises :exc:`DecryptionError`."""
        if len(sealed) < NONCE_BYTES + TAG_BYTES:
            raise DecryptionError("Payload too short")
        nonce, body = sealed[:NONCE_BYTES], sealed[NONCE_BYTES:]
        try:
            return self._cipher.decrypt(nonce, body, aad)
        except InvalidTag as exc:
            raise DecryptionError("Decryption failed: authentication error") from exc


def seal(key: bytes, plaintext: bytes, *, aad: bytes | None) -> bytes:
    """Encrypt *plaintext* under *key* with a fresh nonce. Returns ``nonce ‖ ct ‖ tag``."""
    return AeadKey(key).seal(plaintext, aad=aad)


def open_sealed(key: bytes, sealed: bytes, *, aad: bytes | None) -> bytes:
    """Decrypt ``nonce ‖ ct ‖ tag`` under *key*. Raises :exc:`DecryptionError`."""
    return AeadKey(key).open(sealed, aad=aad)
