"""Error taxonomy for the encryption contract.

Three distinct failure classes let callers map an encryption failure to the
right response instead of treating every failure as "this ciphertext is gone":

- :class:`DecryptionError`: this blob will never decrypt (wrong key, wrong
  context, or corrupt). Retrying cannot help; an operator must re-add the value.
- :class:`EncryptionUnavailableError`: a transient backend failure (throttled,
  timed out, unreachable). Retrying later may succeed.
- :class:`EncryptionAccessDeniedError`: the backend refused the operation
  (permission denied, key disabled or scheduled for deletion). An operator
  must restore access; the stored value is not lost.

The ``local`` backend only ever raises :class:`DecryptionError`. The two
backend errors share :class:`EncryptionBackendError` so call sites can map
them together, and they deliberately do **not** subclass
:class:`DecryptionError`: an ``except DecryptionError`` that tells an operator
to delete a credential must never swallow an outage.

Messages must never carry plaintext, key material or ciphertext.
"""

from __future__ import annotations


class DecryptionError(Exception):
    """The blob cannot be decrypted: unknown key id, malformed, or failed authentication."""


class EncryptionBackendError(Exception):
    """Base for failures of the encryption backend itself, not of a stored value.

    Attributes:
        backend: Registered name of the backend that failed (for example ``local``).
        key_id: Key identifier involved, when known. Never key material.
    """

    code = "encryption_unavailable"

    def __init__(self, message: str, *, backend: str, key_id: str | None = None) -> None:
        super().__init__(message)
        self.backend = backend
        self.key_id = key_id


class EncryptionUnavailableError(EncryptionBackendError):
    """Transient backend failure: throttled, 5xx, timeout or network error.

    Attributes:
        retry_after_s: Suggested delay before retrying, when the backend knows one.
    """

    def __init__(
        self,
        message: str,
        *,
        backend: str,
        key_id: str | None = None,
        retry_after_s: float | None = None,
    ) -> None:
        super().__init__(message, backend=backend, key_id=key_id)
        self.retry_after_s = retry_after_s


class EncryptionAccessDeniedError(EncryptionBackendError):
    """The backend refused the operation; an operator must restore access."""

    code = "encryption_access_denied"
