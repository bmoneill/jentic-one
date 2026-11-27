"""Ciphertext blob encoding shared by every encryption backend.

Every stored ciphertext is ASCII text prefixed with the identifier of the key
that produced it, so rotation inventories and operator queries such as
``split_part(col, ':', 1)`` work for every backend:

=========  ==========================================  =========================
Format     Shape                                       Written by
=========  ==========================================  =========================
legacy     ``<key_id>:<b64(nonce‖ct‖tag)>``            the ``local`` backend
2          ``<key_id>:2:<b64(nonce‖ct‖tag)>``          reserved: context-bound local
3          ``<key_id>:3:<b64(envelope)>``              envelope backends
=========  ==========================================  =========================

An envelope payload is ``u16 len ‖ wrapped_key ‖ nonce ‖ ct ‖ tag``; the
wrapped key is opaque to this module. Standard base64 never contains ``:``, so
the two shapes cannot be confused.

This module never imports ``cryptography``.
"""

from __future__ import annotations

import base64
import binascii
import re
import struct
from dataclasses import dataclass
from enum import Enum

from jentic_one.shared.crypto.errors import DecryptionError

KEY_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")

_U16 = struct.Struct(">H")


class BlobFormat(Enum):
    """Wire format of an encrypted blob. ``LEGACY`` carries no format tag."""

    LEGACY = None
    CONTEXT_BOUND = 2
    ENVELOPE = 3


_TAGGED_FORMATS: dict[str, BlobFormat] = {
    str(fmt.value): fmt for fmt in BlobFormat if fmt.value is not None
}


@dataclass(frozen=True, slots=True)
class DecodedBlob:
    """A parsed blob: the key id prefix, its format and the raw payload bytes."""

    key_id: str
    fmt: BlobFormat
    payload: bytes


def key_id_of(blob: str) -> str:
    """Return the key id prefix of *blob* without decoding the payload.

    Raises:
        DecryptionError: The blob has no ``:`` separator or an empty key id.
    """
    sep = blob.find(":")
    if sep == -1:
        raise DecryptionError("Invalid blob format: missing key_id separator")
    key_id = blob[:sep]
    if not key_id:
        raise DecryptionError("Invalid blob format: empty key_id")
    return key_id


def format_of(blob: str) -> BlobFormat:
    """Return the wire format of *blob* from its prefix alone.

    Raises:
        DecryptionError: The prefix is malformed or names an unknown format.
    """
    key_id = key_id_of(blob)
    rest = blob[len(key_id) + 1 :]
    sep = rest.find(":")
    if sep == -1:
        return BlobFormat.LEGACY
    fmt = _TAGGED_FORMATS.get(rest[:sep])
    if fmt is None:
        raise DecryptionError("Invalid blob format: unknown format tag")
    return fmt


def encode(key_id: str, payload: bytes, *, fmt: BlobFormat = BlobFormat.LEGACY) -> str:
    """Encode *payload* under *key_id* in the given format."""
    # ``match`` (not ``fullmatch``), as config validation uses: any key id that
    # loads from config can write.
    if not KEY_ID_PATTERN.match(key_id):
        raise ValueError("key id must match [a-zA-Z0-9_-]+")
    b64 = base64.b64encode(payload).decode("ascii")
    if fmt is BlobFormat.LEGACY:
        return f"{key_id}:{b64}"
    return f"{key_id}:{fmt.value}:{b64}"


def decode(blob: str) -> DecodedBlob:
    """Parse *blob* into its key id, format and payload.

    Raises:
        DecryptionError: The blob is malformed or its payload is not base64.
    """
    key_id = key_id_of(blob)
    fmt = format_of(blob)
    skip = len(key_id) + 1
    if fmt is not BlobFormat.LEGACY:
        skip += len(str(fmt.value)) + 1
    try:
        # Non-validating, as the keyset always decoded: characters outside the
        # base64 alphabet (stray whitespace) are ignored, not rejected.
        payload = base64.b64decode(blob[skip:])
    except (binascii.Error, ValueError) as exc:
        raise DecryptionError("Invalid base64 payload") from exc
    return DecodedBlob(key_id=key_id, fmt=fmt, payload=payload)


def pack_envelope(wrapped_key: bytes, sealed: bytes) -> bytes:
    """Return ``u16 len(wrapped_key) ‖ wrapped_key ‖ sealed``."""
    if not wrapped_key:
        raise ValueError("wrapped_key must not be empty")
    if len(wrapped_key) > 0xFFFF:
        raise ValueError("wrapped_key must be at most 65535 bytes")
    return _U16.pack(len(wrapped_key)) + wrapped_key + sealed


def unpack_envelope(payload: bytes) -> tuple[bytes, bytes]:
    """Split an envelope payload into ``(wrapped_key, sealed)``.

    Raises:
        DecryptionError: The payload is truncated.
    """
    if len(payload) < _U16.size:
        raise DecryptionError("Envelope too short")
    (length,) = _U16.unpack_from(payload)
    end = _U16.size + length
    if length == 0 or len(payload) <= end:
        raise DecryptionError("Envelope truncated")
    return payload[_U16.size : end], payload[end:]
