"""Audit entries for credential reads.

Credential reads return redacted metadata (names, vendor, owner, state), never
secrets, but enumerating them is still worth a trail: an ``org:admin`` sees
every owner's credentials. ``credentials.read_audit.policy`` decides which
reads are recorded:

- ``cross_owner`` (default): only reads that return a credential the caller did
  not create (``created_by`` is neither the caller nor, for an agent, its
  owner). Owners reading their own credentials write nothing.
- ``all``: every read.
- ``off``: none.

A list writes one ``credential.list`` entry per request carrying the returned
ids; a single-credential read writes one ``credential.read`` entry. Identical
reads by the same actor within ``dedupe_seconds`` are recorded once per
process. Recording is best-effort and never fails the read.
"""

from __future__ import annotations

import threading
import time
import weakref
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from jentic_one.shared.audit import record_audit_best_effort
from jentic_one.shared.auth.identity import Identity
from jentic_one.shared.context import Context
from jentic_one.shared.models.audit import AuditAction, AuditTargetType

#: ``target_id`` of a list entry, which covers many credentials.
LIST_TARGET_ID: Final = "*"

_MAX_DEDUPE_ENTRIES: Final = 10_000


@dataclass(frozen=True, slots=True)
class ReadCredential:
    """A credential a read returned: its id and who created it."""

    credential_id: str
    created_by: str | None


class _Dedupe:
    """Bounded, per-process memory of recently recorded reads."""

    def __init__(self) -> None:
        self._seen: OrderedDict[tuple[str, ...], float] = OrderedDict()
        self._lock = threading.Lock()

    def first_within(self, key: tuple[str, ...], window_s: float) -> bool:
        """Remember *key*; True unless it was already recorded within *window_s*."""
        if window_s <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            seen_at = self._seen.get(key)
            if seen_at is not None and now - seen_at < window_s:
                return False
            self._seen[key] = now
            self._seen.move_to_end(key)
            while len(self._seen) > _MAX_DEDUPE_ENTRIES:
                self._seen.popitem(last=False)
            return True


_DEDUPE: weakref.WeakKeyDictionary[Context, _Dedupe] = weakref.WeakKeyDictionary()
_DEDUPE_LOCK = threading.Lock()


def _dedupe_for(ctx: Context) -> _Dedupe:
    with _DEDUPE_LOCK:
        dedupe = _DEDUPE.get(ctx)
        if dedupe is None:
            dedupe = _Dedupe()
            _DEDUPE[ctx] = dedupe
        return dedupe


def _is_own(credential: ReadCredential, identity: Identity) -> bool:
    owners = {identity.sub}
    if identity.parent_actor_id:
        owners.add(identity.parent_actor_id)
    return credential.created_by in owners


async def record_credential_read(
    ctx: Context,
    identity: Identity,
    *,
    action: AuditAction,
    credentials: Sequence[ReadCredential],
    target_id: str,
    view: str,
) -> None:
    """Record a credential read according to ``credentials.read_audit.policy``.

    Args:
        ctx: The application context.
        identity: The caller.
        action: :attr:`AuditAction.READ` or :attr:`AuditAction.LIST`.
        credentials: The credentials the read returned.
        target_id: The credential id, or :data:`LIST_TARGET_ID` for a list.
        view: Which read this was (``list``, ``detail`` or ``agents``).
    """
    cfg = ctx.config.credentials.read_audit
    if cfg.policy == "off" or not credentials:
        return
    cross_owner = [c for c in credentials if not _is_own(c, identity)]
    if cfg.policy == "cross_owner" and not cross_owner:
        return

    ids = sorted(c.credential_id for c in credentials)
    key = (identity.sub, action.value, view, target_id, *ids)
    if not _dedupe_for(ctx).first_within(key, cfg.dedupe_seconds):
        return

    after: dict[str, object] = {
        "view": view,
        "credential_ids": ids,
        "count": len(ids),
        "cross_owner_count": len(cross_owner),
    }
    await record_audit_best_effort(
        ctx,
        action=action,
        target_type=AuditTargetType.CREDENTIAL,
        target_id=target_id,
        actor_type=identity.actor_type.value,
        actor_id=identity.sub,
        after=after,
        origin=identity.origin.value,
    )
