"""Renewing a credential grant from another surface (a ``grant_renewal`` hold).

A held call of kind ``grant_renewal`` is decided on the admin surface, but the
grant (the agent's binding) and the rule for who may renew it live with the
agents service on the auth surface, which admin may not import. The decision
goes through this protocol instead; the composition root (``jentic_one.wiring``)
installs the agents service's implementation on the app as
``app.state.grant_renewer``. Approving a renewal and renewing from the console
are then one service method, so the authorization rule lives in one place.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from jentic_one.shared.auth.identity import Identity


@dataclass(frozen=True, slots=True)
class GrantRenewalPolicy:
    """The fresh policy a renewal gives the grant (replacing its old one).

    Each field ``None`` (``False`` for the warning) sets no such limit: fresh
    access is exactly what the reviewer chose.
    """

    expires_at: datetime | None = None
    max_idle_period: int | None = None
    idle_warning: bool = False
    max_quota: int | None = None


class GrantRenewalRefusedError(Exception):
    """The reviewer may not renew this grant, or it no longer exists."""


class GrantRenewerProtocol(Protocol):
    """Renew an agent's binding to a credential, as its renew endpoint does."""

    async def may_renew(self, *, identity: Identity, agent_id: str, credential_id: str) -> bool:
        """Whether ``identity`` may renew the binding directly (the renew endpoint's checks)."""
        ...

    async def renew(
        self,
        *,
        identity: Identity,
        agent_id: str,
        credential_id: str,
        policy: GrantRenewalPolicy,
    ) -> None:
        """Reset the binding's policy in place; raise :class:`GrantRenewalRefusedError` if not."""
        ...
