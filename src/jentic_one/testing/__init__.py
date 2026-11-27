"""Public testing seam: compliance and contract base classes for extension points.

A downstream package inherits these in its own test suite to prove its
``SearchStrategy`` / ``Broker`` / ``UnregisteredUrlHandler`` implementations
match the built-in contract —
both the method *names* (``runtime_checkable`` ``isinstance``) and the concrete
*signatures* (``inspect.signature``), which a bare Protocol never checks — and
that a shared-state backend registered with ``register_state_backend`` behaves
like the built-in ones (:class:`BaseStateBackendContract`), and that an
encryption backend registered with ``register_encryption_backend`` follows the
encryption contract (:class:`BaseEncryptionServiceContract`).

Shipped in the wheel so ``import jentic_one.testing`` works for downstream repos.
"""

from jentic_one.testing.compliance import (
    BaseBrokerComplianceTest,
    BaseSearchStrategyComplianceTest,
    BaseUnregisteredUrlHandlerComplianceTest,
    assert_signature_matches,
)
from jentic_one.testing.encryption import (
    BaseEncryptionServiceContract,
    FakeBackendBehaviour,
    FakeEncryptionBackend,
    register_fake_encryption_backend,
)
from jentic_one.testing.state_backend import BaseStateBackendContract

__all__ = [
    "BaseBrokerComplianceTest",
    "BaseEncryptionServiceContract",
    "BaseSearchStrategyComplianceTest",
    "BaseStateBackendContract",
    "BaseUnregisteredUrlHandlerComplianceTest",
    "FakeBackendBehaviour",
    "FakeEncryptionBackend",
    "assert_signature_matches",
    "register_fake_encryption_backend",
]
