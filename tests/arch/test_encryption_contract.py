"""Guard rails for the swappable encryption backend.

- ``encryption`` parameters are typed as the ``EncryptionService`` contract, never
  ``Any`` or left bare: once encrypt and decrypt are async, ``str()`` of a missing
  ``await`` yields a valid-looking string that mypy cannot see behind ``Any``.
- Only the backend factory and the test kit construct
  ``LocalEncryptionService`` directly; everything else goes through
  ``ctx.encryption`` so a registered backend is honoured everywhere.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.arch.conftest import SRC_ROOT, python_files_in

_LOCAL_CONSTRUCTION_ALLOWED = {
    SRC_ROOT / "shared" / "crypto" / "backends.py",
}
_TESTING_ROOT = SRC_ROOT / "testing"


def _parse(path: Path) -> ast.Module | None:
    try:
        return ast.parse(path.read_text())
    except SyntaxError:
        return None


def _annotation_is_any(node: ast.expr | None) -> bool:
    if node is None:
        return True
    if isinstance(node, ast.Name):
        return node.id == "Any"
    if isinstance(node, ast.Attribute):
        return node.attr == "Any"
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.strip() in {"Any", "typing.Any"}
    return False


@pytest.mark.arch
def test_encryption_parameters_are_typed_with_the_contract() -> None:
    violations: list[str] = []
    for path in python_files_in(SRC_ROOT):
        tree = _parse(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            for arg in args:
                if arg.arg == "encryption" and _annotation_is_any(arg.annotation):
                    rel = path.relative_to(SRC_ROOT)
                    violations.append(f"{rel}:{node.lineno} {node.name}(encryption=...)")
    assert not violations, (
        "Type `encryption` parameters as EncryptionService (not Any or unannotated):\n"
        + "\n".join(f"  {v}" for v in violations)
    )


@pytest.mark.arch
def test_local_encryption_service_is_built_only_by_the_factory() -> None:
    violations: list[str] = []
    for path in python_files_in(SRC_ROOT):
        if path in _LOCAL_CONSTRUCTION_ALLOWED or path.is_relative_to(_TESTING_ROOT):
            continue
        tree = _parse(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else None
            )
            if name == "LocalEncryptionService":
                violations.append(f"{path.relative_to(SRC_ROOT)}:{node.lineno}")
    assert not violations, (
        "Use ctx.encryption (or build_local_encryption_service in a backend builder) "
        "instead of constructing LocalEncryptionService:\n"
        + "\n".join(f"  {v}" for v in violations)
    )
