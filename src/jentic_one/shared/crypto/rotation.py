"""Database re-encryption and key-retirement verification across persisted storage.

Covers every persisted :class:`~jentic_one.shared.crypto.encryption.EncryptionService`
consumer in the control and admin databases:

- ``control_db``:
  - ``customer_api_keys`` (``encrypted_key``)
  - ``token_value_credentials`` / ``bearer_token_credentials`` (``encrypted_token_value``)
  - ``basic_credentials`` / ``basic_auth_credentials`` (``encrypted_password``)
  - ``sigv4_credentials`` (``encrypted_secret_access_key``, ``encrypted_session_token``)
  - ``device_authorization_credentials`` (``encrypted_device_code``)
  - ``oauth_client_credentials`` (``encrypted_client_secret``)
  - ``authorization_code_app_registration_details`` / ``oauth_app_registrations``
    (``encrypted_client_secret``)
  - ``oauth_tokens`` (``encrypted_access_token``, ``encrypted_refresh_token``)
- ``admin_db``:
  - ``provider_configs`` (``config_json["client_secret"]``)
  - ``jobs`` (async execution ``payload["inbound_cookie_enc"]``)
  - ``held_executions`` (held job ``payload["_enc"]`` and nested ``inbound_cookie_enc``)
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import OperationalError, ProgrammingError

from jentic_one.shared.crypto.contexts import (
    FIELD_PROVIDER_CLIENT_SECRET,
    app_registration_client_secret_context,
    cookie_context,
    credential_client_secret_context,
    credential_secret_context,
    device_code_context,
    held_payload_context,
    oauth_token_scope,
    provider_config_secret_context,
)
from jentic_one.shared.crypto.errors import DecryptionError
from jentic_one.shared.crypto.service import EncryptionContext, EncryptionService
from jentic_one.shared.db import DatabaseSession

_ENCRYPTED_PAYLOAD_KEY = "_enc"
_INBOUND_COOKIE_PAYLOAD_KEY = "inbound_cookie_enc"
_PROVIDER_SECRET_FIELDS: tuple[str, ...] = (FIELD_PROVIDER_CLIENT_SECRET,)
_MALFORMED_KEY_ID = "<malformed>"
_NEEDS_REWRITE_KEY = "<needs-rewrite>"
_ALL_DATABASES = frozenset({"control", "admin"})

#: Bidirectional aliases between logical family names and SQL table names.
_FAMILY_ALIASES: dict[str, str] = {
    "token_value_credentials": "bearer_token_credentials",
    "bearer_token_credentials": "bearer_token_credentials",
    "basic_credentials": "basic_auth_credentials",
    "basic_auth_credentials": "basic_auth_credentials",
    "authorization_code_app_registration_details": "oauth_app_registrations",
    "oauth_app_registrations": "oauth_app_registrations",
}


def _oauth_token_context(credential_id: str, column: str) -> EncryptionContext:
    return oauth_token_scope(credential_id).field(column)


@dataclass(frozen=True, slots=True)
class _ColumnSpec:
    database: str
    family: str
    table: str
    columns: tuple[str, ...]
    #: Column holding the owner id the storage mapping keys the context on.
    owner_column: str
    #: Builds a value's context from ``(owner_id, column)``.
    context_for: Callable[[str, str], EncryptionContext]


_CONTROL_COLUMN_SPECS: tuple[_ColumnSpec, ...] = (
    _ColumnSpec(
        database="control",
        family="customer_api_keys",
        table="customer_api_keys",
        columns=("encrypted_key",),
        owner_column="credential_id",
        context_for=credential_secret_context,
    ),
    _ColumnSpec(
        database="control",
        family="bearer_token_credentials",
        table="token_value_credentials",
        columns=("encrypted_token_value",),
        owner_column="credential_id",
        context_for=credential_secret_context,
    ),
    _ColumnSpec(
        database="control",
        family="basic_auth_credentials",
        table="basic_credentials",
        columns=("encrypted_password",),
        owner_column="credential_id",
        context_for=credential_secret_context,
    ),
    _ColumnSpec(
        database="control",
        family="sigv4_credentials",
        table="sigv4_credentials",
        columns=("encrypted_secret_access_key", "encrypted_session_token"),
        owner_column="credential_id",
        context_for=credential_secret_context,
    ),
    _ColumnSpec(
        database="control",
        family="device_authorization_credentials",
        table="device_authorization_credentials",
        columns=("encrypted_device_code",),
        owner_column="id",
        context_for=lambda owner, _column: device_code_context(owner),
    ),
    _ColumnSpec(
        database="control",
        family="oauth_client_credentials",
        table="oauth_client_credentials",
        columns=("encrypted_client_secret",),
        owner_column="id",
        context_for=lambda owner, _column: credential_client_secret_context(owner),
    ),
    _ColumnSpec(
        database="control",
        family="oauth_app_registrations",
        table="authorization_code_app_registration_details",
        columns=("encrypted_client_secret",),
        owner_column="id",
        context_for=lambda owner, _column: app_registration_client_secret_context(owner),
    ),
    _ColumnSpec(
        database="control",
        family="oauth_tokens",
        table="oauth_tokens",
        columns=("encrypted_access_token", "encrypted_refresh_token"),
        owner_column="credential_id",
        context_for=_oauth_token_context,
    ),
)


@dataclass(frozen=True, slots=True)
class RotationFailure:
    """One persisted ciphertext or payload that failed inspection or re-encryption."""

    database: str
    family: str
    table: str
    row_id: str
    column: str
    key_id: str | None
    error: str


@dataclass(slots=True)
class FamilyRotationStats:
    """Per-storage-family encryption inventory and rotation counters."""

    database: str
    family: str
    table: str
    scanned_rows: int = 0
    scanned_values: int = 0
    rotated_rows: int = 0
    rotated_values: int = 0
    needs_rotation_values: int = 0
    remaining_non_active_values: int = 0
    counts_by_key_before: dict[str, int] = field(default_factory=dict)
    counts_by_key_after: dict[str, int] = field(default_factory=dict)
    failures: list[RotationFailure] = field(default_factory=list)

    @property
    def counts_by_key(self) -> dict[str, int]:
        """Key distribution across this family after the scan/rotation pass."""
        return self.counts_by_key_after


class FamilyStatsMap(dict[str, FamilyRotationStats]):
    """Dictionary of :class:`FamilyRotationStats` that resolves both family and table names."""

    def _canonical(self, key: object) -> object:
        if isinstance(key, str):
            return _FAMILY_ALIASES.get(key, key)
        return key

    def __getitem__(self, key: str) -> FamilyRotationStats:
        return super().__getitem__(str(self._canonical(key)))

    def __contains__(self, key: object) -> bool:
        return super().__contains__(self._canonical(key))

    def get(  # type: ignore[override]
        self, key: str, default: FamilyRotationStats | None = None
    ) -> FamilyRotationStats | None:
        return super().get(str(self._canonical(key)), default)


class KeyRetirementError(DecryptionError):
    """Raised when a key retirement or active-key-only check fails closed."""

    def __init__(
        self,
        message: str,
        *,
        report: RotationReport,
        remaining_by_key: dict[str, int],
        remaining_by_family: dict[str, dict[str, int]],
    ) -> None:
        super().__init__(message)
        self.report = report
        self.remaining_by_key = remaining_by_key
        self.remaining_by_family = remaining_by_family
        self.failures = tuple(report.failures)


@dataclass(slots=True)
class RotationReport:
    """Aggregate report of a dry-run inventory or bounded-batch re-encryption pass."""

    active_key_id: str
    dry_run: bool
    batch_size: int
    #: Every key id the service currently writes with, across purposes. A key in this set
    #: is still needed for the next write even when no stored ciphertext references it.
    write_key_ids: tuple[str, ...] = ()
    #: Databases this pass scanned. Retirement is only certified when every storage
    #: database was covered, so a partial scan can inform but never approve it.
    covered_databases: frozenset[str] = frozenset()
    batches_executed: int = 0
    scanned_rows: int = 0
    scanned_values: int = 0
    rotated_rows: int = 0
    rotated_values: int = 0
    needs_rotation_values: int = 0
    remaining_non_active_values: int = 0
    counts_by_key_before: dict[str, int] = field(default_factory=dict)
    counts_by_key_after: dict[str, int] = field(default_factory=dict)
    by_family: FamilyStatsMap = field(default_factory=FamilyStatsMap)
    by_table: dict[str, FamilyRotationStats] = field(default_factory=dict)
    failures: list[RotationFailure] = field(default_factory=list)

    @property
    def counts_by_key(self) -> dict[str, int]:
        """Key distribution across all scanned storage after this pass."""
        return self.counts_by_key_after

    @property
    def completed(self) -> bool:
        """True when no non-active ciphertexts and no failures remain."""
        return self.remaining_non_active_values == 0 and not self.failures

    def verify_key_retired(self, retired_key_id: str | None = None) -> None:
        """Fail closed if *retired_key_id* (or any non-active key when None) remains in storage."""
        if retired_key_id is None:
            self.assert_only_active_key()
            return
        self._require_full_coverage()
        if retired_key_id == self.active_key_id or retired_key_id in self.write_key_ids:
            role = (
                "the active encryption key"
                if retired_key_id == self.active_key_id
                else "a current write key"
            )
            raise KeyRetirementError(
                f"Key '{retired_key_id}' is still {role} and cannot be retired",
                report=self,
                remaining_by_key={retired_key_id: self.counts_by_key_after.get(retired_key_id, 0)},
                remaining_by_family=_remaining_by_family(self, {retired_key_id}),
            )
        remaining_count = self.counts_by_key_after.get(retired_key_id, 0)
        if remaining_count > 0 or self.failures:
            remaining_by_key = {retired_key_id: remaining_count} if remaining_count > 0 else {}
            if _MALFORMED_KEY_ID in self.counts_by_key_after:
                remaining_by_key[_MALFORMED_KEY_ID] = self.counts_by_key_after[_MALFORMED_KEY_ID]
            raise KeyRetirementError(
                f"Key '{retired_key_id}' cannot be retired: {remaining_count} ciphertext(s) "
                f"still reference '{retired_key_id}' and {len(self.failures)} failure(s) occurred",
                report=self,
                remaining_by_key=remaining_by_key,
                remaining_by_family=_remaining_by_family(self, {retired_key_id, _MALFORMED_KEY_ID}),
            )

    def _require_full_coverage(self) -> None:
        """Fail closed unless this pass scanned every storage database."""
        missing = sorted(_ALL_DATABASES - self.covered_databases)
        if missing:
            raise KeyRetirementError(
                f"Retirement cannot be certified: the {', '.join(missing)} database(s) were "
                "not scanned. Run the check with every database configured.",
                report=self,
                remaining_by_key={},
                remaining_by_family={},
            )

    def assert_only_active_key(self) -> None:
        """Fail closed unless every stored value is already at its current write target.

        Uses the scan's per-value results (``needs_reencryption`` and failures), not a
        comparison with :attr:`active_key_id`: a secondary key that is the right write
        target for its purpose passes, while a primary-key value that still needs
        rewriting for its purpose or format fails.
        """
        self._require_full_coverage()
        if self.remaining_non_active_values > 0 or self.failures:
            offending_keys = {
                k: count
                for k, count in self.counts_by_key_after.items()
                if k not in self.write_key_ids and count > 0
            }
            if self.remaining_non_active_values > len(offending_keys) and not offending_keys:
                offending_keys[_NEEDS_REWRITE_KEY] = self.remaining_non_active_values
            raise KeyRetirementError(
                f"Storage still has {self.remaining_non_active_values} value(s) that need "
                f"rewriting ({offending_keys}) or {len(self.failures)} failure(s)",
                report=self,
                remaining_by_key=offending_keys,
                remaining_by_family=_remaining_by_family(self, set(offending_keys.keys())),
            )


def _remaining_by_family(
    report: RotationReport, target_keys: set[str]
) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for family, stats in report.by_family.items():
        matched = {
            k: count
            for k, count in stats.counts_by_key_after.items()
            if k in target_keys and count > 0
        }
        if matched:
            out[family] = matched
    return out


KeyRotationReport = RotationReport


def _inc(mapping: dict[str, int], key: str, delta: int = 1) -> None:
    mapping[key] = mapping.get(key, 0) + delta


def _safe_key_id(encryption: EncryptionService, blob: str) -> str | None:
    try:
        return encryption.key_id_of(blob)
    except DecryptionError:
        return None


def _decode_json_dict(raw: Any) -> dict[str, Any] | None:
    if raw is None:
        return None
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        if not raw.strip():
            return None
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
        raise ValueError("expected JSON object")
    raise ValueError(f"unsupported JSON column value type: {type(raw).__name__}")


@dataclass(slots=True)
class _Probe:
    """One encrypted value inspected during a scan, and what a rotation would write for it."""

    blob: str
    context: EncryptionContext
    plaintext: str | None = None
    error: DecryptionError | None = None
    needs: bool = False
    new_blob: str | None = None


async def _probe_values(
    encryption: EncryptionService, probes: list[_Probe], *, dry_run: bool
) -> None:
    """Authenticate each value and, when rotating, seal the ones that need a new key.

    Inspection (``dry_run``) only authenticates with ``decrypt`` and asks
    ``needs_reencryption``: it never requests a replacement key, so it needs no
    write access to the backend. When rotating, values replaced together share
    one prepared write per scope, and a row with any value that cannot be read
    is left untouched.
    """
    for probe in probes:
        try:
            probe.plaintext = await encryption.decrypt(probe.blob, context=probe.context)
        except DecryptionError as exc:
            probe.error = exc
            continue
        probe.needs = encryption.needs_reencryption(probe.blob, context=probe.context)
    if dry_run or any(p.error is not None for p in probes):
        return
    by_scope: dict[Any, list[_Probe]] = {}
    for probe in probes:
        if probe.needs and probe.plaintext is not None:
            by_scope.setdefault(probe.context.scope, []).append(probe)
    for scope, group in by_scope.items():
        async with encryption.prepare_write(scope) as prepared:
            for probe in group:
                assert probe.plaintext is not None
                probe.new_blob = prepared.seal(probe.plaintext, field=probe.context.field)


@dataclass(slots=True)
class _RowCandidate:
    row_id: Any
    update_params: dict[str, Any] | None
    values_scanned: int
    values_needing_rotation: int
    before_keys: list[str]
    after_keys_if_written: list[str]
    after_keys_if_skipped: list[str]
    failures: list[RotationFailure]
    original_values: dict[str, Any] = field(default_factory=dict)


def _apply_candidate_stats(
    report: RotationReport,
    stats: FamilyRotationStats,
    candidate: _RowCandidate,
    *,
    written: bool,
) -> None:
    stats.scanned_rows += 1
    report.scanned_rows += 1
    stats.scanned_values += candidate.values_scanned
    report.scanned_values += candidate.values_scanned
    stats.needs_rotation_values += candidate.values_needing_rotation
    report.needs_rotation_values += candidate.values_needing_rotation

    for k in candidate.before_keys:
        _inc(stats.counts_by_key_before, k)
        _inc(report.counts_by_key_before, k)

    after_keys = candidate.after_keys_if_written if written else candidate.after_keys_if_skipped
    for k in after_keys:
        _inc(stats.counts_by_key_after, k)
        _inc(report.counts_by_key_after, k)

    if written and candidate.values_needing_rotation > 0:
        stats.rotated_rows += 1
        report.rotated_rows += 1
        stats.rotated_values += candidate.values_needing_rotation
        report.rotated_values += candidate.values_needing_rotation
    else:
        stats.remaining_non_active_values += candidate.values_needing_rotation
        report.remaining_non_active_values += candidate.values_needing_rotation

    if candidate.failures:
        stats.failures.extend(candidate.failures)
        report.failures.extend(candidate.failures)


async def _flush_write_batch(
    db: DatabaseSession,
    update_sql: str,
    pending: list[_RowCandidate],
    report: RotationReport,
    stats: FamilyRotationStats,
    *,
    dry_run: bool,
    max_batches: int | None,
) -> None:
    if not pending:
        return
    can_write = (not dry_run) and (max_batches is None or report.batches_executed < max_batches)
    if can_write:
        async with db.transaction() as session:
            for item in pending:
                assert item.update_params is not None
                predicates = " AND ".join(
                    f"(CAST({column} AS TEXT) = CAST(:original_{column} AS TEXT) "
                    f"OR ({column} IS NULL AND :original_{column} IS NULL))"
                    for column in item.original_values
                )
                if not predicates:
                    raise ValueError("rotation update has no optimistic-concurrency predicate")
                stmt = text(f"{update_sql} AND {predicates}")
                params = {
                    **item.update_params,
                    **{
                        f"original_{column}": value
                        for column, value in item.original_values.items()
                    },
                }
                result = await session.execute(stmt, params)
                written = isinstance(result, CursorResult) and result.rowcount == 1
                if not written:
                    item.failures.append(
                        RotationFailure(
                            database=stats.database,
                            family=stats.family,
                            table=stats.table,
                            row_id=str(item.row_id),
                            column=", ".join(item.original_values),
                            key_id=None,
                            error="row changed during rotation; rerun to retry",
                        )
                    )
                _apply_candidate_stats(report, stats, item, written=written)
        report.batches_executed += 1
    else:
        for item in pending:
            _apply_candidate_stats(report, stats, item, written=False)
    pending.clear()


def _inspect_only(report: RotationReport, *, dry_run: bool, max_batches: int | None) -> bool:
    """Whether the next row must be read, not rewritten.

    True for a dry run, and once a bounded rotation has used its allowed batches:
    later rows are still authenticated and counted, but request no write key.
    """
    return dry_run or (max_batches is not None and report.batches_executed >= max_batches)


async def _rotate_column_spec(
    db: DatabaseSession,
    encryption: EncryptionService,
    spec: _ColumnSpec,
    report: RotationReport,
    *,
    dry_run: bool,
    batch_size: int,
    max_batches: int | None,
) -> None:
    stats = report.by_family[spec.family]
    col_list = ", ".join((spec.owner_column, *spec.columns))
    first_query = text(f"SELECT id, {col_list} FROM {spec.table} ORDER BY id ASC LIMIT :limit")
    paged_query = text(
        f"SELECT id, {col_list} FROM {spec.table} WHERE id > :after_id ORDER BY id ASC LIMIT :limit"
    )
    set_clause = ", ".join(f"{col} = :{col}" for col in spec.columns)
    update_sql = f"UPDATE {spec.table} SET {set_clause} WHERE id = :id"

    after_id: Any = None
    pending: list[_RowCandidate] = []

    while True:
        async with db.session() as session:
            if after_id is None:
                rows = (await session.execute(first_query, {"limit": batch_size})).all()
            else:
                rows = (
                    await session.execute(paged_query, {"after_id": after_id, "limit": batch_size})
                ).all()
        if not rows:
            break
        after_id = rows[-1][0]

        for row in rows:
            row_id = row[0]
            owner_id = str(row[1])
            before_keys: list[str] = []
            after_written: list[str] = []
            after_skipped: list[str] = []
            failures: list[RotationFailure] = []
            updated_cols: dict[str, Any] = {}
            values_scanned = 0
            values_needing_rotation = 0
            row_failed = False

            probes: list[_Probe] = []
            probe_cols: list[str] = []
            for idx, col in enumerate(spec.columns, start=2):
                raw_val = row[idx]
                if raw_val is None or raw_val == "":
                    updated_cols[col] = raw_val
                    continue
                probes.append(_Probe(blob=str(raw_val), context=spec.context_for(owner_id, col)))
                probe_cols.append(col)

            await _probe_values(
                encryption,
                probes,
                dry_run=_inspect_only(report, dry_run=dry_run, max_batches=max_batches),
            )

            for col, probe in zip(probe_cols, probes, strict=True):
                values_scanned += 1
                key_id = _safe_key_id(encryption, probe.blob)
                recorded_key = key_id if key_id is not None else _MALFORMED_KEY_ID
                before_keys.append(recorded_key)
                target_key = encryption.write_key_id(probe.context)

                if probe.error is not None:
                    row_failed = True
                    if recorded_key != target_key:
                        values_needing_rotation += 1
                    after_written.append(recorded_key)
                    after_skipped.append(recorded_key)
                    updated_cols[col] = probe.blob
                    failures.append(
                        RotationFailure(
                            database=spec.database,
                            family=spec.family,
                            table=spec.table,
                            row_id=str(row_id),
                            column=col,
                            key_id=key_id,
                            error=str(probe.error),
                        )
                    )
                else:
                    updated_cols[col] = probe.new_blob if probe.new_blob is not None else probe.blob
                    if probe.needs:
                        values_needing_rotation += 1
                        after_written.append(target_key)
                        after_skipped.append(recorded_key)
                    else:
                        after_written.append(recorded_key)
                        after_skipped.append(recorded_key)

            candidate = _RowCandidate(
                row_id=row_id,
                update_params=(
                    {"id": row_id, **updated_cols}
                    if (values_needing_rotation > 0 and not row_failed)
                    else None
                ),
                original_values={col: row[idx] for idx, col in enumerate(spec.columns, start=2)},
                values_scanned=values_scanned,
                values_needing_rotation=values_needing_rotation,
                before_keys=before_keys,
                after_keys_if_written=after_written,
                after_keys_if_skipped=after_skipped,
                failures=failures,
            )
            if candidate.update_params is not None:
                pending.append(candidate)
                if len(pending) >= batch_size:
                    await _flush_write_batch(
                        db,
                        update_sql,
                        pending,
                        report,
                        stats,
                        dry_run=dry_run,
                        max_batches=max_batches,
                    )
            else:
                _apply_candidate_stats(report, stats, candidate, written=False)

        if len(rows) < batch_size:
            break

    await _flush_write_batch(
        db,
        update_sql,
        pending,
        report,
        stats,
        dry_run=dry_run,
        max_batches=max_batches,
    )


async def _rotate_provider_configs(
    admin_db: DatabaseSession,
    encryption: EncryptionService,
    report: RotationReport,
    *,
    dry_run: bool,
    batch_size: int,
    max_batches: int | None,
) -> None:
    stats = report.by_family["provider_configs"]
    first_query = text(
        "SELECT id, config_json, name FROM provider_configs ORDER BY id ASC LIMIT :limit"
    )
    paged_query = text(
        "SELECT id, config_json, name FROM provider_configs "
        "WHERE id > :after_id ORDER BY id ASC LIMIT :limit"
    )
    update_sql = "UPDATE provider_configs SET config_json = :config_json WHERE id = :id"

    after_id: Any = None
    pending: list[_RowCandidate] = []

    while True:
        async with admin_db.session() as session:
            if after_id is None:
                rows = (await session.execute(first_query, {"limit": batch_size})).all()
            else:
                rows = (
                    await session.execute(paged_query, {"after_id": after_id, "limit": batch_size})
                ).all()
        if not rows:
            break
        after_id = rows[-1][0]

        for row in rows:
            row_id = row[0]
            raw_json = row[1]
            provider_name = str(row[2])
            before_keys: list[str] = []
            after_written: list[str] = []
            after_skipped: list[str] = []
            failures: list[RotationFailure] = []
            values_scanned = 0
            values_needing_rotation = 0
            row_failed = False

            try:
                cfg_dict = _decode_json_dict(raw_json)
            except Exception as exc:
                failures.append(
                    RotationFailure(
                        database="admin",
                        family="provider_configs",
                        table="provider_configs",
                        row_id=str(row_id),
                        column="config_json",
                        key_id=None,
                        error=str(exc),
                    )
                )
                candidate = _RowCandidate(
                    row_id=row_id,
                    update_params=None,
                    values_scanned=1,
                    values_needing_rotation=1,
                    before_keys=[_MALFORMED_KEY_ID],
                    after_keys_if_written=[_MALFORMED_KEY_ID],
                    after_keys_if_skipped=[_MALFORMED_KEY_ID],
                    failures=failures,
                )
                _apply_candidate_stats(report, stats, candidate, written=False)
                continue

            if cfg_dict is None:
                cfg_dict = {}
            updated_cfg = dict(cfg_dict)

            probes = []
            probe_fields: list[str] = []
            for secret_field in _PROVIDER_SECRET_FIELDS:
                secret_val = cfg_dict.get(secret_field)
                if not isinstance(secret_val, str) or not secret_val:
                    continue
                probes.append(
                    _Probe(
                        blob=secret_val,
                        context=provider_config_secret_context(provider_name, secret_field),
                    )
                )
                probe_fields.append(secret_field)

            await _probe_values(
                encryption,
                probes,
                dry_run=_inspect_only(report, dry_run=dry_run, max_batches=max_batches),
            )

            for secret_field, probe in zip(probe_fields, probes, strict=True):
                values_scanned += 1
                key_id = _safe_key_id(encryption, probe.blob)
                recorded_key = key_id if key_id is not None else _MALFORMED_KEY_ID
                before_keys.append(recorded_key)
                target_key = encryption.write_key_id(probe.context)

                if probe.error is not None:
                    row_failed = True
                    if recorded_key != target_key:
                        values_needing_rotation += 1
                    after_written.append(recorded_key)
                    after_skipped.append(recorded_key)
                    failures.append(
                        RotationFailure(
                            database="admin",
                            family="provider_configs",
                            table="provider_configs",
                            row_id=str(row_id),
                            column=f"config_json.{secret_field}",
                            key_id=key_id,
                            error=str(probe.error),
                        )
                    )
                else:
                    if probe.new_blob is not None:
                        updated_cfg[secret_field] = probe.new_blob
                    if probe.needs:
                        values_needing_rotation += 1
                        after_written.append(target_key)
                        after_skipped.append(recorded_key)
                    else:
                        after_written.append(recorded_key)
                        after_skipped.append(recorded_key)

            candidate = _RowCandidate(
                row_id=row_id,
                update_params=(
                    {"id": row_id, "config_json": json.dumps(updated_cfg)}
                    if (values_needing_rotation > 0 and not row_failed)
                    else None
                ),
                original_values={
                    "config_json": json.dumps(raw_json) if isinstance(raw_json, dict) else raw_json
                },
                values_scanned=values_scanned,
                values_needing_rotation=values_needing_rotation,
                before_keys=before_keys,
                after_keys_if_written=after_written,
                after_keys_if_skipped=after_skipped,
                failures=failures,
            )
            if candidate.update_params is not None:
                pending.append(candidate)
                if len(pending) >= batch_size:
                    await _flush_write_batch(
                        admin_db,
                        update_sql,
                        pending,
                        report,
                        stats,
                        dry_run=dry_run,
                        max_batches=max_batches,
                    )
            else:
                _apply_candidate_stats(report, stats, candidate, written=False)

        if len(rows) < batch_size:
            break

    await _flush_write_batch(
        admin_db,
        update_sql,
        pending,
        report,
        stats,
        dry_run=dry_run,
        max_batches=max_batches,
    )


async def _inspect_held_job_payload(
    encryption: EncryptionService,
    row_id: Any,
    payload_dict: dict[str, Any],
    *,
    execution_id: str | None,
    raw_payload: Any = None,
    dry_run: bool = False,
) -> _RowCandidate:
    """Inspect and prepare re-encryption for a held execution's encrypted payload.

    The outer ``_enc`` blob and the cookie nested inside it are two ciphertexts,
    each authenticated and counted on its own: either can carry a retired key.
    One row update still rewrites both, sealed under one prepared write.

    A legacy held payload with no envelope can still carry the cookie at the top
    level, where the worker reads it: inspect that cookie as a queued job's.
    """
    if _ENCRYPTED_PAYLOAD_KEY not in payload_dict:
        return await _inspect_async_job_payload(
            encryption,
            row_id,
            payload_dict,
            execution_id=execution_id,
            raw_payload=raw_payload,
            dry_run=dry_run,
            family="held_executions",
        )
    payload_context = held_payload_context(execution_id=execution_id, job_id=str(row_id))
    inner_cookie_context = cookie_context(execution_id=execution_id, job_id=str(row_id))
    outer_target = encryption.write_key_id(payload_context)
    cookie_target = encryption.write_key_id(inner_cookie_context)
    before_keys: list[str] = []
    after_written: list[str] = []
    after_skipped: list[str] = []
    failures: list[RotationFailure] = []
    updated_payload = dict(payload_dict)
    values_scanned = 0
    values_needing_rotation = 0
    row_failed = False

    def _failure(column: str, key_id: str | None, error: object) -> RotationFailure:
        return RotationFailure(
            database="admin",
            family="held_executions",
            table="held_executions",
            row_id=str(row_id),
            column=column,
            key_id=key_id,
            error=str(error),
        )

    enc_blob = payload_dict.get(_ENCRYPTED_PAYLOAD_KEY)
    if _ENCRYPTED_PAYLOAD_KEY in payload_dict and not (isinstance(enc_blob, str) and enc_blob):
        # The worker decrypts whenever the marker is present, so a present but empty or
        # non-string envelope is an unreadable held payload, not a plaintext legacy one.
        row_failed = True
        values_scanned += 1
        values_needing_rotation += 1
        before_keys.append(_MALFORMED_KEY_ID)
        after_written.append(_MALFORMED_KEY_ID)
        after_skipped.append(_MALFORMED_KEY_ID)
        failures.append(
            _failure(
                f"payload.{_ENCRYPTED_PAYLOAD_KEY}",
                None,
                f"held payload envelope is {type(enc_blob).__name__}, not an encrypted string",
            )
        )
    elif isinstance(enc_blob, str) and enc_blob:
        values_scanned += 1
        outer_key_id = _safe_key_id(encryption, enc_blob)
        outer_recorded = outer_key_id if outer_key_id is not None else _MALFORMED_KEY_ID
        before_keys.append(outer_recorded)

        outer = _Probe(blob=enc_blob, context=payload_context)
        await _probe_values(encryption, [outer], dry_run=True)
        inner_dict: dict[str, Any] | None = None
        outer_error: object | None = outer.error
        if outer.error is None:
            try:
                assert outer.plaintext is not None
                inner_dict = _decode_json_dict(outer.plaintext)
                if inner_dict is None:
                    raise ValueError("decrypted held payload is empty")
            except Exception as exc:
                outer_error = exc

        if outer_error is not None or inner_dict is None:
            row_failed = True
            after_written.append(outer_recorded)
            after_skipped.append(outer_recorded)
            if outer_recorded != outer_target:
                values_needing_rotation += 1
            failures.append(
                _failure(f"payload.{_ENCRYPTED_PAYLOAD_KEY}", outer_key_id, outer_error)
            )
        else:
            inner_updated = dict(inner_dict)
            inner_cookie = inner_dict.get(_INBOUND_COOKIE_PAYLOAD_KEY)
            cookie: _Probe | None = None
            cookie_recorded = ""
            cookie_key_id: str | None = None
            if isinstance(inner_cookie, str) and inner_cookie:
                values_scanned += 1
                cookie_key_id = _safe_key_id(encryption, inner_cookie)
                cookie_recorded = cookie_key_id if cookie_key_id is not None else _MALFORMED_KEY_ID
                before_keys.append(cookie_recorded)
                cookie = _Probe(blob=inner_cookie, context=inner_cookie_context)
                await _probe_values(encryption, [cookie], dry_run=True)
                if cookie.error is not None:
                    row_failed = True
                    failures.append(
                        _failure(
                            f"payload.{_ENCRYPTED_PAYLOAD_KEY}.{_INBOUND_COOKIE_PAYLOAD_KEY}",
                            cookie_key_id,
                            cookie.error,
                        )
                    )

            outer_needs = outer.needs
            cookie_needs = bool(cookie is not None and cookie.error is None and cookie.needs)
            if outer_needs:
                values_needing_rotation += 1
            if cookie is not None:
                if cookie.error is not None:
                    if cookie_recorded != cookie_target:
                        values_needing_rotation += 1
                elif cookie_needs:
                    values_needing_rotation += 1

            rewrite = not row_failed and (outer_needs or cookie_needs)
            if rewrite and not dry_run:
                # Cookie and outer payload share one scope, so one prepared write seals both.
                async with encryption.prepare_write(payload_context.scope) as prepared:
                    if cookie_needs:
                        assert cookie is not None and cookie.plaintext is not None
                        inner_updated[_INBOUND_COOKIE_PAYLOAD_KEY] = prepared.seal(
                            cookie.plaintext, field=inner_cookie_context.field
                        )
                    updated_payload[_ENCRYPTED_PAYLOAD_KEY] = prepared.seal(
                        json.dumps(inner_updated), field=payload_context.field
                    )
            elif rewrite:
                updated_payload[_ENCRYPTED_PAYLOAD_KEY] = enc_blob  # inspection: never rewritten

            after_skipped.append(outer_recorded)
            after_written.append(outer_target if rewrite else outer_recorded)
            if cookie is not None:
                after_skipped.append(cookie_recorded)
                after_written.append(cookie_target if cookie_needs and rewrite else cookie_recorded)

    return _RowCandidate(
        row_id=row_id,
        update_params=(
            {"id": row_id, "payload": json.dumps(updated_payload)}
            if (values_needing_rotation > 0 and not row_failed)
            else None
        ),
        original_values={
            "payload": (
                raw_payload
                if isinstance(raw_payload, str)
                else json.dumps(raw_payload if isinstance(raw_payload, dict) else payload_dict)
            )
        },
        values_scanned=values_scanned,
        values_needing_rotation=values_needing_rotation,
        before_keys=before_keys,
        after_keys_if_written=after_written,
        after_keys_if_skipped=after_skipped,
        failures=failures,
    )


async def _inspect_async_job_payload(
    encryption: EncryptionService,
    row_id: Any,
    payload_dict: dict[str, Any],
    *,
    execution_id: str | None,
    raw_payload: Any = None,
    dry_run: bool = False,
    family: str = "jobs",
) -> _RowCandidate:
    """Inspect and prepare re-encryption for a job's top-level encrypted cookie.

    Used for queued execution jobs, and for legacy held jobs whose payload has no
    outer envelope (``family`` then names ``held_executions``).
    """
    context = cookie_context(execution_id=execution_id, job_id=str(row_id))
    target_key = encryption.write_key_id(context)
    before_keys: list[str] = []
    after_written: list[str] = []
    after_skipped: list[str] = []
    failures: list[RotationFailure] = []
    updated_payload = dict(payload_dict)
    values_scanned = 0
    values_needing_rotation = 0
    row_failed = False

    cookie_blob = payload_dict.get(_INBOUND_COOKIE_PAYLOAD_KEY)
    if isinstance(cookie_blob, str) and cookie_blob:
        values_scanned += 1
        key_id = _safe_key_id(encryption, cookie_blob)
        recorded_key = key_id if key_id is not None else _MALFORMED_KEY_ID
        before_keys.append(recorded_key)

        probe = _Probe(blob=cookie_blob, context=context)
        await _probe_values(encryption, [probe], dry_run=dry_run)
        if probe.error is not None:
            row_failed = True
            if recorded_key != target_key:
                values_needing_rotation += 1
            after_written.append(recorded_key)
            after_skipped.append(recorded_key)
            failures.append(
                RotationFailure(
                    database="admin",
                    family=family,
                    table=family,
                    row_id=str(row_id),
                    column=f"payload.{_INBOUND_COOKIE_PAYLOAD_KEY}",
                    key_id=key_id,
                    error=str(probe.error),
                )
            )
        else:
            if probe.new_blob is not None:
                updated_payload[_INBOUND_COOKIE_PAYLOAD_KEY] = probe.new_blob
            if probe.needs:
                values_needing_rotation += 1
                after_written.append(target_key)
                after_skipped.append(recorded_key)
            else:
                after_written.append(recorded_key)
                after_skipped.append(recorded_key)

    return _RowCandidate(
        row_id=row_id,
        update_params=(
            {"id": row_id, "payload": json.dumps(updated_payload)}
            if (values_needing_rotation > 0 and not row_failed)
            else None
        ),
        original_values={
            "payload": (
                raw_payload
                if isinstance(raw_payload, str)
                else json.dumps(raw_payload if isinstance(raw_payload, dict) else payload_dict)
            )
        },
        values_scanned=values_scanned,
        values_needing_rotation=values_needing_rotation,
        before_keys=before_keys,
        after_keys_if_written=after_written,
        after_keys_if_skipped=after_skipped,
        failures=failures,
    )


def _is_missing_held_table_error(exc: OperationalError | ProgrammingError) -> bool:
    """Whether the dialect reports that the optional held-execution table is absent."""
    message = str(exc.orig).lower()
    return "held_executions" in message and (
        "does not exist" in message or "no such table" in message
    )


async def _rotate_jobs_and_held_executions(
    admin_db: DatabaseSession,
    encryption: EncryptionService,
    report: RotationReport,
    *,
    target_held: bool,
    dry_run: bool,
    batch_size: int,
    max_batches: int | None,
) -> None:
    family_name = "held_executions" if target_held else "jobs"
    stats = report.by_family[family_name]

    first_with_held = text(
        "SELECT j.id, j.status, j.payload, "
        "EXISTS(SELECT 1 FROM held_executions h WHERE h.job_id = j.id) AS is_held, "
        "j.execution_id FROM jobs j ORDER BY j.id ASC LIMIT :limit"
    )
    paged_with_held = text(
        "SELECT j.id, j.status, j.payload, "
        "EXISTS(SELECT 1 FROM held_executions h WHERE h.job_id = j.id) AS is_held, "
        "j.execution_id FROM jobs j WHERE j.id > :after_id ORDER BY j.id ASC LIMIT :limit"
    )
    first_jobs_only = text(
        "SELECT j.id, j.status, j.payload, 0 AS is_held, j.execution_id "
        "FROM jobs j ORDER BY j.id ASC LIMIT :limit"
    )
    paged_jobs_only = text(
        "SELECT j.id, j.status, j.payload, 0 AS is_held, j.execution_id "
        "FROM jobs j WHERE j.id > :after_id ORDER BY j.id ASC LIMIT :limit"
    )
    update_sql = "UPDATE jobs SET payload = :payload WHERE id = :id"

    after_id: Any = None
    use_held_subquery = True
    pending: list[_RowCandidate] = []

    while True:
        async with admin_db.session() as session:
            try:
                if after_id is None:
                    q = first_with_held if use_held_subquery else first_jobs_only
                    rows = (await session.execute(q, {"limit": batch_size})).all()
                else:
                    q = paged_with_held if use_held_subquery else paged_jobs_only
                    rows = (
                        await session.execute(q, {"after_id": after_id, "limit": batch_size})
                    ).all()
            except (OperationalError, ProgrammingError) as exc:
                if not use_held_subquery or not _is_missing_held_table_error(exc):
                    raise
                use_held_subquery = False
                # PostgreSQL aborts the current transaction after this error.
                # Leave this session and issue the compatibility query in a new one.
                continue

        if not rows:
            break
        after_id = rows[-1][0]

        for row in rows:
            row_id = row[0]
            job_status = str(row[1] or "")
            raw_payload = row[2]
            is_held_fk = bool(row[3])
            execution_id = str(row[4]) if row[4] else None

            try:
                payload_dict = _decode_json_dict(raw_payload)
            except Exception as exc:
                is_held_row = is_held_fk or job_status == "held"
                if is_held_row != target_held:
                    continue
                failure = RotationFailure(
                    database="admin",
                    family=family_name,
                    table=stats.table,
                    row_id=str(row_id),
                    column="payload",
                    key_id=None,
                    error=str(exc),
                )
                candidate = _RowCandidate(
                    row_id=row_id,
                    update_params=None,
                    values_scanned=1,
                    values_needing_rotation=1,
                    before_keys=[_MALFORMED_KEY_ID],
                    after_keys_if_written=[_MALFORMED_KEY_ID],
                    after_keys_if_skipped=[_MALFORMED_KEY_ID],
                    failures=[failure],
                )
                _apply_candidate_stats(report, stats, candidate, written=False)
                continue

            if payload_dict is None:
                payload_dict = {}

            is_held_row = (
                is_held_fk or job_status == "held" or _ENCRYPTED_PAYLOAD_KEY in payload_dict
            )
            if is_held_row != target_held:
                continue

            if target_held:
                candidate = await _inspect_held_job_payload(
                    encryption,
                    row_id,
                    payload_dict,
                    execution_id=execution_id,
                    raw_payload=raw_payload,
                    dry_run=_inspect_only(report, dry_run=dry_run, max_batches=max_batches),
                )
            else:
                candidate = await _inspect_async_job_payload(
                    encryption,
                    row_id,
                    payload_dict,
                    execution_id=execution_id,
                    raw_payload=raw_payload,
                    dry_run=_inspect_only(report, dry_run=dry_run, max_batches=max_batches),
                )

            if candidate.update_params is not None:
                pending.append(candidate)
                if len(pending) >= batch_size:
                    await _flush_write_batch(
                        admin_db,
                        update_sql,
                        pending,
                        report,
                        stats,
                        dry_run=dry_run,
                        max_batches=max_batches,
                    )
            else:
                _apply_candidate_stats(report, stats, candidate, written=False)

        if len(rows) < batch_size:
            break

    await _flush_write_batch(
        admin_db,
        update_sql,
        pending,
        report,
        stats,
        dry_run=dry_run,
        max_batches=max_batches,
    )


def _init_report(
    encryption: EncryptionService,
    *,
    include_control: bool,
    include_admin: bool,
    dry_run: bool,
    batch_size: int,
) -> RotationReport:
    report = RotationReport(
        active_key_id=encryption.active_key_id,
        dry_run=dry_run,
        batch_size=batch_size,
        write_key_ids=tuple(encryption.write_key_ids),
        covered_databases=frozenset(
            name
            for name, included in (("control", include_control), ("admin", include_admin))
            if included
        ),
    )
    if include_control:
        for spec in _CONTROL_COLUMN_SPECS:
            fstats = FamilyRotationStats(
                database=spec.database,
                family=spec.family,
                table=spec.table,
            )
            report.by_family[spec.family] = fstats
            report.by_table[spec.table] = fstats
            report.by_table[spec.family] = fstats
    if include_admin:
        for family, table in (
            ("provider_configs", "provider_configs"),
            ("jobs", "jobs"),
            ("held_executions", "held_executions"),
        ):
            fstats = FamilyRotationStats(
                database="admin",
                family=family,
                table=table,
            )
            report.by_family[family] = fstats
            report.by_table[table] = fstats
    return report


async def rotate_encrypted_storage(
    encryption: EncryptionService,
    *,
    control_db: DatabaseSession | None = None,
    admin_db: DatabaseSession | None = None,
    dry_run: bool = False,
    batch_size: int = 100,
    max_batches: int | None = None,
) -> RotationReport:
    """Inventory and optionally re-encrypt all persisted ciphertext across databases.

    Processes rows in keyset-ordered pages of *batch_size* and commits each write
    batch in its own transaction, so an interrupted run can be resumed safely:
    already rotated rows carry :attr:`EncryptionService.active_key_id` and are
    skipped without rewriting.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be >= 1")
    if max_batches is not None and max_batches < 1:
        raise ValueError("max_batches must be >= 1 when specified")
    if control_db is None and admin_db is None:
        raise ValueError("At least one of control_db or admin_db must be provided")

    report = _init_report(
        encryption,
        include_control=control_db is not None,
        include_admin=admin_db is not None,
        dry_run=dry_run,
        batch_size=batch_size,
    )

    if control_db is not None:
        for spec in _CONTROL_COLUMN_SPECS:
            await _rotate_column_spec(
                control_db,
                encryption,
                spec,
                report,
                dry_run=dry_run,
                batch_size=batch_size,
                max_batches=max_batches,
            )

    if admin_db is not None:
        await _rotate_provider_configs(
            admin_db,
            encryption,
            report,
            dry_run=dry_run,
            batch_size=batch_size,
            max_batches=max_batches,
        )
        await _rotate_jobs_and_held_executions(
            admin_db,
            encryption,
            report,
            target_held=False,
            dry_run=dry_run,
            batch_size=batch_size,
            max_batches=max_batches,
        )
        await _rotate_jobs_and_held_executions(
            admin_db,
            encryption,
            report,
            target_held=True,
            dry_run=dry_run,
            batch_size=batch_size,
            max_batches=max_batches,
        )

    return report


async def verify_key_retired(
    encryption: EncryptionService,
    retired_key_id: str | None = None,
    *,
    control_db: DatabaseSession | None = None,
    admin_db: DatabaseSession | None = None,
    batch_size: int = 100,
) -> RotationReport:
    """Scan persisted ciphertexts (dry-run) and fail closed if *retired_key_id* remains.

    When *retired_key_id* is ``None``, asserts that every persisted ciphertext uses
    :attr:`EncryptionService.active_key_id`. Raises :exc:`KeyRetirementError` if any
    row still requires the retired/non-active key or fails decryption.
    """
    report = await rotate_encrypted_storage(
        encryption,
        control_db=control_db,
        admin_db=admin_db,
        dry_run=True,
        batch_size=batch_size,
    )
    report.verify_key_retired(retired_key_id)
    return report


async def assert_only_active_key(
    encryption: EncryptionService,
    *,
    control_db: DatabaseSession | None = None,
    admin_db: DatabaseSession | None = None,
    batch_size: int = 100,
) -> RotationReport:
    """Scan persisted ciphertexts and fail closed if any non-active key remains."""
    return await verify_key_retired(
        encryption,
        None,
        control_db=control_db,
        admin_db=admin_db,
        batch_size=batch_size,
    )


class EncryptedStorageRotator:
    """Stateful helper binding an :class:`EncryptionService` to target databases."""

    def __init__(
        self,
        encryption: EncryptionService,
        *,
        control_db: DatabaseSession | None = None,
        admin_db: DatabaseSession | None = None,
        batch_size: int = 100,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        if control_db is None and admin_db is None:
            raise ValueError("At least one of control_db or admin_db must be provided")
        self._encryption = encryption
        self._control_db = control_db
        self._admin_db = admin_db
        self._batch_size = batch_size

    async def rotate(
        self,
        *,
        dry_run: bool = False,
        batch_size: int | None = None,
        max_batches: int | None = None,
    ) -> RotationReport:
        """Run a dry-run inventory or bounded-batch re-encryption pass."""
        return await rotate_encrypted_storage(
            self._encryption,
            control_db=self._control_db,
            admin_db=self._admin_db,
            dry_run=dry_run,
            batch_size=batch_size if batch_size is not None else self._batch_size,
            max_batches=max_batches,
        )

    async def verify_key_retired(
        self,
        retired_key_id: str | None = None,
        *,
        batch_size: int | None = None,
    ) -> RotationReport:
        """Verify that *retired_key_id* (or all non-active keys) is absent from storage."""
        return await verify_key_retired(
            self._encryption,
            retired_key_id,
            control_db=self._control_db,
            admin_db=self._admin_db,
            batch_size=batch_size if batch_size is not None else self._batch_size,
        )

    async def assert_only_active_key(
        self,
        *,
        batch_size: int | None = None,
    ) -> RotationReport:
        """Verify that every persisted ciphertext uses the active key."""
        return await assert_only_active_key(
            self._encryption,
            control_db=self._control_db,
            admin_db=self._admin_db,
            batch_size=batch_size if batch_size is not None else self._batch_size,
        )
