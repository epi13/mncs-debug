"""Bounded Store-backed retention for debug witnesses.

Retention keeps one immutable witness per Store object: the witness bytes are
stored verbatim under the witness identity, with a small descriptor carrying
the execution and failure links. It never dumps unbounded event streams, and
it never retains a witness that fails integrity validation.

The Store itself stays owned by `mncs-store`; this module is a narrow
consumer of its supported embedded boundary. When the sibling Store checkout
is unavailable the commands fail closed with an explicit state instead of a
fake retention claim.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .analysis import load_witness
from .protocol import PROTOCOL_VERSION, RETENTION_SCHEMA, identity


class StoreUnavailable(RuntimeError):
    """The sibling Store consumer boundary is not importable."""


class RetentionError(RuntimeError):
    """Retention or fetch failed inside an available Store."""


WITNESS_DOMAIN_SCHEMA = b"mncs.debug-witness/1"
LIVE_EVIDENCE_DOMAIN_SCHEMA = b"mncs.debug-live-evidence/1"


def store_package():  # type: ignore[no-untyped-def]
    """Import the sibling Store embedded boundary, or raise StoreUnavailable."""

    workspace = Path(__file__).resolve().parents[2]
    candidate = workspace / "mncs-store" / "python"
    if candidate.is_dir() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))
    try:
        import mncs_store  # type: ignore[import-not-found]

        return mncs_store
    except ImportError as exc:
        raise StoreUnavailable(
            "mncs-store embedded boundary is unavailable; "
            f"expected a sibling checkout at {workspace / 'mncs-store'}"
        ) from exc


def _retention_id(witness_id: str, logical_id: bytes, generation: int) -> str:
    return identity(
        "retention",
        {"witness_id": witness_id, "logical_id": logical_id.hex(), "generation": generation},
    )


def retain_witness(*, witness_path: Path, store_path: Path) -> dict[str, Any]:
    """Retain one integrity-validated witness as a single Store object."""

    witness = load_witness(witness_path)
    payload = witness_path.resolve().read_bytes()
    witness_id = str(witness.get("witness_id"))
    outcome = witness.get("outcome") if isinstance(witness.get("outcome"), dict) else {}
    descriptor = {
        "schema_version": "mncs.debug-retention-descriptor/1",
        "witness_id": witness_id,
        "execution_identity": witness.get("execution_identity"),
        "failure_class": outcome.get("failure_class"),
        "producer": "mncs-debug",
    }
    descriptor_bytes = json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode("utf-8")
    mncs_store = store_package()
    codes = mncs_store.StoreResultCode
    store = mncs_store.EmbeddedStore(store_path.resolve())
    try:
        expected = store.current_generation
        result = store.put_bound_object(
            domain_schema=WITNESS_DOMAIN_SCHEMA,
            domain_identity=witness_id.encode("utf-8"),
            descriptor=descriptor_bytes,
            payload=payload,
            expected_generation=expected,
        )
        if result.code == codes.STALE_GENERATION:
            expected = store.current_generation
            result = store.put_bound_object(
                domain_schema=WITNESS_DOMAIN_SCHEMA,
                domain_identity=witness_id.encode("utf-8"),
                descriptor=descriptor_bytes,
                payload=payload,
                expected_generation=expected,
            )
        if not result.committed:
            raise RetentionError(f"store refused the witness object: {result.code}")
        generation = int(result.generation)
        logical_id = bytes(result.logical_id)
        content_id = bytes(result.content_id) if getattr(result, "content_id", None) else b""
    finally:
        store.close()
    return {
        "schema_version": RETENTION_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "retention_id": _retention_id(witness_id, logical_id, generation),
        "witness_id": witness_id,
        "execution_identity": witness.get("execution_identity"),
        "store": {
            "path": store_path.resolve().as_posix(),
            "generation": generation,
            "logical_id": logical_id.hex(),
            "content_id": content_id.hex() if content_id else None,
            "domain_schema": WITNESS_DOMAIN_SCHEMA.decode("ascii"),
        },
        "bytes": len(payload),
        "result": str(result.code),
    }


def retain_live_evidence(*, evidence_path: Path, store_path: Path) -> dict[str, Any]:
    """Retain one finished live-session evidence document as a Store object.

    The evidence bytes (terminal outcome, VM record, observation stream,
    stop history) are stored verbatim under the VM execution identity.
    Only finished live sessions have evidence; live executions are never
    snapshotted into Store.
    """

    from .protocol import LIVE_EVIDENCE_SCHEMA, validate_document

    payload = evidence_path.resolve().read_bytes()
    try:
        evidence = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetentionError(f"live evidence at {evidence_path} is not JSON: {exc}") from exc
    errors = validate_document(evidence, LIVE_EVIDENCE_SCHEMA)
    if errors:
        raise RetentionError("live evidence failed validation: " + "; ".join(errors))
    record = evidence.get("record") if isinstance(evidence.get("record"), dict) else {}
    stream = evidence.get("stream") if isinstance(evidence.get("stream"), dict) else {}
    artifact_id = str(record.get("artifact_id") or "")
    execution_identity = str(stream.get("execution_identity") or artifact_id)
    outcome = evidence.get("outcome") if isinstance(evidence.get("outcome"), dict) else {}
    if not execution_identity:
        raise RetentionError(f"live evidence at {evidence_path} names no execution identity")
    descriptor = {
        "schema_version": "mncs.debug-retention-descriptor/1",
        "evidence_id": execution_identity,
        "execution_identity": execution_identity,
        "artifact_id": artifact_id,
        "outcome_kind": outcome.get("kind"),
        "producer": "mncs-debug",
    }
    descriptor_bytes = json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode("utf-8")
    mncs_store = store_package()
    codes = mncs_store.StoreResultCode
    store = mncs_store.EmbeddedStore(store_path.resolve())
    try:
        expected = store.current_generation
        result = store.put_bound_object(
            domain_schema=LIVE_EVIDENCE_DOMAIN_SCHEMA,
            domain_identity=execution_identity.encode("utf-8"),
            descriptor=descriptor_bytes,
            payload=payload,
            expected_generation=expected,
        )
        if result.code == codes.STALE_GENERATION:
            expected = store.current_generation
            result = store.put_bound_object(
                domain_schema=LIVE_EVIDENCE_DOMAIN_SCHEMA,
                domain_identity=execution_identity.encode("utf-8"),
                descriptor=descriptor_bytes,
                payload=payload,
                expected_generation=expected,
            )
        if not result.committed:
            raise RetentionError(f"store refused the live-evidence object: {result.code}")
        generation = int(result.generation)
        logical_id = bytes(result.logical_id)
        content_id = bytes(result.content_id) if getattr(result, "content_id", None) else b""
    finally:
        store.close()
    return {
        "schema_version": RETENTION_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "retention_id": _retention_id(execution_identity, logical_id, generation),
        "witness_id": execution_identity,
        "execution_identity": execution_identity,
        "store": {
            "path": store_path.resolve().as_posix(),
            "generation": generation,
            "logical_id": logical_id.hex(),
            "content_id": content_id.hex() if content_id else None,
            "domain_schema": LIVE_EVIDENCE_DOMAIN_SCHEMA.decode("ascii"),
        },
        "bytes": len(payload),
        "result": str(result.code),
    }


def fetch_live_evidence(*, store_path: Path, evidence_id: str, output_path: Path) -> dict[str, Any]:
    """Fetch one retained live-evidence document by execution identity."""

    from .protocol import LIVE_EVIDENCE_SCHEMA, validate_document

    mncs_store = store_package()
    store = mncs_store.EmbeddedStore(store_path.resolve(), read_only=True)
    try:
        try:
            stored = store.get_bound_object(LIVE_EVIDENCE_DOMAIN_SCHEMA, evidence_id.encode("utf-8"))
        except Exception as exc:
            raise RetentionError(f"live evidence {evidence_id} is not retained in {store_path}: {exc}") from exc
        payload = bytes(stored.payload)
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(payload)
        try:
            evidence = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RetentionError(f"retained live evidence is not JSON: {exc}") from exc
        errors = validate_document(evidence, LIVE_EVIDENCE_SCHEMA)
        if errors:
            raise RetentionError("retained live evidence failed validation: " + "; ".join(errors))
        generation = int(stored.generation)
        logical_id = bytes(stored.logical_id)
    finally:
        store.close()
    return {
        "schema_version": RETENTION_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "retention_id": _retention_id(evidence_id, logical_id, generation),
        "witness_id": evidence_id,
        "execution_identity": evidence_id,
        "store": {
            "path": store_path.resolve().as_posix(),
            "generation": generation,
            "logical_id": logical_id.hex(),
            "domain_schema": LIVE_EVIDENCE_DOMAIN_SCHEMA.decode("ascii"),
        },
        "bytes": len(payload),
        "result": "fetched",
        "integrity": "valid",
    }


def fetch_witness(*, store_path: Path, witness_id: str, output_path: Path) -> dict[str, Any]:
    """Fetch one retained witness by identity and validate its integrity."""

    mncs_store = store_package()
    store = mncs_store.EmbeddedStore(store_path.resolve(), read_only=True)
    try:
        try:
            stored = store.get_bound_object(WITNESS_DOMAIN_SCHEMA, witness_id.encode("utf-8"))
        except Exception as exc:
            raise RetentionError(f"witness {witness_id} is not retained in {store_path}: {exc}") from exc
        payload = bytes(stored.payload)
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(payload)
        witness = load_witness(output_path)
        if witness.get("witness_id") != witness_id:
            raise RetentionError(
                f"store object identity mismatch: requested {witness_id}, fetched {witness.get('witness_id')}"
            )
        generation = int(stored.generation)
        logical_id = bytes(stored.logical_id)
    finally:
        store.close()
    return {
        "schema_version": RETENTION_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "retention_id": _retention_id(witness_id, logical_id, generation),
        "witness_id": witness_id,
        "execution_identity": witness.get("execution_identity"),
        "store": {
            "path": store_path.resolve().as_posix(),
            "generation": generation,
            "logical_id": logical_id.hex(),
            "domain_schema": WITNESS_DOMAIN_SCHEMA.decode("ascii"),
        },
        "bytes": len(payload),
        "result": "fetched",
        "integrity": "valid",
    }
