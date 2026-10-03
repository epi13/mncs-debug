"""Store-backed witness retention tests."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from mncs_debug.protocol import TRACE_SCHEMA, WITNESS_SCHEMA, identity, validate_document, write_json
from mncs_debug.retain import RetentionError, fetch_witness, retain_witness


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[0]
STORE_PACKAGE = WORKSPACE / "mncs-store" / "python" / "mncs_store"
EMBED_DEBUG = WORKSPACE / "mncs-language" / "target" / "debug" / "libmncs_embed.so"
EMBED_RELEASE = WORKSPACE / "mncs-language" / "target" / "release" / "libmncs_embed.so"
STORE_AVAILABLE = STORE_PACKAGE.is_dir() and (EMBED_DEBUG.is_file() or EMBED_RELEASE.is_file())


def synthetic_witness() -> dict:
    material = {
        "schema_version": WITNESS_SCHEMA,
        "protocol_version": 1,
        "execution_identity": "mncs:test:execution:synthetic",
        "program": {},
        "request": {},
        "outcome": {"status": "returned", "failure_class": "success"},
        "trace": {
            "schema_version": TRACE_SCHEMA,
            "protocol_version": 1,
            "trace_id": "mncs:debug:trace:synthetic",
            "execution_identity": "mncs:test:execution:synthetic",
            "events": [],
            "capture_policy": "bounded",
            "bounded": True,
        },
        "replay": {},
        "capabilities": {},
        "provenance": {},
    }
    return {**material, "witness_id": identity("witness", material)}


@unittest.skipUnless(STORE_AVAILABLE, "mncs-store embedded boundary not available")
class RetentionTests(unittest.TestCase):
    def test_retain_fetch_round_trip_is_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-debug-retain-test-") as directory:
            root = Path(directory)
            witness_path = root / "witness.json"
            write_json(witness_path, synthetic_witness())
            receipt = retain_witness(witness_path=witness_path, store_path=root / "store")
            self.assertEqual(receipt["schema_version"], "mncs.debug-retention/1")
            self.assertEqual(validate_document(receipt, "mncs.debug-retention/1"), [])
            self.assertEqual(receipt["store"]["generation"], 1)
            fetched_path = root / "fetched.json"
            fetched = fetch_witness(
                store_path=root / "store",
                witness_id=synthetic_witness()["witness_id"],
                output_path=fetched_path,
            )
            self.assertEqual(fetched["integrity"], "valid")
            self.assertEqual(
                fetched_path.read_bytes(),
                witness_path.read_bytes(),
            )

    def test_fetch_missing_witness_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-debug-retain-test-") as directory:
            root = Path(directory)
            witness_path = root / "witness.json"
            write_json(witness_path, synthetic_witness())
            retain_witness(witness_path=witness_path, store_path=root / "store")
            with self.assertRaises(RetentionError):
                fetch_witness(
                    store_path=root / "store",
                    witness_id="mncs:debug:witness:absent",
                    output_path=root / "absent.json",
                )

    def test_corrupt_witness_is_never_retained(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mncs-debug-retain-test-") as directory:
            root = Path(directory)
            witness_path = root / "corrupt.json"
            corrupt = synthetic_witness()
            corrupt["witness_id"] = "mncs:debug:witness:corrupt"
            write_json(witness_path, corrupt)
            with self.assertRaises(ValueError):
                retain_witness(witness_path=witness_path, store_path=root / "store")


if __name__ == "__main__":
    unittest.main()
