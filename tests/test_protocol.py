from __future__ import annotations

import copy
import json
import unittest

from mncs_debug.capabilities import capability_document
from mncs_debug.protocol import (
    CAPABILITIES_SCHEMA,
    EVENT_SCHEMA,
    MINIMIZATION_SCHEMA,
    PROTOCOL_VERSION,
    canonical_json,
    identity,
    validate_document,
)


class ProtocolTests(unittest.TestCase):
    def test_canonical_identity_is_order_independent(self) -> None:
        self.assertEqual(identity("example", {"b": 2, "a": 1}), identity("example", {"a": 1, "b": 2}))
        self.assertIn("mncs:debug:example:", identity("example", {"a": 1}))
        self.assertEqual(canonical_json({"b": 2, "a": 1}), '{"a":1,"b":2}')

    def test_event_structural_membrane(self) -> None:
        event = {
            "schema_version": EVENT_SCHEMA,
            "protocol_version": PROTOCOL_VERSION,
            "event_id": "mncs:debug:event:test",
            "execution_identity": "mncs:debug:execution:test",
            "sequence": 0,
            "kind": "failure",
            "location": {},
            "payload": {},
            "relationships": {},
        }
        self.assertEqual(validate_document(event, EVENT_SCHEMA), [])
        invalid = copy.deepcopy(event)
        invalid["sequence"] = -1
        self.assertTrue(validate_document(invalid, EVENT_SCHEMA))

    def test_capability_document_is_versioned_and_truthful(self) -> None:
        document = capability_document()
        self.assertEqual(document["schema_version"], CAPABILITIES_SCHEMA)
        self.assertEqual(validate_document(document, CAPABILITIES_SCHEMA), [])
        states = {item["id"]: item["state"] for item in document["capabilities"]}
        self.assertEqual(states["deterministic_replay"], "unsupported")
        self.assertEqual(states["bounded_semantic_trace"], "supported")
        self.assertEqual(states["actions_provider"], "supported")

    def test_minimization_protocol_is_known_to_validator(self) -> None:
        document = {
            "schema_version": MINIMIZATION_SCHEMA,
            "protocol_version": 1,
            "minimization_id": "mncs:debug:minimization:test",
            "witness_id": "mncs:debug:witness:test",
            "status": "no_reduction",
            "message": "none",
            "attempts": 0,
            "changes": [],
            "equivalence": "bounded signature",
            "conservative": True,
        }
        self.assertEqual(validate_document(document, MINIMIZATION_SCHEMA), [])


if __name__ == "__main__":
    unittest.main()
