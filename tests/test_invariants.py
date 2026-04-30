import unittest
from pathlib import Path

from fastapi import HTTPException

from invariants import (
    canonicalize_workflow_definition,
    classify_session_registration,
    classify_workflow_registration,
    compute_workflow_id,
    resolve_session_workflow_definition,
)


class ClassifySessionRegistrationTests(unittest.TestCase):
    def test_new_session_registration_is_created(self) -> None:
        result = classify_session_registration(
            None, "session-123", "agent-123", "wf-123"
        )

        self.assertEqual(result["status"], "session_registered")
        self.assertEqual(result["binding_status"], "created")

    def test_identical_session_registration_is_idempotent(self) -> None:
        result = classify_session_registration(
            {"agent_id": "agent-123", "workflow_id": "wf-123"},
            "session-123",
            "agent-123",
            "wf-123",
        )

        self.assertEqual(result["status"], "session_already_registered")
        self.assertEqual(result["binding_status"], "unchanged")

    def test_conflicting_session_registration_is_rejected(self) -> None:
        with self.assertRaises(HTTPException) as exc:
            classify_session_registration(
                {"agent_id": "agent-123", "workflow_id": "wf-123"},
                "session-123",
                "agent-999",
                "wf-999",
            )

        self.assertEqual(exc.exception.status_code, 409)
        self.assertEqual(exc.exception.detail["status"], "session_binding_conflict")


class WorkflowIdentityTests(unittest.TestCase):
    def test_canonical_workflow_serialization_is_stable(self) -> None:
        canonical = canonicalize_workflow_definition(
            {"β": ["γ"], "alpha": ["beta"]}
        )

        self.assertEqual(canonical, '{"alpha":["beta"],"β":["γ"]}')

    def test_workflow_id_is_full_sha256_hex(self) -> None:
        workflow_id = compute_workflow_id({"IDLE": ["ANALYZING"]})

        self.assertEqual(len(workflow_id), 64)
        self.assertRegex(workflow_id, r"^[0-9a-f]{64}$")

    def test_same_workflow_definition_produces_same_id(self) -> None:
        workflow_a = {"ANALYZING": ["EXECUTING"], "IDLE": ["ANALYZING"]}
        workflow_b = {"IDLE": ["ANALYZING"], "ANALYZING": ["EXECUTING"]}

        self.assertEqual(
            canonicalize_workflow_definition(workflow_a),
            canonicalize_workflow_definition(workflow_b),
        )
        self.assertEqual(compute_workflow_id(workflow_a), compute_workflow_id(workflow_b))

    def test_different_workflow_definitions_produce_different_ids(self) -> None:
        workflow_a = {"IDLE": ["ANALYZING"]}
        workflow_b = {"IDLE": ["SLEEPING"]}

        self.assertNotEqual(compute_workflow_id(workflow_a), compute_workflow_id(workflow_b))

    def test_simulated_workflow_id_collision_is_rejected(self) -> None:
        existing = {
            "name": "stable-wf",
            "definition": {"IDLE": ["ANALYZING"]},
        }
        incoming_definition = canonicalize_workflow_definition(
            {"IDLE": ["EXECUTING"]}
        )

        with self.assertRaises(HTTPException) as exc:
            classify_workflow_registration(
                existing,
                "forced-collision-id",
                "hostile-wf",
                incoming_definition,
            )

        self.assertEqual(exc.exception.status_code, 409)
        self.assertEqual(exc.exception.detail["status"], "workflow_id_collision")

    def test_identical_workflow_id_replay_is_idempotent(self) -> None:
        canonical_definition = canonicalize_workflow_definition(
            {"IDLE": ["ANALYZING"]}
        )
        existing = {
            "name": "stable-wf",
            "definition": {"IDLE": ["ANALYZING"]},
        }

        result = classify_workflow_registration(
            existing,
            compute_workflow_id({"IDLE": ["ANALYZING"]}),
            "stable-wf",
            canonical_definition,
        )

        self.assertEqual(result["status"], "workflow_locked")
        self.assertEqual(result["workflow_status"], "unchanged")

    def test_no_truncated_workflow_id_logic_remains(self) -> None:
        files = [
            Path("main.py"),
            Path("invariants.py"),
        ]
        joined = "\n".join(path.read_text(encoding="utf-8") for path in files)

        self.assertNotIn("hexdigest()[:16]", joined)
        self.assertNotIn("[:16]", joined)


class ResolveSessionWorkflowDefinitionTests(unittest.TestCase):
    def test_missing_session_raises_session_not_found(self) -> None:
        with self.assertRaises(HTTPException) as exc:
            resolve_session_workflow_definition(None, "session-123")

        self.assertEqual(exc.exception.status_code, 404)
        self.assertEqual(exc.exception.detail["status"], "session_not_found")

    def test_existing_session_without_workflow_raises_workflow_not_found(self) -> None:
        row = {"workflow_id": "wf-123", "workflow_definition": None}

        with self.assertRaises(HTTPException) as exc:
            resolve_session_workflow_definition(row, "session-123")

        self.assertEqual(exc.exception.status_code, 409)
        self.assertEqual(exc.exception.detail["status"], "workflow_not_found")
        self.assertEqual(exc.exception.detail["workflow_id"], "wf-123")

    def test_invalid_json_workflow_raises_internal_error(self) -> None:
        row = {"workflow_id": "wf-123", "workflow_definition": "{not-json"}

        with self.assertRaises(HTTPException) as exc:
            resolve_session_workflow_definition(row, "session-123")

        self.assertEqual(exc.exception.status_code, 500)
        self.assertEqual(
            exc.exception.detail["status"], "invalid_workflow_definition"
        )

    def test_non_mapping_workflow_raises_internal_error(self) -> None:
        row = {"workflow_id": "wf-123", "workflow_definition": '["A", "B"]'}

        with self.assertRaises(HTTPException) as exc:
            resolve_session_workflow_definition(row, "session-123")

        self.assertEqual(exc.exception.status_code, 500)
        self.assertEqual(
            exc.exception.detail["status"], "invalid_workflow_definition"
        )

    def test_valid_json_workflow_decodes_to_mapping(self) -> None:
        row = {
            "workflow_id": "wf-123",
            "workflow_definition": '{"IDLE": ["ANALYZING"]}',
        }

        definition = resolve_session_workflow_definition(row, "session-123")

        self.assertEqual(definition, {"IDLE": ["ANALYZING"]})


if __name__ == "__main__":
    unittest.main()
