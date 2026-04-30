# A.I.R. Invariant Matrix

This matrix is the contract for VaultNode boundary behavior. Each row defines
what must be true before A.I.R. accepts or evaluates an event.

## Event Path

| ID | Invariant | Violation Response | Status |
| --- | --- | --- | --- |
| `AIR-INV-001` | A session must exist before it can emit events. | `404 session_not_found` | Implemented |
| `AIR-INV-002` | An existing session must resolve to a bound workflow definition. | `409 workflow_not_found` | Implemented |
| `AIR-INV-003` | A stored workflow definition must deserialize to a mapping. | `500 invalid_workflow_definition` | Implemented |
| `AIR-INV-004` | `state_after` must be authorized by the workflow for `state_before`. | `409 incident_flagged` | Implemented |
| `AIR-INV-005` | Re-registering a session ID must not silently preserve a conflicting binding. | Identical replay: `200 session_already_registered`; conflicting binding: `409 session_binding_conflict` | Implemented |
| `AIR-INV-006` | Workflow IDs must preserve full content-addressing strength. | Full 64-char SHA-256; identical canonical content is idempotent; conflicting content at same ID -> `409 workflow_id_collision` | Implemented |

## Why This Starts Here

The first reviewed bug in this area was misclassifying "missing workflow" as
"missing session" because `/event` used an inner join during workflow lookup.
That compressed two separate invariants into one ambiguous failure mode.

The matrix now treats them separately:

1. The session must exist.
2. The bound workflow must also exist and be decodable.
3. Only then can A.I.R. evaluate the requested transition.

## Test Coverage

`tests/test_invariants.py` covers:

- new session registration
- identical session registration replay
- conflicting session registration rejection
- canonical workflow serialization
- full-length workflow ID hashing
- conflicting workflow ID collision rejection
- missing session classification
- missing workflow classification
- invalid workflow definition decoding
- valid workflow definition decoding

`tests/test_route_errors.py` covers:

- route-level `session_not_found`
- route-level `workflow_not_found`
- route-level `invalid_workflow_definition`
- route-level `incident_flagged`
- route-level `session_already_registered`
- route-level `session_binding_conflict`
- route-level `workflow_id_collision`
- route-level opaque `db_fault` responses on read and write paths
