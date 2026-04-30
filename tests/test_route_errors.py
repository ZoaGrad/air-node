import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

import main


class FakeAcquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return FakeAcquire(self.conn)

    async def close(self):
        return None


@contextmanager
def client_for_connection(conn, api_key: str | None = None):
    with patch.object(
        main.asyncpg, "create_pool", new=AsyncMock(return_value=FakePool(conn))
    ):
        with patch.object(main.settings, "air_node_api_key", api_key):
            with TestClient(main.app, raise_server_exceptions=False) as client:
                yield client


class RouteDbErrorTests(unittest.TestCase):
    FORBIDDEN_SUBSTRINGS = (
        "asyncpg",
        "select",
        "insert",
        "traceback",
        "connection",
        "relation",
        "column",
    )

    def assert_forbidden_substrings_absent(
        self,
        response,
        extra_fragments: list[str] | None = None,
    ) -> None:
        body_text = response.text.lower()
        for fragment in self.FORBIDDEN_SUBSTRINGS:
            self.assertNotIn(fragment, body_text)
        for fragment in extra_fragments or []:
            self.assertNotIn(fragment.lower(), body_text)

    def assert_opaque_error_response(
        self,
        response,
        expected_status: int,
        expected_body: dict,
        sensitive_fragments: list[str] | None = None,
    ) -> None:
        self.assertEqual(response.status_code, expected_status)
        self.assertEqual(response.json(), expected_body)
        self.assertEqual(
            set(response.json()["detail"].keys()),
            {"code", "message"},
        )
        self.assert_forbidden_substrings_absent(response, sensitive_fragments)

    def assert_route_error_response(
        self,
        response,
        expected_status: int,
        expected_detail: dict,
        sensitive_fragments: list[str] | None = None,
    ) -> None:
        self.assertEqual(response.status_code, expected_status)
        self.assertEqual(response.json(), {"detail": expected_detail})
        self.assert_forbidden_substrings_absent(response, sensitive_fragments)

    def test_agent_postgres_error_is_sanitized(self) -> None:
        conn = SimpleNamespace(
            execute=AsyncMock(
                side_effect=main.asyncpg.PostgresError(
                    "password=secret relation agents stacktrace"
                )
            )
        )

        with client_for_connection(conn) as client:
            response = client.post("/agent", json={"id": "agent-1", "name": "Agent 1"})

        self.assert_opaque_error_response(
            response,
            500,
            {"detail": {"code": "db_fault", "message": "internal database fault"}},
            ["password=secret", "relation agents", "stacktrace"],
        )

    def test_session_postgres_error_is_sanitized(self) -> None:
        conn = SimpleNamespace(
            fetchrow=AsyncMock(
                side_effect=main.asyncpg.PostgresError(
                    "postgres://user:pass@db/sessions SELECT * FROM sessions"
                )
            )
        )

        with client_for_connection(conn) as client:
            response = client.post(
                "/session",
                json={
                    "id": "session-1",
                    "agent_id": "agent-1",
                    "workflow_id": "wf-1",
                },
            )

        self.assert_opaque_error_response(
            response,
            500,
            {"detail": {"code": "db_fault", "message": "internal database fault"}},
            ["postgres://", "SELECT * FROM sessions", "user:pass"],
        )

    def test_session_foreign_key_error_is_sanitized(self) -> None:
        conn = SimpleNamespace(
            fetchrow=AsyncMock(
                side_effect=main.asyncpg.ForeignKeyViolationError(
                    'insert or update on table "sessions" violates foreign key constraint'
                )
            )
        )

        with client_for_connection(conn) as client:
            response = client.post(
                "/session",
                json={
                    "id": "session-1",
                    "agent_id": "agent-1",
                    "workflow_id": "wf-1",
                },
            )

        self.assert_opaque_error_response(
            response,
            400,
            {
                "detail": {
                    "code": "invalid_reference",
                    "message": "referenced entity does not exist",
                }
            },
            ["table", "foreign key constraint", "sessions"],
        )

    def test_event_postgres_error_is_sanitized(self) -> None:
        conn = SimpleNamespace(
            fetchrow=AsyncMock(
                side_effect=main.asyncpg.PostgresError(
                    "SELECT w.definition FROM workflows password=secret"
                )
            )
        )

        with client_for_connection(conn) as client:
            response = client.post(
                "/event",
                json={
                    "agent_id": "agent-1",
                    "session_id": "session-1",
                    "action": "step",
                    "state_before": "IDLE",
                    "state_after": "ANALYZING",
                    "metadata": {},
                },
            )

        self.assert_opaque_error_response(
            response,
            500,
            {"detail": {"code": "db_fault", "message": "internal database fault"}},
            ["SELECT w.definition", "workflows", "password=secret"],
        )

    def test_event_foreign_key_error_is_sanitized(self) -> None:
        conn = SimpleNamespace(
            fetchrow=AsyncMock(
                return_value={
                    "workflow_id": "wf-1",
                    "workflow_definition": {"IDLE": ["ANALYZING"]},
                }
            ),
            execute=AsyncMock(
                side_effect=main.asyncpg.ForeignKeyViolationError(
                    'insert or update on table "events" violates foreign key constraint'
                )
            ),
        )

        with client_for_connection(conn) as client:
            response = client.post(
                "/event",
                json={
                    "agent_id": "agent-1",
                    "session_id": "session-1",
                    "action": "step",
                    "state_before": "IDLE",
                    "state_after": "ANALYZING",
                    "metadata": {},
                },
            )

        self.assert_opaque_error_response(
            response,
            400,
            {
                "detail": {
                    "code": "invalid_reference",
                    "message": "referenced entity does not exist",
                }
            },
            ["table", "foreign key constraint", "events"],
        )

    def test_incidents_postgres_error_is_sanitized(self) -> None:
        conn = SimpleNamespace(
            fetch=AsyncMock(
                side_effect=main.asyncpg.PostgresError(
                    "postgres://user:pass@db/incidents SELECT * FROM incidents"
                )
            )
        )

        with client_for_connection(conn, api_key="test-air-key") as client:
            response = client.get(
                "/incidents",
                headers={"X-API-Key": "test-air-key"},
            )

        self.assert_opaque_error_response(
            response,
            500,
            {"detail": {"code": "db_fault", "message": "internal database fault"}},
            ["postgres://", "SELECT * FROM incidents", "user:pass"],
        )

    def test_session_replay_postgres_error_is_sanitized(self) -> None:
        conn = SimpleNamespace(
            fetch=AsyncMock(
                side_effect=main.asyncpg.PostgresError(
                    "SELECT id, timestamp FROM events where session_id=$1 host=db"
                )
            )
        )

        with client_for_connection(conn) as client:
            response = client.get("/session/session-1")

        self.assert_opaque_error_response(
            response,
            500,
            {"detail": {"code": "db_fault", "message": "internal database fault"}},
            ["SELECT id, timestamp", "events", "host=db"],
        )

    def test_event_missing_session_is_returned_by_route(self) -> None:
        conn = SimpleNamespace(fetchrow=AsyncMock(return_value=None))

        with client_for_connection(conn) as client:
            response = client.post(
                "/event",
                json={
                    "agent_id": "agent-1",
                    "session_id": "session-1",
                    "action": "step",
                    "state_before": "IDLE",
                    "state_after": "ANALYZING",
                    "metadata": {},
                },
            )

        self.assert_route_error_response(
            response,
            404,
            {
                "status": "session_not_found",
                "session_id": "session-1",
                "reason": "session must be registered before submitting events",
            },
        )

    def test_event_missing_workflow_is_returned_by_route(self) -> None:
        conn = SimpleNamespace(
            fetchrow=AsyncMock(
                return_value={
                    "workflow_id": "wf-1",
                    "workflow_definition": None,
                }
            )
        )

        with client_for_connection(conn) as client:
            response = client.post(
                "/event",
                json={
                    "agent_id": "agent-1",
                    "session_id": "session-1",
                    "action": "step",
                    "state_before": "IDLE",
                    "state_after": "ANALYZING",
                    "metadata": {},
                },
            )

        self.assert_route_error_response(
            response,
            409,
            {
                "status": "workflow_not_found",
                "session_id": "session-1",
                "workflow_id": "wf-1",
                "reason": "session is registered but its bound workflow is unavailable",
            },
        )

    def test_event_invalid_workflow_definition_is_returned_by_route(self) -> None:
        conn = SimpleNamespace(
            fetchrow=AsyncMock(
                return_value={
                    "workflow_id": "wf-1",
                    "workflow_definition": "{not-json",
                }
            )
        )

        with client_for_connection(conn) as client:
            response = client.post(
                "/event",
                json={
                    "agent_id": "agent-1",
                    "session_id": "session-1",
                    "action": "step",
                    "state_before": "IDLE",
                    "state_after": "ANALYZING",
                    "metadata": {},
                },
            )

        self.assert_route_error_response(
            response,
            500,
            {
                "status": "invalid_workflow_definition",
                "session_id": "session-1",
                "workflow_id": "wf-1",
                "reason": "stored workflow definition could not be decoded",
            },
        )

    def test_event_incident_flagged_is_returned_by_route(self) -> None:
        conn = SimpleNamespace(
            fetchrow=AsyncMock(
                return_value={
                    "workflow_id": "wf-1",
                    "workflow_definition": {"IDLE": ["ANALYZING"]},
                }
            ),
            execute=AsyncMock(return_value="INSERT 0 1"),
        )

        with client_for_connection(conn) as client:
            response = client.post(
                "/event",
                json={
                    "agent_id": "agent-1",
                    "session_id": "session-1",
                    "action": "step",
                    "state_before": "IDLE",
                    "state_after": "EXECUTING",
                    "metadata": {},
                },
            )

        self.assert_route_error_response(
            response,
            409,
            {
                "status": "incident_flagged",
                "incident_id": "INC-session-1-step",
                "observed": "IDLE -> EXECUTING",
                "authorized": ["ANALYZING"],
            },
        )

    def test_session_already_registered_is_returned_by_route(self) -> None:
        conn = SimpleNamespace(
            fetchrow=AsyncMock(
                side_effect=[
                    None,
                    {"agent_id": "agent-1", "workflow_id": "wf-1"},
                ]
            )
        )

        with client_for_connection(conn) as client:
            response = client.post(
                "/session",
                json={
                    "id": "session-1",
                    "agent_id": "agent-1",
                    "workflow_id": "wf-1",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "status": "session_already_registered",
                "session_id": "session-1",
                "agent_id": "agent-1",
                "workflow_id": "wf-1",
                "binding_status": "unchanged",
            },
        )

    def test_session_binding_conflict_is_returned_by_route(self) -> None:
        conn = SimpleNamespace(
            fetchrow=AsyncMock(
                side_effect=[
                    None,
                    {"agent_id": "agent-1", "workflow_id": "wf-1"},
                ]
            )
        )

        with client_for_connection(conn) as client:
            response = client.post(
                "/session",
                json={
                    "id": "session-1",
                    "agent_id": "agent-2",
                    "workflow_id": "wf-2",
                },
            )

        self.assert_route_error_response(
            response,
            409,
            {
                "status": "session_binding_conflict",
                "session_id": "session-1",
                "existing": {
                    "agent_id": "agent-1",
                    "workflow_id": "wf-1",
                },
                "incoming": {
                    "agent_id": "agent-2",
                    "workflow_id": "wf-2",
                },
                "reason": "session bindings are immutable once registered",
            },
        )

    def test_workflow_collision_is_returned_by_route(self) -> None:
        incoming_definition = {"IDLE": ["ANALYZING"]}
        workflow_id = main.compute_workflow_id(incoming_definition)
        incoming_canonical_definition = main.canonicalize_workflow_definition(
            incoming_definition
        )
        existing_canonical_definition = main.canonicalize_workflow_definition(
            {"IDLE": ["EXECUTING"]}
        )
        conn = SimpleNamespace(
            fetchrow=AsyncMock(
                side_effect=[
                    None,
                    {
                        "id": workflow_id,
                        "name": "stored-wf",
                        "definition": {"IDLE": ["EXECUTING"]},
                    },
                ]
            )
        )

        with client_for_connection(conn) as client:
            response = client.post(
                "/workflow",
                json={"name": "incoming-wf", "definition": incoming_definition},
            )

        self.assert_route_error_response(
            response,
            409,
            {
                "status": "workflow_id_collision",
                "workflow_id": workflow_id,
                "existing": {
                    "name": "stored-wf",
                    "canonical_definition": existing_canonical_definition,
                },
                "incoming": {
                    "name": "incoming-wf",
                    "canonical_definition": incoming_canonical_definition,
                },
                "reason": "workflow_id already exists for different canonical content",
            },
        )


if __name__ == "__main__":
    unittest.main()
