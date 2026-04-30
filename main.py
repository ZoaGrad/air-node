# A.I.R. — Agent Incident Recorder
# VaultNode // Blackglass Continuum LLC
# CAGE: 17TJ5 | UEI: SVZVXPTM9AF4
# Mission: Truth Preservation in Agentic Workflows

import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

import asyncpg
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings
from invariants import (
    canonicalize_workflow_definition,
    classify_session_registration,
    classify_workflow_registration,
    compute_workflow_id,
    resolve_session_workflow_definition,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Settings(BaseSettings):
    air_db_user: str
    air_db_password: str
    air_db_name: str
    air_db_host: str = "localhost"
    air_db_port: int = 5432
    # IA-2: Telemetry channel key. If set, /incidents enforces X-API-Key auth.
    # Leave unset only in local dev (no key = unenforced, logs warning on startup).
    air_node_api_key: Optional[str] = None

    class Config:
        env_file = ".env"

settings = Settings()
logger = logging.getLogger("air_node")


def raise_invalid_reference(route_name: str, exc: Exception) -> None:
    logger.warning("Invalid reference in %s", route_name, exc_info=exc)
    raise HTTPException(
        status_code=400,
        detail={
            "code": "invalid_reference",
            "message": "referenced entity does not exist",
        },
    ) from None


def raise_db_fault(route_name: str, exc: Exception) -> None:
    logger.exception("Database fault in %s", route_name)
    raise HTTPException(
        status_code=500,
        detail={
            "code": "db_fault",
            "message": "internal database fault",
        },
    ) from None


# ---------------------------------------------------------------------------
# Auth dependency — enforces X-API-Key on protected routes
# ---------------------------------------------------------------------------

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

async def require_api_key(key: str | None = Security(_API_KEY_HEADER)) -> None:
    """
    FastAPI dependency: validates X-API-Key against AIR_NODE_API_KEY.
    - If AIR_NODE_API_KEY is not configured: 401 (server misconfigured)
    - If key is missing from request:        401
    - If key does not match:                 403
    """
    if not settings.air_node_api_key:
        raise HTTPException(
            status_code=401,
            detail="AIR_NODE_API_KEY not configured on server — /incidents is locked.",
        )
    if key is None:
        raise HTTPException(
            status_code=401,
            detail="X-API-Key header required.",
        )
    if key != settings.air_node_api_key:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key.",
        )


# ---------------------------------------------------------------------------
# Lifespan — DB pool init/teardown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await asyncpg.create_pool(
        user=settings.air_db_user,
        password=settings.air_db_password,
        database=settings.air_db_name,
        host=settings.air_db_host,
        port=settings.air_db_port,
        min_size=2,
        max_size=10,
    )
    yield
    await app.state.pool.close()


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="A.I.R. VaultNode API",
    version="0.1.0",
    description="Truth Preservation in Agentic Workflows",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Sovereign State Definitions
# ---------------------------------------------------------------------------

class AgentEvent(BaseModel):
    agent_id:     str = Field(..., min_length=1, max_length=128)
    session_id:   str = Field(..., min_length=1, max_length=128)
    action:       str = Field(..., min_length=1, max_length=256)
    state_before: str = Field(..., min_length=1, max_length=128)
    state_after:  str = Field(..., min_length=1, max_length=128)
    metadata:     Dict[str, Any] = Field(default={}, max_length=64)

    @field_validator("metadata")
    @classmethod
    def metadata_size_guard(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        serialized = json.dumps(v)
        if len(serialized) > 16_384:  # 16 KB hard ceiling
            raise ValueError("metadata payload exceeds 16KB limit")
        return v


class AgentDef(BaseModel):
    id:   str = Field(..., min_length=1, max_length=128)
    name: str = Field(..., min_length=1, max_length=128)


class SessionDef(BaseModel):
    id:          str = Field(..., min_length=1, max_length=128)
    agent_id:    str = Field(..., min_length=1, max_length=128)
    workflow_id: str = Field(..., min_length=1, max_length=128)


class WorkflowDef(BaseModel):
    name:       str                      = Field(..., min_length=1, max_length=128)
    definition: Dict[str, List[str]]     = Field(...)

    @field_validator("definition")
    @classmethod
    def definition_not_empty(cls, v: Dict[str, List[str]]) -> Dict[str, List[str]]:
        if not v:
            raise ValueError("workflow definition cannot be empty")
        return v


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/event")
async def log_event(event: AgentEvent):
    """
    Core interdiction vector.
    1. Fetch authorized workflow for this session.
    2. If state_after NOT IN valid_transitions[state_before] → flag incident.
    3. Else → commit event to ledger.
    """
    try:
        async with app.state.pool.acquire() as conn:
            # Resolve session existence separately from workflow availability.
            row = await conn.fetchrow(
                """
                SELECT
                    s.workflow_id,
                    w.definition AS workflow_definition
                FROM sessions s
                LEFT JOIN workflows w ON w.id = s.workflow_id
                WHERE s.id = $1
                """,
                event.session_id,
            )
            definition = resolve_session_workflow_definition(row, event.session_id)
            valid_next = definition.get(event.state_before, [])
            if event.state_after not in valid_next:
                # Unauthorized transition — generate incident
                incident_id = f"INC-{event.session_id}-{event.action}"
                await conn.execute(
                    """
                    INSERT INTO incidents
                        (id, session_id, reason, observed_transition, expected_transition)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    incident_id,
                    event.session_id,
                    "unauthorized_state_transition",
                    f"{event.state_before} -> {event.state_after}",
                    json.dumps(valid_next),
                )
                raise HTTPException(
                    status_code=409,
                    detail={
                        "status": "incident_flagged",
                        "incident_id": incident_id,
                        "observed": f"{event.state_before} -> {event.state_after}",
                        "authorized": valid_next,
                    },
                )

            # Authorized — commit to ledger
            await conn.execute(
                """
                INSERT INTO events
                    (id, session_id, action, state_before, state_after, raw_json)
                VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)
                """,
                event.session_id,
                event.action,
                event.state_before,
                event.state_after,
                json.dumps(event.metadata),
            )

    except HTTPException:
        raise
    except asyncpg.ForeignKeyViolationError as e:
        raise_invalid_reference("/event", e)
    except asyncpg.PostgresError as e:
        raise_db_fault("/event", e)

    return {"status": "committed", "session_id": event.session_id}


@app.post("/agent")
async def register_agent(agent: AgentDef):
    """Registers an AI entity."""
    try:
        async with app.state.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO agents (id, name)
                VALUES ($1, $2)
                ON CONFLICT (id) DO NOTHING
                """,
                agent.id,
                agent.name,
            )
    except asyncpg.PostgresError as e:
        raise_db_fault("/agent", e)
    return {"status": "agent_registered", "agent_id": agent.id}


@app.post("/session")
async def register_session(session: SessionDef):
    """Initializes a bounded chronography for an agent."""
    try:
        async with app.state.pool.acquire() as conn:
            inserted = await conn.fetchrow(
                """
                INSERT INTO sessions (id, agent_id, workflow_id)
                VALUES ($1, $2, $3)
                ON CONFLICT (id) DO NOTHING
                RETURNING id
                """,
                session.id,
                session.agent_id,
                session.workflow_id,
            )
            if inserted is not None:
                return classify_session_registration(
                    None, session.id, session.agent_id, session.workflow_id
                )

            existing = await conn.fetchrow(
                """
                SELECT agent_id, workflow_id
                FROM sessions
                WHERE id = $1
                """,
                session.id,
            )
            return classify_session_registration(
                existing, session.id, session.agent_id, session.workflow_id
            )
    except asyncpg.ForeignKeyViolationError as e:
        raise_invalid_reference("/session", e)
    except asyncpg.PostgresError as e:
        raise_db_fault("/session", e)


@app.post("/workflow")
async def register_workflow(workflow: WorkflowDef):
    """Commits a JSON rule-engine to the workflows table."""
    canonical_definition = canonicalize_workflow_definition(workflow.definition)
    workflow_id = compute_workflow_id(workflow.definition)
    try:
        async with app.state.pool.acquire() as conn:
            inserted = await conn.fetchrow(
                """
                INSERT INTO workflows (id, name, definition)
                VALUES ($1, $2, $3)
                ON CONFLICT (id) DO NOTHING
                RETURNING id, name, definition
                """,
                workflow_id,
                workflow.name,
                canonical_definition,
            )
            if inserted is not None:
                return classify_workflow_registration(
                    None,
                    workflow_id,
                    workflow.name,
                    canonical_definition,
                )

            existing = await conn.fetchrow(
                """
                SELECT id, name, definition
                FROM workflows
                WHERE id = $1
                """,
                workflow_id,
            )
            return classify_workflow_registration(
                existing,
                workflow_id,
                workflow.name,
                canonical_definition,
            )
    except asyncpg.PostgresError as e:
        raise_db_fault("/workflow", e)


@app.get("/incidents", dependencies=[Depends(require_api_key)])
async def list_incidents():
    """Returns the absolute proof of agent drift."""
    try:
        async with app.state.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM incidents ORDER BY created_at DESC"
            )
    except asyncpg.PostgresError as e:
        raise_db_fault("/incidents", e)
    return {"incidents": [dict(r) for r in rows]}


@app.get("/session/{session_id}")
async def replay_session(session_id: str):
    """Reconstructs the exact chronological timeline of an agent's actions."""
    try:
        async with app.state.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, timestamp, action, state_before, state_after
                FROM events
                WHERE session_id = $1
                ORDER BY timestamp ASC
                """,
                session_id,
            )
    except asyncpg.PostgresError as e:
        raise_db_fault("/session/{session_id}", e)
    return {"session_id": session_id, "timeline": [dict(r) for r in rows]}
