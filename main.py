# A.I.R. — Agent Incident Recorder
# VaultNode // Blackglass Continuum LLC
# CAGE: 17TJ5 | UEI: SVZVXPTM9AF4
# Mission: Truth Preservation in Agentic Workflows

import hashlib
import json
from contextlib import asynccontextmanager
from typing import Any, Dict, List

import asyncpg
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Settings(BaseSettings):
    air_db_user: str
    air_db_password: str
    air_db_name: str
    air_db_host: str = "localhost"
    air_db_port: int = 5432

    class Config:
        env_file = ".env"

settings = Settings()


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
            # Fetch workflow bound to this session
            row = await conn.fetchrow(
                """
                SELECT w.definition
                FROM sessions s
                JOIN workflows w ON w.id = s.workflow_id
                WHERE s.id = $1
                """,
                event.session_id,
            )

            if row is None:
                # Session not found in DB — reject rather than pass silently
                raise HTTPException(
                    status_code=404,
                    detail={
                        "status": "session_not_found",
                        "session_id": event.session_id,
                        "reason": "session must be registered before submitting events",
                    },
                )

            definition = json.loads(row["definition"]) if isinstance(row["definition"], str) else row["definition"]
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
        raise HTTPException(
            status_code=400,
            detail={"status": "referential_integrity_violation", "detail": str(e)},
        )
    except asyncpg.PostgresError as e:
        raise HTTPException(
            status_code=500,
            detail={"status": "database_error", "detail": str(e)},
        )

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
        raise HTTPException(
            status_code=500,
            detail={"status": "database_error", "detail": str(e)},
        )
    return {"status": "agent_registered", "agent_id": agent.id}


@app.post("/session")
async def register_session(session: SessionDef):
    """Initializes a bounded chronography for an agent."""
    try:
        async with app.state.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO sessions (id, agent_id, workflow_id)
                VALUES ($1, $2, $3)
                ON CONFLICT (id) DO NOTHING
                """,
                session.id,
                session.agent_id,
                session.workflow_id,
            )
    except asyncpg.ForeignKeyViolationError as e:
        raise HTTPException(
            status_code=400,
            detail={"status": "referential_integrity_violation", "detail": str(e)},
        )
    except asyncpg.PostgresError as e:
        raise HTTPException(
            status_code=500,
            detail={"status": "database_error", "detail": str(e)},
        )
    return {"status": "session_registered", "session_id": session.id}


@app.post("/workflow")
async def register_workflow(workflow: WorkflowDef):
    """Commits a JSON rule-engine to the workflows table."""
    workflow_id = hashlib.sha256((workflow.name + json.dumps(workflow.definition, sort_keys=True)).encode()).hexdigest()[:16]
    try:
        async with app.state.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO workflows (id, name, definition)
                VALUES ($1, $2, $3)
                ON CONFLICT (id) DO NOTHING
                """,
                workflow_id,
                workflow.name,
                json.dumps(workflow.definition),
            )
    except asyncpg.PostgresError as e:
        raise HTTPException(
            status_code=500,
            detail={"status": "database_error", "detail": str(e)},
        )
    return {"status": "workflow_locked", "workflow_id": workflow_id}


@app.get("/incidents")
async def list_incidents():
    """Returns the absolute proof of agent drift."""
    async with app.state.pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM incidents ORDER BY created_at DESC"
        )
    return {"incidents": [dict(r) for r in rows]}


@app.get("/session/{session_id}")
async def replay_session(session_id: str):
    """Reconstructs the exact chronological timeline of an agent's actions."""
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
    return {"session_id": session_id, "timeline": [dict(r) for r in rows]}
