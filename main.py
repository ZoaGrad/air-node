# A.I.R. — Agent Incident Recorder
# VaultNode // Blackglass Continuum LLC
# CAGE: 17TJ5 | UEI: SVZVXPTM9AF4
# Mission: Truth Preservation in Agentic Workflows

import json
from contextlib import asynccontextmanager
from typing import Any, Dict, List

import asyncpg
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
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
    agent_id: str
    session_id: str
    action: str
    state_before: str
    state_after: str
    metadata: Dict[str, Any] = {}


class WorkflowDef(BaseModel):
    name: str
    definition: Dict[str, List[str]]


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
    async with app.state.pool.acquire() as conn:
        # Fetch workflow bound to this session's agent
        row = await conn.fetchrow(
            """
            SELECT w.definition
            FROM sessions s
            JOIN workflows w ON w.name = s.agent_id
            WHERE s.id = $1
            """,
            event.session_id,
        )

        if row:
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

    return {"status": "committed", "session_id": event.session_id}


@app.post("/workflow")
async def register_workflow(workflow: WorkflowDef):
    """Commits a JSON rule-engine to the workflows table."""
    async with app.state.pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO workflows (name, definition)
            VALUES ($1, $2)
            ON CONFLICT (name) DO UPDATE SET definition = EXCLUDED.definition
            """,
            workflow.name,
            json.dumps(workflow.definition),
        )
    return {"status": "workflow_locked", "workflow": workflow.name}


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
