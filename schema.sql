-- A.I.R. — Agent Incident Recorder
-- VaultNode // Blackglass Continuum LLC
-- CAGE: 17TJ5 | UEI: SVZVXPTM9AF4
-- Schema Authority: Ratified Day One
CREATE TABLE agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL
);
CREATE TABLE workflows (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    definition JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    agent_id TEXT REFERENCES agents(id),
    workflow_id TEXT REFERENCES workflows(id),
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE events (
    id UUID PRIMARY KEY,
    session_id TEXT REFERENCES sessions(id),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    state_before TEXT NOT NULL,
    state_after TEXT NOT NULL,
    raw_json JSONB
);
CREATE TABLE incidents (
    id TEXT PRIMARY KEY,
    session_id TEXT REFERENCES sessions(id),
    reason TEXT NOT NULL,
    observed_transition TEXT NOT NULL,
    expected_transition JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);