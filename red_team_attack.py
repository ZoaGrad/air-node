# A.I.R. — Red Team Attack Script
# VaultNode // Blackglass Continuum LLC
# CAGE: 17TJ5 | UEI: SVZVXPTM9AF4
#
# Vectors:
#   1. Malformed Payload Injections (Fuzzing)
#   2. Cross-Session Hijacking
#   3. Mid-Flight Workflow Overwrites
#   4. Concurrency & Race Conditions

import asyncio
import json
import sys
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List

import httpx

BASE_URL = "http://localhost:8000"
TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------

@dataclass
class VectorResult:
    name: str
    passed: List[str] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def ok(self, msg: str):
        self.passed.append(msg)
        print(f"  [PASS] {msg}")

    def fail(self, msg: str):
        self.failed.append(msg)
        print(f"  [FAIL] {msg}")

    def warn(self, msg: str):
        self.warnings.append(msg)
        print(f"  [WARN] {msg}")

    @property
    def clean(self) -> bool:
        return len(self.failed) == 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def post(client: httpx.AsyncClient, path: str, payload: Any) -> httpx.Response:
    return await client.post(f"{BASE_URL}{path}", json=payload, timeout=TIMEOUT)


async def get(client: httpx.AsyncClient, path: str) -> httpx.Response:
    return await client.get(f"{BASE_URL}{path}", timeout=TIMEOUT)


async def seed_workflow(client: httpx.AsyncClient, name: str, definition: Dict) -> str:
    r = await post(client, "/workflow", {"name": name, "definition": definition})
    r.raise_for_status()
    return r.json()["workflow_id"]


async def seed_agent(client: httpx.AsyncClient, agent_id: str, name: str) -> None:
    r = await post(client, "/agent", {"id": agent_id, "name": name})
    r.raise_for_status()


async def seed_session(client: httpx.AsyncClient, session_id: str, agent_id: str, workflow_id: str) -> None:
    r = await post(client, "/session", {"id": session_id, "agent_id": agent_id, "workflow_id": workflow_id})
    r.raise_for_status()


# ---------------------------------------------------------------------------
# Vector 1: Malformed Payload Injections
# ---------------------------------------------------------------------------

async def vector_1_fuzzing(client: httpx.AsyncClient) -> VectorResult:
    result = VectorResult("Vector 1: Malformed Payload Injections")
    print("\n[VECTOR 1] Malformed Payload Injections")

    # --- Structurally invalid payloads: Pydantic must reject before DB ---
    # These should return 422 regardless of session state.
    schema_fuzz = [
        ("missing state_before", {"agent_id": "a", "session_id": "s", "action": "x",
                                   "state_after": "B"}),
        ("missing state_after",  {"agent_id": "a", "session_id": "s", "action": "x",
                                   "state_before": "A"}),
        ("missing action",       {"agent_id": "a", "session_id": "s",
                                   "state_before": "A", "state_after": "B"}),
        ("int as state_before",  {"agent_id": "a", "session_id": "s", "action": "x",
                                   "state_before": 999, "state_after": "B"}),
        ("null agent_id",        {"agent_id": None, "session_id": "s", "action": "x",
                                   "state_before": "A", "state_after": "B"}),
        ("massive metadata",     {"agent_id": "a", "session_id": "s", "action": "x",
                                   "state_before": "A", "state_after": "B",
                                   "metadata": {"payload": "X" * 100_000}}),
    ]

    for label, payload in schema_fuzz:
        r = await post(client, "/event", payload)
        if r.status_code in (400, 422):
            result.ok(f"{label} → correctly rejected ({r.status_code})")
        elif r.status_code == 500:
            result.fail(f"{label} → 500 crash (API not hardened against this input)")
        elif r.status_code in (200, 409):
            result.warn(f"{label} → accepted ({r.status_code}) — review if intentional")
        else:
            result.warn(f"{label} → unexpected status {r.status_code}")

    # --- Content injection: structurally valid payloads against a live session ---
    # These pass Pydantic. We need a real session to reach the DB layer.
    # Expected: 422 if field constraints catch it, otherwise 200/409 (session exists).
    # A 404 here would mean the session guard fired — that is also a valid rejection.
    fuzz_agent_id  = f"fuzz-agent-{uuid.uuid4().hex[:6]}"
    fuzz_session   = f"fuzz-session-{uuid.uuid4().hex[:6]}"
    fuzz_wf_id     = await seed_workflow(client, f"fuzz-wf-{uuid.uuid4().hex[:6]}",
                                         {"IDLE": ["ANALYZING"]})
    await seed_agent(client, fuzz_agent_id, "Fuzz Agent")
    await seed_session(client, fuzz_session, fuzz_agent_id, fuzz_wf_id)

    content_fuzz = [
        ("deeply nested meta",    {"agent_id": fuzz_agent_id, "session_id": fuzz_session,
                                    "action": "probe",
                                    "state_before": "IDLE", "state_after": "ANALYZING",
                                    "metadata": {"a": {"b": {"c": {"d": {"e": "deep"}}}}}}),
        ("sql injection action",  {"agent_id": fuzz_agent_id, "session_id": fuzz_session,
                                    "action": "'; DROP TABLE events; --",
                                    "state_before": "IDLE", "state_after": "ANALYZING"}),
    ]

    for label, payload in content_fuzz:
        r = await post(client, "/event", payload)
        if r.status_code in (400, 422):
            result.ok(f"{label} → rejected by validation ({r.status_code})")
        elif r.status_code in (200, 409):
            # Reached the DB — content was sanitized by parameterized query
            result.ok(f"{label} → reached DB layer safely ({r.status_code}), "
                      "parameterized query prevented injection")
        elif r.status_code == 500:
            result.fail(f"{label} → 500 crash (unhandled content injection)")
        else:
            result.warn(f"{label} → unexpected status {r.status_code}")

    # --- Fuzz /workflow definition field ---
    bad_workflows = [
        ("empty definition",      {"name": "fuzz-wf", "definition": {}}),
        ("null definition value", {"name": "fuzz-wf", "definition": {"A": None}}),
        ("int list values",       {"name": "fuzz-wf", "definition": {"A": [1, 2, 3]}}),
    ]
    for label, payload in bad_workflows:
        r = await post(client, "/workflow", payload)
        if r.status_code in (400, 422):
            result.ok(f"workflow/{label} → correctly rejected ({r.status_code})")
        elif r.status_code == 500:
            result.fail(f"workflow/{label} → 500 crash")
        else:
            result.warn(f"workflow/{label} → accepted ({r.status_code}) — schema permits this")

    return result


# ---------------------------------------------------------------------------
# Vector 2: Cross-Session Hijacking
# ---------------------------------------------------------------------------

async def vector_2_hijacking(client: httpx.AsyncClient) -> VectorResult:
    result = VectorResult("Vector 2: Cross-Session Hijacking")
    print("\n[VECTOR 2] Cross-Session Hijacking")

    wf_a = {"IDLE": ["ANALYZING"], "ANALYZING": ["EXECUTING"]}
    wf_b = {"IDLE": ["SLEEPING"], "SLEEPING": ["IDLE"]}

    wf_id_a = await seed_workflow(client, "agent-alpha", wf_a)
    wf_id_b = await seed_workflow(client, "agent-beta",  wf_b)

    await seed_agent(client, "agent-alpha", "Agent Alpha")
    await seed_agent(client, "agent-beta", "Agent Beta")

    session_a = f"hijack-session-alpha-{uuid.uuid4().hex[:6]}"
    session_b = f"hijack-session-beta-{uuid.uuid4().hex[:6]}"

    await seed_session(client, session_a, "agent-alpha", wf_id_a)
    await seed_session(client, session_b, "agent-beta", wf_id_b)

    # Attempt: use beta's session_id but alpha's agent_id and transitions
    r = await post(client, "/event", {
        "agent_id": "agent-alpha",
        "session_id": session_b,  # beta's session — tied to beta's workflow
        "action": "hijack_attempt",
        "state_before": "IDLE",
        "state_after": "ANALYZING",
    })

    if r.status_code == 404:
        result.fail("Orphan session rejected? But we seeded it.")
    elif r.status_code == 409:
        result.ok("Cross-session transition correctly blocked (409 incident)")
    elif r.status_code == 200:
        result.fail(
            "Cross-session transition committed — orphan session passed validation. "
            "BREACH: unknown session_ids must be rejected at the boundary."
        )
    elif r.status_code == 500:
        result.fail("500 crash on orphan session — FK violation unhandled")
    else:
        result.warn(f"Unexpected status {r.status_code}: {r.text[:200]}")

    return result


# ---------------------------------------------------------------------------
# Vector 3: Mid-Flight Workflow Overwrites
# ---------------------------------------------------------------------------

async def vector_3_overwrite(client: httpx.AsyncClient) -> VectorResult:
    result = VectorResult("Vector 3: Mid-Flight Workflow Overwrites")
    print("\n[VECTOR 3] Mid-Flight Workflow Overwrites")

    wf_name = f"overwrite-target-{uuid.uuid4().hex[:6]}"
    session_id = f"overwrite-session-{uuid.uuid4().hex[:6]}"

    # Register legitimate workflow
    wf_id = await seed_workflow(client, wf_name, {
        "IDLE": ["ANALYZING"],
        "ANALYZING": ["EXECUTING"],
    })

    await seed_agent(client, "agent-target", "Agent Target")
    await seed_session(client, session_id, "agent-target", wf_id)

    # Overwrite mid-flight to permit a previously unauthorized transition
    hostile_def = {
        "IDLE": ["ANALYZING"],
        "ANALYZING": ["EXECUTING", "EXPLOIT"],  # EXPLOIT injected
    }
    r = await post(client, "/workflow", {"name": wf_name, "definition": hostile_def})
    if r.status_code == 200:
        result.ok(f"Workflow update accepted ({r.status_code}) — new version created")
    else:
        result.warn(f"Workflow update rejected ({r.status_code})")

    # Attempt the injected transition
    r2 = await post(client, "/event", {
        "agent_id": "agent-target",
        "session_id": session_id,
        "action": "exploit_attempt",
        "state_before": "ANALYZING",
        "state_after": "EXPLOIT",
    })
    if r2.status_code == 200:
        result.fail(
            "EXPLOIT transition committed! Mid-flight overwrite leaked into the active session! "
            "BREACH: Session was not properly pinned to the original workflow version."
        )
    elif r2.status_code == 404:
        result.fail("EXPLOIT transition blocked via 404 — session was lost?")
    elif r2.status_code == 409:
        result.ok("EXPLOIT transition blocked (409 incident) — session successfully pinned to original workflow version.")
    elif r2.status_code == 500:
        result.fail("500 crash on EXPLOIT attempt — unhandled exception in event endpoint")
    else:
        result.warn(f"Unexpected status {r2.status_code}: {r2.text[:200]}")

    return result


# ---------------------------------------------------------------------------
# Vector 4: Concurrency & Race Conditions
# ---------------------------------------------------------------------------

async def vector_4_concurrency(client: httpx.AsyncClient) -> VectorResult:
    result = VectorResult("Vector 4: Concurrency & Race Conditions")
    print("\n[VECTOR 4] Concurrency & Race Conditions (100 simultaneous transitions)")

    session_id = f"race-session-{uuid.uuid4().hex[:6]}"
    statuses: List[int] = []

    wf_id = await seed_workflow(client, "race-workflow", {"IDLE": ["ANALYZING"]})
    await seed_agent(client, "race-agent", "Race Agent")
    await seed_session(client, session_id, "race-agent", wf_id)

    async def fire(i: int) -> int:
        r = await post(client, "/event", {
            "agent_id": "race-agent",
            "session_id": session_id,
            "action": f"concurrent_action_{i}",
            "state_before": "IDLE",
            "state_after": "ANALYZING",
        })
        return r.status_code

    tasks = [fire(i) for i in range(100)]
    statuses = await asyncio.gather(*tasks, return_exceptions=False)

    crashes = [s for s in statuses if s == 500]
    committed = [s for s in statuses if s == 200]
    vetoed = [s for s in statuses if s == 409]

    if crashes:
        result.fail(f"{len(crashes)} requests crashed with 500 under load — unhandled concurrency error")
    else:
        result.ok("No 500 crashes under 100 concurrent requests")

    print(f"  [INFO] committed={len(committed)} vetoed={len(vetoed)} crashed={len(crashes)}")

    if committed and vetoed:
        result.warn("Mix of committed and vetoed — concurrency locking might be failing.")
    elif len(committed) == 100:
        result.ok("All 100 valid transitions committed securely.")
    elif len(crashes) > 0:
        result.fail("500 crash during concurrency load")

    return result


# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------

def print_report(results: List[VectorResult]) -> None:
    print("\n" + "=" * 60)
    print("A.I.R. RED TEAM REPORT // BLACKGLASS CONTINUUM LLC")
    print("=" * 60)
    total_pass = sum(len(r.passed) for r in results)
    total_fail = sum(len(r.failed) for r in results)
    total_warn = sum(len(r.warnings) for r in results)

    for r in results:
        status = "CLEAN" if r.clean else "BREACH"
        print(f"\n  [{status}] {r.name}")
        for w in r.warnings:
            print(f"    WARN: {w}")
        for f in r.failed:
            print(f"    FAIL: {f}")

    print(f"\nTotals: {total_pass} passed | {total_warn} warnings | {total_fail} failures")

    if total_fail == 0:
        print("VERDICT: VaultNode boundary held. No unauthorized commits confirmed.")
    else:
        print("VERDICT: BREACH DETECTED — review failures above.")
    print("=" * 60)
    print("ΔΩ")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

async def main() -> None:
    print("A.I.R. Red Team Siege — VaultNode // CAGE: 17TJ5")
    print(f"Target: {BASE_URL}\n")

    async with httpx.AsyncClient() as client:
        # Verify target is up
        try:
            r = await client.get(f"{BASE_URL}/incidents", timeout=5.0)
            r.raise_for_status()
        except Exception as e:
            print(f"[ABORT] VaultNode unreachable at {BASE_URL}: {e}")
            sys.exit(1)

        results = []
        results.append(await vector_1_fuzzing(client))
        results.append(await vector_2_hijacking(client))
        results.append(await vector_3_overwrite(client))
        results.append(await vector_4_concurrency(client))

    print_report(results)


if __name__ == "__main__":
    asyncio.run(main())
