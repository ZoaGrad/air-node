"""Invariant helpers for A.I.R. event/session workflow handling."""

import hashlib
import json
from typing import Any, Mapping

from fastapi import HTTPException


def classify_session_registration(
    existing_row: Mapping[str, Any] | None,
    session_id: str,
    agent_id: str,
    workflow_id: str,
) -> dict[str, Any]:
    """
    Enforces immutable session bindings.

    - First registration creates the binding.
    - Replaying the exact same binding is idempotent.
    - Reusing a session ID with a different binding is a conflict.
    """
    if existing_row is None:
        return {
            "status": "session_registered",
            "session_id": session_id,
            "agent_id": agent_id,
            "workflow_id": workflow_id,
            "binding_status": "created",
        }

    existing_agent_id = existing_row.get("agent_id")
    existing_workflow_id = existing_row.get("workflow_id")
    if existing_agent_id == agent_id and existing_workflow_id == workflow_id:
        return {
            "status": "session_already_registered",
            "session_id": session_id,
            "agent_id": existing_agent_id,
            "workflow_id": existing_workflow_id,
            "binding_status": "unchanged",
        }

    raise HTTPException(
        status_code=409,
        detail={
            "status": "session_binding_conflict",
            "session_id": session_id,
            "existing": {
                "agent_id": existing_agent_id,
                "workflow_id": existing_workflow_id,
            },
            "incoming": {
                "agent_id": agent_id,
                "workflow_id": workflow_id,
            },
            "reason": "session bindings are immutable once registered",
        },
    )


def canonicalize_workflow_definition(definition: Mapping[str, Any]) -> str:
    """Stable JSON serialization for content-addressed workflow identities."""
    return json.dumps(
        definition,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def compute_workflow_id(definition: Mapping[str, Any]) -> str:
    canonical_definition = canonicalize_workflow_definition(definition)
    return hashlib.sha256(canonical_definition.encode("utf-8")).hexdigest()


def classify_workflow_registration(
    existing_row: Mapping[str, Any] | None,
    workflow_id: str,
    workflow_name: str,
    canonical_definition: str,
) -> dict[str, Any]:
    """
    Enforces content-addressed workflow identity.

    - First registration creates the workflow.
    - Replaying identical canonical content is idempotent.
    - Reusing an existing workflow_id for different content is a collision.
    """
    if existing_row is None:
        return {
            "status": "workflow_locked",
            "workflow_id": workflow_id,
            "workflow_status": "created",
            "name": workflow_name,
        }

    existing_definition = existing_row.get("definition")
    if isinstance(existing_definition, str):
        try:
            existing_definition = json.loads(existing_definition)
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=500,
                detail={
                    "status": "invalid_workflow_definition",
                    "workflow_id": workflow_id,
                    "reason": "stored workflow definition could not be decoded",
                },
            ) from None

    if not isinstance(existing_definition, dict):
        raise HTTPException(
            status_code=500,
            detail={
                "status": "invalid_workflow_definition",
                "workflow_id": workflow_id,
                "reason": "stored workflow definition must deserialize to a mapping",
            },
        )

    existing_canonical_definition = canonicalize_workflow_definition(
        existing_definition
    )
    if existing_canonical_definition != canonical_definition:
        raise HTTPException(
            status_code=409,
            detail={
                "status": "workflow_id_collision",
                "workflow_id": workflow_id,
                "existing": {
                    "name": existing_row.get("name"),
                    "canonical_definition": existing_canonical_definition,
                },
                "incoming": {
                    "name": workflow_name,
                    "canonical_definition": canonical_definition,
                },
                "reason": "workflow_id already exists for different canonical content",
            },
        )

    return {
        "status": "workflow_locked",
        "workflow_id": workflow_id,
        "workflow_status": "unchanged",
        "name": existing_row.get("name", workflow_name),
    }


def resolve_session_workflow_definition(
    row: Mapping[str, Any] | None, session_id: str
) -> dict[str, list[str]]:
    """
    Classifies session/workflow lookup results for /event.

    Invariant ordering matters:
    1. A session must exist before it can emit events.
    2. An existing session must resolve to a workflow definition.
    3. The workflow definition must deserialize into a mapping.
    """
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={
                "status": "session_not_found",
                "session_id": session_id,
                "reason": "session must be registered before submitting events",
            },
        )

    workflow_id = row.get("workflow_id")
    raw_definition = row.get("workflow_definition")
    if raw_definition is None:
        raise HTTPException(
            status_code=409,
            detail={
                "status": "workflow_not_found",
                "session_id": session_id,
                "workflow_id": workflow_id,
                "reason": "session is registered but its bound workflow is unavailable",
            },
        )

    try:
        definition = (
            json.loads(raw_definition)
            if isinstance(raw_definition, str)
            else raw_definition
        )
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=500,
            detail={
                "status": "invalid_workflow_definition",
                "session_id": session_id,
                "workflow_id": workflow_id,
                "reason": "stored workflow definition could not be decoded",
            },
        ) from None

    if not isinstance(definition, dict):
        raise HTTPException(
            status_code=500,
            detail={
                "status": "invalid_workflow_definition",
                "session_id": session_id,
                "workflow_id": workflow_id,
                "reason": "stored workflow definition must deserialize to a mapping",
            },
        )

    return definition
