import json
import os
from datetime import datetime, timezone

import boto3

from config import scope_for, ROLE_RANK, PERSISTENCE_RESOURCE_TYPES

dynamodb = boto3.resource("dynamodb")
lambda_client = boto3.client("lambda")

LOGS_TABLE = os.environ["LOGS_TABLE"]
KILLSWITCH_FUNCTION_NAME = os.environ["KILLSWITCH_FUNCTION_NAME"]
EGRESS_FUNCTION_NAME = os.environ["EGRESS_FUNCTION_NAME"]


def evaluate(action: dict) -> dict:
    """Runs one action through the four threat-model checks. Each action
    type maps to exactly one category so the categories never overlap."""
    session_id = action.get("session")
    scope = scope_for(session_id)
    action_type = action.get("type")

    if action_type == "http_call":
        target = action.get("target")
        if target not in scope["allowed_network_targets"]:
            return _deny("unauthorized_network_call", f"target '{target}' not on session allow-list")
        return _approve()

    if action_type == "iam_action":
        requested_role = action.get("role")
        if ROLE_RANK.get(requested_role, 99) > ROLE_RANK.get(scope["max_role"], 0):
            return _deny("privilege_escalation", f"requested role '{requested_role}' exceeds session max '{scope['max_role']}'")
        return _approve()

    if action_type == "create_resource":
        resource = action.get("resource")
        if resource in PERSISTENCE_RESOURCE_TYPES:
            return _deny("persistence", f"attempt to create persistent resource '{resource}' outside session scope")
        return _approve()

    # db_write and anything else: only allowed if the session's declared
    # scenario explicitly lists this action type.
    if action_type not in scope["allowed_action_types"]:
        return _deny("scope_deviation", f"action type '{action_type}' not declared for this session's scenario")
    return _approve()


def _approve() -> dict:
    return {"decision": "approved", "reason": None, "category": None}


def _deny(category: str, reason: str) -> dict:
    return {"decision": "denied", "reason": reason, "category": category}


def _log(action: dict, result: dict) -> None:
    table = dynamodb.Table(LOGS_TABLE)
    table.put_item(
        Item={
            "session_id": action.get("session", "unknown"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_type": action.get("type", "unknown"),
            "target": action.get("target") or action.get("role") or action.get("resource") or "n/a",
            "decision": result["decision"],
            "reason": result["reason"] or "within declared scope",
        }
    )


def handler(event, context):
    # Two invocation paths reach this function: a direct Lambda invoke from
    # the sandboxed Agent Lambda (event *is* the action), and an optional
    # API Gateway HttpApi call for manual/external testing (event carries a
    # "requestContext" and a JSON-string "body").
    if isinstance(event, dict) and "requestContext" in event:
        via_api_gateway = True
        body = event.get("body")
        action = json.loads(body) if isinstance(body, str) else (body or {})
    else:
        via_api_gateway = False
        action = event or {}

    result = evaluate(action)
    _log(action, result)

    response_body = {"decision": result["decision"], "reason": result["reason"]}

    if result["decision"] == "denied":
        lambda_client.invoke(
            FunctionName=KILLSWITCH_FUNCTION_NAME,
            InvocationType="Event",
            Payload=json.dumps({"action": action, "reason": result["reason"], "category": result["category"]}),
        )
    elif action.get("type") == "http_call":
        # Forward the approved call to the Egress Lambda, the only
        # component with an actual route to the internet, and hand its
        # result back to the agent as the outcome of the call.
        egress_response = lambda_client.invoke(
            FunctionName=EGRESS_FUNCTION_NAME,
            InvocationType="RequestResponse",
            Payload=json.dumps(action),
        )
        response_body["egress_result"] = json.loads(egress_response["Payload"].read())

    if via_api_gateway:
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(response_body),
        }
    return response_body
