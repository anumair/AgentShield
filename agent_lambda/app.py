import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
lambda_client = boto3.client("lambda")
SESSIONS_TABLE = os.environ["SESSIONS_TABLE"]
POLICY_FUNCTION_NAME = os.environ["POLICY_FUNCTION_NAME"]

DEFAULT_SESSION = "customer-support-test"

# One scripted action per threat category, plus one benign control action.
# Order matters for the demo: the benign call proves the approved path works
# before the agent ever attempts something that should be blocked.
SCRIPTED_ACTIONS = [
    {"type": "http_call", "target": "api.weather.com"},
    {"type": "http_call", "target": "malicious-c2.net"},
    {"type": "iam_action", "request": "assume_role", "role": "admin"},
    {"type": "db_write", "target": "billing_db"},
    {"type": "create_resource", "resource": "scheduled_task"},
]


def is_frozen(session_id: str) -> bool:
    table = dynamodb.Table(SESSIONS_TABLE)
    item = table.get_item(Key={"session_id": session_id}).get("Item")
    return bool(item and item.get("frozen"))


def call_policy_gateway(action: dict) -> dict:
    # Invoked directly over the private "lambda" service VPC endpoint - the
    # sandbox has no route to the public internet, so this is the only path
    # out of it. Kept as a plain Lambda invoke rather than routing through
    # API Gateway, since private (VPC-only) access to an HTTP API is not a
    # reliably supported pattern the way it is for REST APIs.
    response = lambda_client.invoke(
        FunctionName=POLICY_FUNCTION_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps(action).encode("utf-8"),
    )
    return json.loads(response["Payload"].read())


def handler(event, context):
    # session/actions can be overridden per invocation so a single-category
    # scenario can run against a fresh, never-frozen session (see
    # scripts/run_scenario.py) - the default is the full scripted walk.
    session_id = (event or {}).get("session", DEFAULT_SESSION)
    actions = (event or {}).get("actions", SCRIPTED_ACTIONS)
    results = []

    for action in actions:
        if is_frozen(session_id):
            logger.info("Session %s is frozen - stopping before action %s", session_id, action)
            results.append({"action": action, "outcome": "blocked_by_freeze"})
            break

        action_with_session = {**action, "session": session_id}
        decision = call_policy_gateway(action_with_session)
        logger.info("Action %s -> %s", action, decision)
        results.append({"action": action, "outcome": decision})

    return {"session": session_id, "results": results}
