import json
import logging
import os
import urllib.error
import urllib.request

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
SESSIONS_TABLE = os.environ["SESSIONS_TABLE"]
ACTION_API_URL = os.environ["ACTION_API_URL"]

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
    data = json.dumps(action).encode("utf-8")
    request = urllib.request.Request(
        ACTION_API_URL, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return {"decision": "error", "reason": f"gateway returned {exc.code}"}


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
