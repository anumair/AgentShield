import json
import os

import boto3

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

SESSIONS_TABLE = os.environ["SESSIONS_TABLE"]
ALERTS_TOPIC_ARN = os.environ["ALERTS_TOPIC_ARN"]


def handler(event, context):
    """Invoked by the Policy Lambda the moment an action is denied. Freezes
    the session so the Agent Lambda's next iteration stops, and raises an
    alert with full context for the security team."""
    action = event.get("action", {})
    reason = event.get("reason", "unspecified")
    category = event.get("category", "unspecified")
    session_id = action.get("session", "unknown")

    table = dynamodb.Table(SESSIONS_TABLE)
    table.put_item(Item={"session_id": session_id, "frozen": True})

    message = (
        f"AgentShield kill-switch triggered\n\n"
        f"Session: {session_id}\n"
        f"Category: {category}\n"
        f"Reason: {reason}\n"
        f"Action: {json.dumps(action)}\n"
    )
    # SNS subjects are capped at 100 chars and publish() rejects the whole
    # call if exceeded - full session_id already lives in the message body,
    # so keep the subject to just the category and truncate defensively.
    subject = f"AgentShield ALERT - {category}"[:100]
    sns.publish(
        TopicArn=ALERTS_TOPIC_ARN,
        Subject=subject,
        Message=message,
    )

    return {"frozen": True, "session_id": session_id}
