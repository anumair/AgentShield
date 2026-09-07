import logging
import urllib.request
import urllib.error

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    """Only ever invoked directly by the Policy Lambda after it has approved
    an action - never exposed via API Gateway. Runs in the public subnet
    and makes the real outbound call: the single component with an actual
    path to the internet."""
    action = event or {}
    target = action.get("target")

    url = f"https://{target}"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            status = response.status
            snippet = response.read(500).decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        logger.info("Egress call to %s failed: %s", target, exc)
        status = None
        snippet = str(exc)

    logger.info("Egress call to %s completed with status=%s", target, status)

    return {"target": target, "upstream_status": status, "body_snippet": snippet}
