# Per-session test scenario declarations: what a session is allowed to do.
# In a real deployment this would come from a config service or DynamoDB
# table populated when a test session is created; hardcoded here since the
# prototype only needs to prove the four threat categories are detected.

SESSION_SCOPES = {
    "customer-support-test": {
        "allowed_network_targets": {"api.weather.com"},
        "max_role": "read_only",
        "allowed_action_types": {"http_call"},
    },
}

DEFAULT_SCOPE = {
    "allowed_network_targets": set(),
    "max_role": "read_only",
    "allowed_action_types": {"http_call"},
}

ROLE_RANK = {"read_only": 0, "operator": 1, "admin": 2}

PERSISTENCE_RESOURCE_TYPES = {"scheduled_task", "webhook", "credential"}


def scope_for(session_id: str) -> dict:
    # Exact match first; otherwise treat "<scenario>-<run-suffix>" as an
    # instance of that scenario so each test run can use a fresh,
    # never-frozen session id without losing its declared allow-list.
    if session_id in SESSION_SCOPES:
        return SESSION_SCOPES[session_id]
    for scenario, scope in SESSION_SCOPES.items():
        if session_id.startswith(scenario + "-"):
            return scope
    return DEFAULT_SCOPE
