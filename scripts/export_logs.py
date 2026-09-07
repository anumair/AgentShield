#!/usr/bin/env python3
"""Scans AgentShieldLogs and writes a CSV + a per-category summary into
logs_and_results/, for the report's evaluation section."""
import csv
import os
from collections import Counter
from datetime import datetime, timezone

import boto3

LOGS_TABLE = "AgentShieldLogs"
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "logs_and_results")


def scan_all(table) -> list:
    items = []
    kwargs = {}
    while True:
        response = table.scan(**kwargs)
        items.extend(response.get("Items", []))
        if "LastEvaluatedKey" not in response:
            break
        kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
    return items


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    table = boto3.resource("dynamodb").Table(LOGS_TABLE)
    items = scan_all(table)
    items.sort(key=lambda item: item.get("timestamp", ""))

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    csv_path = os.path.join(OUTPUT_DIR, f"agentshield_logs_{timestamp}.csv")

    fieldnames = ["session_id", "timestamp", "action_type", "target", "decision", "reason"]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in items:
            writer.writerow({key: item.get(key, "") for key in fieldnames})

    decisions = Counter(item.get("decision") for item in items)
    print(f"Wrote {len(items)} rows to {csv_path}")
    print(f"approved: {decisions.get('approved', 0)}  denied: {decisions.get('denied', 0)}")


if __name__ == "__main__":
    main()
