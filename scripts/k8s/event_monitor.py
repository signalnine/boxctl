#!/usr/bin/env python3
# boxctl:
#   category: k8s/events
#   tags: [kubernetes, events, monitoring, cluster]
#   requires: [kubectl]
#   privilege: none
#   related: [node_health]
#   brief: Monitor Kubernetes events to track cluster issues

"""
Monitor Kubernetes events to track cluster issues and anomalies.

Aggregates and displays Kubernetes events from the cluster,
helping administrators identify issues before they impact workloads.
Useful for monitoring large-scale Kubernetes deployments.
"""

import argparse
import json
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_events(context: Context, namespace: str | None = None) -> dict[str, Any]:
    """
    Get events in JSON format from kubectl.

    Args:
        context: Execution context
        namespace: Optional namespace filter

    Returns:
        Parsed JSON events data
    """
    cmd = ["kubectl", "get", "events", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    return json.loads(result.stdout)


def categorize_events(events_data: dict[str, Any]) -> tuple[dict, list, list]:
    """
    Categorize events by type and reason.

    Args:
        events_data: Raw events data from kubectl

    Returns:
        Tuple of (categories, warnings, errors)
    """
    categories = defaultdict(list)
    warnings = []
    errors = []

    for event in events_data.get("items", []):
        event_type = event.get("type", "Normal")
        reason = event.get("reason", "Unknown")
        namespace = event["metadata"].get("namespace", "default")
        involved_object = event.get("involvedObject", {})
        object_name = involved_object.get("name", "unknown")
        object_kind = involved_object.get("kind", "Unknown")
        message = event.get("message", "")
        count = event.get("count", 1)
        last_timestamp = event.get("lastTimestamp", "")

        event_info = {
            "namespace": namespace,
            "type": event_type,
            "reason": reason,
            "object": f"{object_kind}/{object_name}",
            "message": message,
            "count": count,
            "last_timestamp": last_timestamp,
        }

        categories[f"{event_type}:{reason}"].append(event_info)

        # Track warnings and errors
        if event_type == "Warning":
            warnings.append(event_info)
        elif event_type == "Error":
            errors.append(event_info)

    return categories, warnings, errors


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no critical events, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes events to track cluster issues"
    )
    parser.add_argument(
        "--namespace", "-n",
        help="Namespace to monitor (default: all namespaces)"
    )
    parser.add_argument(
        "--warn-only", "-w",
        action="store_true",
        help="Only show warnings and errors"
    )
    parser.add_argument(
        "--categories", "-c",
        action="store_true",
        help="Show event category summary"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)"
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found. Install kubectl to use this script.")
        return 2

    # Get events
    try:
        events_data = get_events(context, opts.namespace)
    except Exception as e:
        output.error(f"Failed to get events: {e}")
        return 2

    # Categorize events
    categories, warnings, errors = categorize_events(events_data)

    # Build output data
    result_data = {
        "errors": errors,
        "warnings": warnings,
        "summary": {
            "error_count": len(errors),
            "warning_count": len(warnings),
            "total_categories": len(categories),
        },
    }

    # Add categories if requested
    if opts.categories:
        result_data["categories"] = {
            key: len(events) for key, events in sorted(categories.items())
        }

    output.emit(result_data)

    # Set summary
    has_issues = len(errors) > 0 or len(warnings) > 0
    if has_issues:
        output.set_summary(f"{len(errors)} errors, {len(warnings)} warnings")
    else:
        output.set_summary("No critical events")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
