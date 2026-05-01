#!/usr/bin/env python3
# boxctl:
#   category: k8s/autoscaling
#   tags: [hpa, kubernetes, autoscaling, thrashing, monitoring]
#   requires: [kubectl]
#   brief: Detect HPA thrashing in Kubernetes clusters
#   privilege: user
#   related: [hpa_health, container_restart_analyzer]

"""
Detect Horizontal Pod Autoscaler (HPA) thrashing in Kubernetes clusters.

HPA thrashing occurs when autoscalers rapidly scale up and down, causing:
- Application instability and connection drops
- Wasted resources from constant pod churn
- Increased scheduling pressure on the cluster
- Poor user experience from capacity fluctuations

This script analyzes HPA scaling events to identify:
- Rapid scale-up/scale-down cycles (thrashing)
- HPAs stuck at min or max replicas
- HPAs with metrics unavailable
- Scaling frequency anomalies

Exit codes:
    0 - No thrashing detected, all HPAs healthy
    1 - Thrashing or issues detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_event_time(event: dict) -> datetime | None:
    """Parse event timestamp, handling various formats."""
    # Try lastTimestamp first (older format)
    timestamp = event.get("lastTimestamp")
    if not timestamp:
        # Try eventTime (newer format)
        timestamp = event.get("eventTime")
    if not timestamp:
        # Fall back to firstTimestamp
        timestamp = event.get("firstTimestamp")
    if not timestamp:
        return None

    # Handle microseconds by truncating to 6 digits
    if "." in timestamp:
        base, frac = timestamp.rsplit(".", 1)
        # Remove timezone suffix from fraction
        if "Z" in frac:
            frac = frac.replace("Z", "")
            frac = frac[:6]  # Truncate to 6 digits
            timestamp = f"{base}.{frac}Z"
        elif "+" in frac:
            frac_part, tz = frac.split("+", 1)
            frac_part = frac_part[:6]
            timestamp = f"{base}.{frac_part}+{tz}"

    try:
        # Try ISO format with Z suffix
        if timestamp.endswith("Z"):
            return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return datetime.fromisoformat(timestamp)
    except ValueError:
        return None


def analyze_hpa_events(events: dict, hpa_name: str, namespace: str) -> list:
    """Analyze scaling events for a specific HPA."""
    scaling_events = []

    for event in events.get("items", []):
        involved = event.get("involvedObject", {})
        if involved.get("kind") != "HorizontalPodAutoscaler":
            continue
        if involved.get("name") != hpa_name:
            continue
        if event.get("metadata", {}).get("namespace") != namespace:
            continue

        reason = event.get("reason", "")
        message = event.get("message", "")
        event_time = parse_event_time(event)
        count = event.get("count", 1)

        if reason in ("SuccessfulRescale", "ScaledUpReplicas", "ScaledDownReplicas"):
            scaling_events.append(
                {
                    "time": event_time,
                    "reason": reason,
                    "message": message,
                    "count": count,
                }
            )

    return scaling_events


def detect_thrashing(
    scaling_events: list, window_minutes: int = 30, threshold: int = 4
) -> tuple[bool, int, list]:
    """
    Detect thrashing based on scaling event frequency.

    Thrashing is defined as multiple scale-up/scale-down cycles
    within a short time window.
    """
    if not scaling_events:
        return False, 0, []

    # Sort events by time
    sorted_events = sorted(
        [e for e in scaling_events if e["time"] is not None], key=lambda x: x["time"]
    )

    if not sorted_events:
        return False, 0, []

    # Count events in the window
    now = datetime.now(timezone.utc)
    recent_events = []

    for event in sorted_events:
        age_minutes = (now - event["time"]).total_seconds() / 60
        if age_minutes <= window_minutes:
            recent_events.append(event)

    event_count = sum(e.get("count", 1) for e in recent_events)
    is_thrashing = event_count >= threshold

    return is_thrashing, event_count, recent_events


def check_hpa_status(hpa: dict) -> dict:
    """Check HPA status and return health info."""
    metadata = hpa.get("metadata", {})
    spec = hpa.get("spec", {})
    status = hpa.get("status", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")

    min_replicas = spec.get("minReplicas", 1)
    max_replicas = spec.get("maxReplicas", 1)
    current_replicas = status.get("currentReplicas", 0)
    desired_replicas = status.get("desiredReplicas", 0)

    issues = []

    # Check if stuck at max (potential capacity issue)
    if current_replicas == max_replicas and desired_replicas >= max_replicas:
        issues.append(
            {
                "type": "at_max",
                "message": f"HPA at maximum replicas ({max_replicas}), may need capacity increase",
            }
        )

    # Check conditions
    conditions = status.get("conditions", [])
    for condition in conditions:
        cond_type = condition.get("type", "")
        cond_status = condition.get("status", "Unknown")
        reason = condition.get("reason", "")
        message = condition.get("message", "")

        if cond_type == "ScalingActive" and cond_status != "True":
            issues.append(
                {
                    "type": "scaling_inactive",
                    "message": f"Scaling not active: {reason} - {message}",
                }
            )

        if cond_type == "AbleToScale" and cond_status != "True":
            issues.append(
                {
                    "type": "unable_to_scale",
                    "message": f"Unable to scale: {reason} - {message}",
                }
            )

    # Check current metrics
    current_metrics = status.get("currentMetrics", [])
    if not current_metrics:
        issues.append({"type": "no_metrics", "message": "No current metrics available"})

    return {
        "name": name,
        "namespace": namespace,
        "min_replicas": min_replicas,
        "max_replicas": max_replicas,
        "current_replicas": current_replicas,
        "desired_replicas": desired_replicas,
        "issues": issues,
    }


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Detect HPA thrashing in Kubernetes clusters"
    )
    parser.add_argument(
        "--namespace",
        "-n",
        help="Namespace to check (default: all namespaces)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show HPAs with thrashing or issues",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed scaling event information",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=30,
        help="Time window in minutes to analyze for thrashing (default: 30)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=4,
        help="Number of scaling events in window to consider thrashing (default: 4)",
    )
    opts = parser.parse_args(args)

    # Validate parameters
    if opts.window < 1:
        output.error("--window must be at least 1 minute")
        return 2

    if opts.threshold < 2:
        output.error("--threshold must be at least 2")
        return 2

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get HPAs
    try:
        hpa_args = ["kubectl", "get", "hpa", "-o", "json"]
        if opts.namespace:
            hpa_args.extend(["-n", opts.namespace])
        else:
            hpa_args.append("--all-namespaces")

        result = context.run(hpa_args)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2

        hpas = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get HPAs: {e}")
        return 2

    if not hpas.get("items"):
        if opts.format == "json":
            print(json.dumps([]))
        else:
            print("No HPAs found")
        output.set_summary("No HPAs found")
        return 0

    # Get events
    try:
        event_args = ["kubectl", "get", "events", "-o", "json"]
        if opts.namespace:
            event_args.extend(["-n", opts.namespace])
        else:
            event_args.append("--all-namespaces")

        result = context.run(event_args)
        if result.returncode != 0:
            events = {"items": []}
        else:
            events = json.loads(result.stdout)
    except Exception:
        events = {"items": []}

    # Analyze HPAs
    results = []
    for hpa in hpas.get("items", []):
        hpa_status = check_hpa_status(hpa)

        # Get scaling events for this HPA
        scaling_events = analyze_hpa_events(
            events, hpa_status["name"], hpa_status["namespace"]
        )

        # Detect thrashing
        is_thrashing, event_count, recent_events = detect_thrashing(
            scaling_events, opts.window, opts.threshold
        )

        if is_thrashing:
            hpa_status["issues"].append(
                {
                    "type": "thrashing",
                    "message": f"Thrashing detected: {event_count} scaling events in {opts.window} minutes",
                }
            )

        hpa_status["scaling_events_count"] = event_count
        hpa_status["is_thrashing"] = is_thrashing
        hpa_status["recent_scaling_events"] = [
            {
                "time": e["time"].isoformat() if e["time"] else None,
                "reason": e["reason"],
                "message": e["message"],
            }
            for e in recent_events
        ]

        results.append(hpa_status)

    has_issues = False

    # Filter results if warn_only
    if opts.warn_only:
        results = [r for r in results if r["issues"] or r["is_thrashing"]]

    if opts.format == "json":
        print(json.dumps(results, indent=2, default=str))
        for r in results:
            if r["issues"] or r["is_thrashing"]:
                has_issues = True
    else:
        # Plain format
        thrashing_count = 0
        issue_count = 0

        for r in results:
            name = r["name"]
            namespace = r["namespace"]
            is_thrashing = r["is_thrashing"]
            issues = r["issues"]

            if is_thrashing:
                thrashing_count += 1
                has_issues = True
            if issues:
                issue_count += 1
                has_issues = True

            # Determine status marker
            if is_thrashing:
                marker = "[!!]"
            elif issues:
                marker = "[!]"
            else:
                marker = "[OK]"

            print(f"{marker} {namespace}/{name}")
            print(
                f"    Replicas: {r['current_replicas']}/{r['desired_replicas']} "
                f"(min: {r['min_replicas']}, max: {r['max_replicas']})"
            )
            print(f"    Scaling events (recent): {r['scaling_events_count']}")

            if is_thrashing:
                print("    THRASHING DETECTED")

            for issue in issues:
                print(f"    WARNING: {issue['message']}")

            if opts.verbose and r["recent_scaling_events"]:
                print("    Recent scaling events:")
                for event in r["recent_scaling_events"][:5]:
                    time_str = event["time"][:19] if event["time"] else "unknown"
                    print(
                        f"      - [{time_str}] {event['reason']}: {event['message'][:60]}"
                    )

            print()

        # Summary
        print(f"Summary: {len(results)} HPAs analyzed")
        if thrashing_count > 0:
            print(f"  Thrashing: {thrashing_count} HPAs")
        if issue_count > 0:
            print(f"  With issues: {issue_count} HPAs")
        if thrashing_count == 0 and issue_count == 0:
            print("  All HPAs healthy")

    output.set_summary(
        f"hpas={len(results)}, thrashing={sum(1 for r in results if r['is_thrashing'])}, "
        f"issues={sum(1 for r in results if r['issues'])}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
