#!/usr/bin/env python3
# boxctl:
#   category: k8s/cluster
#   tags: [latency, kubernetes, api, performance, monitoring]
#   requires: [kubectl]
#   privilege: user
#   brief: Measure and analyze Kubernetes API server response times
#   related: [control_plane, node_capacity]

"""
Kubernetes API Server Latency Analyzer - Measure API response times.

Measures and analyzes Kubernetes API server response times to detect
performance degradation before it causes cluster issues.

Performs a series of kubectl operations and measures their response times:
- Early detection of control plane performance issues
- Identifying slow API operations (LIST, GET, WATCH)
- Correlating cluster slowness with API latency
- Baseline performance monitoring

Exit codes:
    0 - API latency is healthy (all operations under threshold)
    1 - API latency issues detected (operations exceeding threshold)
    2 - Usage error or kubectl not available
"""

import argparse
import json
import time
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def measure_api_call(context: Context, cmd: list[str], timeout: int = 30) -> tuple:
    """
    Execute a kubectl command and measure response time.

    Returns:
        Tuple of (success, latency_ms, error_message)
    """
    start_time = time.perf_counter()
    try:
        result = context.run(["kubectl"] + cmd)
        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        if result.returncode == 0:
            return True, latency_ms, None
        else:
            return False, latency_ms, result.stderr.strip()
    except Exception as e:
        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000
        return False, latency_ms, str(e)


def run_latency_tests(
    context: Context, namespace: str | None = None, samples: int = 3
) -> list:
    """
    Run a series of API latency tests.

    Returns:
        List of test results with operation details and latencies
    """
    tests = []

    # Test 1: List namespaces (cluster-wide, lightweight)
    tests.append(
        {
            "operation": "LIST namespaces",
            "verb": "list",
            "resource": "namespaces",
            "args": ["get", "namespaces", "-o", "json"],
            "description": "List all namespaces",
        }
    )

    # Test 2: List nodes (cluster-wide, includes status)
    tests.append(
        {
            "operation": "LIST nodes",
            "verb": "list",
            "resource": "nodes",
            "args": ["get", "nodes", "-o", "json"],
            "description": "List all nodes with status",
        }
    )

    # Test 3: List pods (potentially large, tests pagination)
    pod_args = ["get", "pods", "-o", "json"]
    if namespace:
        pod_args.extend(["-n", namespace])
    else:
        pod_args.append("--all-namespaces")
    tests.append(
        {
            "operation": "LIST pods",
            "verb": "list",
            "resource": "pods",
            "args": pod_args,
            "description": "List pods (all or namespace-scoped)",
        }
    )

    # Test 4: Get cluster info (lightweight, tests connectivity)
    tests.append(
        {
            "operation": "GET cluster-info",
            "verb": "get",
            "resource": "cluster-info",
            "args": ["cluster-info"],
            "description": "Get cluster endpoint info",
        }
    )

    # Test 5: List events (often large, time-series data)
    event_args = ["get", "events", "-o", "json"]
    if namespace:
        event_args.extend(["-n", namespace])
    else:
        event_args.append("--all-namespaces")
    tests.append(
        {
            "operation": "LIST events",
            "verb": "list",
            "resource": "events",
            "args": event_args,
            "description": "List cluster events",
        }
    )

    # Test 6: API resources discovery
    tests.append(
        {
            "operation": "GET api-resources",
            "verb": "get",
            "resource": "api-resources",
            "args": ["api-resources", "--no-headers"],
            "description": "Discover available API resources",
        }
    )

    results = []

    for test in tests:
        latencies = []
        errors = []

        for _ in range(samples):
            success, latency_ms, error = measure_api_call(context, test["args"])
            if success:
                latencies.append(latency_ms)
            else:
                errors.append(error)

        if latencies:
            avg_latency = sum(latencies) / len(latencies)
            min_latency = min(latencies)
            max_latency = max(latencies)
        else:
            avg_latency = min_latency = max_latency = 0

        results.append(
            {
                "operation": test["operation"],
                "verb": test["verb"],
                "resource": test["resource"],
                "description": test["description"],
                "samples": samples,
                "successful_samples": len(latencies),
                "avg_latency_ms": round(avg_latency, 2),
                "min_latency_ms": round(min_latency, 2),
                "max_latency_ms": round(max_latency, 2),
                "errors": errors if errors else None,
            }
        )

    return results


def analyze_latency(
    results: list, warn_threshold_ms: int = 500, critical_threshold_ms: int = 2000
) -> tuple[list, list]:
    """
    Analyze latency results and identify issues.

    Returns:
        Tuple of (issues, warnings)
    """
    issues = []
    warnings = []

    for result in results:
        operation = result["operation"]
        avg_latency = result["avg_latency_ms"]
        max_latency = result["max_latency_ms"]
        errors = result["errors"]

        # Check for complete failures
        if result["successful_samples"] == 0:
            error_msg = errors[0] if errors else "Unknown error"
            issues.append(f"{operation}: All requests failed - {error_msg}")
            continue

        # Check for partial failures
        if result["successful_samples"] < result["samples"]:
            warnings.append(
                f"{operation}: {result['samples'] - result['successful_samples']}/{result['samples']} requests failed"
            )

        # Check for critical latency
        if avg_latency > critical_threshold_ms:
            issues.append(
                f"{operation}: Average latency {avg_latency:.0f}ms exceeds critical threshold ({critical_threshold_ms}ms)"
            )
        elif max_latency > critical_threshold_ms:
            issues.append(
                f"{operation}: Max latency {max_latency:.0f}ms exceeds critical threshold ({critical_threshold_ms}ms)"
            )
        # Check for warning-level latency
        elif avg_latency > warn_threshold_ms:
            warnings.append(
                f"{operation}: Average latency {avg_latency:.0f}ms exceeds warning threshold ({warn_threshold_ms}ms)"
            )
        elif max_latency > warn_threshold_ms:
            warnings.append(
                f"{operation}: Max latency {max_latency:.0f}ms exceeds warning threshold ({warn_threshold_ms}ms)"
            )

    return issues, warnings


def format_plain(
    results: list, issues: list, warnings: list, warn_only: bool = False
) -> str:
    """Format output as plain text."""
    lines = []

    if not warn_only:
        lines.append("Kubernetes API Latency Analysis")
        lines.append("=" * 60)
        lines.append("")
        lines.append(
            f"{'Operation':<25} {'Avg (ms)':<12} {'Min (ms)':<12} {'Max (ms)':<12}"
        )
        lines.append("-" * 60)

        for result in results:
            status = ""
            if result["successful_samples"] == 0:
                status = " [FAIL]"
            elif result["avg_latency_ms"] > 2000:
                status = " [CRITICAL]"
            elif result["avg_latency_ms"] > 500:
                status = " [SLOW]"

            lines.append(
                f"{result['operation']:<25} "
                f"{result['avg_latency_ms']:<12.1f} "
                f"{result['min_latency_ms']:<12.1f} "
                f"{result['max_latency_ms']:<12.1f}"
                f"{status}"
            )

        lines.append("")

    if issues:
        lines.append("ISSUES:")
        for issue in issues:
            lines.append(f"  [!] {issue}")
        lines.append("")

    if warnings:
        lines.append("WARNINGS:")
        for warning in warnings:
            lines.append(f"  [*] {warning}")
        lines.append("")

    if not issues and not warnings:
        if not warn_only:
            lines.append("All API operations within acceptable latency thresholds.")

    return "\n".join(lines)


def format_json(results: list, issues: list, warnings: list) -> str:
    """Format output as JSON."""
    # Calculate overall statistics
    successful_results = [r for r in results if r["successful_samples"] > 0]

    if successful_results:
        overall_avg = sum(r["avg_latency_ms"] for r in successful_results) / len(
            successful_results
        )
        overall_max = max(r["max_latency_ms"] for r in successful_results)
    else:
        overall_avg = overall_max = 0

    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_operations": len(results),
            "successful_operations": len(successful_results),
            "overall_avg_latency_ms": round(overall_avg, 2),
            "overall_max_latency_ms": round(overall_max, 2),
            "issue_count": len(issues),
            "warning_count": len(warnings),
            "healthy": len(issues) == 0,
        },
        "operations": results,
        "issues": issues,
        "warnings": warnings,
    }

    return json.dumps(output, indent=2)


def format_table(
    results: list, issues: list, warnings: list, warn_only: bool = False
) -> str:
    """Format output as ASCII table."""
    lines = []

    if not warn_only:
        # Header
        lines.append("+" + "-" * 78 + "+")
        lines.append("| Kubernetes API Latency Analysis" + " " * 45 + "|")
        lines.append("+" + "-" * 78 + "+")
        lines.append(
            f"| {'Operation':<24} | {'Avg (ms)':<10} | {'Min (ms)':<10} | {'Max (ms)':<10} | {'Status':<10} |"
        )
        lines.append("+" + "-" * 78 + "+")

        for result in results:
            if result["successful_samples"] == 0:
                status = "FAIL"
            elif result["avg_latency_ms"] > 2000:
                status = "CRITICAL"
            elif result["avg_latency_ms"] > 500:
                status = "SLOW"
            else:
                status = "OK"

            lines.append(
                f"| {result['operation']:<24} "
                f"| {result['avg_latency_ms']:<10.1f} "
                f"| {result['min_latency_ms']:<10.1f} "
                f"| {result['max_latency_ms']:<10.1f} "
                f"| {status:<10} |"
            )

        lines.append("+" + "-" * 78 + "+")

    # Issues and warnings
    if issues or warnings:
        if not warn_only:
            lines.append("| Issues & Warnings" + " " * 60 + "|")
            lines.append("+" + "-" * 78 + "+")

        for issue in issues:
            issue_text = f"ISSUE: {issue}"[:76]
            lines.append(f"| {issue_text:<76} |")

        for warning in warnings:
            warn_text = f"WARN: {warning}"[:76]
            lines.append(f"| {warn_text:<76} |")

        lines.append("+" + "-" * 78 + "+")
    elif not warn_only:
        lines.append("| Status: All API operations healthy" + " " * 42 + "|")
        lines.append("+" + "-" * 78 + "+")

    return "\n".join(lines)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = latency issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes API server latency"
    )
    parser.add_argument(
        "-n",
        "--namespace",
        help="Namespace for scoped operations (default: all namespaces)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show output if issues or warnings are detected",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=3,
        help="Number of samples per operation (default: 3)",
    )
    parser.add_argument(
        "--warn-threshold",
        type=int,
        default=500,
        metavar="MS",
        help="Warning latency threshold in ms (default: 500)",
    )
    parser.add_argument(
        "--critical-threshold",
        type=int,
        default=2000,
        metavar="MS",
        help="Critical latency threshold in ms (default: 2000)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information about each test",
    )
    opts = parser.parse_args(args)

    # Validate arguments
    if opts.samples < 1:
        output.error("--samples must be at least 1")
        return 2

    if opts.warn_threshold >= opts.critical_threshold:
        output.error("--warn-threshold must be less than --critical-threshold")
        return 2

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Run latency tests
    results = run_latency_tests(context, opts.namespace, opts.samples)

    # Analyze results
    issues, warnings = analyze_latency(
        results,
        warn_threshold_ms=opts.warn_threshold,
        critical_threshold_ms=opts.critical_threshold,
    )

    # Format output
    if opts.format == "json":
        result = format_json(results, issues, warnings)
    elif opts.format == "table":
        result = format_table(results, issues, warnings, opts.warn_only)
    else:
        result = format_plain(results, issues, warnings, opts.warn_only)

    # Print output (respecting --warn-only)
    if not opts.warn_only or issues or warnings:
        print(result)

    output.set_summary(f"issues={len(issues)}, warnings={len(warnings)}")

    # Return appropriate exit code
    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
