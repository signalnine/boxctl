#!/usr/bin/env python3
# boxctl:
#   category: k8s/storage
#   tags: [configmap, secret, kubernetes, etcd, size, capacity]
#   requires: [kubectl]
#   privilege: user
#   brief: Analyze ConfigMap and Secret sizes for etcd health
#   related: [control_plane, etcd_health]

"""
ConfigMap and Secret Size Analyzer - Find oversized objects in Kubernetes.

Identifies oversized ConfigMaps and Secrets that can cause:
- etcd performance degradation (etcd stores all objects)
- API server slowdowns during large object transfers
- Memory pressure on kubelet when mounting large volumes
- Hitting the 1MB Kubernetes object size limit

Useful for operators managing large-scale clusters where etcd health is critical.

Exit codes:
    0 - No oversized objects found
    1 - Oversized objects detected (above warning threshold)
    2 - Usage error or kubectl not available
"""

import argparse
import base64
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


# Default thresholds in bytes
DEFAULT_WARN_THRESHOLD = 100 * 1024  # 100KB - consider optimizing
DEFAULT_CRIT_THRESHOLD = 500 * 1024  # 500KB - likely problematic
KUBERNETES_LIMIT = 1024 * 1024  # 1MB - hard limit


def get_configmaps(context: Context, namespace: str | None = None) -> dict:
    """Get all ConfigMaps in JSON format."""
    cmd = ["kubectl", "get", "configmaps", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    if result.returncode != 0:
        return {"items": []}
    return json.loads(result.stdout)


def get_secrets(context: Context, namespace: str | None = None) -> dict:
    """Get all Secrets in JSON format."""
    cmd = ["kubectl", "get", "secrets", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    if result.returncode != 0:
        return {"items": []}
    return json.loads(result.stdout)


def calculate_configmap_size(configmap: dict) -> int:
    """Calculate the total size of a ConfigMap's data."""
    total_size = 0
    data = configmap.get("data", {})
    binary_data = configmap.get("binaryData", {})

    # Regular data (stored as strings)
    for key, value in data.items():
        if value:
            total_size += len(key.encode("utf-8"))
            total_size += len(value.encode("utf-8"))

    # Binary data (stored as base64)
    for key, value in binary_data.items():
        if value:
            total_size += len(key.encode("utf-8"))
            # Decode base64 to get actual size
            try:
                decoded = base64.b64decode(value)
                total_size += len(decoded)
            except Exception:
                total_size += len(value)

    return total_size


def calculate_secret_size(secret: dict) -> int:
    """Calculate the total size of a Secret's data."""
    total_size = 0
    data = secret.get("data", {})
    string_data = secret.get("stringData", {})

    # Secret data is base64 encoded
    for key, value in data.items():
        if value:
            total_size += len(key.encode("utf-8"))
            try:
                decoded = base64.b64decode(value)
                total_size += len(decoded)
            except Exception:
                total_size += len(value)

    # String data (not encoded)
    for key, value in string_data.items():
        if value:
            total_size += len(key.encode("utf-8"))
            total_size += len(value.encode("utf-8"))

    return total_size


def get_key_sizes(obj: dict, is_secret: bool = False) -> list:
    """Get individual key sizes for detailed analysis."""
    key_sizes = []

    if is_secret:
        data = obj.get("data", {})
        for key, value in data.items():
            if value:
                try:
                    decoded = base64.b64decode(value)
                    size = len(decoded)
                except Exception:
                    size = len(value)
                key_sizes.append((key, size))

        string_data = obj.get("stringData", {})
        for key, value in string_data.items():
            if value:
                key_sizes.append((key, len(value.encode("utf-8"))))
    else:
        data = obj.get("data", {})
        for key, value in data.items():
            if value:
                key_sizes.append((key, len(value.encode("utf-8"))))

        binary_data = obj.get("binaryData", {})
        for key, value in binary_data.items():
            if value:
                try:
                    decoded = base64.b64decode(value)
                    size = len(decoded)
                except Exception:
                    size = len(value)
                key_sizes.append((key, size))

    return sorted(key_sizes, key=lambda x: x[1], reverse=True)


def format_size(size_bytes: int) -> str:
    """Format byte size in human-readable format."""
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f}MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f}KB"
    else:
        return f"{size_bytes}B"


def get_severity(size: int, warn_threshold: int, crit_threshold: int) -> str:
    """Determine severity based on size thresholds."""
    if size >= crit_threshold:
        return "critical"
    elif size >= warn_threshold:
        return "warning"
    return "ok"


def parse_size(size_str: str) -> int:
    """Parse size string like '100KB' or '1MB' into bytes."""
    size_str = size_str.strip().upper()
    if size_str.endswith("MB"):
        return int(float(size_str[:-2]) * 1024 * 1024)
    elif size_str.endswith("KB"):
        return int(float(size_str[:-2]) * 1024)
    elif size_str.endswith("B"):
        return int(size_str[:-1])
    else:
        return int(size_str)


def analyze_objects(
    configmaps_data: dict,
    secrets_data: dict,
    warn_threshold: int,
    crit_threshold: int,
    warn_only: bool,
    verbose: bool,
    skip_system: bool,
) -> list:
    """Analyze all ConfigMaps and Secrets for size issues."""
    results = []

    # Analyze ConfigMaps
    for cm in configmaps_data.get("items", []):
        namespace = cm["metadata"].get("namespace", "default")
        name = cm["metadata"]["name"]

        # Skip system namespaces if requested
        if skip_system and namespace.startswith("kube-"):
            continue

        size = calculate_configmap_size(cm)
        severity = get_severity(size, warn_threshold, crit_threshold)

        if warn_only and severity == "ok":
            continue

        entry = {
            "type": "ConfigMap",
            "namespace": namespace,
            "name": name,
            "size": size,
            "size_formatted": format_size(size),
            "severity": severity,
            "key_count": len(cm.get("data", {})) + len(cm.get("binaryData", {})),
        }

        if verbose and severity != "ok":
            entry["keys"] = get_key_sizes(cm, is_secret=False)[:5]  # Top 5 largest keys

        results.append(entry)

    # Analyze Secrets
    for secret in secrets_data.get("items", []):
        namespace = secret["metadata"].get("namespace", "default")
        name = secret["metadata"]["name"]
        secret_type = secret.get("type", "Opaque")

        # Skip system namespaces if requested
        if skip_system and namespace.startswith("kube-"):
            continue

        # Skip service account tokens (managed by K8s)
        if secret_type == "kubernetes.io/service-account-token":
            continue

        size = calculate_secret_size(secret)
        severity = get_severity(size, warn_threshold, crit_threshold)

        if warn_only and severity == "ok":
            continue

        entry = {
            "type": "Secret",
            "namespace": namespace,
            "name": name,
            "size": size,
            "size_formatted": format_size(size),
            "severity": severity,
            "secret_type": secret_type,
            "key_count": len(secret.get("data", {})) + len(secret.get("stringData", {})),
        }

        if verbose and severity != "ok":
            # Only show key names, not values for secrets
            key_sizes = get_key_sizes(secret, is_secret=True)[:5]
            entry["keys"] = key_sizes

        results.append(entry)

    # Sort by size descending
    results.sort(key=lambda x: x["size"], reverse=True)
    return results


def format_plain(
    results: list, warn_threshold: int, crit_threshold: int, verbose: bool
) -> str:
    """Print results in plain text format."""
    lines = []

    if not results:
        lines.append("No ConfigMaps or Secrets found matching criteria.")
        return "\n".join(lines)

    # Print header
    lines.append("ConfigMap/Secret Size Analysis")
    lines.append(f"Warning threshold: {format_size(warn_threshold)}")
    lines.append(f"Critical threshold: {format_size(crit_threshold)}")
    lines.append(f"Kubernetes limit: {format_size(KUBERNETES_LIMIT)}")
    lines.append("=" * 70)
    lines.append("")

    # Group by severity
    critical = [r for r in results if r["severity"] == "critical"]
    warning = [r for r in results if r["severity"] == "warning"]
    ok = [r for r in results if r["severity"] == "ok"]

    if critical:
        lines.append("CRITICAL (consider immediate optimization):")
        lines.append("-" * 50)
        for item in critical:
            marker = "!!"
            lines.append(f"{marker} {item['type']}: {item['namespace']}/{item['name']}")
            lines.append(f"   Size: {item['size_formatted']} ({item['key_count']} keys)")
            if verbose and "keys" in item:
                lines.append("   Largest keys:")
                for key, size in item["keys"]:
                    lines.append(f"     - {key}: {format_size(size)}")
            lines.append("")

    if warning:
        lines.append("WARNING (should be optimized):")
        lines.append("-" * 50)
        for item in warning:
            marker = "!"
            lines.append(f"{marker}  {item['type']}: {item['namespace']}/{item['name']}")
            lines.append(f"   Size: {item['size_formatted']} ({item['key_count']} keys)")
            if verbose and "keys" in item:
                lines.append("   Largest keys:")
                for key, size in item["keys"]:
                    lines.append(f"     - {key}: {format_size(size)}")
            lines.append("")

    if ok:
        lines.append(f"OK ({len(ok)} objects below warning threshold)")
        if verbose:
            for item in ok[:10]:  # Show top 10 even if OK
                lines.append(
                    f"   {item['type']}: {item['namespace']}/{item['name']} - {item['size_formatted']}"
                )
            if len(ok) > 10:
                lines.append(f"   ... and {len(ok) - 10} more")
        lines.append("")

    # Summary
    lines.append("=" * 70)
    lines.append(f"Summary: {len(critical)} critical, {len(warning)} warning, {len(ok)} ok")

    total_size = sum(r["size"] for r in results)
    lines.append(f"Total size analyzed: {format_size(total_size)}")

    return "\n".join(lines)


def format_json(results: list, warn_threshold: int, crit_threshold: int) -> str:
    """Print results in JSON format."""
    output = {
        "thresholds": {
            "warning_bytes": warn_threshold,
            "critical_bytes": crit_threshold,
            "kubernetes_limit_bytes": KUBERNETES_LIMIT,
        },
        "summary": {
            "total_objects": len(results),
            "critical_count": len([r for r in results if r["severity"] == "critical"]),
            "warning_count": len([r for r in results if r["severity"] == "warning"]),
            "ok_count": len([r for r in results if r["severity"] == "ok"]),
            "total_size_bytes": sum(r["size"] for r in results),
        },
        "objects": results,
    }
    return json.dumps(output, indent=2)


def format_table(results: list) -> str:
    """Print results in table format."""
    lines = []

    if not results:
        lines.append("No ConfigMaps or Secrets found matching criteria.")
        return "\n".join(lines)

    # Header
    lines.append(
        f"{'TYPE':<10} {'NAMESPACE':<20} {'NAME':<30} {'SIZE':>10} {'KEYS':>5} {'STATUS':<10}"
    )
    lines.append("-" * 90)

    for item in results:
        type_str = item["type"][:10]
        ns = item["namespace"][:20]
        name = item["name"][:30]
        size = item["size_formatted"]
        keys = str(item["key_count"])
        status = item["severity"].upper()

        lines.append(f"{type_str:<10} {ns:<20} {name:<30} {size:>10} {keys:>5} {status:<10}")

    # Summary line
    lines.append("-" * 90)
    total = len(results)
    crit = len([r for r in results if r["severity"] == "critical"])
    warn = len([r for r in results if r["severity"] == "warning"])
    lines.append(f"Total: {total} objects ({crit} critical, {warn} warning)")

    return "\n".join(lines)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = oversized objects found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze ConfigMap and Secret sizes in Kubernetes clusters"
    )
    parser.add_argument(
        "--namespace",
        "-n",
        help="Namespace to analyze (default: all namespaces)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show objects above warning threshold",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed information including largest keys",
    )
    parser.add_argument(
        "--warn-threshold",
        default="100KB",
        help="Warning threshold (default: 100KB). Examples: 50KB, 200KB, 1MB",
    )
    parser.add_argument(
        "--crit-threshold",
        default="500KB",
        help="Critical threshold (default: 500KB). Examples: 200KB, 500KB, 900KB",
    )
    parser.add_argument(
        "--skip-system",
        action="store_true",
        help="Skip kube-* system namespaces",
    )
    parser.add_argument(
        "--configmaps-only",
        action="store_true",
        help="Only analyze ConfigMaps",
    )
    parser.add_argument(
        "--secrets-only",
        action="store_true",
        help="Only analyze Secrets",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Parse thresholds
    try:
        warn_threshold = parse_size(opts.warn_threshold)
        crit_threshold = parse_size(opts.crit_threshold)
    except ValueError as e:
        output.error(f"Error parsing threshold: {e}")
        return 2

    if warn_threshold >= crit_threshold:
        output.error("Warning threshold must be less than critical threshold")
        return 2

    # Get data
    configmaps_data = {"items": []}
    secrets_data = {"items": []}

    if not opts.secrets_only:
        configmaps_data = get_configmaps(context, opts.namespace)

    if not opts.configmaps_only:
        secrets_data = get_secrets(context, opts.namespace)

    # Analyze
    results = analyze_objects(
        configmaps_data,
        secrets_data,
        warn_threshold,
        crit_threshold,
        opts.warn_only,
        opts.verbose,
        opts.skip_system,
    )

    # Output
    if opts.format == "json":
        result = format_json(results, warn_threshold, crit_threshold)
    elif opts.format == "table":
        result = format_table(results)
    else:
        result = format_plain(results, warn_threshold, crit_threshold, opts.verbose)

    print(result)

    # Summary
    critical_count = len([r for r in results if r["severity"] == "critical"])
    warning_count = len([r for r in results if r["severity"] == "warning"])
    output.set_summary(
        f"objects={len(results)}, critical={critical_count}, warning={warning_count}"
    )

    # Exit code based on findings
    has_issues = any(r["severity"] in ("warning", "critical") for r in results)
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
