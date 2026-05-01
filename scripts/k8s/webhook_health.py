#!/usr/bin/env python3
# boxctl:
#   category: k8s/security
#   tags: [webhooks, admission, mutating, validating, certificates, kubernetes]
#   requires: [kubectl]
#   privilege: user
#   brief: Monitor Kubernetes admission webhook health and configuration
#   related: [secret_expiry, api_deprecation]

"""
Kubernetes Webhook Health Monitor

Monitors the health of admission webhooks (validating and mutating) in a Kubernetes cluster:
- Webhook configuration validation
- Certificate expiration checks
- Endpoint availability and connectivity
- Failure policy assessment (fail-open vs fail-closed risks)
- Timeout configuration analysis

Admission webhooks can become single points of failure that silently block deployments.
This tool provides visibility into webhook chains and identifies misconfigured or
failing webhooks before they impact production.

Exit codes:
    0 - All webhooks healthy and properly configured
    1 - Webhook issues detected (warnings or failures)
    2 - Usage error or missing dependencies
"""

import argparse
import base64
import json
from collections import defaultdict
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_certificate(cert_data: str, context: Context) -> dict | None:
    """Parse certificate data to extract expiration information."""
    try:
        cert_bytes = base64.b64decode(cert_data)

        result = context.run(
            ["openssl", "x509", "-noout", "-enddate", "-subject"],
            input=cert_bytes.decode("utf-8", errors="replace"),
            timeout=5,
        )

        if result.returncode != 0:
            return None

        output = result.stdout
        expiry_str = None
        subject = None

        for line in output.split("\n"):
            if line.startswith("notAfter="):
                expiry_str = line.replace("notAfter=", "").strip()
            elif line.startswith("subject="):
                subject = line.replace("subject=", "").strip()

        if not expiry_str:
            return None

        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        expiry_date = expiry_date.replace(tzinfo=timezone.utc)

        days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days

        return {
            "expiry_date": expiry_date.isoformat(),
            "days_until_expiry": days_until_expiry,
            "subject": subject,
        }
    except Exception:
        return None


def check_service_endpoint(
    context: Context, namespace: str, service_name: str, port: int
) -> dict:
    """Check if a webhook service endpoint is available."""
    try:
        result = context.run(
            ["kubectl", "get", "service", service_name, "-n", namespace, "-o", "json"]
        )

        if result.returncode != 0:
            return {"available": False, "reason": "Service not found"}

        service = json.loads(result.stdout)

        result = context.run(
            ["kubectl", "get", "endpoints", service_name, "-n", namespace, "-o", "json"]
        )

        if result.returncode != 0:
            return {"available": False, "reason": "Endpoints not found"}

        endpoints = json.loads(result.stdout)
        subsets = endpoints.get("subsets", [])

        if not subsets:
            return {"available": False, "reason": "No endpoint subsets"}

        ready_addresses = sum(
            len(subset.get("addresses", [])) for subset in subsets
        )

        if ready_addresses == 0:
            return {"available": False, "reason": "No ready endpoints"}

        return {
            "available": True,
            "ready_endpoints": ready_addresses,
            "cluster_ip": service.get("spec", {}).get("clusterIP"),
        }

    except Exception:
        return {"available": False, "reason": "Error checking service"}


def analyze_webhook_health(
    context: Context,
    validating_configs: list[dict],
    mutating_configs: list[dict],
    check_endpoints: bool = True,
) -> tuple[list[str], list[str]]:
    """Analyze webhook configurations and return issues and warnings."""
    issues = []
    warnings = []

    all_configs = [("validating", config) for config in (validating_configs or [])] + [
        ("mutating", config) for config in (mutating_configs or [])
    ]

    if not all_configs:
        warnings.append("No admission webhooks found in cluster")
        return issues, warnings

    for webhook_type, config in all_configs:
        config_name = config.get("metadata", {}).get("name", "unknown")
        webhooks = config.get("webhooks", [])

        for webhook in webhooks:
            webhook_name = webhook.get("name", "unknown")
            full_name = f"{webhook_type}/{config_name}/{webhook_name}"

            # Check failure policy
            failure_policy = webhook.get("failurePolicy", "Fail")
            if failure_policy == "Ignore":
                warnings.append(
                    f"{full_name}: Failure policy is 'Ignore' (fail-open) - "
                    "failures will silently allow requests"
                )

            # Check timeout settings
            timeout_seconds = webhook.get("timeoutSeconds", 10)
            if timeout_seconds > 15:
                warnings.append(
                    f"{full_name}: Timeout is {timeout_seconds}s (high latency risk)"
                )
            elif timeout_seconds < 5:
                warnings.append(
                    f"{full_name}: Timeout is {timeout_seconds}s "
                    "(may cause premature failures)"
                )

            # Check side effects
            side_effects = webhook.get("sideEffects", "Unknown")
            if side_effects == "Unknown":
                warnings.append(
                    f"{full_name}: Side effects are 'Unknown' "
                    "(deprecated, should be explicit)"
                )

            # Check client config
            client_config = webhook.get("clientConfig", {})

            # Check CA bundle
            ca_bundle = client_config.get("caBundle")
            if ca_bundle:
                cert_info = parse_certificate(ca_bundle, context)
                if cert_info:
                    days_left = cert_info["days_until_expiry"]
                    if days_left < 0:
                        issues.append(
                            f"{full_name}: Certificate EXPIRED {abs(days_left)} days ago"
                        )
                    elif days_left < 7:
                        issues.append(
                            f"{full_name}: Certificate expires in {days_left} days "
                            "(critical)"
                        )
                    elif days_left < 30:
                        warnings.append(
                            f"{full_name}: Certificate expires in {days_left} days"
                        )

            # Check service endpoint
            service = client_config.get("service")
            if service and check_endpoints:
                namespace = service.get("namespace", "default")
                service_name = service.get("name")
                port = service.get("port", 443)

                if service_name:
                    endpoint_status = check_service_endpoint(
                        context, namespace, service_name, port
                    )

                    if not endpoint_status.get("available"):
                        issues.append(
                            f"{full_name}: Service endpoint unavailable - "
                            f"{endpoint_status.get('reason')}"
                        )
                    elif endpoint_status.get("ready_endpoints", 0) < 2:
                        warnings.append(
                            f"{full_name}: Only "
                            f"{endpoint_status.get('ready_endpoints')} "
                            "endpoint(s) (consider HA)"
                        )

            # Check admission review versions
            admission_review_versions = webhook.get("admissionReviewVersions", [])
            if "v1" not in admission_review_versions:
                warnings.append(
                    f"{full_name}: Does not support AdmissionReview v1 (deprecated)"
                )

            # Check for broad scope
            object_selector = webhook.get("objectSelector")
            namespace_selector = webhook.get("namespaceSelector")

            if not object_selector and not namespace_selector:
                rules = webhook.get("rules", [])
                if rules:
                    for rule in rules:
                        operations = rule.get("operations", [])
                        resources = rule.get("resources", [])

                        if "*" in operations or "*" in resources:
                            warnings.append(
                                f"{full_name}: Very broad scope "
                                "(all operations/resources) with no selectors - "
                                "may impact cluster performance"
                            )
                            break

    return issues, warnings


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes admission webhook health"
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
        "--no-endpoint-check",
        action="store_true",
        help="Skip service endpoint connectivity checks (faster but less thorough)",
    )

    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get validating webhook configurations
    result = context.run(
        ["kubectl", "get", "validatingwebhookconfigurations", "-o", "json"]
    )
    validating_configs = []
    if result.returncode == 0:
        try:
            validating_configs = json.loads(result.stdout).get("items", [])
        except json.JSONDecodeError:
            pass

    # Get mutating webhook configurations
    result = context.run(
        ["kubectl", "get", "mutatingwebhookconfigurations", "-o", "json"]
    )
    mutating_configs = []
    if result.returncode == 0:
        try:
            mutating_configs = json.loads(result.stdout).get("items", [])
        except json.JSONDecodeError:
            pass

    # Analyze health
    issues, warnings = analyze_webhook_health(
        context,
        validating_configs,
        mutating_configs,
        check_endpoints=not opts.no_endpoint_check,
    )

    # Format output
    if opts.format == "json":
        webhook_summary = []

        all_configs = [
            ("validating", config) for config in validating_configs
        ] + [("mutating", config) for config in mutating_configs]

        for webhook_type, config in all_configs:
            config_name = config.get("metadata", {}).get("name", "unknown")
            webhooks = config.get("webhooks", [])

            for webhook in webhooks:
                webhook_info = {
                    "type": webhook_type,
                    "config_name": config_name,
                    "name": webhook.get("name", "unknown"),
                    "failure_policy": webhook.get("failurePolicy", "Fail"),
                    "timeout_seconds": webhook.get("timeoutSeconds", 10),
                    "side_effects": webhook.get("sideEffects", "Unknown"),
                    "admission_review_versions": webhook.get(
                        "admissionReviewVersions", []
                    ),
                }

                client_config = webhook.get("clientConfig", {})
                ca_bundle = client_config.get("caBundle")
                if ca_bundle:
                    cert_info = parse_certificate(ca_bundle, context)
                    if cert_info:
                        webhook_info["certificate"] = {
                            "days_until_expiry": cert_info["days_until_expiry"],
                            "expiry_date": cert_info["expiry_date"],
                        }

                webhook_summary.append(webhook_info)

        output_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_webhooks": len(webhook_summary),
                "validating_configs": len(validating_configs),
                "mutating_configs": len(mutating_configs),
            },
            "webhooks": webhook_summary,
            "issues": issues,
            "warnings": warnings,
            "healthy": len(issues) == 0,
        }
        print(json.dumps(output_data, indent=2))

    elif opts.format == "table":
        lines = []
        lines.append("+" + "-" * 98 + "+")
        lines.append("| Kubernetes Webhook Health Check" + " " * 66 + "|")
        lines.append("+" + "-" * 98 + "+")

        all_configs = [
            ("Validating", config) for config in validating_configs
        ] + [("Mutating", config) for config in mutating_configs]

        if all_configs:
            lines.append(
                f"| {'Type':<12} | {'Config/Name':<40} | {'Policy':<10} | "
                f"{'Timeout':<8} | {'Status':<10} |"
            )
            lines.append("+" + "-" * 98 + "+")

            for webhook_type, config in all_configs:
                config_name = config.get("metadata", {}).get("name", "unknown")
                webhooks = config.get("webhooks", [])

                for webhook in webhooks:
                    webhook_name = webhook.get("name", "unknown")
                    full_name = f"{config_name}/{webhook_name}"[:40]
                    failure_policy = webhook.get("failurePolicy", "Fail")[:10]
                    timeout = f"{webhook.get('timeoutSeconds', 10)}s"

                    status = "OK"
                    for issue in issues:
                        if full_name in issue:
                            status = "ERROR"
                            break
                    if status == "OK":
                        for warning in warnings:
                            if full_name in warning:
                                status = "WARNING"
                                break

                    lines.append(
                        f"| {webhook_type:<12} | {full_name:<40} | "
                        f"{failure_policy:<10} | {timeout:<8} | {status:<10} |"
                    )

            lines.append("+" + "-" * 98 + "+")

        if issues or warnings:
            lines.append("| Issues & Warnings" + " " * 80 + "|")
            lines.append("+" + "-" * 98 + "+")

            for issue in issues:
                issue_text = f"ERROR: {issue}"[:96]
                lines.append(f"| {issue_text:<96} |")

            for warning in warnings:
                warning_text = f"WARN: {warning}"[:96]
                lines.append(f"| {warning_text:<96} |")

            lines.append("+" + "-" * 98 + "+")
        else:
            lines.append("| Status: All checks passed" + " " * 71 + "|")
            lines.append("+" + "-" * 98 + "+")

        if not opts.warn_only or issues or warnings:
            print("\n".join(lines))

    else:  # plain
        lines = []
        lines.append("Kubernetes Webhook Health Check")
        lines.append("=" * 60)
        lines.append("")

        lines.append("Webhook Summary:")
        lines.append(f"  Validating webhook configurations: {len(validating_configs)}")
        lines.append(f"  Mutating webhook configurations: {len(mutating_configs)}")
        lines.append("")

        all_configs = [
            ("Validating", config) for config in validating_configs
        ] + [("Mutating", config) for config in mutating_configs]

        if all_configs:
            lines.append("Configured Webhooks:")
            for webhook_type, config in all_configs:
                config_name = config.get("metadata", {}).get("name", "unknown")
                webhooks = config.get("webhooks", [])

                for webhook in webhooks:
                    webhook_name = webhook.get("name", "unknown")
                    failure_policy = webhook.get("failurePolicy", "Fail")
                    timeout = webhook.get("timeoutSeconds", 10)

                    lines.append(f"  [{webhook_type}] {config_name}/{webhook_name}")
                    lines.append(f"    Policy: {failure_policy}, Timeout: {timeout}s")
            lines.append("")

        if issues:
            lines.append("ISSUES:")
            for issue in issues:
                lines.append(f"  [X] {issue}")
            lines.append("")

        if warnings:
            lines.append("WARNINGS:")
            for warning in warnings:
                lines.append(f"  [!] {warning}")
            lines.append("")

        if not issues and not warnings:
            lines.append("[OK] All webhook health checks passed")

        if not opts.warn_only or issues or warnings:
            print("\n".join(lines))

    output.set_summary(f"issues={len(issues)}, warnings={len(warnings)}")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
