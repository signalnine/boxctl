#!/usr/bin/env python3
# boxctl:
#   category: k8s/security
#   tags: [secrets, tls, certificates, expiry, security, kubernetes]
#   requires: [kubectl]
#   privilege: user
#   brief: Monitor Kubernetes Secret age and TLS certificate expiration
#   related: [configmap_audit, webhook_health]

"""
Monitor Kubernetes Secret age and TLS certificate expiration.

Analyzes Kubernetes secrets for:
- TLS certificate expiration dates (kubernetes.io/tls secrets)
- Stale secrets that haven't been updated in a long time
- Secrets approaching expiration thresholds

Critical for large-scale environments where expired certificates
cause unexpected outages and stale secrets create security risks.

Exit codes:
    0 - All secrets healthy
    1 - Expiring/expired secrets or issues detected
    2 - Usage error or kubectl not available
"""

import argparse
import base64
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_timestamp(ts_str: str | None) -> datetime | None:
    """Parse Kubernetes timestamp to datetime object."""
    if not ts_str:
        return None
    try:
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str)
    except (ValueError, AttributeError):
        return None


def parse_x509_certificate(cert_pem: str, context: Context) -> dict | None:
    """Parse X.509 certificate and extract expiration info.

    Uses openssl to parse the certificate since we want to avoid
    external Python dependencies.
    """
    try:
        result = context.run(
            ["openssl", "x509", "-noout", "-dates", "-subject"],
            input=cert_pem,
            timeout=5,
        )

        if result.returncode != 0:
            return None

        output = result.stdout
        cert_info = {}

        for line in output.split("\n"):
            line = line.strip()
            if line.startswith("notBefore="):
                date_str = line.replace("notBefore=", "")
                try:
                    cert_info["not_before"] = datetime.strptime(
                        date_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
            elif line.startswith("notAfter="):
                date_str = line.replace("notAfter=", "")
                try:
                    cert_info["not_after"] = datetime.strptime(
                        date_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
            elif line.startswith("subject="):
                cert_info["subject"] = line.replace("subject=", "").strip()

        return cert_info if cert_info else None

    except Exception:
        return None


def analyze_secret(
    secret: dict,
    context: Context,
    expiry_warn_days: int = 30,
    expiry_critical_days: int = 7,
    stale_days: int = 365,
) -> dict:
    """Analyze a single secret for issues."""
    metadata = secret.get("metadata", {})
    secret_type = secret.get("type", "Opaque")
    data = secret.get("data", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")

    creation_time = parse_timestamp(metadata.get("creationTimestamp"))
    now = datetime.now(timezone.utc)
    age_days = None
    if creation_time:
        age_days = (now - creation_time).total_seconds() / 86400

    result = {
        "name": name,
        "namespace": namespace,
        "type": secret_type,
        "creation_time": creation_time.isoformat() if creation_time else None,
        "age_days": round(age_days, 1) if age_days else None,
        "has_issue": False,
        "severity": "ok",
        "issues": [],
        "cert_info": None,
    }

    # Skip service account tokens (auto-managed)
    if secret_type == "kubernetes.io/service-account-token":
        result["skipped"] = True
        result["skip_reason"] = "Service account token (auto-managed)"
        return result

    # Check for stale secrets
    if age_days and age_days > stale_days:
        result["issues"].append(
            f"Secret is {int(age_days)} days old (stale threshold: {stale_days} days)"
        )
        result["has_issue"] = True
        if result["severity"] == "ok":
            result["severity"] = "warning"

    # For TLS secrets, check certificate expiration
    if secret_type == "kubernetes.io/tls":
        tls_crt = data.get("tls.crt")
        if tls_crt:
            try:
                cert_pem = base64.b64decode(tls_crt).decode("utf-8")
                cert_info = parse_x509_certificate(cert_pem, context)

                if cert_info:
                    result["cert_info"] = {
                        "subject": cert_info.get("subject"),
                        "not_before": (
                            cert_info.get("not_before").isoformat()
                            if cert_info.get("not_before")
                            else None
                        ),
                        "not_after": (
                            cert_info.get("not_after").isoformat()
                            if cert_info.get("not_after")
                            else None
                        ),
                    }

                    not_after = cert_info.get("not_after")
                    if not_after:
                        days_until_expiry = (not_after - now).total_seconds() / 86400
                        result["cert_info"]["days_until_expiry"] = round(
                            days_until_expiry, 1
                        )

                        if days_until_expiry < 0:
                            result["issues"].append(
                                f"Certificate EXPIRED {abs(int(days_until_expiry))} days ago"
                            )
                            result["has_issue"] = True
                            result["severity"] = "critical"
                        elif days_until_expiry < expiry_critical_days:
                            result["issues"].append(
                                f"Certificate expires in {int(days_until_expiry)} days (CRITICAL)"
                            )
                            result["has_issue"] = True
                            result["severity"] = "critical"
                        elif days_until_expiry < expiry_warn_days:
                            result["issues"].append(
                                f"Certificate expires in {int(days_until_expiry)} days (warning)"
                            )
                            result["has_issue"] = True
                            if result["severity"] != "critical":
                                result["severity"] = "warning"
                else:
                    result["issues"].append("Could not parse TLS certificate")
                    result["has_issue"] = True
                    result["severity"] = "warning"

            except (base64.binascii.Error, UnicodeDecodeError):
                result["issues"].append("Invalid base64 in tls.crt")
                result["has_issue"] = True
                result["severity"] = "warning"
        else:
            result["issues"].append("TLS secret missing tls.crt")
            result["has_issue"] = True
            result["severity"] = "warning"

    return result


def format_age(days: float | None) -> str:
    """Format age in days to human-readable string."""
    if days is None:
        return "N/A"

    if days < 1:
        return f"{int(days * 24)}h"
    elif days < 30:
        return f"{int(days)}d"
    elif days < 365:
        return f"{int(days / 30)}mo"
    else:
        return f"{days / 365:.1f}y"


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all OK, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes Secret age and TLS certificate expiration"
    )

    parser.add_argument(
        "-n",
        "--namespace",
        help="Namespace to check (default: all namespaces)",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show secrets with issues",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information including service account tokens",
    )

    parser.add_argument(
        "--expiry-warn",
        type=int,
        default=30,
        metavar="DAYS",
        help="Days before certificate expiry to warn (default: 30)",
    )

    parser.add_argument(
        "--expiry-critical",
        type=int,
        default=7,
        metavar="DAYS",
        help="Days before certificate expiry is critical (default: 7)",
    )

    parser.add_argument(
        "--stale-days",
        type=int,
        default=365,
        metavar="DAYS",
        help="Days after which a secret is considered stale (default: 365)",
    )

    parser.add_argument(
        "--tls-only",
        action="store_true",
        help="Only check TLS secrets (kubernetes.io/tls type)",
    )

    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get secrets
    cmd = ["kubectl", "get", "secrets", "-o", "json"]
    if opts.namespace:
        cmd.extend(["-n", opts.namespace])
    else:
        cmd.append("--all-namespaces")

    try:
        result = context.run(cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        secrets = json.loads(result.stdout).get("items", [])
    except Exception as e:
        output.error(f"Failed to get secrets: {e}")
        return 2

    # Filter for TLS only if requested
    if opts.tls_only:
        secrets = [s for s in secrets if s.get("type") == "kubernetes.io/tls"]

    # Analyze each secret
    secrets_data = [
        analyze_secret(
            secret,
            context,
            expiry_warn_days=opts.expiry_warn,
            expiry_critical_days=opts.expiry_critical,
            stale_days=opts.stale_days,
        )
        for secret in secrets
    ]

    # Filter out skipped secrets unless verbose
    if not opts.verbose:
        secrets_data = [s for s in secrets_data if not s.get("skipped")]

    # Filter for warn-only
    if opts.warn_only:
        secrets_data = [s for s in secrets_data if s.get("has_issue")]

    # Count issues
    critical_count = sum(1 for s in secrets_data if s.get("severity") == "critical")
    warning_count = sum(1 for s in secrets_data if s.get("severity") == "warning")

    # Output results
    if opts.format == "json":
        summary = {
            "total": len(secrets_data),
            "critical": critical_count,
            "warning": warning_count,
            "ok": sum(1 for s in secrets_data if s.get("severity") == "ok"),
        }
        output_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "secrets": secrets_data,
        }
        print(json.dumps(output_data, indent=2))

    elif opts.format == "table":
        if not secrets_data:
            print("No secrets to display")
        else:
            print(
                f"{'Severity':<10} {'Namespace':<20} {'Name':<35} "
                f"{'Type':<25} {'Age':<8} {'Cert Expiry':<12}"
            )
            print("=" * 120)

            severity_order = {"critical": 0, "warning": 1, "ok": 2}
            secrets_data.sort(
                key=lambda s: severity_order.get(s.get("severity", "ok"), 3)
            )

            for secret in secrets_data:
                severity = secret.get("severity", "ok").upper()
                namespace = secret["namespace"][:19]
                name = secret["name"][:34]
                secret_type = secret["type"][:24]
                age = format_age(secret.get("age_days"))

                cert_expiry = "N/A"
                if (
                    secret.get("cert_info")
                    and secret["cert_info"].get("days_until_expiry") is not None
                ):
                    days = secret["cert_info"]["days_until_expiry"]
                    if days < 0:
                        cert_expiry = "EXPIRED"
                    else:
                        cert_expiry = f"{int(days)}d"

                print(
                    f"{severity:<10} {namespace:<20} {name:<35} "
                    f"{secret_type:<25} {age:<8} {cert_expiry:<12}"
                )

            print()
            print(
                f"Total: {len(secrets_data)} | Critical: {critical_count} | "
                f"Warning: {warning_count}"
            )

    else:  # plain
        if not secrets_data:
            if opts.warn_only:
                print("No secret issues detected")
            else:
                print("No secrets found")
        else:
            critical = [s for s in secrets_data if s.get("severity") == "critical"]
            warning = [s for s in secrets_data if s.get("severity") == "warning"]
            ok = [s for s in secrets_data if s.get("severity") == "ok"]

            if critical:
                print("=== CRITICAL ===")
                for secret in critical:
                    print(f"[CRITICAL] {secret['namespace']}/{secret['name']}")
                    print(f"  Type: {secret['type']}")
                    if secret.get("cert_info"):
                        cert = secret["cert_info"]
                        print(f"  Subject: {cert.get('subject', 'N/A')}")
                        if cert.get("days_until_expiry") is not None:
                            print(
                                f"  Expires: {cert.get('not_after', 'N/A')} "
                                f"({cert['days_until_expiry']} days)"
                            )
                    for issue in secret.get("issues", []):
                        print(f"  Issue: {issue}")
                    print()

            if warning:
                print("=== WARNINGS ===")
                for secret in warning:
                    print(f"[WARNING] {secret['namespace']}/{secret['name']}")
                    print(
                        f"  Type: {secret['type']} | "
                        f"Age: {format_age(secret.get('age_days'))}"
                    )
                    for issue in secret.get("issues", []):
                        print(f"  Issue: {issue}")
                    print()

            if ok and not opts.warn_only:
                print("=== OK ===")
                for secret in ok:
                    age_str = format_age(secret.get("age_days"))
                    print(
                        f"[OK] {secret['namespace']}/{secret['name']} "
                        f"({secret['type']}, {age_str})"
                    )
                    if opts.verbose and secret.get("cert_info"):
                        cert = secret["cert_info"]
                        if cert.get("days_until_expiry") is not None:
                            print(
                                f"     Certificate expires in "
                                f"{cert['days_until_expiry']} days"
                            )
                print()

    output.set_summary(
        f"secrets={len(secrets_data)}, critical={critical_count}, "
        f"warning={warning_count}"
    )

    has_issues = any(s.get("has_issue") for s in secrets_data)
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
