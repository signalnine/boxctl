#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [audit, security, compliance, logging]
#   requires: [auditctl]
#   privilege: root
#   related: [systemd_service_monitor, systemd_journal_analyzer]
#   brief: Monitor Linux audit daemon health and configuration

"""
Monitor Linux audit daemon (auditd) health and configuration.

Checks the health and status of the Linux audit daemon, verifying that audit
logging is active, rules are loaded, and the audit log is not experiencing
issues. Essential for security compliance monitoring in enterprise baremetal
environments.

Key features:
- Check auditd service status
- Verify audit rules are loaded
- Monitor audit log disk usage
- Detect lost or backlog events
- Check audit configuration settings
"""

import argparse
import os
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def format_size(size_bytes: int) -> str:
    """Format bytes to human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}PB"


def check_auditd_service_status(context: Context) -> dict[str, Any]:
    """Check if auditd service is running."""
    # Try systemctl first
    result = context.run(['systemctl', 'is-active', 'auditd'], check=False)
    if result.returncode == 0 and result.stdout.strip() == 'active':
        return {
            'running': True,
            'method': 'systemctl',
            'status': 'active'
        }

    # Try checking for auditd process directly
    result = context.run(['pgrep', '-x', 'auditd'], check=False)
    if result.returncode == 0 and result.stdout.strip():
        return {
            'running': True,
            'method': 'pgrep',
            'status': 'running',
            'pid': result.stdout.strip().split('\n')[0]
        }

    return {
        'running': False,
        'method': 'systemctl',
        'status': 'inactive'
    }


def get_audit_status(context: Context) -> dict[str, Any] | None:
    """Get audit subsystem status from auditctl."""
    result = context.run(['auditctl', '-s'], check=False)

    if result.returncode != 0:
        return None

    status = {}
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue
        # Parse lines like "enabled 1" or "backlog 0"
        parts = line.split()
        if len(parts) >= 2:
            key = parts[0]
            value = parts[1]
            try:
                status[key] = int(value)
            except ValueError:
                status[key] = value

    return status


def get_audit_rules(context: Context) -> list[str] | None:
    """Get loaded audit rules."""
    result = context.run(['auditctl', '-l'], check=False)

    if result.returncode != 0:
        return None

    rules = []
    for line in result.stdout.strip().split('\n'):
        line = line.strip()
        if line and line != 'No rules':
            rules.append(line)

    return rules


def get_audit_log_info(context: Context) -> dict[str, Any]:
    """Get information about the audit log file."""
    log_path = '/var/log/audit/audit.log'
    log_dir = '/var/log/audit'

    info = {
        'log_path': log_path,
        'exists': False,
        'size_bytes': 0,
        'size_human': '0B',
        'dir_exists': False,
        'dir_size_bytes': 0,
        'dir_size_human': '0B',
        'file_count': 0
    }

    # Check log file
    if context.file_exists(log_path):
        info['exists'] = True
        try:
            content = context.read_file(log_path)
            info['size_bytes'] = len(content.encode('utf-8'))
            info['size_human'] = format_size(info['size_bytes'])
        except (OSError, IOError):
            pass

    # Check log directory using ls
    result = context.run(['ls', '-la', log_dir], check=False)
    if result.returncode == 0:
        info['dir_exists'] = True
        # Count files from ls output
        lines = result.stdout.strip().split('\n')
        info['file_count'] = max(0, len(lines) - 1)  # Subtract header

    return info


def analyze_status(status: dict[str, Any] | None) -> list[dict[str, str]]:
    """Analyze audit status for issues."""
    issues = []

    if status is None:
        issues.append({
            'severity': 'critical',
            'message': 'Cannot retrieve audit status (auditctl -s failed)'
        })
        return issues

    # Check if audit is enabled
    enabled = status.get('enabled', 0)
    if enabled == 0:
        issues.append({
            'severity': 'critical',
            'message': 'Audit subsystem is disabled (enabled=0)'
        })
    elif enabled == 2:
        issues.append({
            'severity': 'info',
            'message': 'Audit rules are locked (enabled=2, immutable mode)'
        })

    # Check for lost events
    lost = status.get('lost', 0)
    if lost > 0:
        issues.append({
            'severity': 'warning',
            'message': f'Audit events lost: {lost} events'
        })

    # Check backlog
    backlog = status.get('backlog', 0)
    backlog_limit = status.get('backlog_limit', 8192)
    if backlog_limit > 0 and backlog > backlog_limit * 0.8:
        issues.append({
            'severity': 'warning',
            'message': f'Audit backlog high: {backlog}/{backlog_limit} ({(backlog / backlog_limit) * 100:.0f}%)'
        })

    # Check failure mode
    failure = status.get('failure', 1)
    if failure == 0:
        issues.append({
            'severity': 'warning',
            'message': 'Audit failure mode is silent (failure=0)'
        })
    elif failure == 2:
        issues.append({
            'severity': 'info',
            'message': 'Audit failure mode is panic (failure=2)'
        })

    return issues


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
    parser = argparse.ArgumentParser(description="Monitor Linux audit daemon health")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--min-rules", type=int, default=0, metavar="N",
                        help="Warn if fewer than N audit rules are loaded")
    opts = parser.parse_args(args)

    # Check for auditctl
    if not context.check_tool("auditctl"):
        output.error("auditctl not found. Install audit tools package.")

        output.render(opts.format, "Monitor Linux audit daemon health and configuration")
        return 2

    # Gather information
    service_status = check_auditd_service_status(context)
    audit_status = get_audit_status(context)
    audit_rules = get_audit_rules(context)
    log_info = get_audit_log_info(context)

    issues = []
    has_issues = False

    # Check service status
    if not service_status['running']:
        issues.append({
            'severity': 'critical',
            'message': 'Audit daemon is not running'
        })
        has_issues = True

    # Analyze audit status
    status_issues = analyze_status(audit_status)
    issues.extend(status_issues)
    if any(i['severity'] in ['critical', 'warning'] for i in status_issues):
        has_issues = True

    # Check log file
    if not log_info['exists']:
        issues.append({
            'severity': 'warning',
            'message': f"Audit log file does not exist: {log_info['log_path']}"
        })
        has_issues = True

    # Check minimum rules
    if opts.min_rules > 0:
        rule_count = len(audit_rules) if audit_rules else 0
        if rule_count < opts.min_rules:
            issues.append({
                'severity': 'warning',
                'message': f'Only {rule_count} audit rules loaded (minimum: {opts.min_rules})'
            })
            has_issues = True

    # Build result
    result = {
        'service_status': service_status,
        'audit_status': audit_status,
        'log_info': {
            'exists': log_info['exists'],
            'size_human': log_info['size_human'],
            'file_count': log_info['file_count']
        },
        'rules_loaded': len(audit_rules) if audit_rules else 0,
        'issues': issues
    }

    if opts.verbose and audit_rules:
        result['audit_rules'] = audit_rules

    output.emit(result)

    # Set summary
    if has_issues:
        critical = sum(1 for i in issues if i['severity'] == 'critical')
        warnings = sum(1 for i in issues if i['severity'] == 'warning')
        output.set_summary(f"{critical} critical, {warnings} warnings")
    else:
        output.set_summary("audit daemon healthy")

    output.render(opts.format, "Monitor Linux audit daemon health and configuration")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
