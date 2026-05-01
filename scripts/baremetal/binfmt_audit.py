#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, audit, binfmt, compliance]
#   requires: []
#   privilege: none
#   related: [kernel_module_audit, sysctl_drift_detector]
#   brief: Audit binfmt_misc binary format handlers for security

"""
Audit binfmt_misc registered binary format handlers for security.

Checks the kernel's binfmt_misc filesystem for registered binary format handlers
that allow executing non-native binaries (e.g., Windows executables via Wine,
QEMU user-mode emulation, Java bytecode). While useful for development and
cross-compilation, these can be security concerns on production servers.

Key checks:
- List all registered binary format handlers
- Identify handlers that could execute unexpected file types
- Detect QEMU user-mode handlers (potential for running untrusted binaries)
- Check for Wine handlers (Windows binary execution)
- Validate handler interpreter paths exist and are secure
- Flag handlers using 'F' (fix-binary) flag that may survive container escapes

Security concerns:
- Attackers can exploit registered handlers to execute malicious binaries
- QEMU user-mode allows running foreign architecture binaries
- 'F' flag handlers persist interpreter path at registration
"""

import argparse
import os
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


BINFMT_PATH = '/proc/sys/fs/binfmt_misc'


def check_binfmt_misc_mounted(context: Context) -> tuple[bool, str]:
    """Check if binfmt_misc filesystem is mounted."""
    if not context.file_exists(BINFMT_PATH):
        return False, "binfmt_misc not mounted"

    status_path = f'{BINFMT_PATH}/status'
    try:
        status = context.read_file(status_path).strip()
        return status == 'enabled', f"binfmt_misc status: {status}"
    except (FileNotFoundError, OSError):
        return False, "Cannot read binfmt_misc status"


def parse_binfmt_entry(name: str, content: str) -> dict[str, Any]:
    """Parse a binfmt_misc entry file content."""
    entry = {
        'name': name,
        'enabled': False,
        'interpreter': None,
        'flags': '',
        'offset': 0,
        'magic': None,
        'mask': None,
        'extension': None,
        'type': None,  # 'M' for magic, 'E' for extension
    }

    lines = content.split('\n')

    for line in lines:
        line = line.strip()
        if line == 'enabled':
            entry['enabled'] = True
        elif line == 'disabled':
            entry['enabled'] = False
        elif line.startswith('interpreter '):
            entry['interpreter'] = line.split(' ', 1)[1]
        elif line.startswith('flags: '):
            entry['flags'] = line.split(': ', 1)[1]
        elif line.startswith('offset '):
            try:
                entry['offset'] = int(line.split(' ', 1)[1])
            except ValueError:
                pass
        elif line.startswith('magic '):
            entry['magic'] = line.split(' ', 1)[1]
            entry['type'] = 'M'
        elif line.startswith('mask '):
            entry['mask'] = line.split(' ', 1)[1]
        elif line.startswith('extension '):
            entry['extension'] = line.split(' ', 1)[1]
            entry['type'] = 'E'

    return entry


def get_binfmt_entries(context: Context) -> list[dict[str, Any]]:
    """Get all registered binfmt_misc entries."""
    entries = []

    if not context.file_exists(BINFMT_PATH):
        return entries

    # List directory contents
    result = context.run(['ls', BINFMT_PATH], check=False)
    if result.returncode != 0:
        return entries

    for name in result.stdout.strip().split('\n'):
        name = name.strip()
        if not name or name in ('register', 'status'):
            continue

        entry_path = f'{BINFMT_PATH}/{name}'
        try:
            content = context.read_file(entry_path)
            entry = parse_binfmt_entry(name, content)
            entries.append(entry)
        except (FileNotFoundError, OSError):
            continue

    return entries


def categorize_handler(entry: dict[str, Any]) -> list[str]:
    """Categorize a binfmt handler by its purpose."""
    name = entry['name'].lower()
    interpreter = (entry['interpreter'] or '').lower()

    categories = []

    # QEMU user-mode emulation
    if 'qemu' in name or 'qemu' in interpreter:
        categories.append('qemu')

    # Wine (Windows binary execution)
    if 'wine' in name or 'wine' in interpreter or 'windows' in name:
        categories.append('wine')

    # Java
    if 'java' in name or 'java' in interpreter:
        categories.append('java')

    # Python
    if 'python' in name or 'python' in interpreter:
        categories.append('python')

    # Mono (.NET)
    if 'mono' in name or 'mono' in interpreter or 'cli' in name:
        categories.append('mono')

    # Misc scripts
    if 'script' in name or interpreter.endswith('sh'):
        categories.append('script')

    # Container-related
    if 'container' in name or 'buildah' in interpreter or 'podman' in interpreter:
        categories.append('container')

    if not categories:
        categories.append('unknown')

    return categories


def analyze_handler_risk(entry: dict[str, Any], context: Context) -> list[dict[str, str]]:
    """Analyze security risk of a binfmt handler."""
    risks = []
    categories = categorize_handler(entry)

    # QEMU is high risk on production servers
    if 'qemu' in categories:
        risks.append({
            'severity': 'high',
            'message': 'QEMU user-mode emulation allows running foreign architecture binaries',
        })

    # Wine is high risk
    if 'wine' in categories:
        risks.append({
            'severity': 'high',
            'message': 'Wine allows executing Windows binaries including potential malware',
        })

    # 'F' flag (fix-binary) has security implications
    if 'F' in entry.get('flags', ''):
        risks.append({
            'severity': 'medium',
            'message': "Handler uses 'F' (fix-binary) flag - interpreter path fixed at registration",
        })

    # 'C' flag (credentials) runs with caller's credentials
    if 'C' in entry.get('flags', ''):
        risks.append({
            'severity': 'low',
            'message': "Handler uses 'C' flag - uses caller's credentials",
        })

    # Check interpreter exists
    interpreter = entry.get('interpreter')
    if interpreter and not context.file_exists(interpreter):
        risks.append({
            'severity': 'medium',
            'message': f'Interpreter not found: {interpreter}',
        })

    # Unknown handlers should be investigated
    if 'unknown' in categories and entry.get('enabled'):
        risks.append({
            'severity': 'medium',
            'message': 'Unknown handler type - should be investigated',
        })

    return risks


def analyze_all_handlers(entries: list[dict], allowed_handlers: list[str] | None,
                         context: Context) -> dict[str, Any]:
    """Analyze all binfmt handlers and return findings."""
    allowed_set = set(allowed_handlers) if allowed_handlers else set()

    findings = []
    issues = []
    warnings = []
    info_msgs = []

    if not entries:
        info_msgs.append("No binfmt_misc handlers registered")
        return {
            'status': 'healthy',
            'findings': findings,
            'issues': issues,
            'warnings': warnings,
            'info': info_msgs,
        }

    info_msgs.append(f"Found {len(entries)} registered handler(s)")

    enabled_count = sum(1 for e in entries if e.get('enabled'))
    if enabled_count > 0:
        info_msgs.append(f"Enabled handlers: {enabled_count}")

    for entry in entries:
        categories = categorize_handler(entry)
        risks = analyze_handler_risk(entry, context)

        finding = {
            'name': entry['name'],
            'enabled': entry.get('enabled', False),
            'interpreter': entry.get('interpreter'),
            'flags': entry.get('flags', ''),
            'categories': categories,
            'risks': risks,
            'allowed': entry['name'] in allowed_set,
        }
        findings.append(finding)

        # Skip allowed handlers
        if entry['name'] in allowed_set:
            continue

        # Only flag enabled handlers
        if not entry.get('enabled'):
            continue

        # Categorize by severity
        for risk in risks:
            msg = f"{entry['name']}: {risk['message']}"
            if risk['severity'] == 'high':
                issues.append(msg)
            elif risk['severity'] == 'medium':
                warnings.append(msg)
            else:
                info_msgs.append(msg)

    # Determine overall status
    if issues:
        status = 'critical'
    elif warnings:
        status = 'warning'
    else:
        status = 'healthy'

    return {
        'status': status,
        'findings': findings,
        'issues': issues,
        'warnings': warnings,
        'info': info_msgs,
    }


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
    parser = argparse.ArgumentParser(description="Audit binfmt_misc binary format handlers")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--allow", nargs='+', metavar="NAME",
                        help="Handler names to allow (skip risk analysis)")
    opts = parser.parse_args(args)

    # Check if binfmt_misc is available
    binfmt_enabled, binfmt_msg = check_binfmt_misc_mounted(context)

    if not binfmt_enabled:
        output.emit({
            'binfmt_misc_enabled': False,
            'handlers': [],
            'analysis': {
                'status': 'healthy',
                'issues': [],
                'warnings': [],
                'info': [binfmt_msg],
            }
        })
        output.set_summary("binfmt_misc not enabled - no handlers to audit")

        output.render(opts.format, "Audit binfmt_misc binary format handlers for security")
        return 0

    # Get all entries
    entries = get_binfmt_entries(context)

    # Analyze
    analysis = analyze_all_handlers(entries, opts.allow, context)

    # Build result
    result = {
        'binfmt_misc_enabled': True,
        'total_handlers': len(entries),
        'enabled_handlers': sum(1 for e in entries if e.get('enabled')),
        'handlers': entries if opts.verbose else None,
        'analysis': analysis
    }

    # Remove None values
    result = {k: v for k, v in result.items() if v is not None}

    output.emit(result)

    # Set summary
    if analysis['status'] == 'critical':
        output.set_summary(f"{len(analysis['issues'])} high-risk handlers detected")
    elif analysis['status'] == 'warning':
        output.set_summary(f"{len(analysis['warnings'])} warnings")
    else:
        output.set_summary("no security concerns detected")

    # Exit code
    if analysis['issues'] or analysis['warnings']:

        output.render(opts.format, "Audit binfmt_misc binary format handlers for security")
        return 1

    output.render(opts.format, "Audit binfmt_misc binary format handlers for security")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
