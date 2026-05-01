#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [mount, security, audit, compliance, cis]
#   requires: []
#   privilege: user
#   related: [security_audit, filesystem_usage]
#   brief: Audit filesystem mount options for security compliance

"""
Audit filesystem mount options for security compliance.

Checks mounted filesystems against security best practices and
CIS benchmark recommendations. Verifies that security-critical mount options
(noexec, nosuid, nodev) are applied to appropriate mount points.
"""

import argparse
from datetime import datetime
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Security requirements for specific mount points
SECURITY_REQUIREMENTS = {
    '/tmp': {
        'required': ['noexec', 'nosuid', 'nodev'],
        'recommended': [],
        'description': 'Temporary files - prevent execution of malicious binaries',
        'cis_ref': 'CIS 1.1.2-1.1.5'
    },
    '/var/tmp': {
        'required': ['noexec', 'nosuid', 'nodev'],
        'recommended': [],
        'description': 'Persistent temporary files - prevent code execution',
        'cis_ref': 'CIS 1.1.6-1.1.9'
    },
    '/dev/shm': {
        'required': ['noexec', 'nosuid', 'nodev'],
        'recommended': [],
        'description': 'Shared memory - prevent exploitation via shared memory',
        'cis_ref': 'CIS 1.1.15-1.1.18'
    },
    '/home': {
        'required': ['nosuid', 'nodev'],
        'recommended': [],
        'description': 'User home directories - prevent setuid/device file exploits',
        'cis_ref': 'CIS 1.1.13-1.1.14'
    },
    '/var': {
        'required': ['nosuid'],
        'recommended': ['nodev'],
        'description': 'Variable data - restrict setuid binaries',
        'cis_ref': 'CIS 1.1.10'
    },
    '/var/log': {
        'required': ['noexec', 'nosuid', 'nodev'],
        'recommended': [],
        'description': 'Log files - prevent log-based attacks',
        'cis_ref': 'CIS 1.1.11'
    },
    '/var/log/audit': {
        'required': ['noexec', 'nosuid', 'nodev'],
        'recommended': [],
        'description': 'Audit logs - protect audit trail integrity',
        'cis_ref': 'CIS 1.1.12'
    },
    '/boot': {
        'required': ['nosuid', 'nodev'],
        'recommended': ['noexec'],
        'description': 'Boot partition - protect bootloader and kernel',
        'cis_ref': 'CIS 1.1.19'
    },
    '/boot/efi': {
        'required': ['nosuid', 'nodev'],
        'recommended': ['noexec'],
        'description': 'EFI partition - protect UEFI binaries',
        'cis_ref': 'CIS 1.1.19'
    },
}

# Strict mode adds more mount points
STRICT_REQUIREMENTS = {
    '/opt': {
        'required': ['nosuid'],
        'recommended': ['nodev'],
        'description': 'Optional software - restrict setuid binaries',
        'cis_ref': 'Custom'
    },
    '/usr': {
        'required': [],
        'recommended': ['nodev'],
        'description': 'System binaries - prevent device file exploits',
        'cis_ref': 'Custom'
    },
    '/srv': {
        'required': ['nosuid', 'nodev'],
        'recommended': ['noexec'],
        'description': 'Service data - restrict execution',
        'cis_ref': 'Custom'
    },
}

# Removable/external media patterns
REMOVABLE_PATTERNS = [
    '/media/',
    '/mnt/',
    '/run/media/',
]


def parse_proc_mounts(context: Context) -> list[dict[str, Any]]:
    """Parse /proc/mounts to get current mount information."""
    mounts = []
    try:
        content = context.read_file('/proc/mounts')
        for line in content.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 4:
                mounts.append({
                    'device': parts[0],
                    'mountpoint': parts[1],
                    'fstype': parts[2],
                    'options': set(parts[3].split(',')),
                })
    except FileNotFoundError:
        raise RuntimeError('/proc/mounts not found - requires Linux')
    except PermissionError:
        raise RuntimeError('Permission denied reading /proc/mounts')
    return mounts


def is_removable_mount(mountpoint: str) -> bool:
    """Check if mountpoint is for removable/external media."""
    for pattern in REMOVABLE_PATTERNS:
        if mountpoint.startswith(pattern):
            return True
    return False


def check_mount_security(mount: dict, requirements: dict) -> dict[str, Any]:
    """Check a single mount against security requirements."""
    options = mount['options']
    required = set(requirements.get('required', []))
    recommended = set(requirements.get('recommended', []))

    missing_required = required - options
    missing_recommended = recommended - options

    return {
        'mountpoint': mount['mountpoint'],
        'device': mount['device'],
        'fstype': mount['fstype'],
        'current_options': sorted(options),
        'missing_required': sorted(missing_required),
        'missing_recommended': sorted(missing_recommended),
        'has_noexec': 'noexec' in options,
        'has_nosuid': 'nosuid' in options,
        'has_nodev': 'nodev' in options,
        'description': requirements.get('description', ''),
        'cis_ref': requirements.get('cis_ref', ''),
        'compliant': len(missing_required) == 0,
        'fully_hardened': len(missing_required) == 0 and len(missing_recommended) == 0,
    }


def audit_mounts(
    mounts: list[dict],
    strict: bool = False,
    check_removable: bool = True
) -> dict[str, Any]:
    """Audit all mounts against security requirements."""
    results = {
        'timestamp': datetime.now().isoformat(),
        'total_mounts': len(mounts),
        'checked': 0,
        'compliant': 0,
        'non_compliant': 0,
        'fully_hardened': 0,
        'findings': [],
        'removable_findings': [],
    }

    # Build requirements map
    requirements = dict(SECURITY_REQUIREMENTS)
    if strict:
        requirements.update(STRICT_REQUIREMENTS)

    # Create mount lookup by mountpoint
    mount_lookup = {m['mountpoint']: m for m in mounts}

    # Check known mount points
    for mountpoint, reqs in requirements.items():
        if mountpoint in mount_lookup:
            mount = mount_lookup[mountpoint]
            result = check_mount_security(mount, reqs)
            results['checked'] += 1
            results['findings'].append(result)

            if result['compliant']:
                results['compliant'] += 1
                if result['fully_hardened']:
                    results['fully_hardened'] += 1
            else:
                results['non_compliant'] += 1

    # Check removable media mounts
    if check_removable:
        removable_reqs = {
            'required': ['noexec', 'nosuid', 'nodev'],
            'recommended': [],
            'description': 'Removable media - prevent execution of untrusted code',
            'cis_ref': 'CIS 1.1.20-1.1.23'
        }

        for mount in mounts:
            if is_removable_mount(mount['mountpoint']):
                result = check_mount_security(mount, removable_reqs)
                results['removable_findings'].append(result)
                results['checked'] += 1

                if result['compliant']:
                    results['compliant'] += 1
                else:
                    results['non_compliant'] += 1

    # Generate summary
    results['summary'] = {
        'total_checked': results['checked'],
        'compliant': results['compliant'],
        'non_compliant': results['non_compliant'],
        'fully_hardened': results['fully_hardened'],
        'compliance_percentage': (
            round(results['compliant'] / results['checked'] * 100, 1)
            if results['checked'] > 0 else 100.0
        )
    }

    return results


def get_remount_command(finding: dict) -> str | None:
    """Generate remount command to fix missing options."""
    all_missing = finding['missing_required'] + finding['missing_recommended']
    if not all_missing:
        return None

    options = ','.join(all_missing)
    return f"mount -o remount,{options} {finding['mountpoint']}"


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = compliant, 1 = non-compliant, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Audit filesystem mount options for security compliance'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed information including CIS references')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    parser.add_argument('--strict', action='store_true',
                        help='Check additional mount points (/opt, /usr, /srv)')
    parser.add_argument('--no-removable', action='store_true',
                        help='Skip checking removable media mount points')
    parser.add_argument('--show-fixes', action='store_true',
                        help='Show commands to fix non-compliant mounts')
    opts = parser.parse_args(args)

    # Parse current mounts
    try:
        mounts = parse_proc_mounts(context)
    except RuntimeError as e:
        output.error(str(e))

        output.render(opts.format, "Audit filesystem mount options for security compliance")
        return 2

    # Run audit
    results = audit_mounts(
        mounts,
        strict=opts.strict,
        check_removable=not opts.no_removable
    )

    # Build output data
    non_compliant = [f for f in results['findings'] if not f['compliant']]
    non_compliant += [f for f in results['removable_findings'] if not f['compliant']]

    data = {
        'summary': results['summary'],
        'non_compliant': non_compliant,
    }

    if opts.verbose:
        data['all_findings'] = results['findings'] + results['removable_findings']

    if opts.show_fixes:
        fixes = []
        for finding in non_compliant:
            cmd = get_remount_command(finding)
            if cmd:
                fixes.append({
                    'mountpoint': finding['mountpoint'],
                    'command': cmd,
                })
        data['remediation'] = fixes

    output.emit(data)

    # Set summary
    summary = results['summary']
    output.set_summary(
        f"{summary['compliant']}/{summary['total_checked']} compliant "
        f"({summary['compliance_percentage']}%)"
    )

    # Exit based on compliance

    output.render(opts.format, "Audit filesystem mount options for security compliance")
    return 1 if summary['non_compliant'] > 0 else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
