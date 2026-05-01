#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [livepatch, security, kernel, compliance]
#   requires: []
#   privilege: user
#   related: [kernel_taint, security_audit]
#   brief: Monitor kernel live patching status for security compliance

"""
Monitor kernel live patching status for security and compliance.

Checks the status of kernel live patches (kpatch, livepatch, ksplice)
to verify security patches are applied without requiring reboots.

Supports:
- Canonical Livepatch (livepatch)
- Red Hat kpatch
- Oracle ksplice
- Kernel sysfs livepatch interface
"""

import argparse
import os
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_livepatch_support(context: Context) -> dict[str, Any]:
    """Check if the kernel supports live patching."""
    support = {
        'kernel_support': False,
        'livepatch_enabled': False,
        'kpatch_available': False,
        'ksplice_available': False,
        'canonical_livepatch': False,
    }

    # Check /sys/kernel/livepatch
    if context.file_exists('/sys/kernel/livepatch'):
        support['livepatch_enabled'] = True
        support['kernel_support'] = True

    # Check for kpatch command
    if context.check_tool('kpatch'):
        support['kpatch_available'] = True

    # Check for ksplice command
    if context.check_tool('ksplice'):
        support['ksplice_available'] = True

    # Check for canonical-livepatch
    if context.check_tool('canonical-livepatch'):
        support['canonical_livepatch'] = True

    # Try to check kernel config for livepatch support
    try:
        result = context.run(['uname', '-r'], check=False)
        kernel_release = result.stdout.strip()
        config_path = f'/boot/config-{kernel_release}'
        if context.file_exists(config_path):
            config = context.read_file(config_path)
            if 'CONFIG_LIVEPATCH=y' in config:
                support['kernel_support'] = True
    except Exception:
        pass

    return support


def get_sysfs_livepatches(context: Context) -> list[dict[str, Any]]:
    """Get live patch status from /sys/kernel/livepatch."""
    patches = []
    livepatch_dir = '/sys/kernel/livepatch'

    if not context.file_exists(livepatch_dir):
        return patches

    try:
        patch_names = context.glob('[a-zA-Z0-9_-]*', livepatch_dir)
        for patch_path in patch_names:
            patch_name = os.path.basename(patch_path)

            patch_info = {
                'name': patch_name,
                'source': 'sysfs',
                'enabled': False,
                'transition': False,
            }

            # Read enabled status
            enabled_path = f'{patch_path}/enabled'
            if context.file_exists(enabled_path):
                content = context.read_file(enabled_path)
                patch_info['enabled'] = content.strip() == '1'

            # Read transition status
            transition_path = f'{patch_path}/transition'
            if context.file_exists(transition_path):
                content = context.read_file(transition_path)
                patch_info['transition'] = content.strip() == '1'

            patches.append(patch_info)
    except Exception:
        pass

    return patches


def get_kpatch_status(context: Context) -> dict[str, Any]:
    """Get kpatch status if available."""
    status = {
        'available': False,
        'loaded_patches': [],
        'installed_patches': [],
    }

    if not context.check_tool('kpatch'):
        return status

    try:
        result = context.run(['kpatch', 'list'], check=False)
        if result.returncode == 0:
            status['available'] = True
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('Loaded') or line.startswith('Installed'):
                    continue
                parts = line.split()
                if parts:
                    patch = {
                        'name': parts[0],
                        'enabled': '[enabled]' in line.lower(),
                    }
                    status['loaded_patches'].append(patch)
    except Exception:
        pass

    return status


def get_canonical_livepatch_status(context: Context) -> dict[str, Any]:
    """Get Canonical Livepatch status if available."""
    import json

    status = {
        'available': False,
        'enabled': False,
        'running': False,
        'patches': [],
        'last_check': None,
        'machine_token': False,
    }

    if not context.check_tool('canonical-livepatch'):
        return status

    try:
        result = context.run(
            ['canonical-livepatch', 'status', '--format', 'json'],
            check=False
        )
        if result.returncode == 0:
            status['available'] = True
            try:
                data = json.loads(result.stdout)
                status['enabled'] = data.get('Status', '') == 'enabled'
                status['running'] = data.get('Running', False)
                status['machine_token'] = bool(data.get('MachineToken', ''))

                if 'Livepatch' in data:
                    lp = data['Livepatch']
                    status['last_check'] = lp.get('CheckState', {}).get('LastCheck')
                    if 'Fixes' in lp:
                        for fix in lp['Fixes']:
                            status['patches'].append({
                                'name': fix.get('Name', 'Unknown'),
                                'description': fix.get('Description', ''),
                                'patched': fix.get('Patched', False),
                            })
            except json.JSONDecodeError:
                status['enabled'] = 'enabled' in result.stdout.lower()
    except Exception:
        pass

    return status


def get_ksplice_status(context: Context) -> dict[str, Any]:
    """Get Oracle Ksplice status if available."""
    status = {
        'available': False,
        'patches': [],
    }

    if not context.check_tool('ksplice'):
        return status

    try:
        result = context.run(['ksplice', 'all'], check=False)
        if result.returncode == 0:
            status['available'] = True
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if not line or 'No updates' in line or line.startswith('Checking'):
                    continue
                status['patches'].append({
                    'name': line,
                    'source': 'ksplice',
                })
    except Exception:
        pass

    return status


def get_kernel_info(context: Context) -> dict[str, str]:
    """Get current kernel version info."""
    info = {'release': 'Unknown', 'version': 'Unknown'}

    try:
        result = context.run(['uname', '-r'], check=False)
        if result.returncode == 0:
            info['release'] = result.stdout.strip()
    except Exception:
        pass

    try:
        result = context.run(['uname', '-v'], check=False)
        if result.returncode == 0:
            info['version'] = result.stdout.strip()
    except Exception:
        pass

    return info


def analyze_livepatch_status(
    support: dict,
    sysfs_patches: list,
    kpatch: dict,
    canonical: dict,
    ksplice: dict
) -> dict[str, Any]:
    """Analyze live patch status and identify issues."""
    issues = []
    summary = {
        'livepatch_in_use': False,
        'total_patches': 0,
        'enabled_patches': 0,
        'disabled_patches': 0,
        'transitioning_patches': 0,
        'systems': [],
    }

    # Check sysfs patches
    for patch in sysfs_patches:
        summary['total_patches'] += 1
        summary['livepatch_in_use'] = True

        if patch['enabled']:
            summary['enabled_patches'] += 1
        else:
            summary['disabled_patches'] += 1
            issues.append({
                'severity': 'WARNING',
                'message': f"Live patch '{patch['name']}' is disabled",
            })

        if patch.get('transition'):
            summary['transitioning_patches'] += 1
            issues.append({
                'severity': 'INFO',
                'message': f"Live patch '{patch['name']}' is transitioning",
            })

    # Check kpatch
    if kpatch['available']:
        summary['systems'].append('kpatch')
        if kpatch.get('error'):
            issues.append({
                'severity': 'WARNING',
                'message': f"kpatch error: {kpatch['error']}",
            })

        for patch in kpatch.get('loaded_patches', []):
            summary['livepatch_in_use'] = True
            if not patch.get('enabled'):
                issues.append({
                    'severity': 'WARNING',
                    'message': f"kpatch '{patch['name']}' is loaded but disabled",
                })

    # Check Canonical Livepatch
    if canonical['available']:
        summary['systems'].append('canonical-livepatch')
        summary['livepatch_in_use'] = True

        if canonical.get('error'):
            issues.append({
                'severity': 'WARNING',
                'message': f"Canonical Livepatch error: {canonical['error']}",
            })

        if not canonical.get('machine_token'):
            issues.append({
                'severity': 'WARNING',
                'message': 'Canonical Livepatch not registered (no machine token)',
            })

        if not canonical.get('enabled'):
            issues.append({
                'severity': 'WARNING',
                'message': 'Canonical Livepatch is disabled',
            })

        summary['total_patches'] += len(canonical.get('patches', []))
        for patch in canonical.get('patches', []):
            if patch.get('patched'):
                summary['enabled_patches'] += 1
            else:
                summary['disabled_patches'] += 1

    # Check Ksplice
    if ksplice['available']:
        summary['systems'].append('ksplice')
        summary['livepatch_in_use'] = True

        if ksplice.get('error'):
            issues.append({
                'severity': 'WARNING',
                'message': f"Ksplice error: {ksplice['error']}",
            })

        summary['total_patches'] += len(ksplice.get('patches', []))

    # Check kernel support
    if not support['kernel_support'] and not summary['livepatch_in_use']:
        issues.append({
            'severity': 'INFO',
            'message': 'Kernel live patching not enabled',
        })

    return {
        'summary': summary,
        'issues': issues,
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
    parser = argparse.ArgumentParser(
        description='Monitor kernel live patching status'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed patch information')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    # Get kernel info
    kernel_info = get_kernel_info(context)

    # Check live patch support
    support = check_livepatch_support(context)

    # Get status from all sources
    sysfs_patches = get_sysfs_livepatches(context)
    kpatch = get_kpatch_status(context)
    canonical = get_canonical_livepatch_status(context)
    ksplice = get_ksplice_status(context)

    # Analyze status
    analysis = analyze_livepatch_status(
        support, sysfs_patches, kpatch, canonical, ksplice
    )

    summary = analysis['summary']
    issues = analysis['issues']

    # Build output data
    data = {
        'kernel': kernel_info,
        'support': support,
        'summary': summary,
        'sysfs_patches': sysfs_patches,
        'kpatch': kpatch,
        'canonical_livepatch': canonical,
        'ksplice': ksplice,
        'issues': issues,
    }

    if not opts.verbose:
        # Remove detailed info in non-verbose mode
        data.pop('kpatch', None)
        data.pop('canonical_livepatch', None)
        data.pop('ksplice', None)
        data.pop('sysfs_patches', None)

    output.emit(data)

    # Set summary
    if summary['livepatch_in_use']:
        output.set_summary(
            f"{summary['enabled_patches']} enabled, "
            f"{summary['disabled_patches']} disabled"
        )
    else:
        output.set_summary('Live patching not in use')

    # Determine exit code
    has_warnings = any(
        i['severity'] in ['WARNING', 'CRITICAL', 'ERROR']
        for i in issues
    )

    output.render(opts.format, "Monitor kernel live patching status for security compliance")

    return 1 if has_warnings else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
