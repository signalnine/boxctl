#!/usr/bin/env python3
# boxctl:
#   category: baremetal/systemd
#   tags: [systemd, drift, config, audit, compliance]
#   requires: [systemctl]
#   privilege: user
#   related: [systemd_service_monitor, systemd_socket, systemd_timer_monitor]
#   brief: Detect systemd unit files with local overrides or modifications

"""
Systemd Unit Drift Detector

Detects systemd unit files that have local overrides, drop-ins, or modifications
from their package-installed versions. Useful for security auditing, configuration
management, and ensuring fleet consistency.

Checks:
- Units with drop-in files (.d/*.conf overrides)
- Units masked locally
- Units with custom symlinks
- Package-installed units vs local modifications
"""

import argparse
import os
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Standard systemd unit paths in priority order
UNIT_PATHS = [
    '/etc/systemd/system',      # Local admin config (highest priority)
    '/run/systemd/system',      # Runtime config
    '/usr/local/lib/systemd/system',  # Local packages
    '/usr/lib/systemd/system',  # Distribution packages
    '/lib/systemd/system',      # Distribution packages (legacy)
]


def get_unit_file_state(unit_name: str, context: Context) -> dict[str, Any]:
    """Get the file state information for a unit."""
    result = context.run(
        ['systemctl', 'show', unit_name,
         '--property=UnitFileState,UnitFilePreset,FragmentPath,DropInPaths'],
        check=False
    )

    info: dict[str, Any] = {
        'unit_file_state': '',
        'unit_file_preset': '',
        'fragment_path': '',
        'drop_in_paths': []
    }

    if result.returncode == 0:
        for line in result.stdout.strip().split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                if key == 'UnitFileState':
                    info['unit_file_state'] = value
                elif key == 'UnitFilePreset':
                    info['unit_file_preset'] = value
                elif key == 'FragmentPath':
                    info['fragment_path'] = value
                elif key == 'DropInPaths':
                    if value:
                        info['drop_in_paths'] = value.split()

    return info


def get_all_units(unit_type: str | None, context: Context) -> list[str]:
    """Get list of all unit files."""
    cmd = ['systemctl', 'list-unit-files', '--no-pager', '--no-legend']
    if unit_type:
        cmd.append(f'--type={unit_type}')

    result = context.run(cmd, check=False)
    if result.returncode != 0:
        return []

    units = []
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if parts:
            units.append(parts[0])

    return units


def find_unit_file_locations(unit_name: str, context: Context) -> dict[str, str]:
    """Find all locations where a unit file exists."""
    locations = {}

    for base_path in UNIT_PATHS:
        full_path = os.path.join(base_path, unit_name)
        if context.file_exists(full_path):
            if base_path == '/etc/systemd/system':
                locations['local_admin'] = full_path
            elif base_path == '/run/systemd/system':
                locations['runtime'] = full_path
            elif 'local' in base_path:
                locations['local_package'] = full_path
            else:
                locations['package'] = full_path

    return locations


def find_drop_in_files(unit_name: str, context: Context) -> list[dict[str, Any]]:
    """Find all drop-in configuration files for a unit."""
    drop_ins = []

    for base_path in UNIT_PATHS:
        drop_in_dir = os.path.join(base_path, f'{unit_name}.d')
        if context.file_exists(drop_in_dir):
            try:
                # Use glob to find .conf files
                conf_files = context.glob('*.conf', drop_in_dir)
                for conf_file in sorted(conf_files):
                    filename = os.path.basename(conf_file)
                    drop_ins.append({
                        'path': conf_file,
                        'filename': filename,
                        'base': base_path,
                        'is_local': base_path in ['/etc/systemd/system', '/run/systemd/system']
                    })
            except (OSError, PermissionError):
                pass

    return drop_ins


def check_if_masked(unit_name: str, context: Context) -> dict[str, Any]:
    """Check if a unit is masked and how."""
    result: dict[str, Any] = {
        'is_masked': False,
        'mask_type': None,
        'mask_path': None
    }

    # Check common mask locations
    for base_path in ['/etc/systemd/system', '/run/systemd/system']:
        unit_path = os.path.join(base_path, unit_name)
        if context.file_exists(unit_path):
            # Check if it's a symlink to /dev/null
            # We can't easily check symlink targets in mock context,
            # so we rely on systemctl show
            pass

    # Use systemctl to check mask status
    show_result = context.run(
        ['systemctl', 'show', unit_name, '--property=LoadState'],
        check=False
    )
    if show_result.returncode == 0:
        for line in show_result.stdout.strip().split('\n'):
            if line.startswith('LoadState='):
                load_state = line.split('=', 1)[1]
                if load_state == 'masked':
                    result['is_masked'] = True
                    # Check where it's masked
                    for base_path in ['/etc/systemd/system', '/run/systemd/system']:
                        unit_path = os.path.join(base_path, unit_name)
                        if context.file_exists(unit_path):
                            result['mask_type'] = 'runtime' if 'run' in base_path else 'persistent'
                            result['mask_path'] = unit_path
                            break

    return result


def analyze_unit_drift(unit_name: str, context: Context) -> dict[str, Any]:
    """Analyze a unit for configuration drift."""
    analysis: dict[str, Any] = {
        'unit': unit_name,
        'has_drift': False,
        'drift_reasons': [],
        'details': {}
    }

    # Get systemctl's view of the unit
    state_info = get_unit_file_state(unit_name, context)
    analysis['details']['state'] = state_info

    # Find all file locations
    locations = find_unit_file_locations(unit_name, context)
    analysis['details']['locations'] = locations

    # Check for local admin overrides
    if 'local_admin' in locations:
        if 'package' in locations:
            analysis['has_drift'] = True
            analysis['drift_reasons'].append('local_override')
        else:
            # Local-only unit (not from package)
            analysis['details']['is_local_only'] = True

    # Find drop-in files
    drop_ins = find_drop_in_files(unit_name, context)
    analysis['details']['drop_ins'] = drop_ins

    local_drop_ins = [d for d in drop_ins if d['is_local']]
    if local_drop_ins:
        analysis['has_drift'] = True
        analysis['drift_reasons'].append('has_drop_ins')
        analysis['details']['local_drop_in_count'] = len(local_drop_ins)

    # Check if masked
    mask_info = check_if_masked(unit_name, context)
    analysis['details']['mask_info'] = mask_info

    if mask_info['is_masked']:
        analysis['has_drift'] = True
        analysis['drift_reasons'].append('masked')

    # Check unit file state
    if state_info['unit_file_state'] == 'masked':
        if 'masked' not in analysis['drift_reasons']:
            analysis['has_drift'] = True
            analysis['drift_reasons'].append('masked')

    return analysis


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no drift, 1 = drift detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Detect systemd unit files with local overrides'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed information')
    parser.add_argument('-w', '--warn-only', action='store_true',
                        help='Only show units with drift')
    parser.add_argument('-t', '--type',
                        help='Filter by unit type (service, timer, socket, etc.)')
    parser.add_argument('-u', '--unit',
                        help='Check a specific unit')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    # Check for systemctl
    if not context.check_tool('systemctl'):
        output.error('systemctl not found. This tool requires systemd.')

        output.render(opts.format, "Detect systemd unit files with local overrides or modifications")
        return 2

    # Get units to check
    if opts.unit:
        units = [opts.unit]
    else:
        units = get_all_units(unit_type=opts.type, context=context)

    if not units:
        output.emit({'units': [], 'message': 'No units found'})
        output.set_summary('No units found')

        output.render(opts.format, "Detect systemd unit files with local overrides or modifications")
        return 0

    # Analyze each unit
    results = []
    for unit in units:
        analysis = analyze_unit_drift(unit, context)
        results.append(analysis)

    # Calculate summary
    total = len(results)
    drifted = [r for r in results if r['has_drift']]
    drift_count = len(drifted)
    clean_count = total - drift_count

    # Apply warn-only filter
    if opts.warn_only:
        results = drifted

    # Prepare output data
    output_data: dict[str, Any] = {
        'units': results,
        'summary': {
            'total_checked': total,
            'units_with_drift': drift_count,
            'clean_units': clean_count,
        }
    }

    # Add drift breakdown
    drift_by_reason: dict[str, int] = {}
    for r in drifted:
        for reason in r['drift_reasons']:
            drift_by_reason[reason] = drift_by_reason.get(reason, 0) + 1
    output_data['summary']['drift_by_reason'] = drift_by_reason

    output.emit(output_data)
    output.set_summary(f'{total} units checked: {drift_count} with drift, {clean_count} clean')

    # Return 1 if drift detected

    output.render(opts.format, "Detect systemd unit files with local overrides or modifications")
    return 1 if drift_count > 0 else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
