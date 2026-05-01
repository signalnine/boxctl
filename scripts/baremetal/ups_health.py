#!/usr/bin/env python3
# boxctl:
#   category: baremetal/power
#   tags: [ups, power, battery, nut, apc, hardware]
#   requires: []
#   privilege: user
#   related: [power_consumption, thermal_throttle]
#   brief: Monitor UPS (Uninterruptible Power Supply) status

"""
Monitor UPS (Uninterruptible Power Supply) status on baremetal systems.

Checks UPS health using Network UPS Tools (NUT) or APC apcaccess including:
- Battery charge level and runtime remaining
- Input/output voltage and frequency
- UPS load percentage
- Battery status (charging, discharging, on battery)
- Alarms and fault conditions

Critical for datacenter environments where power failures can cause data loss
and unexpected outages. Supports proactive alerting before battery depletion.
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_numeric(value_str: str | None) -> float | None:
    """Parse a numeric value from a string, removing units."""
    if not value_str:
        return None

    clean = value_str.split()[0] if value_str else ''
    try:
        return float(clean)
    except (ValueError, TypeError):
        return None


def get_nut_ups_list(context: Context) -> list[str]:
    """Get list of UPS devices from NUT."""
    result = context.run(['upsc', '-l'], check=False)
    if result.returncode != 0:
        return []

    ups_list = []
    for line in result.stdout.strip().split('\n'):
        if line.strip():
            ups_list.append(line.strip())

    return ups_list


def get_nut_ups_data(ups_name: str, context: Context) -> dict[str, Any] | None:
    """Get UPS data from NUT for a specific UPS."""
    result = context.run(['upsc', ups_name], check=False)
    if result.returncode != 0:
        return None

    data: dict[str, Any] = {'name': ups_name, 'source': 'nut'}
    for line in result.stdout.strip().split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            data[key.strip()] = value.strip()

    return data


def get_apcaccess_data(context: Context) -> dict[str, Any] | None:
    """Get UPS data from apcaccess (APC UPS)."""
    result = context.run(['apcaccess'], check=False)
    if result.returncode != 0:
        return None

    data: dict[str, Any] = {'name': 'apc', 'source': 'apcaccess'}
    for line in result.stdout.strip().split('\n'):
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                data[key] = value

    return data


def analyze_ups_health(ups_data: dict[str, Any] | None) -> dict[str, Any]:
    """Analyze UPS data and determine health status."""
    health: dict[str, Any] = {
        'status': 'OK',
        'issues': [],
        'warnings': [],
        'battery_charge': None,
        'runtime_minutes': None,
        'load_percent': None,
        'on_battery': False,
        'input_voltage': None,
        'output_voltage': None
    }

    if not ups_data:
        health['status'] = 'UNKNOWN'
        health['issues'].append('No UPS data available')
        return health

    source = ups_data.get('source', '')

    # Parse based on data source
    if source == 'nut':
        status = ups_data.get('ups.status', '')
        health['battery_charge'] = parse_numeric(ups_data.get('battery.charge'))
        health['runtime_minutes'] = parse_numeric(ups_data.get('battery.runtime'))
        if health['runtime_minutes']:
            health['runtime_minutes'] = health['runtime_minutes'] / 60  # Convert to minutes
        health['load_percent'] = parse_numeric(ups_data.get('ups.load'))
        health['input_voltage'] = parse_numeric(ups_data.get('input.voltage'))
        health['output_voltage'] = parse_numeric(ups_data.get('output.voltage'))

        # Check status flags
        if 'OB' in status:
            health['on_battery'] = True
        if 'LB' in status:
            health['issues'].append('Low battery')
        if 'RB' in status:
            health['warnings'].append('Replace battery')
        if 'ALARM' in status:
            health['issues'].append('UPS alarm active')
        if 'FSD' in status:
            health['issues'].append('Forced shutdown in progress')

    elif source == 'apcaccess':
        status = ups_data.get('STATUS', '')
        health['battery_charge'] = parse_numeric(ups_data.get('BCHARGE'))
        health['runtime_minutes'] = parse_numeric(ups_data.get('TIMELEFT'))
        health['load_percent'] = parse_numeric(ups_data.get('LOADPCT'))
        health['input_voltage'] = parse_numeric(ups_data.get('LINEV'))
        health['output_voltage'] = parse_numeric(ups_data.get('OUTPUTV'))

        # Check status
        if 'ONBATT' in status:
            health['on_battery'] = True
        if 'LOWBATT' in status:
            health['issues'].append('Low battery')
        if 'REPLACEBATT' in status:
            health['warnings'].append('Replace battery')
        if 'CAL' in status:
            health['warnings'].append('Calibration in progress')
        if 'OVERLOAD' in status:
            health['issues'].append('UPS overloaded')

    # Evaluate thresholds
    if health['on_battery']:
        health['warnings'].append('Running on battery power')

    if health['battery_charge'] is not None:
        if health['battery_charge'] < 20:
            health['issues'].append(f"Critical battery level: {health['battery_charge']:.0f}%")
        elif health['battery_charge'] < 50:
            health['warnings'].append(f"Low battery level: {health['battery_charge']:.0f}%")

    if health['runtime_minutes'] is not None:
        if health['runtime_minutes'] < 5:
            health['issues'].append(f"Critical runtime remaining: {health['runtime_minutes']:.1f} min")
        elif health['runtime_minutes'] < 15:
            health['warnings'].append(f"Low runtime remaining: {health['runtime_minutes']:.1f} min")

    if health['load_percent'] is not None:
        if health['load_percent'] > 90:
            health['issues'].append(f"UPS near capacity: {health['load_percent']:.0f}% load")
        elif health['load_percent'] > 75:
            health['warnings'].append(f"High UPS load: {health['load_percent']:.0f}%")

    # Determine overall status
    if health['issues']:
        health['status'] = 'CRITICAL'
    elif health['warnings']:
        health['status'] = 'WARNING'
    else:
        health['status'] = 'OK'

    return health


def collect_all_ups_data(context: Context) -> list[dict[str, Any]]:
    """Collect UPS data from all available sources."""
    ups_units = []

    # Try NUT first
    if context.check_tool('upsc'):
        nut_list = get_nut_ups_list(context)
        for ups_name in nut_list:
            data = get_nut_ups_data(ups_name, context)
            if data:
                data['health'] = analyze_ups_health(data)
                ups_units.append(data)

    # Try apcaccess if no NUT devices or as fallback
    if context.check_tool('apcaccess'):
        apc_data = get_apcaccess_data(context)
        if apc_data and apc_data.get('STATUS'):
            apc_data['health'] = analyze_ups_health(apc_data)
            ups_units.append(apc_data)

    return ups_units


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
        description='Monitor UPS (Uninterruptible Power Supply) status'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed UPS information including raw data')
    parser.add_argument('-w', '--warn-only', action='store_true',
                        help='Only show warning and critical conditions')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    # Check if any UPS tools are available
    has_nut = context.check_tool('upsc')
    has_apc = context.check_tool('apcaccess')

    if not has_nut and not has_apc:
        output.error('No UPS monitoring tools found.')
        output.error('Install nut-client (upsc) or apcupsd (apcaccess)')

        output.render(opts.format, "Monitor UPS (Uninterruptible Power Supply) status")
        return 2

    # Collect UPS data
    ups_units = collect_all_ups_data(context)

    if not ups_units:
        output.emit({
            'ups_units': [],
            'summary': {'total_ups': 0, 'critical': 0, 'warning': 0, 'ok': 0},
            'message': 'No UPS devices found'
        })
        output.set_summary('No UPS devices found')

        output.render(opts.format, "Monitor UPS (Uninterruptible Power Supply) status")
        return 0

    # Apply warn-only filter
    if opts.warn_only:
        ups_units = [u for u in ups_units
                     if u.get('health', {}).get('status') != 'OK']

    # Calculate summary
    total_ups = len(ups_units)
    critical_count = sum(1 for u in ups_units
                         if u.get('health', {}).get('status') == 'CRITICAL')
    warning_count = sum(1 for u in ups_units
                        if u.get('health', {}).get('status') == 'WARNING')
    ok_count = sum(1 for u in ups_units
                   if u.get('health', {}).get('status') == 'OK')

    # Prepare output data
    output_data: dict[str, Any] = {
        'ups_units': ups_units if opts.verbose else [
            {
                'name': u.get('name'),
                'source': u.get('source'),
                'health': u.get('health')
            } for u in ups_units
        ],
        'summary': {
            'total_ups': total_ups,
            'critical': critical_count,
            'warning': warning_count,
            'ok': ok_count
        }
    }

    output.emit(output_data)

    if critical_count > 0:
        output.set_summary(f'UPS CRITICAL: {critical_count} critical issues')
    elif warning_count > 0:
        output.set_summary(f'UPS WARNING: {warning_count} warnings')
    else:
        output.set_summary(f'UPS OK: {total_ups} unit(s) healthy')

    # Determine exit code
    if critical_count > 0 or warning_count > 0:

        output.render(opts.format, "Monitor UPS (Uninterruptible Power Supply) status")
        return 1


    output.render(opts.format, "Monitor UPS (Uninterruptible Power Supply) status")
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
