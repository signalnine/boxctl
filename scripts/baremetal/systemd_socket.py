#!/usr/bin/env python3
# boxctl:
#   category: baremetal/systemd
#   tags: [systemd, socket, activation, services]
#   requires: [systemctl]
#   privilege: user
#   related: [systemd_service_monitor, systemd_drift, systemd_timer_monitor]
#   brief: Monitor systemd socket activation units for health and connection status

"""
Monitor systemd socket activation units for health and connection status.

Socket activation is a systemd feature where services start on-demand when
connections arrive at a listening socket. This script monitors:

- Socket unit status (active, listening, failed)
- Socket-to-service associations
- Connection queues and accepted connections
- Failed socket activations
- Orphaned sockets (no associated service)

Common issues detected:
- Failed socket units preventing service activation
- Socket units stuck in non-listening state
- Services failing to start on socket activation
- Connection backlog buildup indicating performance issues
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_socket_units(context: Context) -> list[dict[str, str]]:
    """Get list of all socket units with their status."""
    sockets = []

    result = context.run([
        'systemctl', 'list-units', '--type=socket', '--all',
        '--no-legend', '--no-pager'
    ], check=False)

    if result.returncode != 0:
        return sockets

    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue

        # Parse: UNIT LOAD ACTIVE SUB DESCRIPTION
        parts = line.split(None, 4)
        if len(parts) >= 4:
            sockets.append({
                'unit': parts[0],
                'load': parts[1],
                'active': parts[2],
                'sub': parts[3],
                'description': parts[4] if len(parts) > 4 else ''
            })

    return sockets


def get_socket_details(unit: str, context: Context) -> dict[str, Any]:
    """Get detailed information about a socket unit."""
    details: dict[str, Any] = {
        'unit': unit,
        'listen': [],
        'triggers': [],
        'accepted': 0,
        'connections': 0,
        'n_refused': 0,
    }

    result = context.run([
        'systemctl', 'show', unit,
        '--property=Listen',
        '--property=Triggers',
        '--property=NAccepted',
        '--property=NConnections',
        '--property=NRefused',
        '--property=ActiveState',
        '--property=SubState',
        '--property=Result',
        '--property=Backlog',
        '--property=MaxConnections',
        '--property=Accept',
    ], check=False)

    if result.returncode == 0:
        for line in result.stdout.strip().split('\n'):
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()

            if key == 'Listen':
                if value:
                    for addr in value.split():
                        if addr and addr not in ['Stream:', 'Datagram:', 'Sequential:']:
                            details['listen'].append(addr)
            elif key == 'Triggers':
                if value:
                    details['triggers'] = [t.strip() for t in value.split() if t.strip()]
            elif key == 'NAccepted':
                try:
                    details['accepted'] = int(value)
                except ValueError:
                    pass
            elif key == 'NConnections':
                try:
                    details['connections'] = int(value)
                except ValueError:
                    pass
            elif key == 'NRefused':
                try:
                    details['n_refused'] = int(value)
                except ValueError:
                    pass
            elif key == 'ActiveState':
                details['active_state'] = value
            elif key == 'SubState':
                details['sub_state'] = value
            elif key == 'Result':
                details['result'] = value
            elif key == 'Accept':
                details['accept'] = value.lower() == 'yes'

    return details


def check_triggered_service_status(triggers: list[str], context: Context) -> dict[str, str]:
    """Check the status of triggered services."""
    service_status = {}

    for service in triggers:
        result = context.run([
            'systemctl', 'show', service,
            '--property=ActiveState', '--property=SubState'
        ], check=False)

        if result.returncode == 0:
            active_state = 'unknown'
            sub_state = 'unknown'
            for line in result.stdout.strip().split('\n'):
                if line.startswith('ActiveState='):
                    active_state = line.split('=', 1)[1]
                elif line.startswith('SubState='):
                    sub_state = line.split('=', 1)[1]
            service_status[service] = f"{active_state}/{sub_state}"
        else:
            service_status[service] = 'unknown'

    return service_status


def analyze_socket(
    socket_info: dict[str, str],
    details: dict[str, Any],
    refuse_warn: int,
    context: Context
) -> dict[str, Any]:
    """Analyze a socket unit and identify issues."""
    result: dict[str, Any] = {
        'unit': socket_info['unit'],
        'status': 'healthy',
        'issues': [],
        'warnings': [],
        'listen': details.get('listen', []),
        'triggers': details.get('triggers', []),
        'metrics': {
            'accepted': details.get('accepted', 0),
            'connections': details.get('connections', 0),
            'refused': details.get('n_refused', 0),
        }
    }

    active = socket_info.get('active', 'unknown')
    sub = socket_info.get('sub', 'unknown')
    load = socket_info.get('load', 'unknown')

    result['active'] = active
    result['sub'] = sub
    result['load'] = load

    # Check for failed state
    if active == 'failed' or sub == 'failed':
        result['status'] = 'critical'
        result['issues'].append({
            'type': 'socket_failed',
            'message': f'Socket unit is in failed state: {active}/{sub}'
        })

    # Check for inactive state (not listening)
    elif active == 'inactive':
        result['status'] = 'warning'
        result['warnings'].append({
            'type': 'socket_inactive',
            'message': 'Socket unit is inactive (not listening)'
        })

    # Check load state
    if load == 'not-found':
        result['status'] = 'critical'
        result['issues'].append({
            'type': 'unit_not_found',
            'message': 'Socket unit file not found'
        })
    elif load == 'error':
        result['status'] = 'critical'
        result['issues'].append({
            'type': 'unit_load_error',
            'message': 'Error loading socket unit file'
        })

    # Check for refused connections
    refused = details.get('n_refused', 0)
    if refused > 0 and refused >= refuse_warn:
        if result['status'] == 'healthy':
            result['status'] = 'warning'
        result['warnings'].append({
            'type': 'connections_refused',
            'value': refused,
            'message': f'{refused} connections refused (indicates overload or misconfiguration)'
        })

    # Check for no triggered service
    triggers = details.get('triggers', [])
    if not triggers and active == 'active':
        if result['status'] == 'healthy':
            result['status'] = 'warning'
        result['warnings'].append({
            'type': 'no_triggered_service',
            'message': 'Socket has no associated service to trigger'
        })

    # Check triggered service status
    if triggers:
        service_status = check_triggered_service_status(triggers, context)
        result['service_status'] = service_status

        for service, status in service_status.items():
            if 'failed' in status:
                if result['status'] != 'critical':
                    result['status'] = 'critical'
                result['issues'].append({
                    'type': 'triggered_service_failed',
                    'service': service,
                    'message': f'Triggered service {service} is in failed state: {status}'
                })

    # Check result field (for sockets that ran and stopped)
    socket_result = details.get('result', 'success')
    if socket_result not in ['success', '']:
        if result['status'] == 'healthy':
            result['status'] = 'warning'
        result['warnings'].append({
            'type': 'socket_result',
            'value': socket_result,
            'message': f'Socket activation result: {socket_result}'
        })

    return result


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Monitor systemd socket activation units'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed metrics')
    parser.add_argument('-w', '--warn-only', action='store_true',
                        help='Only show sockets with issues')
    parser.add_argument('-u', '--unit', metavar='NAME',
                        help='Specific socket unit to check')
    parser.add_argument('--refuse-warn', type=int, default=10, metavar='COUNT',
                        help='Warn if refused connections exceed count (default: 10)')
    parser.add_argument('--include-inactive', action='store_true',
                        help='Include inactive socket units')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    # Check for systemctl
    if not context.check_tool('systemctl'):
        output.error('systemctl not found. This tool requires systemd.')

        output.render(opts.format, "Monitor systemd socket activation units for health and connection status")
        return 2

    # Get sockets to check
    if opts.unit:
        unit = opts.unit
        if not unit.endswith('.socket'):
            unit = f'{unit}.socket'

        # Verify unit exists
        result = context.run(['systemctl', 'show', unit, '--property=LoadState'],
                            check=False)
        if 'LoadState=not-found' in result.stdout:
            output.error(f'Socket unit {unit} not found')
            return 2

        sockets = [{
            'unit': unit,
            'load': 'loaded',
            'active': 'unknown',
            'sub': 'unknown',
            'description': ''
        }]

        # Get actual status
        result = context.run([
            'systemctl', 'show', unit,
            '--property=LoadState', '--property=ActiveState', '--property=SubState'
        ], check=False)
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line.startswith('LoadState='):
                    sockets[0]['load'] = line.split('=', 1)[1]
                elif line.startswith('ActiveState='):
                    sockets[0]['active'] = line.split('=', 1)[1]
                elif line.startswith('SubState='):
                    sockets[0]['sub'] = line.split('=', 1)[1]
    else:
        sockets = get_socket_units(context)

    if not sockets:
        output.emit({'sockets': [], 'message': 'No socket units found'})
        output.set_summary('No socket units found')

        output.render(opts.format, "Monitor systemd socket activation units for health and connection status")
        return 0

    # Filter inactive if not requested
    if not opts.include_inactive and not opts.unit:
        sockets = [s for s in sockets if s['active'] != 'inactive' or s['load'] == 'error']
        # Always include failed sockets
        all_sockets = get_socket_units(context)
        inactive_failed = [s for s in all_sockets
                          if s['active'] == 'inactive' and s['sub'] == 'failed']
        for s in inactive_failed:
            if s not in sockets:
                sockets.append(s)

    if not sockets:
        output.emit({'sockets': [], 'message': 'No active socket units'})
        output.set_summary('No active socket units')

        output.render(opts.format, "Monitor systemd socket activation units for health and connection status")
        return 0

    # Analyze each socket
    results = []
    for socket in sockets:
        details = get_socket_details(socket['unit'], context)
        result = analyze_socket(socket, details, opts.refuse_warn, context)
        results.append(result)

    # Sort by status (critical first, then warning, then healthy)
    status_order = {'critical': 0, 'warning': 1, 'healthy': 2}
    results.sort(key=lambda x: (status_order.get(x['status'], 3), x['unit']))

    # Apply warn-only filter
    if opts.warn_only:
        results = [r for r in results if r['status'] != 'healthy']

    # Prepare output
    total = len(results)
    healthy = sum(1 for r in results if r['status'] == 'healthy')
    warning = sum(1 for r in results if r['status'] == 'warning')
    critical = sum(1 for r in results if r['status'] == 'critical')

    total_accepted = sum(r.get('metrics', {}).get('accepted', 0) for r in results)
    total_refused = sum(r.get('metrics', {}).get('refused', 0) for r in results)

    output.emit({
        'sockets': results,
        'summary': {
            'total': total,
            'healthy': healthy,
            'warning': warning,
            'critical': critical,
            'total_accepted': total_accepted,
            'total_refused': total_refused,
        }
    })

    output.set_summary(f'{total} sockets: {healthy} healthy, {warning} warning, {critical} critical')

    # Determine exit code
    if critical > 0 or warning > 0:

        output.render(opts.format, "Monitor systemd socket activation units for health and connection status")
        return 1

    output.render(opts.format, "Monitor systemd socket activation units for health and connection status")
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
