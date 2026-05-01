#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [network, latency, ping, monitoring, performance]
#   requires: [ping]
#   privilege: user
#   related: [network_qdisc_monitor, socket_state_monitor]
#   brief: Monitor network latency to configured peers and gateways

"""
Monitor network latency to configured peers and gateways.

Measures round-trip time (RTT) to specified network targets using ICMP ping
or TCP connect probes. Useful for detecting network degradation, high latency
paths, or connectivity issues.
"""

import argparse
import re
import socket
import time
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_default_gateway(context: Context) -> str | None:
    """Get the default gateway IP address."""
    try:
        result = context.run(['ip', 'route', 'show', 'default'], check=False)
        if result.returncode != 0:
            return None

        match = re.search(r'default via ([\d.]+)', result.stdout)
        return match.group(1) if match else None
    except Exception:
        return None


def ping_target(
    context: Context,
    target: str,
    count: int = 5,
    timeout: int = 2
) -> dict[str, Any]:
    """Ping a target and return latency statistics."""
    result_data = {
        'target': target,
        'reachable': False,
        'method': 'icmp',
        'packets_sent': count,
        'packets_received': 0,
        'packet_loss_pct': 100.0,
        'min_ms': None,
        'avg_ms': None,
        'max_ms': None,
        'stddev_ms': None,
        'error': None,
    }

    try:
        result = context.run(
            ['ping', '-c', str(count), '-W', str(timeout), target],
            check=False
        )
    except Exception as e:
        result_data['error'] = str(e)
        return result_data

    stdout = result.stdout

    # Parse packet statistics
    stats_match = re.search(
        r'(\d+) packets transmitted, (\d+) (?:packets )?received',
        stdout
    )
    if stats_match:
        result_data['packets_sent'] = int(stats_match.group(1))
        result_data['packets_received'] = int(stats_match.group(2))
        if result_data['packets_sent'] > 0:
            result_data['packet_loss_pct'] = (
                (result_data['packets_sent'] - result_data['packets_received']) /
                result_data['packets_sent'] * 100
            )

    # Parse RTT statistics
    rtt_match = re.search(
        r'(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = '
        r'([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)',
        stdout
    )
    if rtt_match:
        result_data['min_ms'] = float(rtt_match.group(1))
        result_data['avg_ms'] = float(rtt_match.group(2))
        result_data['max_ms'] = float(rtt_match.group(3))
        result_data['stddev_ms'] = float(rtt_match.group(4))
        result_data['reachable'] = True
    elif result_data['packets_received'] > 0:
        result_data['reachable'] = True

    return result_data


def tcp_probe_target(
    target: str,
    port: int = 443,
    count: int = 5,
    timeout: int = 2
) -> dict[str, Any]:
    """Measure TCP connect latency to a target."""
    result_data = {
        'target': target,
        'port': port,
        'reachable': False,
        'method': 'tcp',
        'attempts': count,
        'successful': 0,
        'failure_rate_pct': 100.0,
        'min_ms': None,
        'avg_ms': None,
        'max_ms': None,
        'error': None,
    }

    latencies = []

    for _ in range(count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            start_time = time.perf_counter()
            sock.connect((target, port))
            end_time = time.perf_counter()

            latency_ms = (end_time - start_time) * 1000
            latencies.append(latency_ms)
            result_data['successful'] += 1

            sock.close()
        except socket.timeout:
            pass
        except socket.gaierror as e:
            result_data['error'] = f"DNS resolution failed: {e}"
            break
        except socket.error as e:
            result_data['error'] = str(e)
        except Exception as e:
            result_data['error'] = str(e)

    if latencies:
        result_data['min_ms'] = min(latencies)
        result_data['max_ms'] = max(latencies)
        result_data['avg_ms'] = sum(latencies) / len(latencies)
        result_data['reachable'] = True

    if result_data['attempts'] > 0:
        result_data['failure_rate_pct'] = (
            (result_data['attempts'] - result_data['successful']) /
            result_data['attempts'] * 100
        )

    return result_data


def analyze_results(
    results: list[dict[str, Any]],
    warn_ms: float,
    crit_ms: float,
    max_loss_pct: float
) -> list[dict[str, Any]]:
    """Analyze results and add status based on thresholds."""
    for result in results:
        result['status'] = 'ok'
        result['issues'] = []

        if not result['reachable']:
            result['status'] = 'critical'
            result['issues'].append('unreachable')
            continue

        avg_ms = result.get('avg_ms')
        if avg_ms is not None:
            if avg_ms >= crit_ms:
                result['status'] = 'critical'
                result['issues'].append(f'latency {avg_ms:.1f}ms >= {crit_ms}ms')
            elif avg_ms >= warn_ms:
                result['status'] = 'warning'
                result['issues'].append(f'latency {avg_ms:.1f}ms >= {warn_ms}ms')

        loss_pct = result.get('packet_loss_pct', result.get('failure_rate_pct', 0))
        if loss_pct > max_loss_pct:
            if result['status'] != 'critical':
                result['status'] = 'warning'
            result['issues'].append(f'packet loss {loss_pct:.1f}% > {max_loss_pct}%')

    return results


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all OK, 1 = issues detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Monitor network latency to peers and gateways'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed information')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    parser.add_argument('-t', '--targets',
                        help='Comma-separated list of targets (default: gateway)')
    parser.add_argument('-c', '--count', type=int, default=5,
                        help='Number of probes per target (default: 5)')
    parser.add_argument('--timeout', type=int, default=2,
                        help='Timeout per probe in seconds (default: 2)')
    parser.add_argument('--tcp', action='store_true',
                        help='Use TCP connect probes instead of ICMP')
    parser.add_argument('-p', '--port', type=int, default=443,
                        help='TCP port for --tcp mode (default: 443)')
    parser.add_argument('--warn-ms', type=float, default=50.0,
                        help='Warning threshold for avg latency (default: 50)')
    parser.add_argument('--crit-ms', type=float, default=100.0,
                        help='Critical threshold for avg latency (default: 100)')
    parser.add_argument('--max-loss', type=float, default=10.0,
                        help='Maximum acceptable packet loss %% (default: 10)')
    opts = parser.parse_args(args)

    # Determine targets
    targets = []
    if opts.targets:
        targets = [t.strip() for t in opts.targets.split(',') if t.strip()]
    else:
        gateway = get_default_gateway(context)
        if gateway:
            targets = [gateway]
        else:
            output.error('No default gateway found and no targets specified')
            return 2

    # Check dependencies for ICMP mode
    if not opts.tcp and not context.check_tool('ping'):
        output.error('ping command not available. Use --tcp for TCP probes')

        output.render(opts.format, "Monitor network latency to configured peers and gateways")
        return 2

    # Probe all targets
    results = []
    for target in targets:
        if opts.tcp:
            result = tcp_probe_target(
                target,
                port=opts.port,
                count=opts.count,
                timeout=opts.timeout
            )
        else:
            result = ping_target(
                context,
                target,
                count=opts.count,
                timeout=opts.timeout
            )
        results.append(result)

    # Analyze results
    results = analyze_results(
        results,
        warn_ms=opts.warn_ms,
        crit_ms=opts.crit_ms,
        max_loss_pct=opts.max_loss
    )

    # Build output
    ok_count = sum(1 for r in results if r['status'] == 'ok')
    warn_count = sum(1 for r in results if r['status'] == 'warning')
    crit_count = sum(1 for r in results if r['status'] == 'critical')

    data = {
        'summary': {
            'total_targets': len(results),
            'ok': ok_count,
            'warning': warn_count,
            'critical': crit_count,
            'has_issues': (warn_count + crit_count) > 0,
        },
        'results': results,
    }

    output.emit(data)

    # Set summary
    output.set_summary(
        f"{ok_count} OK, {warn_count} warnings, {crit_count} critical"
    )

    # Determine exit code
    if crit_count > 0 or warn_count > 0:

        output.render(opts.format, "Monitor network latency to configured peers and gateways")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
