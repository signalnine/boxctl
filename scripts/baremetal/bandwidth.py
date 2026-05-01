#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [network, bandwidth, throughput, monitoring]
#   requires: []
#   privilege: none
#   related: [tcp_connection_monitor]
#   brief: Monitor network interface bandwidth utilization

"""
Monitor network interface bandwidth utilization and throughput.

Samples /proc/net/dev over a configurable interval to calculate:
- Bytes per second (RX/TX)
- Packets per second (RX/TX)
- Bandwidth utilization percentage (if speed known)
- Saturation warnings when utilization exceeds thresholds

Useful for:
- Detecting network bottlenecks and saturation
- Monitoring traffic patterns across interfaces
- Identifying high-bandwidth consumers
- Capacity planning and trending
"""

import argparse
import time
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_net_dev(content: str) -> dict[str, dict[str, int]]:
    """Parse /proc/net/dev content into interface statistics."""
    stats = {}
    lines = content.strip().split('\n')

    # Skip header lines (first 2 lines)
    for line in lines[2:]:
        line = line.strip()
        if not line:
            continue

        # Format: iface: rx_bytes rx_packets ... tx_bytes tx_packets ...
        parts = line.split(':')
        if len(parts) != 2:
            continue

        iface = parts[0].strip()
        values = parts[1].split()

        if len(values) >= 16:
            stats[iface] = {
                'rx_bytes': int(values[0]),
                'rx_packets': int(values[1]),
                'rx_errors': int(values[2]),
                'rx_dropped': int(values[3]),
                'tx_bytes': int(values[8]),
                'tx_packets': int(values[9]),
                'tx_errors': int(values[10]),
                'tx_dropped': int(values[11]),
            }

    return stats


def get_interface_speed(iface: str, context: Context) -> int | None:
    """Get interface speed in bits per second."""
    speed_file = f'/sys/class/net/{iface}/speed'
    try:
        content = context.read_file(speed_file)
        speed_mbps = int(content.strip())
        if speed_mbps > 0:
            return speed_mbps * 1_000_000  # Convert Mbps to bps
    except (FileNotFoundError, ValueError, OSError):
        pass

    # Fall back to ethtool if available
    if context.check_tool('ethtool'):
        result = context.run(['ethtool', iface], check=False)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'Speed:' in line:
                    speed_str = line.split(':')[1].strip()
                    if 'Mb/s' in speed_str:
                        try:
                            speed_mbps = int(speed_str.replace('Mb/s', ''))
                            return speed_mbps * 1_000_000
                        except ValueError:
                            pass
                    elif 'Gb/s' in speed_str:
                        try:
                            speed_gbps = int(speed_str.replace('Gb/s', ''))
                            return speed_gbps * 1_000_000_000
                        except ValueError:
                            pass

    return None


def get_interface_operstate(iface: str, context: Context) -> str:
    """Check if interface is up."""
    operstate_file = f'/sys/class/net/{iface}/operstate'
    try:
        return context.read_file(operstate_file).strip()
    except (FileNotFoundError, OSError):
        return 'unknown'


def format_bytes(bytes_val: float) -> str:
    """Format bytes to human-readable string."""
    if bytes_val >= 1_000_000_000:
        return f"{bytes_val / 1_000_000_000:.2f} GB/s"
    elif bytes_val >= 1_000_000:
        return f"{bytes_val / 1_000_000:.2f} MB/s"
    elif bytes_val >= 1_000:
        return f"{bytes_val / 1_000:.2f} KB/s"
    else:
        return f"{bytes_val:.0f} B/s"


def format_speed(bps: int | None) -> str:
    """Format bits per second to human-readable string."""
    if bps is None:
        return "N/A"
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.0f} Gbps"
    elif bps >= 1_000_000:
        return f"{bps / 1_000_000:.0f} Mbps"
    elif bps >= 1_000:
        return f"{bps / 1_000:.0f} Kbps"
    else:
        return f"{bps:.0f} bps"


def calculate_rates(before: dict, after: dict, interval: float) -> dict[str, dict[str, float]]:
    """Calculate per-second rates from two samples."""
    rates = {}

    for iface in after:
        if iface not in before:
            continue

        b = before[iface]
        a = after[iface]

        # Handle counter wraps
        def safe_diff(new: int, old: int) -> int:
            diff = new - old
            if diff < 0:
                diff = (2**64 + new) - old
            return diff

        rx_bytes = safe_diff(a['rx_bytes'], b['rx_bytes'])
        tx_bytes = safe_diff(a['tx_bytes'], b['tx_bytes'])
        rx_packets = safe_diff(a['rx_packets'], b['rx_packets'])
        tx_packets = safe_diff(a['tx_packets'], b['tx_packets'])

        rates[iface] = {
            'rx_bytes_sec': rx_bytes / interval,
            'tx_bytes_sec': tx_bytes / interval,
            'rx_packets_sec': rx_packets / interval,
            'tx_packets_sec': tx_packets / interval,
            'rx_bits_sec': (rx_bytes * 8) / interval,
            'tx_bits_sec': (tx_bytes * 8) / interval,
        }

    return rates


def analyze_bandwidth(rates: dict, context: Context, warn_threshold: float, crit_threshold: float) -> tuple[list, list]:
    """Analyze bandwidth utilization and generate results/issues."""
    results = []
    issues = []

    for iface, rate in rates.items():
        # Skip loopback
        if iface == 'lo':
            continue

        operstate = get_interface_operstate(iface, context)
        speed_bps = get_interface_speed(iface, context)

        result = {
            'interface': iface,
            'operstate': operstate,
            'rx_bytes_sec': round(rate['rx_bytes_sec'], 2),
            'tx_bytes_sec': round(rate['tx_bytes_sec'], 2),
            'rx_packets_sec': round(rate['rx_packets_sec'], 2),
            'tx_packets_sec': round(rate['tx_packets_sec'], 2),
            'speed_bps': speed_bps,
            'rx_utilization_pct': None,
            'tx_utilization_pct': None,
            'status': 'ok'
        }

        # Calculate utilization if speed is known
        if speed_bps and speed_bps > 0:
            rx_util = (rate['rx_bits_sec'] / speed_bps) * 100
            tx_util = (rate['tx_bits_sec'] / speed_bps) * 100
            result['rx_utilization_pct'] = round(rx_util, 2)
            result['tx_utilization_pct'] = round(tx_util, 2)

            max_util = max(rx_util, tx_util)

            if max_util >= crit_threshold:
                result['status'] = 'critical'
                issues.append({
                    'severity': 'critical',
                    'interface': iface,
                    'message': f"{iface}: {max_util:.1f}% utilization exceeds critical threshold ({crit_threshold}%)"
                })
            elif max_util >= warn_threshold:
                result['status'] = 'warning'
                issues.append({
                    'severity': 'warning',
                    'interface': iface,
                    'message': f"{iface}: {max_util:.1f}% utilization exceeds warning threshold ({warn_threshold}%)"
                })

        results.append(result)

    return results, issues


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
    parser = argparse.ArgumentParser(description="Monitor network interface bandwidth")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-i", "--interval", type=float, default=1.0, metavar="SECONDS",
                        help="Sampling interval in seconds (default: 1.0)")
    parser.add_argument("--interface", metavar="IFACE", help="Monitor specific interface only")
    parser.add_argument("--warn", type=float, default=80.0, metavar="PCT",
                        help="Warning threshold percentage (default: 80)")
    parser.add_argument("--crit", type=float, default=95.0, metavar="PCT",
                        help="Critical threshold percentage (default: 95)")
    parser.add_argument("--exclude-down", action="store_true",
                        help="Exclude interfaces that are not up")
    opts = parser.parse_args(args)

    if opts.interval <= 0:
        output.error("Interval must be positive")

        output.render(opts.format, "Monitor network interface bandwidth utilization")
        return 2

    if opts.warn >= opts.crit:
        output.error("Warning threshold must be less than critical threshold")

        output.render(opts.format, "Monitor network interface bandwidth utilization")
        return 2

    # Read /proc/net/dev
    try:
        before_content = context.read_file('/proc/net/dev')
    except FileNotFoundError:
        output.error("Cannot read /proc/net/dev")

        output.render(opts.format, "Monitor network interface bandwidth utilization")
        return 2

    before = parse_net_dev(before_content)
    if not before:
        output.error("No network interfaces found")

        output.render(opts.format, "Monitor network interface bandwidth utilization")
        return 2

    # Wait for sampling interval
    time.sleep(opts.interval)

    # Take second sample
    try:
        after_content = context.read_file('/proc/net/dev')
    except FileNotFoundError:
        output.error("Cannot read /proc/net/dev")

        output.render(opts.format, "Monitor network interface bandwidth utilization")
        return 2

    after = parse_net_dev(after_content)

    # Calculate rates
    rates = calculate_rates(before, after, opts.interval)

    # Filter to specific interface if requested
    if opts.interface:
        if opts.interface not in rates:
            output.error(f"Interface '{opts.interface}' not found")
            return 2
        rates = {opts.interface: rates[opts.interface]}

    # Analyze bandwidth
    results, issues = analyze_bandwidth(rates, context, opts.warn, opts.crit)

    # Exclude down interfaces if requested
    if opts.exclude_down:
        results = [r for r in results if r['operstate'] == 'up']
        affected_ifaces = {r['interface'] for r in results}
        issues = [i for i in issues if i['interface'] in affected_ifaces]

    # Emit results
    output.emit({
        'sample_interval_sec': opts.interval,
        'interfaces': results,
        'issues': issues
    })

    # Set summary
    up_count = len([r for r in results if r['operstate'] == 'up'])
    if issues:
        output.set_summary(f"{len(issues)} interfaces with high utilization")
    else:
        output.set_summary(f"{up_count} interfaces within thresholds")

    output.render(opts.format, "Monitor network interface bandwidth utilization")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
