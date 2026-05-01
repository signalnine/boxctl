#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart, storage, hardware]
#   requires: [smartctl]
#   privilege: root
#   related: [disk_space_forecaster, disk_life_predictor, disk_io_latency]
#   brief: Check disk health using SMART attributes

"""
Check disk health using SMART (Self-Monitoring, Analysis and Reporting Technology).

Scans all disk devices and reports their SMART health status.
Returns exit code 1 if any disk is failing or has concerning attributes.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_disk_list(context: Context) -> list[str]:
    """Get list of disk devices."""
    result = context.run(["lsblk", "-d", "-n", "-o", "NAME,TYPE"])
    disks = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "disk":
            disks.append(f"/dev/{parts[0]}")
    return disks


def check_smart_health(disk: str, context: Context) -> dict[str, Any]:
    """Check SMART health status for a disk."""
    result = context.run(["smartctl", "-H", disk], check=False)
    output = result.stdout

    status = "UNKNOWN"
    # SATA drives
    if "SMART overall-health self-assessment test result: PASSED" in output:
        status = "PASSED"
    elif "SMART overall-health self-assessment test result: FAILED" in output:
        status = "FAILED"
    # SAS drives
    elif "SMART Health Status: OK" in output:
        status = "PASSED"
    elif "SMART Health Status:" in output and "OK" not in output.split("SMART Health Status:")[1].split("\n")[0]:
        status = "FAILED"
    elif "SMART support is: Unavailable" in output:
        status = "UNAVAILABLE"
    elif "SMART support is: Disabled" in output:
        status = "DISABLED"

    info = {
        "device": disk,
        "status": status,
    }

    # Extract model — SATA uses "Device Model:", SAS uses "Product:"
    model_match = re.search(r"(?:Device Model|Product):\s+(.+)", output)
    if model_match:
        info["model"] = model_match.group(1).strip()

    # Extract serial — SATA uses "Serial Number:", SAS uses "Serial number:"
    serial_match = re.search(r"Serial [Nn]umber:\s+(.+)", output)
    if serial_match:
        info["serial"] = serial_match.group(1).strip()

    return info


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
    parser = argparse.ArgumentParser(description="Check disk health using SMART")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for smartctl
    if not context.check_tool("smartctl"):
        output.error("smartctl not found. Install smartmontools package.")

        output.render(opts.format, "Check disk health using SMART attributes")
        return 2

    # Get disk list
    try:
        disks = get_disk_list(context)
    except Exception as e:
        output.error(f"Failed to list disks: {e}")

        output.render(opts.format, "Check disk health using SMART attributes")
        return 2

    if not disks:
        output.warning("No disks found")
        output.emit({"disks": []})

        output.render(opts.format, "Check disk health using SMART attributes")
        return 1

    # Check each disk
    results = []
    has_issues = False

    for disk in disks:
        info = check_smart_health(disk, context)
        results.append(info)

        if info["status"] == "FAILED":
            has_issues = True

        if not opts.verbose:
            # Remove extra fields in non-verbose mode
            info.pop("model", None)
            info.pop("serial", None)

    output.emit({"disks": results})

    # Set summary
    passed = sum(1 for r in results if r["status"] == "PASSED")
    failed = sum(1 for r in results if r["status"] == "FAILED")
    output.set_summary(f"{passed} healthy, {failed} failing")


    output.render(opts.format, "Check disk health using SMART attributes")
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
