#!/usr/bin/env python3
# boxctl:
#   category: baremetal/hardware
#   tags: [hardware, inventory, dmi, smbios, bios, asset]
#   requires: []
#   privilege: user
#   related: [firmware_inventory]
#   brief: Report DMI/SMBIOS hardware inventory and asset information

"""
Report DMI/SMBIOS hardware inventory and asset information.

Reads from /sys/class/dmi/id/ to collect system identification and
BIOS information including vendor, model, serial number, BIOS version
and release date. Warns if BIOS is more than 3 years old.

Exit codes:
    0: Inventory collected successfully
    1: Issues found (e.g., old BIOS)
    2: DMI interface not available
"""

import argparse
from datetime import datetime, timedelta
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output

DMI_DIR = '/sys/class/dmi/id'

DMI_FIELDS = [
    'sys_vendor',
    'product_name',
    'product_serial',
    'bios_vendor',
    'bios_version',
    'bios_date',
    'board_vendor',
    'board_name',
    'chassis_type',
]


def read_dmi_fields(context: Context) -> dict[str, str | None]:
    """Read DMI fields from sysfs, returning None for missing ones."""
    fields: dict[str, str | None] = {}
    for field in DMI_FIELDS:
        path = f'{DMI_DIR}/{field}'
        if context.file_exists(path):
            try:
                fields[field] = context.read_file(path).strip()
            except Exception:
                fields[field] = None
        else:
            fields[field] = None
    return fields


def parse_bios_date(date_str: str | None) -> datetime | None:
    """Parse BIOS date in MM/DD/YYYY format. Returns None on failure."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, '%m/%d/%Y')
    except ValueError:
        return None


def check_bios_age(bios_date: datetime | None, now: datetime | None = None) -> list[dict[str, str]]:
    """Check if BIOS date is more than 3 years old. Returns list of issues."""
    if bios_date is None:
        return []
    if now is None:
        now = datetime.now()
    threshold = now - timedelta(days=3 * 365)
    if bios_date < threshold:
        age_days = (now - bios_date).days
        age_years = age_days / 365.25
        return [{
            'severity': 'WARNING',
            'message': f'BIOS date is {age_years:.1f} years old ({bios_date.strftime("%m/%d/%Y")})',
        }]
    return []


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
        description="Report DMI/SMBIOS hardware inventory and asset information"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check DMI directory exists
    if not context.file_exists(DMI_DIR):
        output.error("DMI interface not available at /sys/class/dmi/id/")
        output.render(opts.format, "DMI/SMBIOS Hardware Inventory")
        return 2

    # Read all DMI fields
    fields = read_dmi_fields(context)

    # Parse and check BIOS age
    bios_date_parsed = parse_bios_date(fields.get('bios_date'))
    issues = check_bios_age(bios_date_parsed)

    # Build inventory dict
    inventory = {
        'system': {
            'vendor': fields['sys_vendor'],
            'product_name': fields['product_name'],
            'serial': fields['product_serial'],
        },
        'bios': {
            'vendor': fields['bios_vendor'],
            'version': fields['bios_version'],
            'date': fields['bios_date'],
        },
        'board': {
            'vendor': fields['board_vendor'],
            'name': fields['board_name'],
        },
        'chassis': {
            'type': fields['chassis_type'],
        },
    }

    data = {
        'inventory': inventory,
        'issues': issues,
    }

    output.emit(data)

    # Generate summary
    if issues:
        output.set_summary(f"{len(issues)} issue(s) found")
    else:
        output.set_summary("DMI inventory collected successfully")

    output.render(opts.format, "DMI/SMBIOS Hardware Inventory")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
