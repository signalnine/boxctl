"""Tests for btrfs_health script."""

from datetime import datetime, timedelta

import pytest
from pathlib import Path

from boxctl.core.output import Output


def _recent_scrub_line() -> str:
    d = datetime.now() - timedelta(days=5)
    return d.strftime("%a %b %d %H:%M:%S %Y")


@pytest.fixture
def btrfs_usage_healthy(fixtures_dir):
    """Load healthy BTRFS usage output."""
    return (fixtures_dir / "storage" / "btrfs_usage_healthy.txt").read_text()


@pytest.fixture
def btrfs_usage_high(fixtures_dir):
    """Load high usage BTRFS output."""
    return (fixtures_dir / "storage" / "btrfs_usage_high.txt").read_text()


@pytest.fixture
def btrfs_device_stats_healthy(fixtures_dir):
    """Load healthy device stats output."""
    return (fixtures_dir / "storage" / "btrfs_device_stats_healthy.txt").read_text()


@pytest.fixture
def btrfs_device_stats_errors(fixtures_dir):
    """Load device stats with errors."""
    return (fixtures_dir / "storage" / "btrfs_device_stats_errors.txt").read_text()


@pytest.fixture
def btrfs_scrub_healthy(fixtures_dir):
    """Load healthy scrub status (scrub date re-templated to stay recent)."""
    text = (fixtures_dir / "storage" / "btrfs_scrub_healthy.txt").read_text()
    return text.replace("Wed Jan 29 10:00:00 2026", _recent_scrub_line())


@pytest.fixture
def btrfs_scrub_old(fixtures_dir):
    """Load old scrub status."""
    return (fixtures_dir / "storage" / "btrfs_scrub_old.txt").read_text()


@pytest.fixture
def btrfs_scrub_never(fixtures_dir):
    """Load never-scrubbed status."""
    return (fixtures_dir / "storage" / "btrfs_scrub_never.txt").read_text()


@pytest.fixture
def btrfs_show_healthy(fixtures_dir):
    """Load healthy filesystem show output."""
    return (fixtures_dir / "storage" / "btrfs_show_healthy.txt").read_text()


@pytest.fixture
def btrfs_show_missing(fixtures_dir):
    """Load filesystem show with missing devices."""
    return (fixtures_dir / "storage" / "btrfs_show_missing.txt").read_text()


@pytest.fixture
def findmnt_btrfs(fixtures_dir):
    """Load findmnt output for BTRFS."""
    return (fixtures_dir / "storage" / "findmnt_btrfs.txt").read_text()


class TestBtrfsHealth:
    """Tests for btrfs_health script."""

    def test_missing_btrfs_returns_error(self, mock_context):
        """Returns exit code 2 when btrfs not available."""
        from scripts.baremetal import btrfs_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = btrfs_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("btrfs" in e.lower() for e in output.errors)

    def test_no_btrfs_filesystems(self, mock_context):
        """Returns 0 with info when no BTRFS filesystems found."""
        from scripts.baremetal import btrfs_health

        ctx = mock_context(
            tools_available=["btrfs"],
            command_outputs={
                ("findmnt", "-t", "btrfs", "-n", "-o", "TARGET,SOURCE,OPTIONS"): "",
            }
        )
        output = Output()

        exit_code = btrfs_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data["filesystems"] == []

    def test_healthy_filesystem(
        self,
        mock_context,
        findmnt_btrfs,
        btrfs_usage_healthy,
        btrfs_device_stats_healthy,
        btrfs_scrub_healthy,
        btrfs_show_healthy,
    ):
        """Returns 0 when filesystem is healthy."""
        from scripts.baremetal import btrfs_health

        ctx = mock_context(
            tools_available=["btrfs"],
            command_outputs={
                ("findmnt", "-t", "btrfs", "-n", "-o", "TARGET,SOURCE,OPTIONS"): findmnt_btrfs,
                ("btrfs", "filesystem", "usage", "-b", "/mnt/data"): btrfs_usage_healthy,
                ("btrfs", "device", "stats", "/mnt/data"): btrfs_device_stats_healthy,
                ("btrfs", "scrub", "status", "/mnt/data"): btrfs_scrub_healthy,
                ("btrfs", "filesystem", "show", "/mnt/data"): btrfs_show_healthy,
            }
        )
        output = Output()

        exit_code = btrfs_health.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["filesystems"]) == 1
        assert output.data["issues"] == []

    def test_high_capacity_warning(
        self,
        mock_context,
        findmnt_btrfs,
        btrfs_usage_high,
        btrfs_device_stats_healthy,
        btrfs_scrub_healthy,
        btrfs_show_healthy,
    ):
        """Returns 1 when filesystem usage exceeds threshold."""
        from scripts.baremetal import btrfs_health

        ctx = mock_context(
            tools_available=["btrfs"],
            command_outputs={
                ("findmnt", "-t", "btrfs", "-n", "-o", "TARGET,SOURCE,OPTIONS"): findmnt_btrfs,
                ("btrfs", "filesystem", "usage", "-b", "/mnt/data"): btrfs_usage_high,
                ("btrfs", "device", "stats", "/mnt/data"): btrfs_device_stats_healthy,
                ("btrfs", "scrub", "status", "/mnt/data"): btrfs_scrub_healthy,
                ("btrfs", "filesystem", "show", "/mnt/data"): btrfs_show_healthy,
            }
        )
        output = Output()

        exit_code = btrfs_health.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data["issues"]) > 0
        assert any(i["metric"] == "capacity" for i in output.data["issues"])

    def test_device_errors_detected(
        self,
        mock_context,
        findmnt_btrfs,
        btrfs_usage_healthy,
        btrfs_device_stats_errors,
        btrfs_scrub_healthy,
        btrfs_show_healthy,
    ):
        """Returns 1 when device has errors."""
        from scripts.baremetal import btrfs_health

        ctx = mock_context(
            tools_available=["btrfs"],
            command_outputs={
                ("findmnt", "-t", "btrfs", "-n", "-o", "TARGET,SOURCE,OPTIONS"): findmnt_btrfs,
                ("btrfs", "filesystem", "usage", "-b", "/mnt/data"): btrfs_usage_healthy,
                ("btrfs", "device", "stats", "/mnt/data"): btrfs_device_stats_errors,
                ("btrfs", "scrub", "status", "/mnt/data"): btrfs_scrub_healthy,
                ("btrfs", "filesystem", "show", "/mnt/data"): btrfs_show_healthy,
            }
        )
        output = Output()

        exit_code = btrfs_health.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data["issues"]) > 0
        assert any(i["metric"] == "io_errors" for i in output.data["issues"])

    def test_missing_devices_critical(
        self,
        mock_context,
        findmnt_btrfs,
        btrfs_usage_healthy,
        btrfs_device_stats_healthy,
        btrfs_scrub_healthy,
        btrfs_show_missing,
    ):
        """Returns 1 when devices are missing."""
        from scripts.baremetal import btrfs_health

        ctx = mock_context(
            tools_available=["btrfs"],
            command_outputs={
                ("findmnt", "-t", "btrfs", "-n", "-o", "TARGET,SOURCE,OPTIONS"): findmnt_btrfs,
                ("btrfs", "filesystem", "usage", "-b", "/mnt/data"): btrfs_usage_healthy,
                ("btrfs", "device", "stats", "/mnt/data"): btrfs_device_stats_healthy,
                ("btrfs", "scrub", "status", "/mnt/data"): btrfs_scrub_healthy,
                ("btrfs", "filesystem", "show", "/mnt/data"): btrfs_show_missing,
            }
        )
        output = Output()

        exit_code = btrfs_health.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data["issues"]) > 0
        assert any(i["metric"] == "missing_devices" for i in output.data["issues"])

    def test_never_scrubbed_warning(
        self,
        mock_context,
        findmnt_btrfs,
        btrfs_usage_healthy,
        btrfs_device_stats_healthy,
        btrfs_scrub_never,
        btrfs_show_healthy,
    ):
        """Returns 1 when filesystem has never been scrubbed."""
        from scripts.baremetal import btrfs_health

        ctx = mock_context(
            tools_available=["btrfs"],
            command_outputs={
                ("findmnt", "-t", "btrfs", "-n", "-o", "TARGET,SOURCE,OPTIONS"): findmnt_btrfs,
                ("btrfs", "filesystem", "usage", "-b", "/mnt/data"): btrfs_usage_healthy,
                ("btrfs", "device", "stats", "/mnt/data"): btrfs_device_stats_healthy,
                ("btrfs", "scrub", "status", "/mnt/data"): btrfs_scrub_never,
                ("btrfs", "filesystem", "show", "/mnt/data"): btrfs_show_healthy,
            }
        )
        output = Output()

        exit_code = btrfs_health.run([], output, ctx)

        assert exit_code == 1
        assert any(
            i["metric"] == "scrub_age_days" and "never" in i["message"].lower()
            for i in output.data["issues"]
        )
