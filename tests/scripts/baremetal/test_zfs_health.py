"""Tests for zfs_health script."""

from datetime import datetime, timedelta

import pytest
from pathlib import Path

from boxctl.core.output import Output


def _recent_scrub_line() -> str:
    """Format a scrub date a few days ago so fixtures don't age out."""
    d = datetime.now() - timedelta(days=5)
    return d.strftime("%a %b %d %H:%M:%S %Y")


@pytest.fixture
def zpool_names(fixtures_dir):
    """Load pool names."""
    return (fixtures_dir / "storage" / "zpool_names.txt").read_text()


@pytest.fixture
def zpool_list_healthy(fixtures_dir):
    """Load healthy pool list."""
    return (fixtures_dir / "storage" / "zpool_list_healthy.txt").read_text()


@pytest.fixture
def zpool_list_high(fixtures_dir):
    """Load high capacity pool list."""
    return (fixtures_dir / "storage" / "zpool_list_high.txt").read_text()


@pytest.fixture
def zpool_list_degraded(fixtures_dir):
    """Load degraded pool list."""
    return (fixtures_dir / "storage" / "zpool_list_degraded.txt").read_text()


@pytest.fixture
def zpool_status_healthy(fixtures_dir):
    """Load healthy pool status (scrub date re-templated to stay recent)."""
    text = (fixtures_dir / "storage" / "zpool_status_healthy.txt").read_text()
    return text.replace("Wed Jan 29 10:00:00 2026", _recent_scrub_line())


@pytest.fixture
def zpool_status_degraded(fixtures_dir):
    """Load degraded pool status."""
    return (fixtures_dir / "storage" / "zpool_status_degraded.txt").read_text()


@pytest.fixture
def zpool_status_errors(fixtures_dir):
    """Load pool status with device errors."""
    return (fixtures_dir / "storage" / "zpool_status_errors.txt").read_text()


@pytest.fixture
def zpool_status_no_scrub(fixtures_dir):
    """Load pool status with no scrub."""
    return (fixtures_dir / "storage" / "zpool_status_no_scrub.txt").read_text()


class TestZfsHealth:
    """Tests for zfs_health script."""

    def test_missing_zpool_returns_error(self, mock_context):
        """Returns exit code 2 when zpool not available."""
        from scripts.baremetal import zfs_health

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = zfs_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("zpool" in e.lower() for e in output.errors)

    def test_no_pools_found(self, mock_context):
        """Returns 0 with info when no pools found."""
        from scripts.baremetal import zfs_health

        ctx = mock_context(
            tools_available=["zpool"],
            command_outputs={
                ("zpool", "list", "-H", "-o", "name"): "",
            }
        )
        output = Output()

        exit_code = zfs_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data["pools"] == []

    def test_healthy_pool(
        self,
        mock_context,
        zpool_names,
        zpool_list_healthy,
        zpool_status_healthy,
    ):
        """Returns 0 when pool is healthy."""
        from scripts.baremetal import zfs_health

        ctx = mock_context(
            tools_available=["zpool"],
            command_outputs={
                ("zpool", "list", "-H", "-o", "name"): zpool_names,
                ("zpool", "list", "-H", "-p", "-o", "name,size,alloc,free,frag,cap,health,altroot", "tank"): zpool_list_healthy,
                ("zpool", "status", "-v", "tank"): zpool_status_healthy,
            }
        )
        output = Output()

        exit_code = zfs_health.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["pools"]) == 1
        assert output.data["issues"] == []

    def test_degraded_pool_critical(
        self,
        mock_context,
        zpool_names,
        zpool_list_degraded,
        zpool_status_degraded,
    ):
        """Returns 1 when pool is degraded."""
        from scripts.baremetal import zfs_health

        ctx = mock_context(
            tools_available=["zpool"],
            command_outputs={
                ("zpool", "list", "-H", "-o", "name"): zpool_names,
                ("zpool", "list", "-H", "-p", "-o", "name,size,alloc,free,frag,cap,health,altroot", "tank"): zpool_list_degraded,
                ("zpool", "status", "-v", "tank"): zpool_status_degraded,
            }
        )
        output = Output()

        exit_code = zfs_health.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data["issues"]) > 0
        assert any(
            i["metric"] == "health" and i["value"] == "DEGRADED"
            for i in output.data["issues"]
        )

    def test_high_capacity_warning(
        self,
        mock_context,
        zpool_names,
        zpool_list_high,
        zpool_status_healthy,
    ):
        """Returns 1 when pool capacity exceeds threshold."""
        from scripts.baremetal import zfs_health

        ctx = mock_context(
            tools_available=["zpool"],
            command_outputs={
                ("zpool", "list", "-H", "-o", "name"): zpool_names,
                ("zpool", "list", "-H", "-p", "-o", "name,size,alloc,free,frag,cap,health,altroot", "tank"): zpool_list_high,
                ("zpool", "status", "-v", "tank"): zpool_status_healthy,
            }
        )
        output = Output()

        exit_code = zfs_health.run([], output, ctx)

        assert exit_code == 1
        assert any(i["metric"] == "capacity" for i in output.data["issues"])

    def test_device_errors_detected(
        self,
        mock_context,
        zpool_names,
        zpool_list_healthy,
        zpool_status_errors,
    ):
        """Returns 1 when device has errors."""
        from scripts.baremetal import zfs_health

        ctx = mock_context(
            tools_available=["zpool"],
            command_outputs={
                ("zpool", "list", "-H", "-o", "name"): zpool_names,
                ("zpool", "list", "-H", "-p", "-o", "name,size,alloc,free,frag,cap,health,altroot", "tank"): zpool_list_healthy,
                ("zpool", "status", "-v", "tank"): zpool_status_errors,
            }
        )
        output = Output()

        exit_code = zfs_health.run([], output, ctx)

        assert exit_code == 1
        assert any(i["metric"] == "errors" for i in output.data["issues"])

    def test_never_scrubbed_warning(
        self,
        mock_context,
        zpool_names,
        zpool_list_healthy,
        zpool_status_no_scrub,
    ):
        """Returns 1 when pool has never been scrubbed."""
        from scripts.baremetal import zfs_health

        ctx = mock_context(
            tools_available=["zpool"],
            command_outputs={
                ("zpool", "list", "-H", "-o", "name"): zpool_names,
                ("zpool", "list", "-H", "-p", "-o", "name,size,alloc,free,frag,cap,health,altroot", "tank"): zpool_list_healthy,
                ("zpool", "status", "-v", "tank"): zpool_status_no_scrub,
            }
        )
        output = Output()

        exit_code = zfs_health.run([], output, ctx)

        assert exit_code == 1
        assert any(
            i["metric"] == "scrub_age_days" and "never" in i["message"].lower()
            for i in output.data["issues"]
        )

    def test_verbose_output(
        self,
        mock_context,
        zpool_names,
        zpool_list_healthy,
        zpool_status_healthy,
    ):
        """--verbose shows full pool details."""
        from scripts.baremetal import zfs_health

        ctx = mock_context(
            tools_available=["zpool"],
            command_outputs={
                ("zpool", "list", "-H", "-o", "name"): zpool_names,
                ("zpool", "list", "-H", "-p", "-o", "name,size,alloc,free,frag,cap,health,altroot", "tank"): zpool_list_healthy,
                ("zpool", "status", "-v", "tank"): zpool_status_healthy,
            }
        )
        output = Output()

        exit_code = zfs_health.run(["--verbose"], output, ctx)

        assert exit_code == 0
        # Verbose mode should include full properties and status
        assert "properties" in output.data["pools"][0]
        assert "status" in output.data["pools"][0]
