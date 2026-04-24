"""Tests for Output helper."""

import json
import pytest
from boxctl.core.output import Output


class TestOutput:
    """Tests for structured output helper."""

    def test_emit_stores_data(self):
        """emit() stores data for later retrieval."""
        output = Output()
        output.emit({"disks": [{"name": "sda", "status": "ok"}]})
        assert output.data["disks"][0]["name"] == "sda"

    def test_error_stores_message(self):
        """error() stores error messages."""
        output = Output()
        output.error("smartctl not found")
        assert "smartctl not found" in output.errors

    def test_warning_stores_message(self):
        """warning() stores warning messages."""
        output = Output()
        output.warning("disk degraded")
        assert "disk degraded" in output.warnings

    def test_json_format(self):
        """to_json() returns valid JSON string."""
        output = Output()
        output.emit({"test": "value"})
        result = output.to_json()
        parsed = json.loads(result)
        assert parsed["test"] == "value"

    def test_plain_format_with_data(self):
        """to_plain() formats data as readable text."""
        output = Output()
        output.emit({"status": "ok", "count": 5})
        result = output.to_plain()
        assert "status" in result
        assert "ok" in result

    def test_summary_property(self):
        """summary returns first line of plain output."""
        output = Output()
        output.emit({"status": "ok"})
        output.set_summary("All checks passed")
        assert output.summary == "All checks passed"

    def test_summary_from_error(self):
        """summary auto-generates from errors if not set."""
        output = Output()
        output.error("Something failed")
        assert "Something failed" in output.summary

    def test_summary_from_warning(self):
        """summary auto-generates from warnings if no errors."""
        output = Output()
        output.warning("Disk degraded")
        assert "Disk degraded" in output.summary

    def test_emit_merges_data(self):
        """Multiple emit() calls merge data."""
        output = Output()
        output.emit({"key1": "value1"})
        output.emit({"key2": "value2"})
        assert output.data["key1"] == "value1"
        assert output.data["key2"] == "value2"


class TestRenderNonFiniteFloats:
    """render() must not crash when scripts emit NaN/Inf floats.

    Real scripts produce these (e.g. ratio computations with zero denominators
    in scripts/baremetal/softnet_backlog_monitor.py and scripts/k8s/zone_balance.py),
    so the framework's plain renderer cannot blow up on them.
    """

    def test_plain_render_handles_inf(self, capsys):
        o = Output()
        o.emit({"ratio": float("inf")})
        o.render(format="plain")
        out = capsys.readouterr().out
        assert "Ratio:" in out
        assert "inf" in out.lower()

    def test_plain_render_handles_negative_inf(self, capsys):
        o = Output()
        o.emit({"delta": float("-inf")})
        o.render(format="plain")
        out = capsys.readouterr().out
        assert "Delta:" in out
        assert "inf" in out.lower()

    def test_plain_render_handles_nan(self, capsys):
        o = Output()
        o.emit({"score": float("nan")})
        o.render(format="plain")
        out = capsys.readouterr().out
        assert "Score:" in out
        assert "nan" in out.lower()

    def test_plain_render_handles_nested_inf(self, capsys):
        o = Output()
        o.emit({"stats": {"ratio": float("inf"), "count": 5}})
        o.render(format="plain")
        out = capsys.readouterr().out
        assert "Ratio:" in out
        assert "inf" in out.lower()
        assert "Count:" in out


class TestRenderSurfacesErrorsAndWarnings:
    """render() must surface messages recorded via output.error()/warning().

    Scripts commonly call ``output.error("kubectl not found")`` then
    ``output.render()`` on failure paths where no data is emitted. Previously,
    render() early-returned on empty self.data and silently dropped every
    error/warning message.
    """

    def test_plain_render_shows_errors_without_data(self, capsys):
        o = Output()
        o.error("kubectl not found")
        o.render(format="plain")
        out = capsys.readouterr().out
        assert "kubectl not found" in out

    def test_plain_render_shows_warnings_without_data(self, capsys):
        o = Output()
        o.warning("disk degraded")
        o.render(format="plain")
        out = capsys.readouterr().out
        assert "disk degraded" in out

    def test_plain_render_shows_errors_with_data(self, capsys):
        o = Output()
        o.emit({"status": "ok"})
        o.error("partial failure")
        o.render(format="plain")
        out = capsys.readouterr().out
        assert "partial failure" in out

    def test_json_render_includes_errors_without_data(self, capsys):
        import json as _json
        o = Output()
        o.error("kubectl not found")
        o.render(format="json")
        out = capsys.readouterr().out
        assert out.strip(), "expected JSON body, got empty output"
        payload = _json.loads(out)
        assert payload.get("errors") == ["kubectl not found"]

    def test_json_render_includes_warnings_without_data(self, capsys):
        import json as _json
        o = Output()
        o.warning("disk degraded")
        o.render(format="json")
        payload = _json.loads(capsys.readouterr().out)
        assert payload.get("warnings") == ["disk degraded"]

    def test_empty_render_still_returns_nothing(self, capsys):
        """With no data, errors, or warnings, render() is a no-op."""
        o = Output()
        o.render(format="plain")
        assert capsys.readouterr().out == ""

    def test_emitted_errors_not_overwritten_by_recorded_errors(self, capsys):
        """If data already has an 'errors' key, recorded self.errors merge after."""
        o = Output()
        o.emit({"status": "fail", "errors": ["emitted-err"]})
        o.error("recorded-err")
        o.render(format="plain")
        out = capsys.readouterr().out
        assert "emitted-err" in out
        assert "recorded-err" in out
