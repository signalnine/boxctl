"""Structured output helper for scripts."""

import json
import math
import os
from typing import Any

from boxctl.core.redact import redact_value


class Output:
    """Helper for structured script output."""

    def __init__(self):
        self.data: dict[str, Any] = {}
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self._summary: str | None = None
        self._printed: bool = False

    def emit(self, data: dict[str, Any]) -> None:
        """Store structured output data."""
        self.data.update(data)

    def error(self, message: str) -> None:
        """Record an error message."""
        self.errors.append(message)

    def warning(self, message: str) -> None:
        """Record a warning message."""
        self.warnings.append(message)

    def set_summary(self, summary: str) -> None:
        """Set a one-line summary."""
        self._summary = summary

    @property
    def summary(self) -> str:
        """Get summary or generate from data."""
        if self._summary:
            return self._summary
        if self.errors:
            return f"Error: {self.errors[0]}"
        if self.warnings:
            return f"Warning: {self.warnings[0]}"
        return "ok"

    def to_json(self) -> str:
        """Return data as JSON string."""
        return json.dumps(self.data, indent=2, default=str)

    def to_plain(self) -> str:
        """Return data as plain text."""
        lines = []
        for key, value in self.data.items():
            if isinstance(value, list):
                lines.append(f"{key}:")
                for item in value:
                    if isinstance(item, dict):
                        lines.append(f"  - {item}")
                    else:
                        lines.append(f"  - {item}")
            else:
                lines.append(f"{key}: {value}")
        return "\n".join(lines)

    def render(
        self,
        format: str = "plain",
        title: str | None = None,
        warn_only: bool = False,
        redact: bool = True,
    ) -> None:
        """Print output in the specified format.

        Args:
            format: Output format - "json" or "plain"
            title: Optional title for plain text output
            warn_only: If True, only print if issues or warnings exist
            redact: If True (default), scrub secrets (PEM keys, AWS keys,
                JWTs, sk-* tokens, DB credentials) from rendered output.
                ``self.data`` itself is not mutated.
        """
        if self._printed:
            return
        self._printed = True

        if not self.data and not self.errors and not self.warnings:
            return

        # Merge messages recorded via output.error()/output.warning() into the
        # rendered view so failure paths that don't emit data still surface.
        merged = dict(self.data)
        if self.errors:
            merged["errors"] = list(merged.get("errors", [])) + list(self.errors)
        if self.warnings:
            merged["warnings"] = list(merged.get("warnings", [])) + list(self.warnings)

        if warn_only:
            issues = merged.get("issues", [])
            warnings = merged.get("warnings", [])
            errors = merged.get("errors", [])
            if not issues and not warnings and not errors:
                return

        if os.environ.get("BOXCTL_NO_REDACT") == "1":
            redact = False
        view = redact_value(merged) if redact else merged
        if format == "json":
            print(json.dumps(view, indent=2, default=str))
        else:
            self._render_plain(title, view)

    def _render_plain(self, title: str | None = None, data: dict | None = None) -> None:
        """Render output as formatted plain text."""
        if data is None:
            data = self.data
        lines = []

        # Title
        if title:
            lines.append(title)
            lines.append("=" * len(title))
            lines.append("")

        # Status/summary at top if present
        status = data.get("status")
        if status:
            status_upper = status.upper()
            if status in ("healthy", "ok"):
                lines.append(f"[OK] Status: {status_upper}")
            elif status in ("warning", "degraded"):
                lines.append(f"[WARNING] Status: {status_upper}")
            else:
                lines.append(f"[CRITICAL] Status: {status_upper}")
            lines.append("")

        # Main data (skip status, issues, timestamp which are handled separately)
        skip_keys = {"status", "issues", "timestamp", "errors", "warnings"}
        for key, value in data.items():
            if key in skip_keys:
                continue
            self._render_value(lines, key, value, indent=0)

        # Issues section
        issues = data.get("issues", [])
        if issues:
            lines.append("")
            lines.append("Issues:")
            for issue in issues:
                if isinstance(issue, dict):
                    severity = issue.get("severity", "warning").upper()
                    message = issue.get("message", str(issue))
                    lines.append(f"  [{severity}] {message}")
                else:
                    lines.append(f"  - {issue}")
        elif status in ("healthy", "ok"):
            lines.append("")
            lines.append("[OK] No issues detected")

        # Errors section (from output.error() and any emitted errors key)
        errors = data.get("errors", [])
        if errors:
            lines.append("")
            lines.append("Errors:")
            for err in errors:
                if isinstance(err, dict):
                    message = err.get("message", str(err))
                    lines.append(f"  [ERROR] {message}")
                else:
                    lines.append(f"  [ERROR] {err}")

        # Warnings section
        warnings = data.get("warnings", [])
        if warnings:
            lines.append("")
            lines.append("Warnings:")
            for warning in warnings:
                if isinstance(warning, dict):
                    message = warning.get("message", str(warning))
                    lines.append(f"  [WARNING] {message}")
                else:
                    lines.append(f"  [WARNING] {warning}")

        print("\n".join(lines))

    def _render_value(self, lines: list, key: str | int, value: Any, indent: int = 0) -> None:
        """Recursively render a value with proper formatting."""
        prefix = "  " * indent

        # Format key nicely (handle int keys from dicts with numeric keys)
        if isinstance(key, int):
            display_key = str(key)
        else:
            display_key = str(key).replace("_", " ").title()

        if isinstance(value, dict):
            lines.append(f"{prefix}{display_key}:")
            for k, v in value.items():
                self._render_value(lines, k, v, indent + 1)
        elif isinstance(value, list):
            if not value:
                lines.append(f"{prefix}{display_key}: (none)")
            elif all(isinstance(x, (str, int, float, bool)) for x in value):
                # Simple list - show inline or as bullets
                if len(value) <= 3 and all(len(str(x)) < 20 for x in value):
                    lines.append(f"{prefix}{display_key}: {', '.join(str(x) for x in value)}")
                else:
                    lines.append(f"{prefix}{display_key}:")
                    for item in value[:10]:  # Limit to 10 items
                        lines.append(f"{prefix}  - {item}")
                    if len(value) > 10:
                        lines.append(f"{prefix}  ... and {len(value) - 10} more")
            else:
                # Complex list
                lines.append(f"{prefix}{display_key}:")
                for i, item in enumerate(value[:10]):
                    if isinstance(item, dict):
                        # Show dict items compactly
                        summary = ", ".join(f"{k}={v}" for k, v in list(item.items())[:3])
                        lines.append(f"{prefix}  - {summary}")
                    else:
                        lines.append(f"{prefix}  - {item}")
                if len(value) > 10:
                    lines.append(f"{prefix}  ... and {len(value) - 10} more")
        elif isinstance(value, bool):
            lines.append(f"{prefix}{display_key}: {'yes' if value else 'no'}")
        elif isinstance(value, float):
            # Non-finite floats (NaN, +/-Inf) cannot be coerced to int and
            # break numeric formatting; emit their str repr unchanged.
            if not math.isfinite(value):
                lines.append(f"{prefix}{display_key}: {value}")
            elif value == int(value):
                lines.append(f"{prefix}{display_key}: {int(value)}")
            elif abs(value) < 0.01 or abs(value) >= 1000:
                lines.append(f"{prefix}{display_key}: {value:.2e}")
            else:
                lines.append(f"{prefix}{display_key}: {value:.2f}")
        else:
            lines.append(f"{prefix}{display_key}: {value}")
