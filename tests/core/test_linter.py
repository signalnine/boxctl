"""Tests for script linter."""

import pytest
from pathlib import Path

from boxctl.core.linter import lint_script, lint_all, LintResult


VALID_SCRIPT = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart]
#   requires: [smartctl]
#   privilege: root
#   brief: Check disk health

def main():
    pass
'''

MISSING_CATEGORY = '''#!/usr/bin/env python3
# boxctl:
#   tags: [health]
#   brief: Missing category
'''

INVALID_CATEGORY_FORMAT = '''#!/usr/bin/env python3
# boxctl:
#   category: invalid
#   tags: [health]
#   brief: Bad category format
'''

EMPTY_TAGS = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: []
#   brief: Empty tags
'''

INVALID_PRIVILEGE = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health]
#   privilege: admin
#   brief: Invalid privilege
'''

NO_HEADER = '''#!/usr/bin/env python3
"""A script without boxctl header."""

def main():
    pass
'''


class TestLintScript:
    """Tests for lint_script function."""

    def test_valid_script_no_errors(self, tmp_path):
        """Valid script returns no errors."""
        script_file = tmp_path / "valid.py"
        script_file.write_text(VALID_SCRIPT)

        result = lint_script(script_file)

        assert result.errors == []
        assert result.warnings == []

    def test_missing_category_error(self, tmp_path):
        """Missing category returns error."""
        script_file = tmp_path / "nocat.py"
        script_file.write_text(MISSING_CATEGORY)

        result = lint_script(script_file)

        assert any("category" in e.lower() for e in result.errors)

    def test_invalid_category_format_warning(self, tmp_path):
        """Invalid category format returns warning."""
        script_file = tmp_path / "badcat.py"
        script_file.write_text(INVALID_CATEGORY_FORMAT)

        result = lint_script(script_file)

        assert any("category" in w.lower() for w in result.warnings)

    def test_empty_tags_warning(self, tmp_path):
        """Empty tags returns warning."""
        script_file = tmp_path / "notags.py"
        script_file.write_text(EMPTY_TAGS)

        result = lint_script(script_file)

        assert any("tags" in w.lower() for w in result.warnings)

    def test_invalid_privilege_warning(self, tmp_path):
        """Invalid privilege returns warning."""
        script_file = tmp_path / "badpriv.py"
        script_file.write_text(INVALID_PRIVILEGE)

        result = lint_script(script_file)

        assert any("privilege" in w.lower() for w in result.warnings)

    def test_no_header_error(self, tmp_path):
        """Script without header returns error."""
        script_file = tmp_path / "noheader.py"
        script_file.write_text(NO_HEADER)

        result = lint_script(script_file)

        assert any("header" in e.lower() or "metadata" in e.lower() for e in result.errors)


class TestLintAll:
    """Tests for lint_all function."""

    def test_lints_multiple_scripts(self, tmp_path):
        """Lints all scripts in directory."""
        (tmp_path / "valid.py").write_text(VALID_SCRIPT)
        (tmp_path / "invalid.py").write_text(MISSING_CATEGORY)

        results = lint_all(tmp_path)

        assert len(results) == 2

    def test_returns_lint_results(self, tmp_path):
        """Returns LintResult for each script."""
        (tmp_path / "test.py").write_text(VALID_SCRIPT)

        results = lint_all(tmp_path)

        assert len(results) == 1
        assert isinstance(results[0], LintResult)
        assert results[0].path.name == "test.py"

    def test_counts_errors_and_warnings(self, tmp_path):
        """Counts total errors and warnings."""
        (tmp_path / "valid.py").write_text(VALID_SCRIPT)
        (tmp_path / "bad1.py").write_text(MISSING_CATEGORY)
        (tmp_path / "bad2.py").write_text(INVALID_CATEGORY_FORMAT)

        results = lint_all(tmp_path)

        total_errors = sum(len(r.errors) for r in results)
        total_warnings = sum(len(r.warnings) for r in results)

        assert total_errors >= 1  # Missing category is an error
        assert total_warnings >= 1  # Invalid format is a warning

    def test_skips_files_without_boxctl_header(self, tmp_path):
        """lint_all ignores .py files that don't claim to be boxctl scripts."""
        (tmp_path / "script.py").write_text(VALID_SCRIPT)
        (tmp_path / "__init__.py").write_text('"""Package init."""\n')
        (tmp_path / "helper.py").write_text(NO_HEADER)

        results = lint_all(tmp_path)

        assert len(results) == 1
        assert results[0].path.name == "script.py"

    def test_still_reports_malformed_boxctl_headers(self, tmp_path):
        """lint_all still catches files with a boxctl header that is broken."""
        (tmp_path / "bad.py").write_text(MISSING_CATEGORY)
        (tmp_path / "__init__.py").write_text('"""Package init."""\n')

        results = lint_all(tmp_path)

        assert len(results) == 1
        assert results[0].path.name == "bad.py"
        assert results[0].errors


class TestLintResult:
    """Tests for LintResult dataclass."""

    def test_ok_property_true(self, tmp_path):
        """ok is True when no errors."""
        script_file = tmp_path / "valid.py"
        script_file.write_text(VALID_SCRIPT)

        result = lint_script(script_file)

        assert result.ok is True

    def test_ok_property_false(self, tmp_path):
        """ok is False when has errors."""
        script_file = tmp_path / "bad.py"
        script_file.write_text(MISSING_CATEGORY)

        result = lint_script(script_file)

        assert result.ok is False
