"""Script metadata linter."""

from dataclasses import dataclass, field
from pathlib import Path

from boxctl.core.metadata import (
    MAX_HEADER_LINES,
    MetadataError,
    parse_metadata,
    validate_metadata,
)


def _claims_boxctl_header(content: str) -> bool:
    """True if the file opens with the ``# boxctl:`` metadata marker.

    Mirrors ``parse_metadata``'s lookup so we only lint files that declare
    themselves boxctl scripts, ignoring any file that just happens to mention
    the marker string (e.g. framework source or test fixtures).
    """
    for line in content.split("\n", MAX_HEADER_LINES)[:MAX_HEADER_LINES]:
        if line.strip() == "# boxctl:":
            return True
    return False


@dataclass
class LintResult:
    """Result of linting a script."""

    path: Path
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True if no errors."""
        return len(self.errors) == 0


def lint_script(path: Path) -> LintResult:
    """
    Lint a single script.

    Args:
        path: Path to the script file

    Returns:
        LintResult with errors and warnings
    """
    result = LintResult(path=path)

    try:
        content = path.read_text()
    except OSError as e:
        result.errors.append(f"Cannot read file: {e}")
        return result

    try:
        metadata = parse_metadata(content)
    except MetadataError as e:
        result.errors.append(str(e))
        return result

    if metadata is None:
        result.errors.append("No boxctl metadata header found")
        return result

    # Run validation for warnings
    warnings = validate_metadata(metadata)
    result.warnings.extend(warnings)

    return result


def lint_all(directory: Path) -> list[LintResult]:
    """
    Lint all Python scripts in a directory.

    Only files that declare themselves as boxctl scripts (via a ``# boxctl:``
    header) are linted. Other .py files (framework code, __init__.py, tests,
    helpers) are skipped so bulk lint stays focused on script metadata.

    Args:
        directory: Directory to search

    Returns:
        List of LintResult for each discovered boxctl script
    """
    results = []

    for path in directory.rglob("*.py"):
        if not path.is_file():
            continue
        try:
            content = path.read_text()
        except OSError:
            continue
        if not _claims_boxctl_header(content):
            continue
        results.append(lint_script(path))

    return results
