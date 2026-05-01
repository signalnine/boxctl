"""Script metadata linter."""

import ast
from dataclasses import dataclass, field
from pathlib import Path

from boxctl.core.metadata import (
    MetadataError,
    parse_metadata,
    validate_metadata,
)


REQUIRED_RUN_PARAMS = ("args", "output", "context")


def _check_run_entrypoint(content: str) -> str | None:
    """Validate that the script defines ``def run(args, output, context)``.

    Returns ``None`` if the entrypoint is well-formed, or an error message
    describing what's wrong (no top-level run, wrong signature, etc.).
    Files that fail to parse return a syntax-error message so the linter
    surfaces the cause instead of silently passing.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError as e:
        return f"Cannot parse script: {e.msg} (line {e.lineno})"

    run_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run":
            run_node = node
            break

    if run_node is None:
        return (
            "Missing top-level entrypoint: scripts must define "
            "'def run(args, output, context)'"
        )

    args = run_node.args
    if args.vararg or args.kwarg:
        return (
            "run() must take exactly (args, output, context); "
            "*args/**kwargs are not allowed"
        )

    positional = [a.arg for a in args.posonlyargs] + [a.arg for a in args.args]
    if len(positional) != len(REQUIRED_RUN_PARAMS):
        return (
            f"run() must take exactly {len(REQUIRED_RUN_PARAMS)} parameters "
            f"({', '.join(REQUIRED_RUN_PARAMS)}); got "
            f"{len(positional)} ({', '.join(positional) or 'none'})"
        )

    if tuple(positional) != REQUIRED_RUN_PARAMS:
        return (
            f"run() parameters must be named "
            f"({', '.join(REQUIRED_RUN_PARAMS)}); got "
            f"({', '.join(positional)})"
        )

    return None


def _claims_boxctl_header(content: str) -> bool:
    """True if the file opens with the ``# boxctl:`` metadata marker.

    Real scripts put ``# boxctl:`` on line 1 or 2 (immediately after the
    optional shebang). Restricting the scan to the first few physical lines
    avoids false positives from test files that embed fixture strings
    containing the marker further down.
    """
    for line in content.split("\n", 4)[:4]:
        stripped = line.strip()
        if stripped == "# boxctl:":
            return True
        if stripped.startswith("#!") or stripped == "":
            continue
        return False
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


def collect_script_names(directory: Path) -> set[str]:
    """Return the set of valid boxctl script names (without ``.py``) in a tree.

    Used by lint_all and the CLI to resolve ``related:`` references across the
    full script corpus.
    """
    names: set[str] = set()
    for path in directory.rglob("*.py"):
        if not path.is_file():
            continue
        try:
            content = path.read_text()
        except OSError:
            continue
        if not _claims_boxctl_header(content):
            continue
        try:
            metadata = parse_metadata(content)
        except MetadataError:
            continue
        if metadata is None:
            continue
        names.add(path.stem)
    return names


def lint_script(path: Path, known_scripts: set[str] | None = None) -> LintResult:
    """
    Lint a single script.

    Args:
        path: Path to the script file
        known_scripts: If provided, ``related:`` entries are checked against
            this set of valid script names (without ``.py``). Unresolved
            entries are reported as errors. Pass ``None`` to skip the check.

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

    entrypoint_error = _check_run_entrypoint(content)
    if entrypoint_error is not None:
        result.errors.append(entrypoint_error)

    if known_scripts is not None:
        related = metadata.get("related") or []
        if isinstance(related, list):
            for ref in related:
                if not isinstance(ref, str):
                    continue
                ref_name = ref.removesuffix(".py")
                if ref_name == path.stem:
                    continue
                if ref_name not in known_scripts:
                    result.errors.append(
                        f"Unknown related script: '{ref}' does not resolve to a real script"
                    )

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
    known_scripts = collect_script_names(directory)
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
        results.append(lint_script(path, known_scripts=known_scripts))

    return results
