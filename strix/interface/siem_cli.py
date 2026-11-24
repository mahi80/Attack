"""``strix siem`` — attribute a finished scan's findings to your SIEM detections.

Read-only by construction: each detector adapter only ever issues search
requests, and the artifacts written land next to the run's other reports.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from strix.core.paths import latest_run_dir, run_dir_for
from strix.report.siem import (
    AttributionSummary,
    SiemError,
    SiemReadOnlyError,
    attribute_run,
    parse_detector,
    render_markdown,
    write_attribution,
)


logger = logging.getLogger(__name__)

_USAGE = """Usage:
  strix siem --run <name|latest|path> --detector <dsn> [--detector <dsn> ...]

Detectors (read-only, search requests only):
  jsonl:///path/to/events.jsonl                     replay or export
  splunk://user:pw@host:8089?index=main             Splunk search/export
  elastic://user:pw@host:9200/winlogbeat-*          Elasticsearch _search
  sentinel://WORKSPACE_ID[?table=SecurityEvent]     Log Analytics (SENTINEL_TOKEN)

Options:
  --window SECONDS     Per-finding time window, both directions (default 600)
  --max-events N       Event cap per detector (default 5000)
  --write              Write siem_attribution.{json,md} into the run directory
  --fail-on-blind      Exit 3 when a class no named rule covered
"""


class _CliExitError(Exception):
    """A user-facing failure, carrying the exit code it maps to."""

    def __init__(self, message: str, code: int = 2) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


def run_siem(argv: list[str]) -> int:
    """Entry point for ``strix siem …``. Returns a process exit code."""

    console = Console()
    if argv and argv[0] in ("-h", "--help", "help"):
        console.print(_USAGE, markup=False, soft_wrap=True)
        return 0

    args = _parse_args(argv, console)
    if args is None:
        return 2

    try:
        run_dir, summary = _attribute(args)
    except _CliExitError as exc:
        if exc.message:
            console.print(f"[red]{exc.message}[/]")
        return exc.code

    if summary is None:
        console.print(f"[yellow]No findings in[/] {run_dir} — nothing to attribute.")
        return 0

    for renderable in _summary_renderable(summary):
        console.print(renderable)
    _write_outputs(args, run_dir, summary, console)
    if args.fail_on_blind and summary.blind_classes:
        console.print(
            f"[yellow]{len(summary.blind_classes)} class(es) had no named rule:[/] "
            + ", ".join(summary.blind_classes),
        )
        return 3
    return 0


def _parse_args(argv: list[str], console: Console) -> argparse.Namespace | None:
    parser = argparse.ArgumentParser(prog="strix siem", add_help=False)
    parser.add_argument("--run", default="latest")
    parser.add_argument("--detector", action="append", default=[])
    parser.add_argument("--window", type=int, default=600)
    parser.add_argument("--max-events", type=int, default=5000)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--json", dest="json_out")
    parser.add_argument("--md", dest="md_out")
    parser.add_argument("--fail-on-blind", action="store_true")
    try:
        return parser.parse_args(argv)
    except SystemExit:
        console.print(_USAGE, markup=False, soft_wrap=True)
        return None


def _attribute(args: argparse.Namespace) -> tuple[Path, AttributionSummary | None]:
    if not args.detector:
        raise _CliExitError("No detector given. Pass at least one --detector DSN.\n" + _USAGE)
    try:
        run_dir = _resolve_run_dir(args.run)
        reports = _load_reports(run_dir)
    except SiemError as exc:
        raise _CliExitError(str(exc)) from exc
    if reports is None:
        raise _CliExitError(
            f"No vulnerabilities.json in {run_dir}\n"
            "Run a scan first, or point --run at a finished run directory.",
        )
    if not reports:
        return run_dir, None
    try:
        detectors = [parse_detector(dsn) for dsn in args.detector]
        summary = attribute_run(
            reports,
            detectors,
            window_seconds=args.window,
            max_events=args.max_events,
            timeout=args.timeout,
        )
    except SiemReadOnlyError as exc:
        raise _CliExitError(f"Refused: {exc}") from exc
    except SiemError as exc:
        raise _CliExitError(f"Detector error: {exc}") from exc
    return run_dir, summary


def _write_outputs(
    args: argparse.Namespace,
    run_dir: Path,
    summary: AttributionSummary,
    console: Console,
) -> None:
    if args.write:
        json_path, md_path = write_attribution(run_dir, summary)
        console.print(f"Wrote [green]{json_path}[/] and [green]{md_path}[/]")
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(summary.as_dict(), indent=2) + "\n",
            encoding="utf-8",
        )
        console.print(f"Wrote [green]{args.json_out}[/]")
    if args.md_out:
        Path(args.md_out).write_text(render_markdown(summary), encoding="utf-8")
        console.print(f"Wrote [green]{args.md_out}[/]")


def _resolve_run_dir(name: str) -> Path:
    candidate = Path(name)
    if candidate.is_dir():
        return candidate
    if name in ("latest", ""):
        latest = latest_run_dir()
        if latest is None:
            raise SiemError("no runs found; run a scan first or pass --run <path>")
        return latest
    if candidate.name == name and candidate.parent == Path():
        resolved = run_dir_for(name)
        if resolved.is_dir():
            return resolved
        raise SiemError(f"run {name!r} not found under strix_runs/")
    raise SiemError(f"run path does not exist: {candidate}")


def _load_reports(run_dir: Path) -> list[dict[str, Any]] | None:
    path = run_dir / "vulnerabilities.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SiemError(f"cannot read {path}: {exc}") from exc
    return payload if isinstance(payload, list) else []


def _summary_renderable(summary: AttributionSummary) -> list[object]:
    table = Table(title="SIEM attribution", show_lines=False)
    table.add_column("Class")
    table.add_column("Findings", justify="right")
    table.add_column("Seen", justify="right")
    table.add_column("Rules")
    for coverage in sorted(
        summary.classes.values(),
        key=lambda cov: (-cov.findings, cov.vuln_class),
    ):
        table.add_row(
            coverage.vuln_class,
            str(coverage.findings),
            str(coverage.attributed),
            ", ".join(sorted(coverage.rules)) or "-",
        )
    headline = (
        f"{summary.attributed}/{summary.findings_total} findings attributed; "
        f"{summary.unattributed} unattributed, {summary.unanchored} unanchored, "
        f"{summary.unmatched_events} events unmatched."
    )
    renderables: list[object] = [headline, table]
    if summary.blind_classes:
        renderables.append(
            "Blind spots (no named rule): " + ", ".join(summary.blind_classes),
        )
    return renderables


def _main(argv: list[str] | None = None) -> int:
    return run_siem(list(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    raise SystemExit(_main())
