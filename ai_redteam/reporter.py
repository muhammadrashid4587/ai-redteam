"""Reporter — Rich console output and JSON export with severity levels."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import IO, Optional

from ai_redteam.models import ScanReport, Severity


# ---------------------------------------------------------------------------
# ANSI colour helpers (no dependency on Rich for lighter installs)
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_MAGENTA = "\033[95m"
_DIM = "\033[2m"

SEVERITY_COLOURS: dict[Severity, str] = {
    Severity.CRITICAL: _RED + _BOLD,
    Severity.HIGH: _RED,
    Severity.MEDIUM: _YELLOW,
    Severity.LOW: _CYAN,
    Severity.INFO: _DIM,
    Severity.NONE: _GREEN,
}


def _coloured(text: str, colour: str) -> str:
    return f"{colour}{text}{_RESET}"


class Reporter:
    """Generates scan reports for the console and as JSON files."""

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    # ------------------------------------------------------------------
    # Console report
    # ------------------------------------------------------------------

    def print_report(self, report: ScanReport, file: IO[str] | None = None) -> None:
        """Print a human-readable report to *file* (default: stdout)."""
        out = file or sys.stdout

        self._header(out, report)
        self._category_summary(out, report)
        self._severity_summary(out, report)

        if self.verbose:
            self._detailed_results(out, report)

        self._footer(out, report)

    def _header(self, out: IO[str], report: ScanReport) -> None:
        out.write("\n")
        out.write(_coloured("=" * 70, _BOLD) + "\n")
        out.write(_coloured("  AI RED-TEAM SCAN REPORT", _BOLD + _MAGENTA) + "\n")
        out.write(_coloured("=" * 70, _BOLD) + "\n")
        out.write(f"  Target  : {report.target}\n")
        out.write(f"  Suites  : {', '.join(report.suites_run)}\n")
        out.write(f"  Started : {report.started_at.isoformat()}\n")
        if report.finished_at:
            elapsed = (report.finished_at - report.started_at).total_seconds()
            out.write(f"  Finished: {report.finished_at.isoformat()} ({elapsed:.1f}s)\n")
        out.write("\n")

    def _category_summary(self, out: IO[str], report: ScanReport) -> None:
        out.write(_coloured("  RESULTS BY CATEGORY", _BOLD) + "\n")
        out.write(_coloured("  " + "-" * 50, _DIM) + "\n")
        breakdown = report.category_breakdown()
        for cat, counts in breakdown.items():
            total = counts["total"]
            success = counts["successful"]
            pct = (success / total * 100) if total else 0
            colour = _RED if pct > 50 else (_YELLOW if pct > 20 else _GREEN)
            out.write(f"  {cat:<15} {success:>3}/{total:<3} attacks succeeded ")
            out.write(_coloured(f"({pct:.0f}%)", colour) + "\n")
        out.write("\n")

    def _severity_summary(self, out: IO[str], report: ScanReport) -> None:
        out.write(_coloured("  FINDINGS BY SEVERITY", _BOLD) + "\n")
        out.write(_coloured("  " + "-" * 50, _DIM) + "\n")
        breakdown = report.severity_breakdown()
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = breakdown.get(sev.value, 0)
            if count > 0:
                colour = SEVERITY_COLOURS.get(sev, "")
                label = _coloured(f"{sev.value.upper():<10}", colour)
                out.write(f"  {label} {count} finding(s)\n")
        if not breakdown:
            out.write(_coloured("  No successful attacks detected.", _GREEN) + "\n")
        out.write("\n")

    def _detailed_results(self, out: IO[str], report: ScanReport) -> None:
        out.write(_coloured("  DETAILED RESULTS", _BOLD) + "\n")
        out.write(_coloured("  " + "-" * 50, _DIM) + "\n")
        for i, r in enumerate(report.results, 1):
            status_colour = _RED if r.success else _GREEN
            status_label = "VULNERABLE" if r.success else "SAFE"
            out.write(f"\n  [{i:>3}] {r.attack_name}\n")
            out.write(f"        Status     : {_coloured(status_label, status_colour)}\n")
            out.write(f"        Severity   : {_coloured(r.severity.value, SEVERITY_COLOURS.get(r.severity, ''))}\n")
            out.write(f"        Confidence : {r.confidence:.0%}\n")
            out.write(f"        Details    : {r.details}\n")
            # Truncate payload/response for readability
            payload_preview = r.payload[:100] + ("..." if len(r.payload) > 100 else "")
            response_preview = r.response[:100] + ("..." if len(r.response) > 100 else "")
            out.write(f"        Payload    : {payload_preview}\n")
            out.write(f"        Response   : {response_preview}\n")
        out.write("\n")

    def _footer(self, out: IO[str], report: ScanReport) -> None:
        total = report.total_attacks
        success = report.successful_attacks
        pct = report.success_rate * 100
        colour = _RED if pct > 50 else (_YELLOW if pct > 20 else _GREEN)

        out.write(_coloured("  " + "=" * 50, _BOLD) + "\n")
        out.write(f"  Total attacks: {total}  |  Successful: {success}  |  ")
        out.write(_coloured(f"Success rate: {pct:.1f}%", colour) + "\n")
        out.write(_coloured("  " + "=" * 50, _BOLD) + "\n\n")

    # ------------------------------------------------------------------
    # JSON export
    # ------------------------------------------------------------------

    def export_json(self, report: ScanReport, path: str | Path) -> None:
        """Export the full report as a JSON file."""
        data = self._report_to_dict(report)
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def export_json_string(self, report: ScanReport) -> str:
        """Return the report as a JSON string."""
        data = self._report_to_dict(report)
        return json.dumps(data, indent=2, default=str)

    @staticmethod
    def _report_to_dict(report: ScanReport) -> dict:
        return {
            "target": report.target,
            "suites_run": report.suites_run,
            "started_at": report.started_at.isoformat(),
            "finished_at": report.finished_at.isoformat() if report.finished_at else None,
            "total_attacks": report.total_attacks,
            "successful_attacks": report.successful_attacks,
            "success_rate": round(report.success_rate, 4),
            "severity_breakdown": report.severity_breakdown(),
            "category_breakdown": report.category_breakdown(),
            "results": [
                {
                    "attack_name": r.attack_name,
                    "category": r.category.value,
                    "payload": r.payload,
                    "response": r.response,
                    "success": r.success,
                    "severity": r.severity.value,
                    "confidence": r.confidence,
                    "details": r.details,
                    "timestamp": r.timestamp.isoformat(),
                }
                for r in report.results
            ],
        }
