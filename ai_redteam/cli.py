"""Click CLI for ai-redteam.

Usage:
    ai-redteam scan --target http://localhost:8000/chat --suite all
    ai-redteam scan --target http://localhost:8000/chat --suite injection,jailbreak --output report.json
    ai-redteam scan --target http://localhost:8000/chat --suite all --verbose
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

import click

from ai_redteam import __version__
from ai_redteam.models import Target
from ai_redteam.reporter import Reporter
from ai_redteam.scanner import ALL_SUITES, Scanner


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
@click.version_option(version=__version__, prog_name="ai-redteam")
def cli() -> None:
    """AI Red-Team -- Automated red-teaming toolkit for LLM applications."""
    pass


@cli.command()
@click.option(
    "--target",
    required=True,
    help="Target LLM endpoint URL (e.g. http://localhost:8000/chat).",
)
@click.option(
    "--suite",
    default="all",
    show_default=True,
    help=f"Comma-separated attack suites to run. Options: {', '.join(ALL_SUITES)}, all.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Path to write JSON report (optional).",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable verbose output with detailed per-attack results.",
)
@click.option(
    "--header",
    "-H",
    multiple=True,
    help="HTTP headers as 'Key: Value'. Can be specified multiple times.",
)
@click.option(
    "--timeout",
    default=30.0,
    show_default=True,
    help="Request timeout in seconds.",
)
@click.option(
    "--request-field",
    default="prompt",
    show_default=True,
    help="JSON field name for the prompt in the request body.",
)
@click.option(
    "--response-field",
    default="response",
    show_default=True,
    help="JSON field name for the response in the reply body.",
)
def scan(
    target: str,
    suite: str,
    output: Optional[str],
    verbose: bool,
    header: tuple[str, ...],
    timeout: float,
    request_field: str,
    response_field: str,
) -> None:
    """Run red-team attack suites against an LLM endpoint."""
    _configure_logging(verbose)

    # Parse headers
    headers: dict[str, str] = {}
    for h in header:
        if ":" not in h:
            click.echo(f"Invalid header format (expected 'Key: Value'): {h}", err=True)
            sys.exit(1)
        key, value = h.split(":", 1)
        headers[key.strip()] = value.strip()

    # Parse suites
    suites = [s.strip().lower() for s in suite.split(",")]

    # Build target
    target_obj = Target(
        url=target,
        headers=headers,
        timeout=timeout,
        request_field=request_field,
        response_field=response_field,
    )

    try:
        scanner = Scanner(target=target_obj, suites=suites, verbose=verbose)
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Starting scan against {target} with suites: {', '.join(scanner.suites)}")
    click.echo()

    report = scanner.scan()

    # Print console report
    reporter = Reporter(verbose=verbose)
    reporter.print_report(report)

    # Export JSON if requested
    if output:
        reporter.export_json(report, output)
        click.echo(f"JSON report written to: {output}")


@cli.command()
def list_suites() -> None:
    """List all available attack suites."""
    click.echo("Available attack suites:")
    for name in ALL_SUITES:
        click.echo(f"  - {name}")
    click.echo(f"\nUse --suite all to run all suites.")


@cli.command()
def info() -> None:
    """Show toolkit information."""
    from ai_redteam.payloads import total_payload_count

    click.echo(f"ai-redteam v{__version__}")
    click.echo(f"Total built-in payloads: {total_payload_count()}")
    click.echo(f"Attack suites: {', '.join(ALL_SUITES)}")


def main() -> None:
    """Entry point."""
    cli()


if __name__ == "__main__":
    main()
