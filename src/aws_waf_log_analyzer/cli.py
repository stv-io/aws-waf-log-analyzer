"""
Command-line interface for AWS WAF Log Analyzer.
"""

import sys
from datetime import datetime

import click
from rich.console import Console

# Import version
from . import __version__
from .analyzer import WAFLogAnalyzer
from .utils import (
    get_default_config,
    load_config,
    merge_configs,
    parse_time_range,
    setup_logging,
    validate_config,
)

# Global console for CLI output
console = Console()


@click.command()
@click.option(
    "--bucket", "-b", help="S3 bucket name (auto-discovered if not specified)"
)
@click.option(
    "--time-range",
    "-t",
    default="last 1 hour",
    help='Time range (ISO: "2026-03-10T14:00:00 to 2026-03-10T15:00:00" or natural: "last 2 hours", "yesterday")',
)
@click.option("--host", "-h", help="Filter by host name")
@click.option(
    "--action",
    "-a",
    type=click.Choice(["BLOCK", "ALLOW", "COUNT"]),
    help="Filter by WAF action",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "csv", "json"]),
    default="table",
    help="Output format",
)
@click.option("--output-file", "-f", help="Output file (required for csv/json)")
@click.option("--region", "-r", default="eu-west-1", help="AWS region")
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging")
@click.option(
    "--config", "-c", type=click.Path(exists=True), help="Configuration file path"
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    help="Override logging level",
)
@click.option("--log-file", type=click.Path(), help="Log to file instead of console")
@click.option("--version", is_flag=True, help="Show version information")
def main(
    bucket: str | None,
    time_range: str,
    host: str | None,
    action: str | None,
    output: str,
    output_file: str | None,
    region: str,
    verbose: bool,
    config: str | None,
    log_level: str | None,
    log_file: str | None,
    version: bool,
) -> None:
    """AWS WAF Log Analyzer - Analyze WAF logs from S3 with high performance.

    Examples:
        \b
        # Basic usage with auto-discovered buckets
        aws-waf-log-analyzer --time-range "last 2 hours"

        # Filter by specific host and action
        aws-waf-log-analyzer --host api.example.com --action BLOCK

        # Export to CSV with custom time range
        aws-waf-log-analyzer --output csv --output-file results.csv --time-range "2026-03-10T14:00:00 to 2026-03-10T15:00:00"

        # Use configuration file
        aws-waf-log-analyzer --config config.yaml --verbose
    """

    # Show version and exit
    if version:
        console.print(f"aws-waf-log-analyzer version {__version__}")
        sys.exit(0)

    # Load configuration
    try:
        if config:
            user_config = load_config(config)
            default_config = get_default_config()
            app_config = merge_configs(default_config, user_config)
        else:
            app_config = get_default_config()

        # Validate configuration
        validate_config(app_config)

    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)

    # Setup logging
    try:
        # Determine log level
        if verbose:
            level = "DEBUG"
        elif log_level:
            level = log_level
        else:
            level = app_config["logging"]["level"]

        # Setup logging
        logger = setup_logging(
            level=level,
            format_string=app_config["logging"].get("format"),
            file_path=log_file,
        )

        logger.info("AWS WAF Log Analyzer started")

    except Exception as e:
        console.print(f"[red]Error setting up logging: {e}[/red]")
        sys.exit(1)

    # Validate output file requirements
    if output in ["csv", "json"] and not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"waf_results_{timestamp}.{output}"
        console.print(
            f"[yellow]No output file specified, using: {output_file}[/yellow]"
        )

    # Override config with CLI options
    if bucket:
        app_config["aws"]["bucket"] = bucket
    if region:
        app_config["aws"]["region"] = region

    try:
        # Create analyzer with configuration
        analyzer = WAFLogAnalyzer(bucket_name=bucket, region=region, config=app_config)

        # Set up filters
        filters = {}
        if host:
            filters["host"] = host
        if action:
            filters["action"] = action.upper()

        # Run analysis
        console.print("[bold blue]AWS WAF Log Analyzer[/bold blue]")
        console.print(f"Time Range: {time_range}")
        if host:
            console.print(f"Host Filter: {host}")
        if action:
            console.print(f"Action Filter: {action}")
        console.print("=" * 50)

        # Initialize S3 client
        analyzer.initialize_s3_client()

        # Parse time range
        start_time, end_time = parse_time_range(time_range)
        console.print(f"Analyzing logs from {start_time} to {end_time}")

        # Run the analysis using the enhanced analyze method
        analyzer.analyze_enhanced(
            time_range=time_range,
            filters=filters,
            output_format=output,
            output_file=output_file,
        )

        logger.info("Analysis completed successfully")

    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        console.print(f"[red]Analysis failed: {e}[/red]")
        sys.exit(1)


@click.group()
def config():
    """Configuration management commands."""
    pass


@config.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="waf-analyzer-config.yaml",
    help="Output configuration file path",
)
def init(output: str) -> None:
    """Initialize a default configuration file."""
    try:
        default_config = get_default_config()

        import yaml

        with open(output, "w") as f:
            yaml.dump(default_config, f, default_flow_style=False, indent=2)

        console.print(f"[green]Default configuration created: {output}[/green]")
        console.print("Edit this file to customize your settings.")

    except Exception as e:
        console.print(f"[red]Error creating configuration file: {e}[/red]")
        sys.exit(1)


@config.command()
@click.argument("config_file", type=click.Path(exists=True))
def validate(config_file: str) -> None:
    """Validate a configuration file."""
    try:
        user_config = load_config(config_file)
        default_config = get_default_config()
        merged_config = merge_configs(default_config, user_config)

        validate_config(merged_config)

        console.print(f"[green]Configuration file {config_file} is valid[/green]")

    except Exception as e:
        console.print(f"[red]Configuration validation failed: {e}[/red]")
        sys.exit(1)


@config.command()
@click.argument("config_file", type=click.Path(exists=True))
def show(config_file: str) -> None:
    """Show current configuration."""
    try:
        user_config = load_config(config_file)
        default_config = get_default_config()
        merged_config = merge_configs(default_config, user_config)

        import yaml

        console.print("[bold blue]Current Configuration:[/bold blue]")
        console.print(yaml.dump(merged_config, default_flow_style=False, indent=2))

    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)


# Add config group to main CLI
cli = click.CommandCollection()
cli.add_command(main, name="analyze")
cli.add_command(config, name="config")


if __name__ == "__main__":
    cli()
