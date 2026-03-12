"""
Main WAF Log Analyzer class with enhanced features and configuration support.
"""

import gzip
import json
import logging
import re
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.exceptions import NoCredentialsError
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table

logger = logging.getLogger(__name__)


class WAFLogAnalyzer:
    """Main WAF Log Analyzer class with enhanced features."""

    def __init__(
        self,
        bucket_name: str | None = None,
        region: str = "eu-west-1",
        config: dict[str, Any] | None = None,
    ):
        """Initialize the WAF Log Analyzer.

        Args:
            bucket_name: S3 bucket name (auto-discovered if None)
            region: AWS region
            config: Configuration dictionary
        """
        self.bucket_name = bucket_name
        self.region = region
        self.config = config or {}
        self.s3_client = None
        self.console = Console()
        self.stats = {
            "total_files": 0,
            "processed_files": 0,
            "total_entries": 0,
            "filtered_entries": 0,
            "errors": 0,
        }
        self.current_filters = {}

    def initialize_s3_client(self):
        """Initialize S3 client with proper credentials."""
        try:
            session = boto3.Session()
            self.s3_client = session.client("s3", region_name=self.region)
            # Test connection
            self.s3_client.list_buckets()
            logger.info("S3 client initialized successfully")
        except NoCredentialsError:
            self.console.print(
                "[red]Error: AWS credentials not found. Please configure your AWS credentials.[/red]"
            )
            self.console.print(
                "Run 'aws configure' or set environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
            )
            raise
        except Exception as e:
            logger.error(f"Failed to initialize S3 client: {e}")
            raise

    def discover_waf_buckets(self) -> list[str]:
        """Auto-discover WAF log buckets."""
        if self.bucket_name:
            return [self.bucket_name]

        buckets = []
        try:
            response = self.s3_client.list_buckets()
            for bucket in response["Buckets"]:
                bucket_name = bucket["Name"]
                # Look for WAF log patterns
                if any(
                    keyword in bucket_name.lower()
                    for keyword in ["waf", "logs", "webacl"]
                ):
                    buckets.append(bucket_name)
                    logger.info(f"Found potential WAF bucket: {bucket_name}")
        except Exception as e:
            logger.error(f"Failed to list buckets: {e}")

        return buckets

    def discover_waf_log_prefixes(self, bucket_name: str) -> list[str]:
        """Discover WAF log prefixes in bucket."""
        prefixes = set()
        try:
            paginator = self.s3_client.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=bucket_name, Delimiter="/")

            for page in pages:
                for prefix_info in page.get("CommonPrefixes", []):
                    prefix = prefix_info["Prefix"]
                    # Look for WAF log patterns
                    if any(keyword in prefix.lower() for keyword in ["waf", "logs"]):
                        prefixes.add(prefix)

        except Exception as e:
            logger.error(f"Failed to discover prefixes in {bucket_name}: {e}")

        return list(prefixes)

    def filter_s3_objects_by_time(
        self, bucket_name: str, prefix: str, start_time: datetime, end_time: datetime
    ) -> list[str]:
        """Filter S3 objects by time range using prefix patterns."""
        objects = []
        try:
            paginator = self.s3_client.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

            for page in pages:
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    # Extract timestamp from filename
                    timestamp_match = re.search(r"(\d{8}T\d{4}Z)", key)
                    if timestamp_match:
                        timestamp_str = timestamp_match.group(1)
                        try:
                            # Parse timestamp from filename
                            file_time = datetime.strptime(timestamp_str, "%Y%m%dT%H%MZ")
                            # Make it timezone-aware by assuming UTC
                            file_time = file_time.replace(tzinfo=UTC)
                            if start_time <= file_time <= end_time:
                                objects.append(key)
                        except ValueError:
                            continue

        except Exception as e:
            logger.error(f"Failed to filter objects in {bucket_name}/{prefix}: {e}")

        return objects

    def download_and_decompress_file(
        self, bucket_name: str, key: str
    ) -> Iterator[dict[str, Any]]:
        """Download and decompress a single file, yielding JSON objects."""
        try:
            response = self.s3_client.get_object(Bucket=bucket_name, Key=key)
            content = response["Body"].read()

            # Check if file is gzipped
            if key.endswith(".gz"):
                content = gzip.decompress(content)

            # Parse JSON lines
            for line in content.decode("utf-8").split("\n"):
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse JSON line in {key}: {e}")
                        self.stats["errors"] += 1

        except Exception as e:
            logger.error(f"Failed to process file {key}: {e}")
            self.stats["errors"] += 1

    def extract_waf_fields(self, log_entry: dict[str, Any]) -> dict[str, Any]:
        """Extract relevant fields from WAF log entry."""
        extracted = {
            "timestamp": log_entry.get("timestamp"),
            "action": log_entry.get("action"),
            "terminating_rule_id": log_entry.get("terminatingRuleId"),
            "terminating_rule_type": log_entry.get("terminatingRuleType"),
            "webacl_id": log_entry.get("webaclId"),
            "http_source_name": log_entry.get("httpSourceName"),
            "http_source_id": log_entry.get("httpSourceId"),
        }

        # Extract HTTP request information
        http_request = log_entry.get("httpRequest", {})
        extracted.update(
            {
                "client_ip": http_request.get("clientIp"),
                "country": http_request.get("country"),
                "uri": http_request.get("uri"),
                "method": http_request.get("httpMethod"),
                "http_version": http_request.get("httpVersion"),
                "request_id": http_request.get("requestId"),
                "args": http_request.get("args", ""),
                "body_size": log_entry.get("requestBodySize", 0),
            }
        )

        # Extract host from headers
        headers = http_request.get("headers", [])
        host = None
        for header in headers:
            if header.get("name", "").lower() == "host":
                host = header.get("value")
                break
        extracted["host"] = host

        # Extract rule group information
        rule_groups = log_entry.get("ruleGroupList", [])
        extracted["rule_groups"] = []
        for rg in rule_groups:
            if rg.get("terminatingRule"):
                extracted["rule_groups"].append(
                    {
                        "group_id": rg.get("ruleGroupId"),
                        "terminating_rule": rg.get("terminatingRule", {}).get("ruleId"),
                        "action": rg.get("terminatingRule", {}).get("action"),
                    }
                )

        # Extract labels
        labels = log_entry.get("labels", [])
        extracted["labels"] = [label.get("name", "") for label in labels]

        return extracted

    def process_files_parallel(
        self, bucket_name: str, file_keys: list[str], filters: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Process multiple files in parallel."""
        results = []

        max_workers = self.config.get("max_workers", 10)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit download tasks
            future_to_key = {
                executor.submit(
                    self.download_and_decompress_file, bucket_name, key
                ): key
                for key in file_keys
            }

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console,
            ) as progress:
                task = progress.add_task("Processing files...", total=len(file_keys))

                for future in as_completed(future_to_key):
                    key = future_to_key[future]
                    try:
                        log_entries = future.result()
                        self.stats["processed_files"] += 1

                        for entry in log_entries:
                            self.stats["total_entries"] += 1
                            extracted = self.extract_waf_fields(entry)

                            # Apply filters
                            if self.matches_filters(extracted, filters):
                                results.append(extracted)
                                self.stats["filtered_entries"] += 1

                    except Exception as e:
                        logger.error(f"Error processing {key}: {e}")
                        self.stats["errors"] += 1

                    progress.advance(task)

        return results

    def matches_filters(self, entry: dict[str, Any], filters: dict[str, Any]) -> bool:
        """Check if entry matches all filters."""
        for key, value in filters.items():
            if key == "host" and entry.get("host") != value:
                return False
            elif key == "action" and entry.get("action") != value:
                return False
            elif key == "client_ip" and entry.get("client_ip") != value:
                return False
            elif key == "rule_id" and entry.get("terminating_rule_id") != value:
                return False
        return True

    def format_output_table(self, results: list[dict[str, Any]]) -> None:
        """Format results as a table."""
        if not results:
            self.console.print(
                "[yellow]No results found matching the criteria.[/yellow]"
            )
            return

        table = Table(title="WAF Log Analysis Results")
        table.add_column("Timestamp", style="cyan")
        table.add_column("Action", style="magenta")
        table.add_column("Rule ID", style="green")
        table.add_column("Client IP", style="blue")
        table.add_column("Country", style="yellow")
        table.add_column("Method", style="red")
        table.add_column("URI", style="white")
        table.add_column("Host", style="cyan")

        max_display = self.config.get("max_display_rows", 100)

        for entry in results[:max_display]:
            timestamp = entry.get("timestamp", 0)
            if timestamp:
                # Convert milliseconds timestamp to readable date
                dt = datetime.fromtimestamp(timestamp / 1000)
                timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            else:
                timestamp_str = "N/A"

            table.add_row(
                timestamp_str,
                entry.get("action", "N/A"),
                entry.get("terminating_rule_id", "N/A"),
                entry.get("client_ip", "N/A"),
                entry.get("country", "N/A"),
                entry.get("method", "N/A"),
                entry.get("uri", "N/A")[:50] + "..."
                if len(entry.get("uri", "")) > 50
                else entry.get("uri", "N/A"),
                entry.get("host", "N/A"),
            )

        self.console.print(table)
        self.print_statistics()

    def format_output_csv(
        self, results: list[dict[str, Any]], output_file: str
    ) -> None:
        """Format results as CSV."""
        import csv

        if not results:
            self.console.print(
                "[yellow]No results found matching the criteria.[/yellow]"
            )
            return

        fieldnames = [
            "timestamp",
            "action",
            "terminating_rule_id",
            "terminating_rule_type",
            "client_ip",
            "country",
            "host",
            "method",
            "uri",
            "http_version",
            "request_id",
            "body_size",
            "webacl_id",
            "http_source_name",
            "http_source_id",
        ]

        with open(output_file, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for entry in results:
                # Convert timestamp to readable format
                timestamp = entry.get("timestamp", 0)
                if timestamp:
                    dt = datetime.fromtimestamp(timestamp / 1000)
                    entry["timestamp"] = dt.isoformat()

                writer.writerow({field: entry.get(field, "") for field in fieldnames})

        self.console.print(f"[green]Results exported to {output_file}[/green]")
        self.print_statistics()

    def format_output_json(
        self, results: list[dict[str, Any]], output_file: str
    ) -> None:
        """Format results as JSON."""
        if not results:
            self.console.print(
                "[yellow]No results found matching the criteria.[/yellow]"
            )
            return

        # Convert timestamps to readable format
        for entry in results:
            timestamp = entry.get("timestamp", 0)
            if timestamp:
                dt = datetime.fromtimestamp(timestamp / 1000)
                entry["timestamp_readable"] = dt.isoformat()

        output_data = {
            "metadata": {
                "total_entries": len(results),
                "generated_at": datetime.now(UTC).isoformat(),
                "filters": self.current_filters,
                "statistics": self.stats,
                "version": getattr(self, "__version__", "unknown"),
            },
            "results": results,
        }

        with open(output_file, "w") as jsonfile:
            json.dump(output_data, jsonfile, indent=2, default=str)

        self.console.print(f"[green]Results exported to {output_file}[/green]")
        self.print_statistics()

    def print_statistics(self) -> None:
        """Print processing statistics."""
        stats_panel = Panel(
            f"""[bold blue]Processing Statistics[/bold blue]

Total Files Found: {self.stats['total_files']}
Files Processed: {self.stats['processed_files']}
Total Log Entries: {self.stats['total_entries']}
Filtered Entries: {self.stats['filtered_entries']}
Errors: {self.stats['errors']}""",
            title="Statistics",
        )
        self.console.print(stats_panel)

    def analyze_enhanced(
        self,
        time_range: str,
        filters: dict[str, Any],
        output_format: str = "table",
        output_file: str | None = None,
    ) -> None:
        """Enhanced analysis method with improved configuration support.

        Args:
            time_range: Time range string
            filters: Dictionary of filters to apply
            output_format: Output format (table, csv, json)
            output_file: Output file path (required for csv/json)
        """
        from .utils import parse_time_range

        # Parse time range
        start_time, end_time = parse_time_range(time_range)

        # Store current filters for metadata
        self.current_filters = filters

        # Discover buckets and prefixes
        buckets = self.discover_waf_buckets()
        if not buckets:
            self.console.print(
                "[red]No WAF log buckets found. Please specify a bucket name.[/red]"
            )
            return

        all_results = []

        for bucket_name in buckets:
            self.console.print(f"Scanning bucket: {bucket_name}")

            # Discover prefixes
            prefixes = self.discover_waf_log_prefixes(bucket_name)
            if not prefixes:
                prefixes = [""]  # Search root if no prefixes found

            for prefix in prefixes:
                # Filter objects by time
                file_keys = self.filter_s3_objects_by_time(
                    bucket_name, prefix, start_time, end_time
                )
                self.stats["total_files"] += len(file_keys)

                if file_keys:
                    self.console.print(
                        f"Found {len(file_keys)} files in {bucket_name}/{prefix}"
                    )

                    # Process files
                    results = self.process_files_parallel(
                        bucket_name, file_keys, filters
                    )
                    all_results.extend(results)

        # Output results
        if not all_results:
            self.console.print(
                "[yellow]No results found matching the criteria.[/yellow]"
            )
            return

        if output_format == "table":
            self.format_output_table(all_results)
        elif output_format == "csv":
            if not output_file:
                from datetime import datetime

                output_file = (
                    f"waf_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                )
            self.format_output_csv(all_results, output_file)
        elif output_format == "json":
            if not output_file:
                from datetime import datetime

                output_file = (
                    f"waf_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                )
            self.format_output_json(all_results, output_file)
