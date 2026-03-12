"""
Utility functions for WAF log analyzer including time parsing and logging configuration.
"""

import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from dateutil import parser as date_parser


def parse_time_range(time_input: str) -> tuple[datetime, datetime]:
    """Parse time range from various input formats.

    Args:
        time_input: Time range string in various formats:
                   - Natural language: "last 2 hours", "yesterday", "today"
                   - ISO range: "2026-03-10T14:00:00 to 2026-03-10T15:00:00"
                   - Single time: "2026-03-10T14:00:00"

    Returns:
        Tuple of (start_time, end_time) as timezone-aware datetime objects
    """
    now = datetime.now(UTC)

    # Natural language patterns
    natural_patterns = {
        r"last (\d+) (hour|hours|hr|hrs)": lambda m: now
        - timedelta(hours=int(m.group(1))),
        r"last (\d+) (day|days)": lambda m: now - timedelta(days=int(m.group(1))),
        r"last (\d+) (minute|minutes|min|mins)": lambda m: now
        - timedelta(minutes=int(m.group(1))),
        r"yesterday": lambda m: now - timedelta(days=1),
        r"today": lambda m: now.replace(hour=0, minute=0, second=0, microsecond=0),
        r"today (\d{2}):(\d{2})-(\d{2}):(\d{2})": lambda m: now.replace(
            hour=int(m.group(1)), minute=int(m.group(2)), second=0, microsecond=0
        ),
    }

    # Check natural language patterns
    for pattern, func in natural_patterns.items():
        match = re.match(pattern, time_input.lower())
        if match:
            if "today" in time_input and ":" in time_input:
                # Handle time range for today
                start_time = func(match)
                if len(match.groups()) == 4:
                    end_time = now.replace(
                        hour=int(match.group(3)),
                        minute=int(match.group(4)),
                        second=0,
                        microsecond=0,
                    )
                    return start_time, end_time
            else:
                # Handle relative time
                start_time = func(match)
                return start_time, now

    # Try ISO format or specific dates
    try:
        if " to " in time_input:
            # Range format: "2026-03-10T14:00:00 to 2026-03-10T15:00:00"
            start_str, end_str = time_input.split(" to ")
            start_time = date_parser.parse(start_str)
            end_time = date_parser.parse(end_str)
            # Ensure timezone awareness
            if start_time.tzinfo is None:
                start_time = start_time.replace(tzinfo=UTC)
            if end_time.tzinfo is None:
                end_time = end_time.replace(tzinfo=UTC)
            return start_time, end_time
        else:
            # Single time - assume last hour from that time
            parsed_time = date_parser.parse(time_input)
            if parsed_time.tzinfo is None:
                parsed_time = parsed_time.replace(tzinfo=UTC)
            return parsed_time - timedelta(hours=1), parsed_time
    except Exception:
        pass

    # Default to last hour
    return now - timedelta(hours=1), now


def setup_logging(
    level: str = "INFO",
    format_string: str | None = None,
    file_path: str | None = None,
) -> logging.Logger:
    """Setup logging configuration.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_string: Custom format string
        file_path: Optional file path for log output

    Returns:
        Configured logger instance
    """
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        format=format_string,
        filename=file_path,
        filemode="a" if file_path else None,
    )

    logger = logging.getLogger(__name__)

    # Add console handler if no file specified
    if not file_path:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(numeric_level)
        console_formatter = logging.Formatter(format_string)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    return logger


def load_config(config_path: str) -> dict[str, Any]:
    """Load configuration from YAML file.

    Args:
        config_path: Path to configuration file

    Returns:
        Configuration dictionary

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid YAML
    """
    config_file = Path(config_path)

    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_file) as f:
        try:
            config = yaml.safe_load(f)
            return config or {}
        except yaml.YAMLError as e:
            raise yaml.YAMLError(
                f"Invalid YAML in configuration file {config_path}: {e}"
            ) from e


def get_default_config() -> dict[str, Any]:
    """Get default configuration values.

    Returns:
        Default configuration dictionary
    """
    return {
        "max_workers": 10,
        "max_display_rows": 100,
        "aws": {
            "region": "eu-west-1",
            "profile": None,
        },
        "logging": {
            "level": "INFO",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        },
        "output": {
            "default_format": "table",
            "include_statistics": True,
        },
        "filters": {
            "default_action": None,
            "default_host": None,
        },
    }


def merge_configs(
    base_config: dict[str, Any], override_config: dict[str, Any]
) -> dict[str, Any]:
    """Merge two configuration dictionaries, with override taking precedence.

    Args:
        base_config: Base configuration
        override_config: Override configuration

    Returns:
        Merged configuration dictionary
    """
    merged = base_config.copy()

    for key, value in override_config.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = merge_configs(merged[key], value)
        else:
            merged[key] = value

    return merged


def validate_config(config: dict[str, Any]) -> bool:
    """Validate configuration dictionary.

    Args:
        config: Configuration dictionary to validate

    Returns:
        True if valid, raises ValueError if invalid
    """
    # Check required sections
    required_sections = ["aws", "logging", "output"]
    for section in required_sections:
        if section not in config:
            raise ValueError(f"Missing required configuration section: {section}")

    # Validate AWS section
    aws_config = config["aws"]
    if "region" not in aws_config:
        raise ValueError("Missing 'region' in AWS configuration")

    # Validate logging section
    logging_config = config["logging"]
    if "level" not in logging_config:
        raise ValueError("Missing 'level' in logging configuration")

    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if logging_config["level"].upper() not in valid_levels:
        raise ValueError(f"Invalid logging level: {logging_config['level']}")

    # Validate output section
    output_config = config["output"]
    if "default_format" not in output_config:
        raise ValueError("Missing 'default_format' in output configuration")

    valid_formats = ["table", "csv", "json"]
    if output_config["default_format"] not in valid_formats:
        raise ValueError(
            f"Invalid default output format: {output_config['default_format']}"
        )

    return True


def format_timestamp(timestamp: int) -> str:
    """Format millisecond timestamp to readable string.

    Args:
        timestamp: Millisecond timestamp

    Returns:
        Formatted timestamp string
    """
    if timestamp:
        dt = datetime.fromtimestamp(timestamp / 1000)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    return "N/A"


def truncate_string(text: str, max_length: int = 50, suffix: str = "...") -> str:
    """Truncate string to maximum length with suffix.

    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated

    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


def sanitize_filename(filename: str) -> str:
    """Sanitize filename by removing invalid characters.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    import re

    # Remove invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', "_", filename)
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip(" .")
    # Ensure it's not empty
    return sanitized or "unnamed"
