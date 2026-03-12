"""Tests for utility functions."""

import tempfile
from datetime import UTC, datetime, timedelta

import pytest
import yaml

from aws_waf_log_analyzer.utils import (
    format_timestamp,
    get_default_config,
    load_config,
    merge_configs,
    parse_time_range,
    sanitize_filename,
    setup_logging,
    truncate_string,
    validate_config,
)


class TestTimeRangeParsing:
    """Test time range parsing functionality."""

    def test_parse_last_hours(self):
        """Test parsing 'last X hours' format."""
        start_time, end_time = parse_time_range("last 2 hours")

        assert isinstance(start_time, datetime)
        assert isinstance(end_time, datetime)
        assert start_time.tzinfo is not None  # Should be timezone-aware
        assert end_time.tzinfo is not None
        assert (end_time - start_time) == timedelta(hours=2)

    def test_parse_last_minutes(self):
        """Test parsing 'last X minutes' format."""
        start_time, end_time = parse_time_range("last 30 minutes")

        assert (end_time - start_time) == timedelta(minutes=30)

    def test_parse_last_days(self):
        """Test parsing 'last X days' format."""
        start_time, end_time = parse_time_range("last 3 days")

        assert (end_time - start_time) == timedelta(days=3)

    def test_parse_yesterday(self):
        """Test parsing 'yesterday' format."""
        start_time, end_time = parse_time_range("yesterday")

        now = datetime.now(UTC)
        yesterday_start = (now - timedelta(days=1)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )

        # Allow for small time differences due to test execution
        assert abs((start_time - yesterday_start).total_seconds()) < 60
        assert abs((end_time - now).total_seconds()) < 60

    def test_parse_today_time_range(self):
        """Test parsing 'today HH:MM-HH:MM' format."""
        start_time, end_time = parse_time_range("today 09:00-17:00")

        now = datetime.now(UTC)
        assert start_time.hour == 9
        assert end_time.hour == 17
        assert start_time.date() == now.date()
        assert end_time.date() == now.date()

    def test_parse_iso_range(self):
        """Test parsing ISO format range."""
        start_time, end_time = parse_time_range(
            "2023-01-01T10:00:00 to 2023-01-01T15:00:00"
        )

        assert start_time.year == 2023
        assert start_time.month == 1
        assert start_time.day == 1
        assert start_time.hour == 10

        assert end_time.year == 2023
        assert end_time.month == 1
        assert end_time.day == 1
        assert end_time.hour == 15

        assert start_time.tzinfo is not None
        assert end_time.tzinfo is not None

    def test_parse_single_time(self):
        """Test parsing single time (defaults to last hour from that time)."""
        start_time, end_time = parse_time_range("2023-01-01T12:00:00")

        assert end_time.year == 2023
        assert end_time.month == 1
        assert end_time.day == 1
        assert end_time.hour == 12

        assert (end_time - start_time) == timedelta(hours=1)

    def test_parse_invalid_format(self):
        """Test parsing invalid format (defaults to last hour)."""
        start_time, end_time = parse_time_range("invalid format")

        assert isinstance(start_time, datetime)
        assert isinstance(end_time, datetime)
        assert (end_time - start_time) == timedelta(hours=1)


class TestLoggingSetup:
    """Test logging setup functionality."""

    def test_setup_logging_default(self):
        """Test default logging setup."""
        logger = setup_logging()

        assert logger is not None
        assert logger.name == "aws_waf_log_analyzer.utils"

    def test_setup_logging_with_level(self):
        """Test logging setup with custom level."""
        logger = setup_logging(level="DEBUG")

        assert logger is not None
        assert logger.level == 10  # DEBUG level

    def test_setup_logging_with_file(self):
        """Test logging setup with file output."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            logger = setup_logging(file_path=tmp_path)

            assert logger is not None

            # Test that logging to file works
            logger.info("Test message")

            with open(tmp_path) as f:
                content = f.read()
                assert "Test message" in content

        finally:
            import os

            os.unlink(tmp_path)


class TestConfigManagement:
    """Test configuration management functionality."""

    def test_get_default_config(self):
        """Test getting default configuration."""
        config = get_default_config()

        assert isinstance(config, dict)
        assert "aws" in config
        assert "logging" in config
        assert "output" in config
        assert "filters" in config

        assert config["aws"]["region"] == "eu-west-1"
        assert config["logging"]["level"] == "INFO"
        assert config["output"]["default_format"] == "table"

    def test_load_config_valid_file(self):
        """Test loading valid configuration file."""
        config_data = {"aws": {"region": "us-west-2"}, "logging": {"level": "DEBUG"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            yaml.dump(config_data, tmp)
            tmp_path = tmp.name

        try:
            loaded_config = load_config(tmp_path)

            assert loaded_config["aws"]["region"] == "us-west-2"
            assert loaded_config["logging"]["level"] == "DEBUG"

        finally:
            import os

            os.unlink(tmp_path)

    def test_load_config_nonexistent_file(self):
        """Test loading non-existent configuration file."""
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config.yaml")

    def test_load_config_invalid_yaml(self):
        """Test loading invalid YAML configuration file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            tmp.write("invalid: yaml: content: [")
            tmp_path = tmp.name

        try:
            with pytest.raises(yaml.YAMLError):
                load_config(tmp_path)

        finally:
            import os

            os.unlink(tmp_path)

    def test_merge_configs(self):
        """Test configuration merging."""
        base_config = {
            "aws": {"region": "us-east-1", "profile": None},
            "logging": {"level": "INFO"},
            "new_section": {"value": "original"},
        }

        override_config = {
            "aws": {"region": "us-west-2"},
            "logging": {"level": "DEBUG"},
            "new_section": {"value": "overridden"},
        }

        merged = merge_configs(base_config, override_config)

        assert merged["aws"]["region"] == "us-west-2"  # Overridden
        assert merged["aws"]["profile"] is None  # Preserved
        assert merged["logging"]["level"] == "DEBUG"  # Overridden
        assert merged["new_section"]["value"] == "overridden"  # Overridden

    def test_validate_config_valid(self):
        """Test validation of valid configuration."""
        config = get_default_config()

        assert validate_config(config) is True

    def test_validate_config_missing_section(self):
        """Test validation with missing required section."""
        config = {"aws": {"region": "us-east-1"}}  # Missing logging, output

        with pytest.raises(ValueError, match="Missing required configuration section"):
            validate_config(config)

    def test_validate_config_invalid_log_level(self):
        """Test validation with invalid log level."""
        config = get_default_config()
        config["logging"]["level"] = "INVALID"

        with pytest.raises(ValueError, match="Invalid logging level"):
            validate_config(config)

    def test_validate_config_invalid_output_format(self):
        """Test validation with invalid output format."""
        config = get_default_config()
        config["output"]["default_format"] = "invalid"

        with pytest.raises(ValueError, match="Invalid default output format"):
            validate_config(config)


class TestUtilityFunctions:
    """Test utility functions."""

    def test_format_timestamp(self):
        """Test timestamp formatting."""
        # Test with valid timestamp
        timestamp = 1672531200000  # 2023-01-01 00:00:00 UTC
        formatted = format_timestamp(timestamp)

        assert "2023-01-01" in formatted
        assert "00:00:00" in formatted
        assert "UTC" in formatted

    def test_format_timestamp_invalid(self):
        """Test timestamp formatting with invalid input."""
        formatted = format_timestamp(0)
        assert formatted == "N/A"

        formatted = format_timestamp(None)
        assert formatted == "N/A"

    def test_truncate_string(self):
        """Test string truncation."""
        long_text = "This is a very long string that needs to be truncated"

        truncated = truncate_string(long_text, 20)
        assert len(truncated) == 20
        assert truncated.endswith("...")

        short_text = "Short"
        truncated = truncate_string(short_text, 20)
        assert truncated == "Short"

    def test_sanitize_filename(self):
        """Test filename sanitization."""
        invalid_chars = '<>:"/\\|?*'
        filename = f"test{invalid_chars}file.txt"

        sanitized = sanitize_filename(filename)

        assert "<" not in sanitized
        assert ">" not in sanitized
        assert ":" not in sanitized
        assert '"' not in sanitized
        assert "/" not in sanitized
        assert "\\" not in sanitized
        assert "|" not in sanitized
        assert "?" not in sanitized
        assert "*" not in sanitized
        assert sanitized.endswith(".txt")

    def test_sanitize_filename_empty(self):
        """Test sanitization of empty filename."""
        sanitized = sanitize_filename("")
        assert sanitized == "unnamed"

        sanitized = sanitize_filename("   .   ")
        assert sanitized == "unnamed"
