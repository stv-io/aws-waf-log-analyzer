"""Tests for the CLI interface."""

import tempfile
from unittest.mock import Mock, patch

import yaml
from click.testing import CliRunner

from aws_waf_log_analyzer.cli import config, main
from aws_waf_log_analyzer.utils import get_default_config


class TestCLI:
    """Test cases for CLI interface."""

    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    @patch("aws_waf_log_analyzer.cli.WAFLogAnalyzer")
    @patch("aws_waf_log_analyzer.cli.setup_logging")
    def test_main_basic_usage(self, mock_logging, mock_analyzer_class):
        """Test basic CLI usage."""
        mock_analyzer = Mock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        result = self.runner.invoke(
            main,
            [
                "--bucket",
                "test-bucket",
                "--time-range",
                "last 1 hour",
                "--host",
                "example.com",
            ],
        )

        assert result.exit_code == 0
        mock_analyzer_class.assert_called_once()
        mock_analyzer.initialize_s3_client.assert_called_once()
        mock_analyzer.analyze_enhanced.assert_called_once()

    @patch("aws_waf_log_analyzer.cli.WAFLogAnalyzer")
    @patch("aws_waf_log_analyzer.cli.setup_logging")
    def test_main_with_csv_output(self, mock_logging, mock_analyzer_class):
        """Test CLI with CSV output."""
        mock_analyzer = Mock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        with tempfile.NamedTemporaryFile(suffix=".csv") as tmp:
            result = self.runner.invoke(
                main,
                [
                    "--output",
                    "csv",
                    "--output-file",
                    tmp.name,
                    "--time-range",
                    "last 1 hour",
                ],
            )

            assert result.exit_code == 0
            call_args = mock_analyzer.analyze_enhanced.call_args[1]
            assert call_args["output_format"] == "csv"
            assert call_args["output_file"] == tmp.name

    @patch("aws_waf_log_analyzer.cli.WAFLogAnalyzer")
    @patch("aws_waf_log_analyzer.cli.setup_logging")
    def test_main_verbose_logging(self, mock_logging, mock_analyzer_class):
        """Test CLI with verbose logging."""
        mock_analyzer = Mock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        result = self.runner.invoke(main, ["--verbose"])

        assert result.exit_code == 0
        mock_logging.assert_called_once_with(level="DEBUG", file_path=None)

    @patch("aws_waf_log_analyzer.cli.WAFLogAnalyzer")
    @patch("aws_waf_log_analyzer.cli.setup_logging")
    def test_main_with_config_file(self, mock_logging, mock_analyzer_class):
        """Test CLI with configuration file."""
        mock_analyzer = Mock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        # Create temporary config file
        config_data = {
            "aws": {"region": "us-west-2"},
            "logging": {"level": "WARNING"},
            "output": {"default_format": "json"},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            yaml.dump(config_data, tmp)
            tmp_path = tmp.name

        try:
            result = self.runner.invoke(main, ["--config", tmp_path])

            assert result.exit_code == 0
            # Check that analyzer was created with config
            call_args = mock_analyzer_class.call_args[1]
            assert "config" in call_args

        finally:
            import os

            os.unlink(tmp_path)

    def test_main_version(self):
        """Test version flag."""
        with patch("aws_waf_log_analyzer.cli.__version__", "1.0.0"):
            result = self.runner.invoke(main, ["--version"])

            assert result.exit_code == 0
            assert "1.0.0" in result.output

    @patch("aws_waf_log_analyzer.cli.setup_logging")
    def test_main_invalid_config_file(self, mock_logging):
        """Test CLI with invalid configuration file."""
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        with tempfile.NamedTemporaryFile(suffix=".yaml") as tmp:
            # Write invalid YAML
            tmp.write(b"invalid: yaml: content: [")
            tmp.flush()

            result = self.runner.invoke(main, ["--config", tmp.name])

            assert result.exit_code == 1
            assert "Error loading configuration" in result.output

    def test_config_init_command(self):
        """Test config init command."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = f"{tmp_dir}/test-config.yaml"

            result = self.runner.invoke(config, ["init", "--output", config_path])

            assert result.exit_code == 0
            assert "Default configuration created" in result.output

            # Check that file was created and contains valid YAML
            import os

            assert os.path.exists(config_path)

            with open(config_path) as f:
                loaded_config = yaml.safe_load(f)
                assert "aws" in loaded_config
                assert "logging" in loaded_config
                assert "output" in loaded_config

    def test_config_validate_command(self):
        """Test config validate command."""
        # Create a valid config file
        config_data = get_default_config()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            yaml.dump(config_data, tmp)
            tmp_path = tmp.name

        try:
            result = self.runner.invoke(config, ["validate", tmp_path])

            assert result.exit_code == 0
            assert "is valid" in result.output

        finally:
            import os

            os.unlink(tmp_path)

    def test_config_validate_invalid(self):
        """Test config validate with invalid file."""
        # Create an invalid config file
        invalid_config = {
            "aws": {"region": "us-east-1"},
            "logging": {"level": "INVALID_LEVEL"},  # Invalid log level
            "output": {"default_format": "table"},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            yaml.dump(invalid_config, tmp)
            tmp_path = tmp.name

        try:
            result = self.runner.invoke(config, ["validate", tmp_path])

            assert result.exit_code == 1
            assert "Configuration validation failed" in result.output

        finally:
            import os

            os.unlink(tmp_path)

    def test_config_show_command(self):
        """Test config show command."""
        config_data = get_default_config()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            yaml.dump(config_data, tmp)
            tmp_path = tmp.name

        try:
            result = self.runner.invoke(config, ["show", tmp_path])

            assert result.exit_code == 0
            assert "Current Configuration" in result.output
            assert "aws:" in result.output

        finally:
            import os

            os.unlink(tmp_path)

    @patch("aws_waf_log_analyzer.cli.WAFLogAnalyzer")
    @patch("aws_waf_log_analyzer.cli.setup_logging")
    def test_main_keyboard_interrupt(self, mock_logging, mock_analyzer_class):
        """Test CLI handling of keyboard interrupt."""
        mock_analyzer = Mock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_analyzer.analyze_enhanced.side_effect = KeyboardInterrupt()
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        result = self.runner.invoke(main, ["--bucket", "test-bucket"])

        assert result.exit_code == 130
        assert "interrupted by user" in result.output

    @patch("aws_waf_log_analyzer.cli.WAFLogAnalyzer")
    @patch("aws_waf_log_analyzer.cli.setup_logging")
    def test_main_analysis_error(self, mock_logging, mock_analyzer_class):
        """Test CLI handling of analysis errors."""
        mock_analyzer = Mock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_analyzer.initialize_s3_client.side_effect = Exception("Test error")
        mock_logger = Mock()
        mock_logging.return_value = mock_logger

        result = self.runner.invoke(main, ["--bucket", "test-bucket"])

        assert result.exit_code == 1
        assert "Analysis failed" in result.output
