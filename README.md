# AWS WAF Log Analyzer

[![CI](https://github.com/stv-io/aws-waf-log-analyzer/workflows/Test%20Suite/badge.svg)](https://github.com/stv-io/aws-waf-log-analyzer/actions)
[![PyPI version](https://badge.fury.io/py/aws-waf-log-analyzer.svg)](https://badge.fury.io/py/aws-waf-log-analyzer)
[![Python versions](https://img.shields.io/pypi/pyversions/aws-waf-log-analyzer.svg)](https://pypi.org/project/aws-waf-log-analyzer/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-stvio%2Faws--waf--log--analyzer-blue.svg)](https://hub.docker.com/r/stvio/aws-waf-log-analyzer)

A high-performance Python tool for analyzing AWS WAF logs from S3 with parallel processing and multiple output formats.

## Features

- **Auto-discovery** of S3 buckets containing WAF logs
- **Flexible time range parsing** (ISO format and natural language)
- **Parallel S3 fetching** and processing for maximum performance
- **Multiple output formats**: Rich table, CSV, JSON
- **Memory-efficient streaming** JSON processing
- **Comprehensive CLI interface** with helpful error messages
- **Configuration file support** for default settings
- **Docker containerization** for easy deployment
- **Version management** with UpdateCLI automation

## Quick Start

### Installation

#### Option 1: Install from PyPI (Recommended)

```bash
pip install aws-waf-log-analyzer
```

#### Option 2: Install with uv (Fast)

```bash
uv pip install aws-waf-log-analyzer
```

#### Option 3: Docker

```bash
docker pull stvio/aws-waf-log-analyzer:latest
docker run --rm stvio/aws-waf-log-analyzer --help
```

#### Option 4: Install from Source

```bash
git clone https://github.com/stv-io/aws-waf-log-analyzer.git
cd aws-waf-log-analyzer
pip install -e .
```

### Configuration

#### AWS Credentials

Configure AWS credentials using any of these methods:

```bash
# Method 1: AWS CLI
aws configure

# Method 2: Environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=eu-west-1

# Method 3: IAM roles (when running on EC2/ECS)
```

#### Configuration File

Create a configuration file for default settings:

```bash
aws-waf-log-analyzer config init --output ~/.waf-analyzer-config.yaml
```

Edit the configuration file to customize your settings:

```yaml
aws:
  region: eu-west-1
  # bucket: your-waf-bucket  # Optional: specify default bucket

logging:
  level: INFO
  # file: /var/log/waf-analyzer.log  # Optional: log to file

output:
  default_format: table
  max_display_rows: 100

performance:
  max_workers: 10
```

### Usage Examples

#### Basic Usage

```bash
# Analyze last hour of logs (auto-discovers buckets)
aws-waf-log-analyzer --time-range "last 1 hour"

# Filter by specific host
aws-waf-log-analyzer --host api.example.com --action BLOCK

# Natural language time ranges
aws-waf-log-analyzer --time-range "last 2 hours"
aws-waf-log-analyzer --time-range "yesterday"
aws-waf-log-analyzer --time-range "today 09:00-17:00"
```

#### Advanced Usage

```bash
# Specific time range with ISO format
aws-waf-log-analyzer \
  --bucket my-waf-logs \
  --time-range "2026-03-10T14:00:00 to 2026-03-10T15:00:00" \
  --host api.example.com \
  --action BLOCK \
  --output csv \
  --output-file results.csv

# Use configuration file
aws-waf-log-analyzer \
  --config ~/.waf-analyzer-config.yaml \
  --verbose \
  --time-range "last 30 minutes"

# JSON output with metadata
aws-waf-log-analyzer \
  --output json \
  --output-file analysis-results.json \
  --time-range "last 1 hour"
```

#### Docker Usage

```bash
# Basic Docker usage
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION \
  stvio/aws-waf-log-analyzer \
  --time-range "last 1 hour"

# Mount configuration file
docker run --rm \
  -v ~/.waf-analyzer-config.yaml:/app/config.yaml \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  stvio/aws-waf-log-analyzer \
  --config /app/config.yaml \
  --time-range "last 2 hours"

# Volume mount for output files
docker run --rm \
  -v $(pwd)/results:/app/results \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  stvio/aws-waf-log-analyzer \
  --output csv \
  --output-file /app/results/waf-analysis.csv \
  --time-range "last 1 hour"
```

### Configuration Management

```bash
# Initialize default configuration
aws-waf-log-analyzer config init

# Validate configuration file
aws-waf-log-analyzer config validate ~/.waf-analyzer-config.yaml

# Show current configuration
aws-waf-log-analyzer config show ~/.waf-analyzer-config.yaml
```

## Command Line Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--bucket` | `-b` | S3 bucket name (auto-discovered if not specified) | `--bucket my-waf-logs` |
| `--time-range` | `-t` | Time range for analysis | `--time-range "last 2 hours"` |
| `--host` | `-h` | Filter by host name | `--host api.example.com` |
| `--action` | `-a` | Filter by WAF action | `--action BLOCK` |
| `--output` | `-o` | Output format | `--output csv` |
| `--output-file` | `-f` | Output file path | `--output-file results.csv` |
| `--region` | `-r` | AWS region | `--region us-west-2` |
| `--config` | `-c` | Configuration file | `--config config.yaml` |
| `--verbose` | `-v` | Enable verbose logging | `--verbose` |
| `--log-level` | | Override log level | `--log-level DEBUG` |
| `--log-file` | | Log to file | `--log-file analysis.log` |
| `--version` | | Show version information | `--version` |

## Time Range Formats

The tool supports multiple time range formats:

### Natural Language
- `last X hours/minutes/days` - Relative time
- `yesterday` - All of yesterday
- `today HH:MM-HH:MM` - Today between specified hours

### ISO Format
- `2026-03-10T14:00:00 to 2026-03-10T15:00:00` - Specific range
- `2026-03-10T14:00:00` - Single time (last hour from that time)

## Output Formats

### Table Output
Rich, formatted table with color coding (default format):
```
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ Timestamp       ┃ Action ┃ Rule ID          ┃ Client IP     ┃ Country ┃ Method ┃ URI             ┃ Host             ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ 2026-03-10      │ BLOCK  │ AWSManagedRules… │ 52.213.31.110 │ IE      │ POST   │ /api/upload     │ api.example.com  │
```

### CSV Output
Machine-readable CSV format with all fields:
```csv
timestamp,action,terminating_rule_id,client_ip,country,host,method,uri
2026-03-10T10:46:56+00:00,BLOCK,AWSManagedRulesCommonRuleSet-rule-1,52.213.31.110,IE,api.example.com,POST,/api/upload
```

### JSON Output
Structured JSON with metadata:
```json
{
  "metadata": {
    "total_entries": 4,
    "generated_at": "2026-03-10T10:56:33.910479+00:00",
    "filters": {"host": "api.example.com", "action": "BLOCK"},
    "statistics": {...}
  },
  "results": [...]
}
```

## Development

### Local Development Setup

```bash
# Clone repository
git clone https://github.com/stv-io/aws-waf-log-analyzer.git
cd aws-waf-log-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
black src tests
ruff check src tests
mypy src
```

### Docker Development

```bash
# Build Docker image
docker build -t aws-waf-log-analyzer:dev .

# Run tests in Docker
docker run --rm aws-waf-log-analyzer:dev --version

# Interactive development
docker run -it --rm -v $(pwd):/app aws-waf-log-analyzer:dev bash
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`pytest`)
6. Run linting (`black src tests && ruff check src tests`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## Performance Tips

- Use specific time ranges to limit data processing
- Increase `max_workers` in configuration for faster processing (up to CPU limits)
- Use CSV/JSON output for large datasets to avoid terminal rendering overhead
- Consider running in Docker for consistent performance

## Troubleshooting

### Common Issues

**"AWS credentials not found"**
- Configure AWS credentials with `aws configure` or environment variables
- Ensure credentials have proper S3 permissions

**"No WAF log buckets found"**
- Specify bucket name with `--bucket` option
- Check that your AWS account has access to WAF log buckets
- Verify bucket naming contains 'waf', 'logs', or 'webacl'

**"Permission denied" errors**
- Ensure AWS credentials have S3 read permissions
- Check IAM policies for bucket access

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
aws-waf-log-analyzer --verbose --log-level DEBUG --time-range "last 10 minutes"
```

### Getting Help

- Check the [Issues page](https://github.com/stv-io/aws-waf-log-analyzer/issues) for known problems
- Create a new issue with detailed information
- Include configuration file (with sensitive data removed) and error messages

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.

## Acknowledgments

- Built with [boto3](https://boto3.amazonaws.com/) for AWS integration
- UI powered by [Rich](https://rich.readthedocs.io/)
- CLI framework by [Click](https://click.palletsprojects.com/)
- Containerized with [uv](https://github.com/astral-sh/uv) for fast Python package management
