# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of AWS WAF Log Analyzer
- High-performance parallel processing of WAF logs
- Multiple output formats (table, CSV, JSON)
- Configuration file support with YAML
- Docker containerization with multi-architecture support
- Comprehensive CLI interface with Click
- Auto-discovery of S3 buckets and prefixes
- Flexible time range parsing (natural language and ISO)
- Enhanced logging configuration
- UpdateCLI integration for automated updates
- Comprehensive test suite with pytest
- GitHub Actions CI/CD pipeline
- PyPI publishing automation
- Docker Hub integration

### Features
- **Core Functionality**
  - Parse and analyze AWS WAF logs from S3
  - Extract relevant fields (timestamp, action, rule, client IP, etc.)
  - Filter by host, action, client IP, rule ID
  - Parallel processing for optimal performance
  
- **CLI Interface**
  - Rich table output with color coding
  - CSV export for data analysis
  - JSON export with metadata
  - Configuration management commands
  - Verbose logging and debugging
  
- **Configuration**
  - YAML configuration file support
  - Default settings management
  - Environment variable overrides
  - AWS credential management
  
- **Deployment**
  - Docker container with minimal footprint
  - Multi-architecture builds (amd64, arm64)
  - PyPI package distribution
  - Automated dependency updates

### Security
- Support for all AWS authentication methods
- Secure credential handling
- Non-root Docker execution
- Input validation and sanitization

### Performance
- Parallel S3 file processing
- Memory-efficient JSON streaming
- Configurable worker threads
- Optimized for large log datasets

### Documentation
- Comprehensive README with examples
- API documentation
- Configuration guide
- Troubleshooting section
- Docker usage examples

## [0.1.0] - 2026-03-12

### Added
- Initial public release
- Complete feature set as described above
- Full documentation and examples
- Production-ready Docker images
- PyPI package availability

---

## Version History

### Development Phase
- **v0.0.1** - Initial prototype with basic functionality
- **v0.0.2** - Added parallel processing and multiple output formats
- **v0.0.3** - Enhanced CLI interface and configuration support
- **v0.0.4** - Docker containerization and CI/CD pipeline
- **v0.0.5** - Comprehensive testing and documentation

### Release Phase
- **v0.1.0** - First stable public release

---

## Breaking Changes

### v0.1.0
- No breaking changes from development versions
- Configuration file format is stable
- CLI interface is finalized
- Docker image tags follow semantic versioning

---

## Deprecations

### Future Considerations
- Python 3.12 support may be deprecated in favor of 3.13+ only
- Legacy configuration formats may be deprecated in favor of YAML only
- Docker image tags without semantic versioning may be deprecated

---

## Security Updates

### v0.1.0
- Uses latest security patches for all dependencies
- Docker base image regularly updated
- AWS SDK (boto3) kept up to date
- Regular security scanning in CI/CD pipeline

---

## Performance Improvements

### v0.1.0
- Optimized S3 pagination for large buckets
- Improved JSON parsing performance with ijson
- Enhanced parallel processing with configurable workers
- Reduced memory footprint for large datasets

---

## Known Issues

### v0.1.0
- No known critical issues
- Minor improvements planned for future releases
- Community feedback appreciated for enhancement priorities

---

## Migration Guide

### From Development Versions
- Configuration file format unchanged
- CLI commands remain compatible
- Docker usage remains the same
- No migration required for v0.1.0

---

## Support

- **Issues**: Report bugs and feature requests on [GitHub Issues](https://github.com/stv-io/aws-waf-log-analyzer/issues)
- **Discussions**: Community support and questions on [GitHub Discussions](https://github.com/stv-io/aws-waf-log-analyzer/discussions)
- **Documentation**: Full documentation available in the repository
- **Docker Hub**: Image tags and usage examples available
