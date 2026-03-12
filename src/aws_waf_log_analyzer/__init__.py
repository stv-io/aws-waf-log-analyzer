"""
AWS WAF Log Analyzer

A high-performance Python package for analyzing AWS WAF logs from S3 with parallel processing
and multiple output formats.
"""

__version__ = "0.1.0"
__author__ = "Steve"
__email__ = "steve@stv.io"

from .analyzer import WAFLogAnalyzer
from .utils import parse_time_range, setup_logging

__all__ = [
    "WAFLogAnalyzer",
    "parse_time_range",
    "setup_logging",
]
