"""Tests for the WAF Log Analyzer."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

from aws_waf_log_analyzer.analyzer import WAFLogAnalyzer


class TestWAFLogAnalyzer:
    """Test cases for WAFLogAnalyzer class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = WAFLogAnalyzer(bucket_name="test-bucket", region="us-east-1")
    
    @patch('boto3.Session')
    def test_initialize_s3_client_success(self, mock_session):
        """Test successful S3 client initialization."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        mock_client.list_buckets.return_value = {'Buckets': []}
        
        self.analyzer.initialize_s3_client()
        
        assert self.analyzer.s3_client is not None
        mock_session.return_value.client.assert_called_once_with('s3', region_name='us-east-1')
    
    @patch('boto3.Session')
    def test_initialize_s3_client_no_credentials(self, mock_session):
        """Test S3 client initialization with no credentials."""
        from botocore.exceptions import NoCredentialsError
        
        mock_session.side_effect = NoCredentialsError()
        
        with pytest.raises(NoCredentialsError):
            self.analyzer.initialize_s3_client()
    
    def test_discover_waf_buckets_with_bucket_name(self):
        """Test bucket discovery when bucket name is specified."""
        analyzer = WAFLogAnalyzer(bucket_name="specific-bucket")
        buckets = analyzer.discover_waf_buckets()
        
        assert buckets == ["specific-bucket"]
    
    @patch('aws_waf_log_analyzer.analyzer.logger')
    def test_discover_waf_buckets_auto_discovery(self, mock_logger):
        """Test automatic bucket discovery."""
        # Mock S3 client
        mock_client = Mock()
        mock_client.list_buckets.return_value = {
            'Buckets': [
                {'Name': 'waf-logs-bucket'},
                {'Name': 'regular-bucket'},
                {'Name': 'webacl-logs'}
            ]
        }
        self.analyzer.s3_client = mock_client
        
        buckets = self.analyzer.discover_waf_buckets()
        
        assert len(buckets) == 2
        assert 'waf-logs-bucket' in buckets
        assert 'webacl-logs' in buckets
        assert 'regular-bucket' not in buckets
    
    def test_extract_waf_fields(self):
        """Test WAF field extraction from log entry."""
        log_entry = {
            'timestamp': 1672531200000,  # 2023-01-01 00:00:00 UTC
            'action': 'BLOCK',
            'terminatingRuleId': 'AWSManagedRulesCommonRuleSet-rule-1',
            'terminatingRuleType': 'MANAGED_RULE_GROUP',
            'webaclId': 'webacl-123',
            'httpRequest': {
                'clientIp': '192.168.1.1',
                'country': 'US',
                'uri': '/api/test',
                'httpMethod': 'POST',
                'httpVersion': 'HTTP/1.1',
                'requestId': 'req-123',
                'headers': [
                    {'name': 'Host', 'value': 'example.com'}
                ]
            },
            'requestBodySize': 1024,
            'labels': [{'name': 'label1'}, {'name': 'label2'}]
        }
        
        extracted = self.analyzer.extract_waf_fields(log_entry)
        
        assert extracted['timestamp'] == 1672531200000
        assert extracted['action'] == 'BLOCK'
        assert extracted['terminating_rule_id'] == 'AWSManagedRulesCommonRuleSet-rule-1'
        assert extracted['client_ip'] == '192.168.1.1'
        assert extracted['country'] == 'US'
        assert extracted['uri'] == '/api/test'
        assert extracted['method'] == 'POST'
        assert extracted['host'] == 'example.com'
        assert extracted['body_size'] == 1024
        assert extracted['labels'] == ['label1', 'label2']
    
    def test_matches_filters(self):
        """Test filter matching logic."""
        entry = {
            'host': 'example.com',
            'action': 'BLOCK',
            'client_ip': '192.168.1.1',
            'terminating_rule_id': 'rule-1'
        }
        
        # Test matching filters
        filters = {'host': 'example.com', 'action': 'BLOCK'}
        assert self.analyzer.matches_filters(entry, filters) is True
        
        # Test non-matching filters
        filters = {'host': 'different.com'}
        assert self.analyzer.matches_filters(entry, filters) is False
        
        # Test empty filters
        assert self.analyzer.matches_filters(entry, {}) is True
    
    @patch('aws_waf_log_analyzer.analyzer.logger')
    def test_filter_s3_objects_by_time(self, mock_logger):
        """Test S3 object filtering by time."""
        # Mock S3 client
        mock_client = Mock()
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        
        # Mock response with objects
        mock_paginator.paginate.return_value = [
            {
                'Contents': [
                    {
                        'Key': 'AWSLogs/123456789/waflogs/eu-west-1/20230101T1200Z_file1.gz',
                        'LastModified': datetime.now(timezone.utc)
                    },
                    {
                        'Key': 'AWSLogs/123456789/waflogs/eu-west-1/20230101T1300Z_file2.gz',
                        'LastModified': datetime.now(timezone.utc)
                    },
                    {
                        'Key': 'other/file.txt',  # No timestamp pattern
                        'LastModified': datetime.now(timezone.utc)
                    }
                ]
            }
        ]
        
        self.analyzer.s3_client = mock_client
        
        start_time = datetime(2023, 1, 1, 11, 0, tzinfo=timezone.utc)
        end_time = datetime(2023, 1, 1, 14, 0, tzinfo=timezone.utc)
        
        objects = self.analyzer.filter_s3_objects_by_time(
            'test-bucket', 'AWSLogs/', start_time, end_time
        )
        
        assert len(objects) == 2
        assert '20230101T1200Z_file1.gz' in objects[0]
        assert '20230101T1300Z_file2.gz' in objects[1]
    
    def test_format_output_table_no_results(self):
        """Test table output formatting with no results."""
        with patch.object(self.analyzer.console, 'print') as mock_print:
            self.analyzer.format_output_table([])
            mock_print.assert_called_with("[yellow]No results found matching the criteria.[/yellow]")
    
    def test_format_output_csv_no_results(self):
        """Test CSV output formatting with no results."""
        with patch.object(self.analyzer.console, 'print') as mock_print:
            self.analyzer.format_output_csv([], 'test.csv')
            mock_print.assert_called_with("[yellow]No results found matching the criteria.[/yellow]")
    
    def test_format_output_json_no_results(self):
        """Test JSON output formatting with no results."""
        with patch.object(self.analyzer.console, 'print') as mock_print:
            self.analyzer.format_output_json([], 'test.json')
            mock_print.assert_called_with("[yellow]No results found matching the criteria.[/yellow]")
    
    def test_print_statistics(self):
        """Test statistics printing."""
        self.analyzer.stats = {
            'total_files': 10,
            'processed_files': 8,
            'total_entries': 1000,
            'filtered_entries': 50,
            'errors': 2
        }
        
        with patch.object(self.analyzer.console, 'print') as mock_print:
            self.analyzer.print_statistics()
            mock_print.assert_called_once()
            # Check that the call contains statistics information
            call_args = mock_print.call_args[0][0]
            assert '10' in call_args  # total_files
            assert '8' in call_args   # processed_files
            assert '1000' in call_args  # total_entries
            assert '50' in call_args   # filtered_entries
            assert '2' in call_args    # errors
