# PPL vs DSL Performance Testing

This repository contains performance testing scripts and query files for comparing PPL (Piped Processing Language) and DSL (Domain Specific Language) query performance in OpenSearch.

## Contents

The repository is organized by log type, with each directory containing performance test scripts and query definitions:

### CloudTrail
- `cloudtrail_ppl_queries.json` - PPL query definitions for CloudTrail logs
- `performance_test_cloudtrail_logs_improved.py` - Performance testing script for CloudTrail logs

### Network Firewall (NFW)
- `nfw_ppl_queries.json` - PPL query definitions for Network Firewall logs
- `performance_test_nfw_logs_improved.py` - Performance testing script for Network Firewall logs

### VPC Flow Logs
- `vpc_ppl_queries.json` - PPL query definitions for VPC Flow logs
- `performance_test_vpc_logs_improved.py` - Performance testing script for VPC Flow logs
- `vpc_performance_summary_improved_calcite.csv` - Performance results with Calcite optimization
- `vpc_performance_summary_improved_non_calcite.csv` - Performance results without Calcite optimization

### WAF (Web Application Firewall)
- `waf_ppl_queries.json` - PPL query definitions for WAF logs
- `performance_test_waf_logs_improved.py` - Performance testing script for WAF logs

## Purpose

These scripts are designed to:
- Compare query performance between PPL and DSL syntaxes
- Test various query patterns including aggregations, filters, and time-based queries
- Evaluate the impact of Calcite optimization on query performance
- Provide benchmarking data for OpenSearch query optimization

## Usage

Each performance test script can be run independently to test the corresponding log type. Make sure to configure your OpenSearch endpoint and credentials before running the tests.

## Results

Performance results are provided in CSV format for analysis, showing comparative metrics between different query approaches and optimization settings.
