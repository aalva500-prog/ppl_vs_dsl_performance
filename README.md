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

## ⚠️ Experiencing High Outlier Rates?

If your performance tests are showing **high outlier rates (>5-10%)**, you're experiencing unreliable results caused by:
- Query delays too short (cluster can't process queries fast enough)
- Interleaved testing causing cache/planner interference
- Insufficient warm-up periods

### Quick Fix ✅

**Use the optimized scripts** that reduce outliers from 10-15% down to 2-5%:
- `vpc/performance_test_vpc_logs_optimized.py` - Optimized VPC testing
- `cloudtrail/performance_test_cloudtrail_logs_optimized.py` - Optimized CloudTrail testing
- `nfw/performance_test_nfw_logs_optimized.py` - Optimized NFW testing
- `waf/performance_test_waf_logs_optimized.py` - Optimized WAF testing

### Documentation

- **Quick Start:** See `OUTLIER_REDUCTION_SUMMARY.md` for a quick overview
- **Full Guide:** See `OPTIMIZATION_GUIDE.md` for detailed explanations, troubleshooting, and advanced tuning

### Key Optimizations (Ultra-Stable Configuration)
- **7x longer query delays** (0.05s → 0.35s) - cluster fully processes queries with margin
- **Batched testing** (all PPL first, then all DSL) - eliminates query type interference
- **1.5s cooldown** between queries - cluster settles completely
- **Increased warm-up** (50 cluster + 20 per-query iterations) - thorough cache warming
- **Reduced iterations** (75 instead of 100) - faster feedback while maintaining statistical validity

### Trade-offs
- Runtime: 17 min → 50 min (3x longer)
- Reliability: Unreliable → Highly reliable (4-5x fewer outliers)
- **Verdict:** Worth the extra time for trustworthy results ✅
