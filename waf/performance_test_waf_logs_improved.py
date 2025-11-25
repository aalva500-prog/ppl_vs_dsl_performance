#!/usr/bin/env python3
"""
Improved VPC Performance Tester with Robust Outlier Detection

Key improvements:
1. MAD-based outlier detection during data collection
2. Robust statistics calculation with outlier filtering
3. Increased warm-up iterations
4. Better reporting with outlier counts
5. Separate tracking of raw vs cleaned metrics
"""
import json
import time
import statistics
import csv
import re
import requests
import traceback
import numpy as np
from requests.auth import HTTPBasicAuth

class ImprovedWAFLogsPerformanceTester:
    def __init__(self, endpoint, username, password, iterations=100, query_delay=0.05, outlier_threshold=3.5):
        self.endpoint = endpoint.rstrip('/')
        self.iterations = iterations
        self.auth = HTTPBasicAuth(username, password)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update({'Content-Type': 'application/json'})
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=3
        )
        self.session.mount('https://', adapter)
        self.query_delay = query_delay
        self.outlier_threshold = outlier_threshold
    
    def parse_waf_queries_file(self, file_path):
        """Parse WAF queries file"""
        with open(file_path, 'r') as f:
            content = f.read()
        
        queries = []
        query_pattern = r'Query #(\d+):'
        query_matches = list(re.finditer(query_pattern, content))
        
        for i, match in enumerate(query_matches):
            query_num = int(match.group(1))
            start_pos = match.end()
            end_pos = query_matches[i + 1].start() if i + 1 < len(query_matches) else len(content)
            
            block = content[start_pos:end_pos]
            lines = block.split('\n')
            
            ppl_query = None
            dsl_query = None
            index_name = None
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('-') and not line.startswith('POST'):
                    if line.startswith('SOURCE') or line.startswith('source'):
                        ppl_query = line.rstrip('\t\n\r ')
                        break
            
            post_idx = -1
            for j, line in enumerate(lines):
                if line.startswith('POST '):
                    post_idx = j
                    index_name = line.split()[1].split('/')[0]
                    break
            
            if post_idx >= 0:
                post_line = lines[post_idx]
                if '{' in post_line:
                    json_part = post_line[post_line.index('{'):]
                    json_lines = [json_part]
                    brace_count = json_part.count('{') - json_part.count('}')
                    
                    for j in range(post_idx + 1, len(lines)):
                        line = lines[j].strip()
                        if not line:
                            continue
                        json_lines.append(line)
                        brace_count += line.count('{') - line.count('}')
                        if brace_count == 0 and line.endswith('}'):
                            break
                else:
                    json_start = -1
                    for j in range(post_idx + 1, len(lines)):
                        line = lines[j].strip()
                        if line == '{':
                            json_start = j
                            break
                    
                    if json_start >= 0:
                        json_lines = []
                        brace_count = 0
                        for j in range(json_start, len(lines)):
                            line = lines[j].strip()
                            if not line:
                                continue
                            json_lines.append(line)
                            brace_count += line.count('{') - line.count('}')
                            if brace_count == 0 and line.endswith('}'):
                                break
                
                try:
                    dsl_query = json.loads('\n'.join(json_lines))
                except json.JSONDecodeError:
                    continue
            
            if ppl_query and dsl_query and index_name:
                queries.append({
                    'id': query_num,
                    'ppl': ppl_query,
                    'dsl': dsl_query,
                    'index': index_name
                })
        
        return queries
    
    def execute_query(self, method, url, payload=None, retry_count=0, max_retries=5):
        """Execute query with retry logic - same as before"""
        start_time = time.time()
        try:
            if method == 'POST':
                response = self.session.post(url, json=payload, timeout=60)
            else:
                response = self.session.get(url, timeout=60)
            
            end_time = time.time()
            response.raise_for_status()
            return end_time - start_time, True, ""
        except Exception as e:
            end_time = time.time()
            error_msg = str(e)
            
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.text
                    error_msg = f"{error_msg} - Response: {error_detail[:300]}"
                except:
                    pass
            
            retry_conditions = [
                "circuit" in error_msg.lower(),
                "too many requests" in error_msg.lower(),
                "429" in error_msg,
                "timeout" in error_msg.lower(),
                "connection" in error_msg.lower(),
                "pool" in error_msg.lower(),
                "broken" in error_msg.lower(),
                "reset" in error_msg.lower(),
                "500" in error_msg,
                "502" in error_msg,
                "503" in error_msg
            ]
            
            if any(retry_conditions) and retry_count < max_retries:
                wait_time = (2 ** retry_count) + (retry_count * 0.5)
                print(f"\n    Retry {retry_count+1}/{max_retries}, waiting {wait_time:.1f}s...", end="")
                time.sleep(wait_time)
                return self.execute_query(method, url, payload, retry_count + 1, max_retries)
            
            return end_time - start_time, False, error_msg[:500]
    
    def is_outlier(self, value, data_points, threshold=None):
        """
        Detect outliers using Modified Z-Score (MAD-based).
        More robust than standard z-score for small samples.
        
        Reference: Boris Iglewicz and David Hoaglin (1993), 
        "Volume 16: How to Detect and Handle Outliers", The ASQC Basic References in Quality Control
        """
        if threshold is None:
            threshold = self.outlier_threshold
            
        if len(data_points) < 3:
            return False
        
        data_array = np.array(data_points)
        median = np.median(data_array)
        mad = np.median(np.abs(data_array - median))
        
        if mad == 0:
            # Fall back to standard deviation if MAD is zero
            std = np.std(data_array)
            if std == 0:
                return False
            z_score = abs(value - np.mean(data_array)) / std
            return z_score > threshold
        
        # Modified Z-Score: 0.6745 is the 75th percentile of the standard normal distribution
        modified_z_score = 0.6745 * (value - median) / mad
        return abs(modified_z_score) > threshold
    
    def cluster_warm_up(self, queries, iterations=20):
        """
        Initial cluster warm-up - INCREASED from 10 to 20 iterations
        """
        print(f"\n🔥 Cluster Warm-up: Running {iterations} iterations to wake up cluster resources...")
        
        sample_size = min(5, len(queries))
        sample_queries = queries[:sample_size]
        
        successes = 0
        failures = 0
        for iteration in range(iterations):
            print(f"  Cluster warm-up iteration {iteration + 1}/{iterations}...", end=" ")
            for query_data in sample_queries:
                _, success, _ = self.execute_query('POST', f"{self.endpoint}/_plugins/_ppl", {"query": query_data['ppl']})
                if success:
                    successes += 1
                else:
                    failures += 1
                time.sleep(self.query_delay)
            print("✓")
        
        success_rate = (successes / (successes + failures) * 100) if (successes + failures) > 0 else 0
        print(f"🔥 Cluster warm-up complete! Success rate: {success_rate:.1f}% ({successes}/{successes + failures})\n")
        time.sleep(0.5)
    
    def per_query_warm_up(self, ppl_query, dsl_query, index, iterations=10):
        """
        Per-query warm-up - INCREASED from 5 to 10 iterations
        """
        print(f"  Per-query warm-up ({iterations} iterations)...", end=" ", flush=True)
        
        ppl_successes = 0
        dsl_successes = 0
        
        for _ in range(iterations):
            _, success, _ = self.execute_query('POST', f"{self.endpoint}/_plugins/_ppl", {"query": ppl_query})
            if success:
                ppl_successes += 1
            time.sleep(self.query_delay)
        
        for _ in range(iterations):
            _, success, _ = self.execute_query('POST', f"{self.endpoint}/{index}/_search", dsl_query)
            if success:
                dsl_successes += 1
            time.sleep(self.query_delay)
        
        print(f"✓ (PPL: {ppl_successes}/{iterations}, DSL: {dsl_successes}/{iterations})")
        time.sleep(0.1)
    
    def calculate_robust_metrics(self, times):
        """
        Calculate metrics with outlier detection and robust statistics.
        
        Returns both raw stats (with outliers) and clean stats (outliers removed).
        """
        if not times:
            return {
                "avg": 0, "median": 0, "std": 0, "mad": 0, 
                "p90": 0, "p95": 0, "p99": 0, "min": 0, "max": 0,
                "raw_max": 0, "outlier_count": 0, "success_rate": 0,
                "clean_avg": 0, "clean_std": 0
            }
        
        times_array = np.array(times)
        
        # Identify outliers using Modified Z-Score
        outlier_mask = np.array([self.is_outlier(t, times_array) for t in times_array])
        clean_times = times_array[~outlier_mask]
        
        if len(clean_times) == 0:
            clean_times = times_array  # Fallback if all marked as outliers
        
        # Calculate metrics on CLEAN data (outliers removed)
        median_val = np.median(clean_times)
        mad_val = np.median(np.abs(clean_times - median_val))
        
        return {
            # Metrics calculated on clean data (outliers removed)
            "avg": float(round(float(np.mean(clean_times)), 2)),
            "median": float(round(float(median_val), 2)),
            "std": float(round(float(np.std(clean_times)), 2)),
            "mad": float(round(float(mad_val), 2)),
            "p90": float(round(float(np.percentile(clean_times, 90)), 2)),
            "p95": float(round(float(np.percentile(clean_times, 95)), 2)),
            "p99": float(round(float(np.percentile(clean_times, 99)), 2)),
            "min": float(round(float(np.min(clean_times)), 2)),
            "max": float(round(float(np.max(clean_times)), 2)),
            
            # Raw metrics (for debugging)
            "raw_max": float(round(float(np.max(times_array)), 2)),
            "raw_avg": float(round(float(np.mean(times_array)), 2)),
            "outlier_count": int(np.sum(outlier_mask)),
            "success_rate": float(round(len(times) / self.iterations * 100, 1))
        }
    
    def run_waf_performance_test(self, query_data):
        """Run performance test with improved statistics"""
        query_id = query_data['id']
        ppl_query = query_data['ppl']
        dsl_query = query_data['dsl']
        index = query_data['index']
        
        print(f"\nTesting WAF Query #{query_id}...")
        print(f"PPL: {ppl_query[:80]}{'...' if len(ppl_query) > 80 else ''}")
        print(f"Index: {index}")
        
        # Increased per-query warm-up (now 10 iterations)
        self.per_query_warm_up(ppl_query, dsl_query, index, iterations=10)
        
        # Interleaved testing
        ppl_times = []
        ppl_errors = []
        dsl_times = []
        dsl_errors = []
        
        print(f"  Running {self.iterations} interleaved test iterations (PPL/DSL pairs)...", end=" ", flush=True)
        for i in range(self.iterations):
            if (i + 1) % 10 == 0:
                print(f"{i + 1}", end=" ", flush=True)
            
            # Run PPL query
            exec_time, success, error = self.execute_query(
                'POST', 
                f"{self.endpoint}/_plugins/_ppl",
                {"query": ppl_query}
            )
            if success:
                ppl_times.append(exec_time * 1000)
            else:
                ppl_errors.append(error)
            
            time.sleep(self.query_delay)
            
            # Run DSL query
            exec_time, success, error = self.execute_query(
                'POST',
                f"{self.endpoint}/{index}/_search",
                dsl_query
            )
            if success:
                dsl_times.append(exec_time * 1000)
            else:
                dsl_errors.append(error)
            
            if i < self.iterations - 1:
                time.sleep(self.query_delay)
        
        print()
        
        # Calculate robust metrics
        ppl_metrics = self.calculate_robust_metrics(ppl_times)
        dsl_metrics = self.calculate_robust_metrics(dsl_times)
        
        # Report outliers if detected
        if ppl_metrics['outlier_count'] > 0:
            print(f"  ⚠️  PPL outliers detected: {ppl_metrics['outlier_count']}/{len(ppl_times)} "
                  f"(raw_max: {ppl_metrics['raw_max']:.1f}ms, clean_max: {ppl_metrics['max']:.1f}ms)")
        if dsl_metrics['outlier_count'] > 0:
            print(f"  ⚠️  DSL outliers detected: {dsl_metrics['outlier_count']}/{len(dsl_times)} "
                  f"(raw_max: {dsl_metrics['raw_max']:.1f}ms, clean_max: {dsl_metrics['max']:.1f}ms)")
        
        # Calculate statistical significance on CLEAN data
        statistically_significant = False
        if len(ppl_times) > 1 and len(dsl_times) > 1:
            try:
                from scipy import stats
                # Use clean data for t-test
                ppl_array = np.array(ppl_times)
                dsl_array = np.array(dsl_times)
                ppl_clean = ppl_array[~np.array([self.is_outlier(t, ppl_array) for t in ppl_array])]
                dsl_clean = dsl_array[~np.array([self.is_outlier(t, dsl_array) for t in dsl_array])]
                
                if len(ppl_clean) > 1 and len(dsl_clean) > 1:
                    _, p_value = stats.ttest_ind(ppl_clean, dsl_clean)
                    statistically_significant = bool(p_value < 0.05)
            except:
                pass
        
        sig_marker = " ***" if statistically_significant else ""
        print(f"  Results: PPL {ppl_metrics['avg']}ms avg, {ppl_metrics['median']}ms median "
              f"(p95: {ppl_metrics['p95']}ms, outliers: {ppl_metrics['outlier_count']}) [{ppl_metrics['success_rate']}%] vs "
              f"DSL {dsl_metrics['avg']}ms avg, {dsl_metrics['median']}ms median "
              f"(p95: {dsl_metrics['p95']}ms, outliers: {dsl_metrics['outlier_count']}) [{dsl_metrics['success_rate']}%]{sig_marker}")
        
        return {
            "query_id": query_id,
            "ppl": ppl_metrics,
            "dsl": dsl_metrics,
            "statistically_significant": statistically_significant,
            "ppl_errors": ppl_errors[:3],
            "dsl_errors": dsl_errors[:3]
        }
    
    def detect_outliers(self, results):
        """
        Detect outlier QUERIES (not outlier executions within a query).
        Uses deterministic criteria based on performance characteristics.
        """
        if len(results) < 4:
            return set()
        
        outliers = set()
        
        # 1. Queries with high PPL/DSL ratio (PPL significantly slower)
        for r in results:
            if r['ppl']['median'] > 0 and r['dsl']['median'] > 0:
                ratio = r['ppl']['median'] / r['dsl']['median']
                if ratio > 1.5:  # PPL is 50% slower than DSL
                    outliers.add(r['query_id'])
        
        # 2. Queries with many outlier executions (inconsistent performance)
        for r in results:
            outlier_rate = r['ppl']['outlier_count'] / self.iterations if self.iterations > 0 else 0
            if outlier_rate > 0.05:  # More than 5% outliers
                outliers.add(r['query_id'])
        
        # 3. Queries with absolute slow performance (using IQR on medians)
        ppl_medians = [(r['query_id'], r['ppl']['median']) for r in results if r['ppl']['median'] > 0]
        if ppl_medians:
            median_values = [med for _, med in ppl_medians]
            q1 = np.percentile(median_values, 25)
            q3 = np.percentile(median_values, 75)
            iqr = q3 - q1
            upper_bound = q3 + 1.5 * iqr
            
            for query_id, median in ppl_medians:
                if median > upper_bound:
                    outliers.add(query_id)
        
        return outliers
    
    def save_waf_csv_summary(self, results, queries, filename='waf_performance_summary_improved.csv'):
        """Save results with improved outlier reporting and interpretation guide"""
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                'Query_ID', 'PPL_Query', 'DSL_Query', 
                'PPL_Avg_ms', 'PPL_Median_ms', 'PPL_Std_ms', 'PPL_MAD_ms', 
                'PPL_P90_ms', 'PPL_P95_ms', 'PPL_P99_ms', 'PPL_Min_ms', 'PPL_Max_ms', 
                'PPL_Raw_Max_ms', 'PPL_Outlier_Count', 'PPL_Success_Rate',
                'DSL_Avg_ms', 'DSL_Median_ms', 'DSL_Std_ms', 'DSL_MAD_ms', 
                'DSL_P90_ms', 'DSL_P95_ms', 'DSL_P99_ms', 'DSL_Min_ms', 'DSL_Max_ms',
                'DSL_Raw_Max_ms', 'DSL_Outlier_Count', 'DSL_Success_Rate', 
                'Winner', 'PPL_DSL_Ratio', 'Statistically_Significant', 
                'Performance_Outlier', 'Outlier_Reason'
            ])
            
            outliers = self.detect_outliers(results)
            query_dict = {q['id']: q for q in queries}
            
            for result in results:
                ppl = result['ppl']
                dsl = result['dsl']
                query_id = result['query_id']
                
                ppl_valid = ppl['success_rate'] >= 80
                dsl_valid = dsl['success_rate'] >= 80
                
                if ppl_valid and dsl_valid:
                    winner = "PPL" if ppl['avg'] < dsl['avg'] else "DSL"
                elif ppl_valid:
                    winner = "PPL"
                elif dsl_valid:
                    winner = "DSL"
                else:
                    winner = "BOTH FAILED"
                
                ppl_query = query_dict.get(query_id, {}).get('ppl', '')
                dsl_query = json.dumps(query_dict.get(query_id, {}).get('dsl', {}), separators=(',', ':'))
                
                is_outlier = "Yes" if query_id in outliers else "No"
                ppl_dsl_ratio = round(ppl['median'] / dsl['median'], 2) if dsl['median'] > 0 else 0
                
                # Determine outlier reason
                outlier_reason = ""
                if query_id in outliers:
                    reasons = []
                    
                    if ppl_dsl_ratio > 1.5:
                        reasons.append(f"Slow_vs_DSL(ratio:{ppl_dsl_ratio}x)")
                    
                    outlier_rate = ppl['outlier_count'] / self.iterations if self.iterations > 0 else 0
                    if outlier_rate > 0.05:
                        reasons.append(f"High_Outlier_Rate({ppl['outlier_count']}/{self.iterations}={outlier_rate:.1%})")
                    
                    ppl_medians = [r['ppl']['median'] for r in results if r['ppl']['median'] > 0]
                    if ppl_medians:
                        q3 = np.percentile(ppl_medians, 75)
                        iqr = np.percentile(ppl_medians, 75) - np.percentile(ppl_medians, 25)
                        if ppl['median'] > q3 + 1.5 * iqr:
                            reasons.append(f"Slow_PPL_Absolute(median:{ppl['median']}ms)")
                    
                    outlier_reason = ";".join(reasons) if reasons else "Statistical_Outlier"
                
                stat_sig = result.get('statistically_significant', False)
                
                writer.writerow([
                    query_id, ppl_query, dsl_query,
                    ppl['avg'], ppl['median'], ppl['std'], ppl['mad'], 
                    ppl['p90'], ppl['p95'], ppl['p99'], ppl['min'], ppl['max'],
                    ppl['raw_max'], ppl['outlier_count'], ppl['success_rate'],
                    dsl['avg'], dsl['median'], dsl['std'], dsl['mad'],
                    dsl['p90'], dsl['p95'], dsl['p99'], dsl['min'], dsl['max'],
                    dsl['raw_max'], dsl['outlier_count'], dsl['success_rate'],
                    winner, ppl_dsl_ratio, "Yes" if stat_sig else "No", 
                    is_outlier, outlier_reason
                ])
            
            # Add interpretation guide at the end
            writer.writerow([])
            writer.writerow([])
            writer.writerow(['=== INTERPRETATION GUIDE ==='])
            writer.writerow([])
            
            writer.writerow(['KEY METRICS EXPLAINED:'])
            writer.writerow(['PPL_Max_ms', 'Maximum execution time from CLEANED data (outliers removed) - represents typical worst case'])
            writer.writerow(['PPL_Raw_Max_ms', 'Maximum execution time from ALL data (including outliers) - represents absolute worst case'])
            writer.writerow(['PPL_Outlier_Count', 'Number of outlier executions detected (out of ' + str(self.iterations) + ' total)'])
            writer.writerow(['PPL_DSL_Ratio', 'Performance ratio - how much slower/faster PPL is vs DSL (1.0 = equal performance)'])
            writer.writerow(['Performance_Outlier', 'Yes = Query is an outlier compared to other queries; No = Normal performance'])
            writer.writerow(['Outlier_Reason', 'Why query was flagged - e.g., Slow_vs_DSL, High_Outlier_Rate, Slow_PPL_Absolute'])
            writer.writerow([])
            
            writer.writerow(['HEALTH INDICATORS:'])
            writer.writerow(['Metric', 'Healthy', 'Needs Attention', 'Critical'])
            writer.writerow(['PPL_Outlier_Count', '0-2', '3-5', '>5'])
            writer.writerow(['Raw vs Clean Max Difference', '<10%', '10-25%', '>25%'])
            writer.writerow(['PPL_DSL_Ratio', '<1.1 (±10%)', '1.1-1.5 (10-50% slower)', '>1.5 (>50% slower)'])
            writer.writerow(['PPL_Success_Rate', '≥95%', '80-95%', '<80%'])
            writer.writerow(['Performance_Outlier', 'No', '-', 'Yes'])
            writer.writerow([])
            
            writer.writerow(['HOW TO IDENTIFY PROBLEMATIC QUERIES:'])
            writer.writerow(['1. Check Performance_Outlier column', 'Yes = Query needs investigation'])
            writer.writerow(['2. Check PPL_Outlier_Count', '>5 outliers = Inconsistent performance (network/cluster issues)'])
            writer.writerow(['3. Check PPL_DSL_Ratio', '>1.5 = PPL significantly slower than DSL (optimization opportunity)'])
            writer.writerow(['4. Check PPL_Success_Rate', '<95% = Query reliability issues'])
            writer.writerow(['5. Compare PPL_Raw_Max_ms vs PPL_Max_ms', '>25% difference = Large performance spikes'])
            writer.writerow([])
            
            writer.writerow(['OUTLIER DETECTION METHOD:'])
            writer.writerow(['Algorithm', 'Modified Z-Score using MAD (Median Absolute Deviation)'])
            writer.writerow(['Threshold', str(self.outlier_threshold) + ' (default)'])
            writer.writerow(['Reference', 'Iglewicz & Hoaglin (1993) - How to Detect and Handle Outliers'])
            writer.writerow(['Purpose', 'Identifies statistical anomalies caused by network issues, GC pauses, cluster delays'])
            writer.writerow([])
            
            writer.writerow(['TEST SUMMARY:'])
            total_ppl_outliers = sum(r['ppl']['outlier_count'] for r in results)
            total_dsl_outliers = sum(r['dsl']['outlier_count'] for r in results)
            total_executions = len(results) * self.iterations
            total_query_outliers = len(outliers)
            avg_ppl_ratio = np.mean([r['ppl']['median'] / r['dsl']['median'] if r['dsl']['median'] > 0 else 1 for r in results])
            
            writer.writerow(['Total Queries Tested', len(results)])
            writer.writerow(['Queries Flagged as Outliers', total_query_outliers])
            writer.writerow(['Iterations per Query', self.iterations])
            writer.writerow(['PPL Outlier Executions', f"{total_ppl_outliers}/{total_executions} ({total_ppl_outliers/total_executions*100:.1f}%)"])
            writer.writerow(['DSL Outlier Executions', f"{total_dsl_outliers}/{total_executions} ({total_dsl_outliers/total_executions*100:.1f}%)"])
            writer.writerow(['Average PPL/DSL Ratio', f"{avg_ppl_ratio:.2f}"])
            writer.writerow(['Outlier Detection Threshold', self.outlier_threshold])
            writer.writerow([])
            
            # Add per-query outlier analysis
            writer.writerow([])
            writer.writerow(['=== PER-QUERY OUTLIER ANALYSIS ==='])
            writer.writerow([])
            writer.writerow(['This section explains why each query was or was not flagged as an outlier.'])
            writer.writerow(['Three detection criteria are evaluated: PPL/DSL Ratio, Outlier Execution Rate, and Absolute Performance.'])
            writer.writerow([])
            
            # Calculate thresholds for absolute performance detection
            ppl_medians = [r['ppl']['median'] for r in results if r['ppl']['median'] > 0]
            if ppl_medians:
                q1 = np.percentile(ppl_medians, 25)
                q3 = np.percentile(ppl_medians, 75)
                iqr = q3 - q1
                upper_bound = q3 + 1.5 * iqr
            else:
                upper_bound = 0
            
            for result in results:
                query_id = result['query_id']
                ppl = result['ppl']
                dsl = result['dsl']
                is_outlier = query_id in outliers
                ppl_dsl_ratio = ppl['median'] / dsl['median'] if dsl['median'] > 0 else 0
                outlier_rate = ppl['outlier_count'] / self.iterations if self.iterations > 0 else 0
                raw_clean_diff_pct = ((ppl['raw_max'] - ppl['max']) / ppl['max'] * 100) if ppl['max'] > 0 else 0
                
                writer.writerow([])
                writer.writerow([f"Query #{query_id}", f"{'⚠️ FLAGGED AS OUTLIER' if is_outlier else '✓ Normal Performance'}"])
                writer.writerow(['PPL Median', f"{ppl['median']}ms"])
                writer.writerow(['DSL Median', f"{dsl['median']}ms"])
                writer.writerow(['Success Rate', f"{ppl['success_rate']}%"])
                writer.writerow([])
                
                # Criterion 1: PPL/DSL Ratio
                ratio_pass = ppl_dsl_ratio <= 1.5
                writer.writerow(['Criterion 1: PPL/DSL Performance Ratio'])
                writer.writerow(['  Value', f"{ppl_dsl_ratio:.2f}x"])
                writer.writerow(['  Threshold', '≤1.5x (PPL should not be >50% slower than DSL)'])
                writer.writerow(['  Status', f"{'✓ PASS' if ratio_pass else '✗ FAIL - PPL significantly slower than DSL'}"])
                writer.writerow([])
                
                # Criterion 2: Outlier Execution Rate
                rate_pass = outlier_rate <= 0.05
                writer.writerow(['Criterion 2: Outlier Execution Rate'])
                writer.writerow(['  Value', f"{ppl['outlier_count']}/{self.iterations} ({outlier_rate:.1%})"])
                writer.writerow(['  Threshold', '≤5% (no more than 5 outlier executions per 100)'])
                writer.writerow(['  Status', f"{'✓ PASS' if rate_pass else '✗ FAIL - Too many inconsistent executions'}"])
                writer.writerow([])
                
                # Criterion 3: Absolute Performance
                absolute_pass = ppl['median'] <= upper_bound
                writer.writerow(['Criterion 3: Absolute Performance (vs other queries)'])
                writer.writerow(['  Value', f"{ppl['median']}ms"])
                writer.writerow(['  Threshold', f"≤{upper_bound:.2f}ms (Q3 + 1.5×IQR)"])
                writer.writerow(['  Status', f"{'✓ PASS' if absolute_pass else '✗ FAIL - Significantly slower than other queries'}"])
                writer.writerow([])
                
                # Additional diagnostics
                writer.writerow(['Additional Diagnostics:'])
                writer.writerow(['  Raw vs Clean Max Diff', f"{raw_clean_diff_pct:.1f}% ({ppl['raw_max']}ms vs {ppl['max']}ms)"])
                writer.writerow(['  P95 Latency', f"{ppl['p95']}ms"])
                writer.writerow(['  Variability (MAD)', f"{ppl['mad']}ms"])
                writer.writerow([])
                
                # Summary verdict
                if is_outlier:
                    failed_criteria = []
                    if not ratio_pass:
                        failed_criteria.append('slow vs DSL')
                    if not rate_pass:
                        failed_criteria.append('inconsistent executions')
                    if not absolute_pass:
                        failed_criteria.append('slow absolute performance')
                    
                    writer.writerow(['VERDICT', f"⚠️ OUTLIER - Failed {len(failed_criteria)} criterion/criteria: {', '.join(failed_criteria)}"])
                    writer.writerow(['Recommendation', 'Investigate query for optimization opportunities or system issues'])
                else:
                    writer.writerow(['VERDICT', '✓ HEALTHY - Passed all outlier detection criteria'])
                    if outlier_rate > 0:
                        writer.writerow(['Note', f"Had {ppl['outlier_count']} outlier executions but within acceptable range (<5%)"])

def main():
    # Configuration - IMPROVED
    CLUSTER_WARMUP_ITERATIONS = 20   # Increased from 10
    PER_QUERY_WARMUP_ITERATIONS = 10  # Increased from 5
    TEST_ITERATIONS = 100
    QUERY_DELAY = 0.05
    OUTLIER_THRESHOLD = 3.5  # MAD-based z-score threshold
    
    import os
    ENDPOINT = os.getenv('OPENSEARCH_ENDPOINT', 'https://your-opensearch-endpoint.region.es.amazonaws.com')
    USERNAME = os.getenv('OPENSEARCH_USERNAME', 'your-username')
    PASSWORD = os.getenv('OPENSEARCH_PASSWORD', 'your-password')
    
    tester = ImprovedWAFLogsPerformanceTester(
        ENDPOINT,
        USERNAME,
        PASSWORD,
        TEST_ITERATIONS,
        QUERY_DELAY,
        OUTLIER_THRESHOLD
    )
    
    queries = tester.parse_waf_queries_file('waf_ppl_queries.json')
    print(f"Found {len(queries)} WAF query pairs")
    print(f"Configuration: {CLUSTER_WARMUP_ITERATIONS} cluster warm-up iterations, "
          f"{PER_QUERY_WARMUP_ITERATIONS} per-query warm-up iterations, "
          f"{TEST_ITERATIONS} test iterations per query")
    print(f"Outlier detection: MAD-based z-score threshold = {OUTLIER_THRESHOLD}\n")
    
    # Run cluster warm-up
    if queries:
        tester.cluster_warm_up(queries, iterations=CLUSTER_WARMUP_ITERATIONS)
    
    results = []
    for query_data in queries:
        try:
            result = tester.run_waf_performance_test(query_data)
            results.append(result)
        except KeyboardInterrupt:
            print("\nTest interrupted by user")
            break
        except Exception as e:
            print(f"Unexpected error testing WAF query #{query_data['id']}: {e}")
            traceback.print_exc()
            continue
    
    if results:
        tester.save_waf_csv_summary(results, queries)
        with open('waf_performance_results_improved.json', 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to waf_performance_summary_improved.csv and waf_performance_results_improved.json")
        print(f"Tested {len(results)} out of {len(queries)} WAF query pairs")
        
        # Summary statistics
        total_ppl_outliers = sum(r['ppl']['outlier_count'] for r in results)
        total_dsl_outliers = sum(r['dsl']['outlier_count'] for r in results)
        total_executions = len(results) * TEST_ITERATIONS
        print(f"\nOutlier Summary:")
        print(f"  PPL: {total_ppl_outliers}/{total_executions} executions flagged as outliers ({total_ppl_outliers/total_executions*100:.1f}%)")
        print(f"  DSL: {total_dsl_outliers}/{total_executions} executions flagged as outliers ({total_dsl_outliers/total_executions*100:.1f}%)")

if __name__ == "__main__":
    main()
