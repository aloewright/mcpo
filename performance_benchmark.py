#!/usr/bin/env python3
"""
Performance benchmark script for the optimized Composio proxy server.
Tests response times and throughput improvements.
"""

import time
import json
import sys
import os
from typing import List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    import requests
except ImportError:
    print("Error: requests module not available. Using urllib instead.")
    requests = None
    import urllib.request
    import urllib.parse
    import urllib.error

# Test configuration
BASE_URL = "http://localhost:8000"
CONCURRENT_REQUESTS = 5
WARMUP_REQUESTS = 2

def make_request(url: str, method: str = 'GET', headers: Dict[str, str] = None, data: bytes = None) -> Tuple[str, float, int, int]:
    """Make HTTP request and measure response time."""
    start = time.time()
    
    if requests:
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=30)
            elif method == 'POST':
                response = requests.post(url, headers=headers, data=data, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            duration = time.time() - start
            return url, duration, response.status_code, len(response.content)
        except Exception as e:
            duration = time.time() - start
            return url, duration, -1, str(e)[:100]
    else:
        # Fallback to urllib
        try:
            req = urllib.request.Request(url, data=data, headers=headers or {})
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read()
                duration = time.time() - start
                return url, duration, response.getcode(), len(data)
        except Exception as e:
            duration = time.time() - start
            return url, duration, -1, str(e)[:100]

def benchmark_endpoint(endpoint: str, name: str, concurrent: int = 1) -> Dict[str, Any]:
    """Benchmark a specific endpoint."""
    url = f"{BASE_URL}{endpoint}"
    print(f"Benchmarking {name} ({url})...")
    
    # Warmup
    for _ in range(WARMUP_REQUESTS):
        make_request(url)
    
    # Actual test
    start_time = time.time()
    results = []
    
    if concurrent == 1:
        # Sequential requests
        for i in range(5):
            result = make_request(url)
            results.append(result)
    else:
        # Concurrent requests
        with ThreadPoolExecutor(max_workers=concurrent) as executor:
            futures = [executor.submit(make_request, url) for _ in range(concurrent * 2)]
            for future in as_completed(futures):
                results.append(future.result())
    
    total_time = time.time() - start_time
    
    # Analyze results
    successful_results = [r for r in results if isinstance(r[2], int) and r[2] < 400]
    if not successful_results:
        return {
            "name": name,
            "endpoint": endpoint,
            "error": "All requests failed",
            "results": results
        }
    
    response_times = [r[1] for r in successful_results]
    response_sizes = [r[3] for r in successful_results if isinstance(r[3], int)]
    
    return {
        "name": name,
        "endpoint": endpoint,
        "total_requests": len(results),
        "successful_requests": len(successful_results),
        "success_rate": len(successful_results) / len(results) * 100,
        "total_time": total_time,
        "avg_response_time": sum(response_times) / len(response_times),
        "min_response_time": min(response_times),
        "max_response_time": max(response_times),
        "avg_response_size": sum(response_sizes) / len(response_sizes) if response_sizes else 0,
        "throughput": len(successful_results) / total_time,
        "raw_results": results[:3]  # First 3 results for debugging
    }

def run_performance_tests() -> List[Dict[str, Any]]:
    """Run comprehensive performance tests."""
    print("Starting Performance Benchmark")
    print("=" * 50)
    
    test_cases = [
        ("/", "Health Check", 1),
        ("/health", "Detailed Health", 1),
        ("/models", "Models Endpoint", 1),
        ("/v1/models", "V1 Models Endpoint", 1),
        ("/openapi.json", "OpenAPI Spec", 1),
        ("/openapi.tools.json?mode=generic&max=10", "Dynamic OpenAPI (Small)", 1),
        ("/openapi.tools.json?mode=generic&max=50", "Dynamic OpenAPI (Medium)", 1),
        ("/", "Health Check (Concurrent)", CONCURRENT_REQUESTS),
        ("/models", "Models (Concurrent)", CONCURRENT_REQUESTS),
    ]
    
    results = []
    for endpoint, name, concurrent in test_cases:
        result = benchmark_endpoint(endpoint, name, concurrent)
        results.append(result)
        
        # Print quick summary
        if "error" not in result:
            print(f"  {name:30s}: {result['avg_response_time']:6.3f}s avg, {result['success_rate']:5.1f}% success")
        else:
            print(f"  {name:30s}: ERROR - {result['error']}")
        
        # Small delay between tests
        time.sleep(0.5)
    
    return results

def print_detailed_results(results: List[Dict[str, Any]]):
    """Print detailed benchmark results."""
    print("\n" + "=" * 80)
    print("DETAILED PERFORMANCE RESULTS")
    print("=" * 80)
    
    for result in results:
        print(f"\n{result['name']}")
        print("-" * len(result['name']))
        
        if "error" in result:
            print(f"ERROR: {result['error']}")
            if 'results' in result:
                print("Sample errors:")
                for r in result['results'][:3]:
                    print(f"  {r}")
            continue
        
        print(f"Endpoint:           {result['endpoint']}")
        print(f"Total Requests:     {result['total_requests']}")
        print(f"Successful:         {result['successful_requests']} ({result['success_rate']:.1f}%)")
        print(f"Total Time:         {result['total_time']:.3f}s")
        print(f"Average Response:   {result['avg_response_time']:.3f}s")
        print(f"Min Response:       {result['min_response_time']:.3f}s")
        print(f"Max Response:       {result['max_response_time']:.3f}s")
        print(f"Average Size:       {result['avg_response_size']:.0f} bytes")
        print(f"Throughput:         {result['throughput']:.2f} req/s")
        
        if result.get('raw_results'):
            print("Sample Results:")
            for url, duration, status, size in result['raw_results']:
                print(f"  {status} - {duration:.3f}s - {size} bytes")

def analyze_performance(results: List[Dict[str, Any]]):
    """Analyze and provide performance insights."""
    print("\n" + "=" * 80)
    print("PERFORMANCE ANALYSIS")
    print("=" * 80)
    
    successful_results = [r for r in results if "error" not in r and r['success_rate'] > 90]
    
    if not successful_results:
        print("❌ No successful benchmarks to analyze")
        return
    
    # Fast endpoints (< 100ms average)
    fast_endpoints = [r for r in successful_results if r['avg_response_time'] < 0.1]
    print(f"⚡ Fast endpoints (< 100ms): {len(fast_endpoints)}")
    for r in fast_endpoints:
        print(f"  {r['name']:30s}: {r['avg_response_time']*1000:5.1f}ms")
    
    # Slow endpoints (> 500ms average)
    slow_endpoints = [r for r in successful_results if r['avg_response_time'] > 0.5]
    if slow_endpoints:
        print(f"🐌 Slow endpoints (> 500ms): {len(slow_endpoints)}")
        for r in slow_endpoints:
            print(f"  {r['name']:30s}: {r['avg_response_time']*1000:5.1f}ms")
    else:
        print("✅ No slow endpoints detected")
    
    # High throughput endpoints
    high_throughput = [r for r in successful_results if r['throughput'] > 10]
    if high_throughput:
        print(f"🚀 High throughput endpoints (>10 req/s): {len(high_throughput)}")
        for r in high_throughput:
            print(f"  {r['name']:30s}: {r['throughput']:5.1f} req/s")
    
    # Overall health
    avg_response = sum(r['avg_response_time'] for r in successful_results) / len(successful_results)
    print(f"\n📊 Overall average response time: {avg_response*1000:.1f}ms")
    
    if avg_response < 0.2:
        print("✅ Excellent performance!")
    elif avg_response < 0.5:
        print("✅ Good performance")
    elif avg_response < 1.0:
        print("⚠️  Moderate performance")
    else:
        print("❌ Poor performance - needs optimization")

def main():
    """Main benchmark function."""
    print("Composio Proxy Performance Benchmark")
    print(f"Testing against: {BASE_URL}")
    print(f"Concurrent requests: {CONCURRENT_REQUESTS}")
    print(f"Warmup requests per test: {WARMUP_REQUESTS}")
    print()
    
    # Check if server is running
    try:
        result = make_request(f"{BASE_URL}/")
        if isinstance(result[2], int) and result[2] == 200:
            print("✅ Server is running")
        else:
            print(f"❌ Server returned status {result[2]}")
            return 1
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        print(f"Make sure the proxy server is running on {BASE_URL}")
        return 1
    
    # Run benchmarks
    results = run_performance_tests()
    
    # Show results
    print_detailed_results(results)
    analyze_performance(results)
    
    # Save results to file
    timestamp = int(time.time())
    filename = f"benchmark_results_{timestamp}.json"
    with open(filename, 'w') as f:
        json.dump({
            "timestamp": timestamp,
            "base_url": BASE_URL,
            "concurrent_requests": CONCURRENT_REQUESTS,
            "results": results
        }, f, indent=2)
    
    print(f"\n📁 Results saved to: {filename}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
