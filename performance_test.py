#!/usr/bin/env python3
"""
Performance test script for the Composio proxy.
Tests response times for various endpoints to identify bottlenecks.
"""

import requests
import time
import statistics
import argparse

def test_endpoint(url, num_requests=5, headers=None):
    """Test an endpoint multiple times and return performance stats."""
    times = []
    
    print(f"Testing {url} ({num_requests} requests)...")
    
    for i in range(num_requests):
        start = time.time()
        try:
            response = requests.get(url, headers=headers, timeout=30)
            duration = time.time() - start
            times.append(duration)
            print(f"  Request {i+1}: {duration:.3f}s (Status: {response.status_code})")
        except Exception as e:
            duration = time.time() - start
            times.append(duration)
            print(f"  Request {i+1}: {duration:.3f}s (Error: {str(e)})")
    
    if times:
        avg = statistics.mean(times)
        median = statistics.median(times)
        min_time = min(times)
        max_time = max(times)
        
        print(f"  📊 Results: avg={avg:.3f}s, median={median:.3f}s, min={min_time:.3f}s, max={max_time:.3f}s")
        return {
            'avg': avg,
            'median': median, 
            'min': min_time,
            'max': max_time,
            'times': times
        }
    
    return None

def main():
    parser = argparse.ArgumentParser(description="Performance test for Composio proxy")
    parser.add_argument("--url", default="https://mcpo-open-pr-3.up.railway.app", 
                       help="Base URL to test")
    parser.add_argument("--requests", type=int, default=5,
                       help="Number of requests per endpoint")
    
    args = parser.parse_args()
    base_url = args.url.rstrip('/')
    
    print(f"🚀 Performance testing: {base_url}")
    print("=" * 60)
    
    # Test different endpoints
    endpoints = [
        ('Health Check', '/'),
        ('Detailed Health', '/health'),
        ('OpenAPI Spec', '/openapi.json'),
    ]
    
    results = {}
    
    for name, endpoint in endpoints:
        print(f"\n🔍 {name}")
        url = f"{base_url}{endpoint}"
        result = test_endpoint(url, args.requests)
        if result:
            results[name] = result
    
    # Summary
    print("\n" + "=" * 60)
    print("📈 PERFORMANCE SUMMARY")
    print("=" * 60)
    
    for name, result in results.items():
        print(f"{name:20} | avg: {result['avg']:.3f}s | median: {result['median']:.3f}s")
    
    # Recommendations
    print("\n💡 RECOMMENDATIONS:")
    
    for name, result in results.items():
        if result['avg'] > 1.0:
            print(f"⚠️  {name}: Slow response ({result['avg']:.3f}s avg) - investigate bottlenecks")
        elif result['avg'] > 0.5:
            print(f"⚡ {name}: Moderate response time ({result['avg']:.3f}s avg) - could be optimized")
        else:
            print(f"✅ {name}: Good response time ({result['avg']:.3f}s avg)")
    
    # Check consistency
    for name, result in results.items():
        variance = result['max'] - result['min']
        if variance > 1.0:
            print(f"📊 {name}: High variance ({variance:.3f}s) - inconsistent performance")

if __name__ == "__main__":
    main()
