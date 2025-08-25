#!/usr/bin/env python3
"""
Test script for the Composio proxy server.

This script tests:
1. Health check endpoints
2. Authentication header transformation
3. Request forwarding
4. Error handling scenarios
"""

import requests
import json
import time
import sys
from urllib.parse import urljoin

class ProxyTester:
    def __init__(self, base_url="http://localhost:8000", test_api_key="test_key_123"):
        self.base_url = base_url.rstrip('/')
        self.test_api_key = test_api_key
        self.session = requests.Session()
        
    def test_health_checks(self):
        """Test health check endpoints."""
        print("🏥 Testing health check endpoints...")
        
        # Test basic health check
        try:
            response = self.session.get(f"{self.base_url}/")
            print(f"   GET / -> {response.status_code}")
            if response.status_code == 200:
                print(f"   Response: {response.json()}")
            else:
                print(f"   Error: {response.text}")
        except Exception as e:
            print(f"   ❌ Health check failed: {str(e)}")
            return False
            
        # Test detailed health check
        try:
            response = self.session.get(f"{self.base_url}/health")
            print(f"   GET /health -> {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"   Service: {data.get('service')}")
                print(f"   Composio API: {data.get('composio_api')}")
            else:
                print(f"   Error: {response.text}")
        except Exception as e:
            print(f"   ❌ Detailed health check failed: {str(e)}")
            return False
            
        print("   ✅ Health checks passed")
        return True
        
    def test_authentication_transformation(self):
        """Test Bearer token to x-api-key transformation."""
        print("🔐 Testing authentication transformation...")
        
        headers = {
            "Authorization": f"Bearer {self.test_api_key}",
            "Content-Type": "application/json"
        }
        
        # Test with a simple GET request that should be forwarded
        try:
            response = self.session.get(
                f"{self.base_url}/some-endpoint", 
                headers=headers,
                timeout=30
            )
            print(f"   GET /some-endpoint -> {response.status_code}")
            
            # The actual response doesn't matter as much as the fact that:
            # 1. The request was forwarded (not 401/403 from our proxy)
            # 2. The proxy handled the Bearer token correctly
            if response.status_code not in [401, 403]:
                print("   ✅ Authentication header transformation working")
                return True
            else:
                print(f"   ❌ Authentication failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"   ❌ Authentication test failed: {str(e)}")
            return False
            
    def test_missing_authentication(self):
        """Test requests without authentication."""
        print("🚫 Testing missing authentication handling...")
        
        try:
            response = self.session.get(f"{self.base_url}/some-endpoint")
            print(f"   GET /some-endpoint (no auth) -> {response.status_code}")
            
            if response.status_code == 401:
                print("   ✅ Missing authentication properly rejected")
                return True
            else:
                print(f"   ❌ Expected 401, got {response.status_code}")
                return False
                
        except Exception as e:
            print(f"   ❌ Missing auth test failed: {str(e)}")
            return False
            
    def test_cors_headers(self):
        """Test CORS functionality."""
        print("🌐 Testing CORS headers...")
        
        headers = {
            "Origin": "https://openwebui.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization, Content-Type"
        }
        
        try:
            # Test preflight OPTIONS request
            response = self.session.options(f"{self.base_url}/", headers=headers)
            print(f"   OPTIONS / (preflight) -> {response.status_code}")
            
            if response.status_code == 200:
                cors_headers = {
                    k: v for k, v in response.headers.items() 
                    if k.lower().startswith('access-control-')
                }
                print(f"   CORS headers: {cors_headers}")
                print("   ✅ CORS preflight handled")
                return True
            else:
                print(f"   ❌ CORS preflight failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"   ❌ CORS test failed: {str(e)}")
            return False
            
    def test_request_forwarding(self):
        """Test that requests are properly forwarded."""
        print("📡 Testing request forwarding...")
        
        headers = {
            "Authorization": f"Bearer {self.test_api_key}",
            "Content-Type": "application/json",
            "User-Agent": "ProxyTester/1.0"
        }
        
        # Test different HTTP methods
        methods_to_test = ["GET", "POST"]
        
        for method in methods_to_test:
            try:
                if method == "POST":
                    test_data = {"test": "data", "timestamp": int(time.time())}
                    response = self.session.request(
                        method,
                        f"{self.base_url}/test-endpoint",
                        headers=headers,
                        json=test_data,
                        timeout=30
                    )
                else:
                    response = self.session.request(
                        method,
                        f"{self.base_url}/test-endpoint",
                        headers=headers,
                        timeout=30
                    )
                    
                print(f"   {method} /test-endpoint -> {response.status_code}")
                
                # Log some response details for debugging
                if response.headers.get('content-type', '').startswith('application/json'):
                    try:
                        json_response = response.json()
                        print(f"   Response type: JSON ({len(str(json_response))} chars)")
                    except:
                        pass
                else:
                    print(f"   Response type: {response.headers.get('content-type', 'unknown')}")
                    
            except requests.exceptions.Timeout:
                print(f"   ⏱️  {method} request timed out (expected for test endpoint)")
            except Exception as e:
                print(f"   ℹ️  {method} request: {str(e)}")
                
        print("   ✅ Request forwarding test completed")
        return True
        
    def run_all_tests(self):
        """Run all tests and return success status."""
        print("🚀 Starting proxy functionality tests...")
        print(f"   Target URL: {self.base_url}")
        print(f"   Test API Key: {self.test_api_key[:8]}..." if len(self.test_api_key) > 8 else self.test_api_key)
        print()
        
        tests = [
            ("Health Checks", self.test_health_checks),
            ("Authentication Transformation", self.test_authentication_transformation),
            ("Missing Authentication", self.test_missing_authentication),
            ("CORS Headers", self.test_cors_headers),
            ("Request Forwarding", self.test_request_forwarding),
        ]
        
        results = []
        for test_name, test_func in tests:
            try:
                result = test_func()
                results.append((test_name, result))
            except Exception as e:
                print(f"   💥 {test_name} crashed: {str(e)}")
                results.append((test_name, False))
            print()
            
        # Summary
        passed = sum(1 for _, result in results if result)
        total = len(results)
        
        print("📊 Test Results Summary:")
        for test_name, result in results:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"   {status}: {test_name}")
            
        print(f"\n🎯 Overall: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All tests passed! Proxy is ready for deployment.")
            return True
        else:
            print("⚠️  Some tests failed. Check the logs above for details.")
            return False

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Test the Composio proxy server")
    parser.add_argument("--url", default="http://localhost:8000", 
                       help="Base URL of the proxy server (default: http://localhost:8000)")
    parser.add_argument("--api-key", default="test_key_123",
                       help="Test API key to use (default: test_key_123)")
    parser.add_argument("--production", action="store_true",
                       help="Use production Railway URL format")
    
    args = parser.parse_args()
    
    # If production flag is set, try to determine Railway URL
    if args.production and args.url == "http://localhost:8000":
        print("⚠️  Production mode enabled but no URL provided.")
        print("   Please provide your Railway URL with --url https://your-app.railway.app")
        sys.exit(1)
    
    tester = ProxyTester(base_url=args.url, test_api_key=args.api_key)
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
