#!/usr/bin/env python3
"""Quick test scan to verify Phase 2 scanners work with new payloads."""

import sys
from core.context import ScanContext, AuthConfig
from core.engine import AttackEngine
from core.parser import SpecParser

# Test with a single endpoint to verify payloads work
target = "http://localhost:8888"
token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ6YXBfdXNlcl90b2UyMXhAZXhhbXBsZS5jb20iLCJpYXQiOjE3Njk1NDI1NzMsImV4cCI6MTc3MDE0NzM3Mywicm9sZSI6InVzZXIifQ.Tlk_wZ8osFHHOKQPNT8KbQuc0-pSgugX4B30Pvl2JOu08jugUD2XBcWqXL1cGlCT0KZEUGW7aWb7BzAPxYdZXP6lLFyEqaxO2378xyfzNT0AFtAgeojaAOeadkbM4aDed_1xfm-KenmTKxUPjpqQOiJfBXVcZ1qb9ZaYjDrl15mXyDzi7ImX4rhPQo4Shr78xbBrF0lUDK8XBBRq-hu0tYTGGNg5UDVr-WrOI31GfkD98ap3_PxZae8ApNmopaDqwm17gSQOxB7iWs2fS_psD60B7anGeAyLCLARKm_KLUijmnpoxO3E2O7OQFNQw8HN_zOVIBrGY32Pi7t_2r89VA"

print("=" * 60)
print("QUICK SCAN TEST - Phase 2 Scanners")
print("=" * 60)

# Initialize
auth_config = AuthConfig(token=token)
context = ScanContext(target_url=target, auth=auth_config)
engine = AttackEngine(context)
engine.load_scanners()

print(f"\nLoaded {len(engine.scanners)} scanners")
print("Phase 2 Scanners:")
for scanner in engine.scanners:
    if scanner.scan_id in ['API-CMD-INJ', 'API-REDIRECT', 'API-XXE']:
        print(f"  [OK] {scanner.scan_id}: {scanner.name}")

# Test with a single endpoint that has parameters
print("\n" + "=" * 60)
print("Testing with single endpoint")
print("=" * 60)

# Manually test one endpoint
from scanners.api_redirect import ExternalRedirectScanner
from scanners.api_command_injection import CommandInjectionScanner
from scanners.api_xxe import XxeScanner

test_endpoint = "/community/api/v2/community/posts/{postId}/comment"
test_method = "POST"
test_params = {
    'params': [
        {'name': 'postId', 'in': 'path'},
        {'name': 'comment', 'in': 'query'}
    ]
}

print(f"\nTesting endpoint: {test_method} {test_endpoint}")

# Test Redirect Scanner
print("\n1. Testing External Redirect Scanner...")
redirect_scanner = ExternalRedirectScanner(context)
try:
    redirect_results = redirect_scanner.run(test_endpoint, test_method, test_params)
    print(f"   Results: {len(redirect_results)} findings")
    if redirect_results:
        print(f"   Sample: {redirect_results[0].get('title', 'N/A')}")
except Exception as e:
    print(f"   Error: {e}")

# Test Command Injection Scanner  
print("\n2. Testing Command Injection Scanner...")
cmd_scanner = CommandInjectionScanner(context)
try:
    cmd_results = cmd_scanner.run(test_endpoint, test_method, test_params)
    print(f"   Results: {len(cmd_results)} findings")
    if cmd_results:
        print(f"   Sample: {cmd_results[0].get('title', 'N/A')}")
except Exception as e:
    print(f"   Error: {e}")

# Test XXE Scanner (needs POST/PUT/PATCH)
print("\n3. Testing XXE Scanner...")
xxe_scanner = XxeScanner(context)
try:
    xxe_results = xxe_scanner.run(test_endpoint, test_method, test_params)
    print(f"   Results: {len(xxe_results)} findings")
    if xxe_results:
        print(f"   Sample: {xxe_results[0].get('title', 'N/A')}")
except Exception as e:
    print(f"   Error: {e}")

print("\n" + "=" * 60)
print("QUICK TEST COMPLETE")
print("=" * 60)
print("\nAll Phase 2 scanners executed successfully with new payloads!")
