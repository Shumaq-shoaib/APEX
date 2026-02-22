import sys
import os

# Ensure app can be imported. 
# We need to add 'apex-dynamic-service' to path so 'app.main' moves to 'app' module correctly?
# Actually app is inside apex-dynamic-service.
# The imports in the project use "from app.core...", so we need 'apex-dynamic-service' in sys.path
# AND we need to make sure we don't double import.

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir) # APEX-main
service_dir = os.path.join(project_root, "apex-dynamic-service")

if service_dir not in sys.path:
    sys.path.insert(0, service_dir)

try:
    from fastapi.testclient import TestClient
    from app.main import app
    from app.core import config
except ImportError as e:
    print(f"[ERROR] ImportError: {e}")
    print("Please run: pip install -r requirements.txt")
    sys.exit(1)

client = TestClient(app)

def test_health_check():
    print("\n[TEST] Health Endpoint...")
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    print(f"Response: {data}")
    assert "status" in data
    assert "components" in data
    assert "database" in data["components"]
    assert "scanner" in data["components"]
    print("[PASS] Health Check Passed")

def test_rate_limit():
    print("\n[TEST] Rate Limiting (Expect 429 after limit)...")
    success_count = 0
    blocked_count = 0
    
    # Using a distinct mock ID to avoid conflict
    payload = {"spec_id": "test_rate_limit", "target_url": "http://example.com"}
    
    for i in range(15):
        # We expect 422 if DB fails or validation passes but spec missing
        # We expect 404 if orchestrator fails on missing spec
        # We want to catch the 429
        res = client.post("/api/sessions/", json=payload)
        status = res.status_code
        
        if status == 429:
            blocked_count += 1
        else:
            success_count += 1
            
    print(f"Requests: {success_count} passed/handled, {blocked_count} rate limited")
    if blocked_count > 0:
        print("[PASS] Rate Limiting Active")
    else:
        print("[WARN] Rate Limiting did not trigger (Check if slowapi enabled or limit too high)")

def test_validation():
    print("\n[TEST] Request Validation...")
    
    # Invalid URL Scheme
    payload = {"spec_id": "test", "target_url": "ftp://bad-url.com"}
    res = client.post("/api/sessions/", json=payload)
    print(f"FTP URL Response: {res.status_code}")
    # Pydantic HttpUrl usually returns 422
    assert res.status_code == 422
    print("[PASS] Invalid URL Scheme Blocked")
    
    # Valid URL
    payload = {"spec_id": "test", "target_url": "https://good-url.com"}
    res = client.post("/api/sessions/", json=payload)
    # Should get past 422 validation, potentially hitting 404 (spec not found)
    assert res.status_code != 422
    print("[PASS] Valid URL Syntax Accepted")

if __name__ == "__main__":
    print("=== Phase 2 Verification ===")
    test_health_check()
    test_validation()
    test_rate_limit()
