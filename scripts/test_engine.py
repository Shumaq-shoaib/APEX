import requests
import time
import json

API_URL = "http://localhost:8000/api"
SELF_SPEC = json.dumps({
    "openapi": "3.0.0",
    "info": {"title": "Engine Test API", "version": "1.0"},
    "paths": {
        "/health": {
            "get": {"responses": {"200": {"description": "OK"}}}
        },
        "/api/users/{id}": {
            "get": {
                "responses": {"200": {"description": "User Data"}},
                "security": [{"bearerAuth": []}]
            }
        },
        "/api/admin/dashboard": {
            "get": {
                "responses": {"200": {"description": "Admin Only"}},
                "security": [{"bearerAuth": []}]
            }
        }
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer"
            }
        }
    }
}, indent=2)

def run():
    print("Starting Engine Verification (Self-Scan)...")
    
    # 1. Upload Spec
    print("1. Uploading Spec...")
    files = {'file': ('self_scan.yaml', SELF_SPEC)}
    res = requests.post(f"{API_URL}/specs/", files=files)
    if res.status_code != 201:
        print(f"Upload Failed: {res.text}")
        return
    
    spec_id = res.json().get("spec_id")
    print(f"   Spec ID: {spec_id}")
    
    # Debug: Print Static Analysis Results
    summary = res.json().get("summary", {})
    endpoints = res.json().get("endpoints", [])
    print(f"   Static Findings: {json.dumps(endpoints, indent=2)}")

    # 2. Create Session
    print("2. Creating Session...")
    payload = {
        "spec_id": spec_id,
        "target_url": "http://apex-backend:8000" # Internal Docker DNS
    }
    res = requests.post(f"{API_URL}/sessions/", json=payload)
    if res.status_code != 201:
        print(f"Session Creation Failed: {res.text}")
        return
    
    session_id = res.json()["id"]
    print(f"   Session ID: {session_id}")

    # 3. Start Scan
    print("3. Starting Scan...")
    res = requests.post(f"{API_URL}/sessions/{session_id}/start")
    if res.status_code != 202:
        print(f"Start Failed: {res.text}")
        return
    print("   Scan started in background.")

    # 4. Poll Results
    print("4. Polling for Completion...")
    for _ in range(10):
        time.sleep(2)
        res = requests.get(f"{API_URL}/sessions/{session_id}")
        data = res.json()
        status = data["status"]
        print(f"   Status: {status}")
        
        if status == "COMPLETED":
            print("SUCCESS: Engine executed successfully.")
            
            # Print Findings
            findings = data.get("findings", [])
            print(f"--- Findings ({len(findings)}) ---")
            for f in findings:
                print(f"[{f['severity']}] {f['title']} (CVSS: {f['cvss_score']})")
                print(f"   Remediation: {f['remediation'][:60]}...")
            return
        if status == "FAILED":
            print("FAILURE: Engine reported failure.")
            return

    print("TIMEOUT: Scan did not complete in 20s.")

if __name__ == "__main__":
    run()
