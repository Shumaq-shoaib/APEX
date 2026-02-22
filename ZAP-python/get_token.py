import httpx
import random
import string

try:
    # 1. Check Main Page
    print("Checking connectivity...")
    with httpx.Client() as client:
        client.get("http://localhost:8888", timeout=5)
    
        # 2. Register with Random User
        print("Attempting registration...")
        reg_url = "http://localhost:8888/identity/api/auth/signup"
        rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        rand_phone = ''.join(random.choices(string.digits, k=10))
        import os
        
        email = f"zap_user_{rand_suffix}@example.com"
        password = os.getenv("ZAP_USER_PASSWORD")
        if not password:
            print("ERROR: ZAP_USER_PASSWORD env var is required")
            exit(1)
        
        reg_data = {
            "email": email,
            "password": password,
            "number": rand_phone,
            "name": f"Zap User {rand_suffix}"
        }
        
        reg_res = client.post(reg_url, json=reg_data)
        print(f"Registration Status: {reg_res.status_code}")
        if reg_res.status_code != 200:
            print(f"Registration Body: {reg_res.text}")

        # 3. Login
        print("Attempting login...")
        url = "http://localhost:8888/identity/api/auth/login"
        login_data = {
            "email": email,
            "password": password
        }
        res = client.post(url, json=login_data)
        
        if res.status_code == 200:
            token = res.json().get('token')
            print(f"TOKEN_SUCCESS: {token}")
        else:
            print(f"LOGIN_FAILED: {res.status_code} {res.text}")

except Exception as e:
    print(f"ERROR: {e}")
