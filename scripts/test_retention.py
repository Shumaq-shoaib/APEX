import requests
import time

API_URL = "http://localhost:8000/api/specs"
DUMMY_SPEC = """
openapi: 3.0.0
info:
  title: Dummy Spec {i}
  version: 1.0.0
paths: {}
"""

def run():
    print("Starting Retention Test...")
    
    # 1. Clean slate? No, let's just add to existing.
    
    # 2. Upload 25 files
    for i in range(25):
        spec_content = DUMMY_SPEC.replace("{i}", str(i))
        files = {'file': (f'dummy_{i}.yaml', spec_content)}
        try:
            res = requests.post(API_URL, files=files)
            if res.status_code == 201:
                print(f"Uploaded Dummy {i} (Count: {i+1}/25)")
            else:
                print(f"Failed {i}: {res.status_code}")
        except Exception as e:
            print(f"Error {i}: {e}")
            
    # 3. Check Count
    res = requests.get(API_URL)
    specs = res.json()
    count = len(specs)
    print(f"Total Specs in DB: {count}")
    
    if count == 20:
        print("SUCCESS: Retention Policy Active (Limit 20 enforced).")
    elif count < 20:
         print(f"WARNING: Count is {count} (Less than limit, maybe DB was empty?)")
    else:
        print(f"FAILURE: Count is {count} (Policy failed).")

if __name__ == "__main__":
    run()
