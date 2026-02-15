import os
import requests
import sys

API_URL = "http://localhost:8000/api/specs"
DIR = os.path.abspath("static_analysis/api")

def run():
    print(f"Scanning directory: {DIR}")
    if not os.path.exists(DIR):
        print("Directory not found!")
        return

    files = [f for f in os.listdir(DIR) if f.endswith(('.yaml', '.yml', '.json'))]
    print(f"Found {len(files)} spec files.")

    for filename in files:
        filepath = os.path.join(DIR, filename)
        print(f"Uploading {filename}...", end=" ")
        
        try:
            with open(filepath, 'rb') as f:
                # Basic Post without advanced options (defaults used)
                response = requests.post(API_URL, files={'file': f})
            
            if response.status_code in [200, 201]:
                print(f"SUCCESS (ID: {response.json().get('spec_id')})")
            else:
                print(f"FAILED ({response.status_code}): {response.text}")
        except Exception as e:
            print(f"ERROR: {e}")

if __name__ == "__main__":
    run()
