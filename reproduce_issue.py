import requests
import os

# Base URL for the backend
BASE_URL = "http://localhost:8000"

def test_upload_and_analyze():
    # Use the crapi-openapi-spec.json for testing
    spec_path = "g:/APEX-main/static_analysis/api/crapi-openapi-spec.json"
    
    if not os.path.exists(spec_path):
        print(f"Error: Spec file not found at {spec_path}")
        return

    with open(spec_path, 'rb') as f:
        files = {'file': (os.path.basename(spec_path), f, 'application/json')}
        data = {
            'profile': 'default',
            'fail_on': 'none',
            'generate_blueprint': 'true'
        }
        
        print(f"Uploading {spec_path} to {BASE_URL}/api/specs/ ...")
        try:
            response = requests.post(f"{BASE_URL}/api/specs/", files=files, data=data)
            print(f"Status Code: {response.status_code}")
            if response.status_code == 201:
                print("Analysis Successful!")
                # print(json.dumps(response.json(), indent=2))
            else:
                print("Analysis Failed!")
                print(f"Response: {response.text}")
        except Exception as e:
            print(f"Request Error: {e}")

if __name__ == "__main__":
    test_upload_and_analyze()
