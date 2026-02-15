from core.parser import SpecParser
import logging

logging.basicConfig(level=logging.INFO)

try:
    spec_path = "c:\\Users\\iamsh\\Downloads\\Backup\\FYP\\APEX-code\\static_analysis\\api\\crapi-openapi-spec.json"
    parser = SpecParser(spec_path)
    endpoints = parser.parse()
    
    print(f"Total Endpoints: {len(endpoints)}")
    for ep in endpoints:
        print(f"{ep.method} {ep.path}")

except Exception as e:
    print(f"Error: {e}")
