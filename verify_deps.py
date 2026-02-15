import sys
import os
from pathlib import Path

def verify():
    print("--- ZAP-Python Dependency Verification ---")
    
    # 1. Check Python Interpreter
    print(f"Python: {sys.executable}")
    
    # 2. Add Path for local modules
    project_root = str(Path(__file__).parent.absolute())
    zap_dir = os.path.join(project_root, "ZAP-python")
    sys.path.insert(0, zap_dir)
    
    dependencies = [
        "httpx", "typer", "rich", "fastapi", "sqlalchemy", 
        "mysql.connector", "pydantic", "alembic", "yaml"
    ]
    
    all_ok = True
    for dep in dependencies:
        try:
            __import__(dep)
            print(f"[OK] {dep}")
        except ImportError:
            print(f"[FAIL] {dep} is missing")
            all_ok = False
            
    # 3. Check Internal Modules
    internal = ["core.engine", "scanners.base", "utils.http_utils"]
    for mod in internal:
        try:
            __import__(mod)
            print(f"[OK] {mod}")
        except ImportError as e:
            print(f"[FAIL] {mod} could not be loaded: {e}")
            all_ok = False
            
    if all_ok:
        print("\nSUCCESS: All dependencies and internal modules are correctly resolved!")
    else:
        print("\nFAILURE: Some issues were found.")

if __name__ == "__main__":
    verify()
