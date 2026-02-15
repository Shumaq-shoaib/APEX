import sys
import os
from unittest.mock import MagicMock

# Setup paths similar to how main.py does it
project_root = os.path.dirname(os.path.abspath(__file__))
zap_python_path = os.path.join(project_root, "ZAP-python")
dynamic_service_path = os.path.join(project_root, "apex-dynamic-service")

sys.path.insert(0, zap_python_path)
sys.path.insert(0, dynamic_service_path)

# Mock app.models.dynamic and app.services.reporting before importing AttackEngine
# to avoid DB dependency issues during simple loading test
sys.modules['app.db'] = MagicMock()
sys.modules['app.db.base_class'] = MagicMock()

from app.services.engine import AttackEngine
from app.models.dynamic import CheckType

def test_load_scanners():
    # Mock DB session
    db = MagicMock()
    try:
        attack_engine = AttackEngine(session_id="test-session", db_session=db)
        print(f"Loaded {len(attack_engine.scanners)} scanners.")
        for scanner in attack_engine.scanners:
            print(f" - {scanner.name} ({scanner.scan_id})")
        
        if not attack_engine.scanners:
            print("ERROR: No scanners loaded!")
            sys.exit(1)

        # Test mapping
        mapping_tests = [
            CheckType.BOLA,
            CheckType.BROKEN_AUTH,
            CheckType.SQLI,
            CheckType.INJECTION,
            CheckType.SSRF,
            CheckType.DATA_EXPOSURE,
            CheckType.OTHER
        ]
        
        for ct in mapping_tests:
            scanners = attack_engine._get_scanners_for_check(ct)
            print(f"CheckType.{ct.name} maps to: {[s.name for s in scanners]}")
            if not scanners:
                print(f" WARNING: No scanners mapped for {ct.name}")
        
    except Exception as e:
        print(f"INTEGRATION TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    test_load_scanners()
