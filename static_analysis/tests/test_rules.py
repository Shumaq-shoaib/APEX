
import unittest
import sys
import os
# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from v6_refactor.models import OasDetails
from v6_refactor.rules import (
    check_broken_authentication, check_unsafe_consumption, assign_severity,
    CONFIG
)

class TestRules(unittest.TestCase):
    def test_check_broken_authentication_missing(self):
        spec = {"openapi": "3.0.0", "components": {}} # no securitySchemes
        details = OasDetails(spec)
        findings = check_broken_authentication(details)
        self.assertTrue(any("No security schemes" in f["description"] for f in findings))

    def test_check_broken_authentication_basic(self):
        spec = {
            "components": {
                "securitySchemes": {
                    "basicAuth": {"type": "http", "scheme": "basic"}
                }
            }
        }
        details = OasDetails(spec)
        findings = check_broken_authentication(details)
        self.assertTrue(any("Weak HTTP auth scheme" in f["description"] for f in findings))

    def test_check_unsafe_consumption(self):
        spec = {
            "servers": [
                {"url": "http://api.example.com"}
            ]
        }
        details = OasDetails(spec)
        findings = check_unsafe_consumption(details)
        self.assertTrue(any("Insecure server URL" in f["description"] for f in findings))

    def test_assign_severity(self):
        # Test base severity
        self.assertEqual(assign_severity("check_broken_object_level_authorization", {}), "Critical")
        
        # Test override
        default_overrides = CONFIG.get("override_severity")
        CONFIG["override_severity"] = {"check_broken_object_level_authorization": "Low"}
        try:
            self.assertEqual(assign_severity("check_broken_object_level_authorization", {}), "Low")
        finally:
            CONFIG["override_severity"] = default_overrides

        # Test profile adjustment (production)
        default_profile = CONFIG.get("profile")
        CONFIG["profile"] = "production"
        try:
            sev = assign_severity("check_unsafe_consumption", {})
            self.assertIn(sev, ("Medium", "High", "Critical")) # Originally Low, but escalated by logic + profile
        finally:
            CONFIG["profile"] = default_profile

if __name__ == '__main__':
    unittest.main()
