
import unittest
import os
import sys
# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from v6_refactor.helpers import (
    _derive_op_pointer, _traverse_pointer, _verb_implies_privileged,
    _resource_guess, _scope_match, _is_urlish_field, _is_https_only_pattern,
    _rfc1918_or_meta_ip, _endpoint_method_path
)

class TestHelpers(unittest.TestCase):
    def test_derive_op_pointer(self):
        self.assertEqual(_derive_op_pointer("GET", "/pets"), "/paths/~1pets/get")
        self.assertEqual(_derive_op_pointer("POST", "/users/{id}"), "/paths/~1users~1{id}/post")

    def test_traverse_pointer(self):
        doc = {"a": {"b": [1, 2]}}
        self.assertEqual(_traverse_pointer(doc, "/a/b"), [1, 2])
        self.assertIsNone(_traverse_pointer(doc, "/c"))

    def test_verb_implies_privileged(self):
        self.assertIn("write", _verb_implies_privileged("POST", "Create user", ""))
        self.assertIn("delete", _verb_implies_privileged("DELETE", "", ""))
        self.assertIn("admin", _verb_implies_privileged("GET", "Admin list", ""))
        self.assertFalse(_verb_implies_privileged("GET", "List public items", ""))

    def test_resource_guess(self):
        self.assertEqual(_resource_guess(["Cats"], "/pets"), "cats")
        self.assertEqual(_resource_guess([], "/api/v1/users/{id}"), "user")
        self.assertEqual(_resource_guess([], "/stats"), "stat")

    def test_scope_match(self):
        # required, available, resource
        self.assertTrue(_scope_match({"write"}, {"pets:write"}, "pets"))
        self.assertTrue(_scope_match({"write"}, {"*:write"}, "pets"))
        self.assertTrue(_scope_match({"admin"}, {"admin:super"}, "pets"))
        self.assertFalse(_scope_match({"write"}, {"read"}, "pets"))
        self.assertTrue(_scope_match({"write", "delete"}, {"pets:write", "pets:delete"}, "pets"))

    def test_is_urlish_field(self):
        self.assertTrue(_is_urlish_field("image_url", {"type": "string"}, ""))
        self.assertTrue(_is_urlish_field("foo", {"type": "string", "format": "uri"}, ""))
        self.assertFalse(_is_urlish_field("name", {"type": "string"}, ""))

    def test_is_https_only_pattern(self):
        self.assertTrue(_is_https_only_pattern("^https://.*"))
        self.assertTrue(_is_https_only_pattern("^(?:https://|wss://)"))
        self.assertFalse(_is_https_only_pattern("^http://"))

    def test_rfc1918_or_meta_ip(self):
        self.assertTrue(_rfc1918_or_meta_ip("192.168.1.1"))
        self.assertTrue(_rfc1918_or_meta_ip("10.0.0.50"))
        self.assertTrue(_rfc1918_or_meta_ip("169.254.169.254"))
        self.assertFalse(_rfc1918_or_meta_ip("8.8.8.8"))

    def test_endpoint_method_path(self):
        self.assertEqual(_endpoint_method_path({"endpoint": "GET /foo"}), ("GET", "/foo"))
        self.assertEqual(_endpoint_method_path({"endpoint": "global"}), ("", "global"))

if __name__ == '__main__':
    unittest.main()
