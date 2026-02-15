
import unittest
import os
import tempfile
import sys
# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from v6_refactor.utils import (
    _resolve_ref, _merge_allOf, _walk_properties, _semver_ok, _sha256_file
)

class TestUtils(unittest.TestCase):
    def test_resolve_ref_inline(self):
        spec = {"components": {"schemas": {"Target": {"type": "string"}}}}
        name, resolved = _resolve_ref(spec, "#/components/schemas/Target")
        self.assertEqual(name, "Target")
        self.assertEqual(resolved, {"type": "string"})

    def test_resolve_ref_inline_fail(self):
        spec = {}
        name, resolved = _resolve_ref(spec, "#/missing")
        self.assertEqual(name, "missing")
        self.assertEqual(resolved, {})

    def test_merge_allof(self):
        spec = {}
        schema = {
            "allOf": [
                {"properties": {"a": {"type": "string"}}, "required": ["a"]},
                {"properties": {"b": {"type": "integer"}}, "required": ["b"]}
            ]
        }
        merged = _merge_allOf(schema, spec, set())
        self.assertIn("a", merged["properties"])
        self.assertIn("b", merged["properties"])
        self.assertIn("a", merged["required"])
        self.assertIn("b", merged["required"])

    def test_walk_properties(self):
        spec = {}
        schema = {
            "properties": {
                "root": {
                    "type": "object",
                    "properties": {
                        "child": {"type": "string"}
                    }
                }
            }
        }
        results = list(_walk_properties(spec, schema))
        # Expect: root, root.child
        paths = [r[0] for r in results]
        self.assertIn("root", paths)
        self.assertIn("root.child", paths)

    def test_semver_ok(self):
        self.assertTrue(_semver_ok("1.0.0"))
        self.assertTrue(_semver_ok("0.1.0-beta"))
        self.assertTrue(_semver_ok("2.3.4+build"))
        self.assertFalse(_semver_ok("v1"))
        self.assertFalse(_semver_ok("1.0"))

    def test_sha256_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"hello")
            tmp_name = tmp.name
        try:
            # sha256 of "hello" -> 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
            h = _sha256_file(tmp_name)
            self.assertEqual(h, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        finally:
            os.remove(tmp_name)

if __name__ == '__main__':
    unittest.main()
