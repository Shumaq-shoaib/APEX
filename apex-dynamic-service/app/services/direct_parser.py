import json
import logging
import yaml
from pathlib import Path

logger = logging.getLogger(__name__)

class DirectOASParser:
    """
    Parses an OpenAPI Spec (JSON/YAML) to generate a Dynamic Analysis Blueprint
    without requiring the full Static Analysis engine.
    """
    def __init__(self, spec_content: bytes, filename: str):
        self.filename = filename
        self.spec = self._load_spec(spec_content)
        
    def _load_spec(self, content: bytes):
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            try:
                return yaml.safe_load(content)
            except yaml.YAMLError:
                raise ValueError("Invalid Spec Format (Not JSON or YAML)")

    def generate_blueprint(self) -> dict:
        """
        Produce the JSON blueprint structure required by DynamicTestSession.
        """
        spec = self.spec
        paths = spec.get("paths", {})
        blueprint_endpoints = []

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch", "options", "head"]:
                    continue
                
                # Extract Parameters
                params = []
                # Path-level parameters
                all_params = methods.get("parameters", []) + details.get("parameters", [])
                
                for p in all_params:
                    # Dereferencing is skipped for simplicity in direct mode, 
                    # assuming standard inline or simple refs. 
                    # Real parser would resolve $ref.
                    params.append({
                        "name": p.get("name"),
                        "in": p.get("in"),
                        "required": p.get("required", False)
                    })

                # Extract Request Body (OAS 3)
                request_body = details.get("requestBody", {})
                content = request_body.get("content", {})
                json_content = content.get("application/json", {})
                schema = json_content.get("schema", {})
                example = json_content.get("example", {})

                blueprint_endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "params": params,
                    "schema": schema,
                    "example": example,
                    "auth": {"schemes": [], "types": []}, # Auth Parsing can be added if needed
                    "risk": {"static_analysis_issues": 0} # No static scan
                })

        return {
            "meta": {"title": spec.get("info", {}).get("title", "Direct Scan"), "version": "1.0"},
            "endpoints": blueprint_endpoints
        }
