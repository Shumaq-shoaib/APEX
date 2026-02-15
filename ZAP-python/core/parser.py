import logging
from typing import List, Dict, Any
from urllib.parse import urljoin
try:
    from prance import ResolvingParser
except ImportError:
    ResolvingParser = None  # Handle missing dependency gracefully in IDE

class APIEndpoint:
    """Represents a testable API endpoint."""
    def __init__(self, path: str, method: str, params: List[Dict], body_schema: Dict = None, example: Dict = None):
        self.path = path
        self.method = method.upper()
        self.params = params  # Query/Path parameters
        self.body_schema = body_schema
        self.example = example
    
    def __repr__(self):
        return f"<{self.method} {self.path}>"

class SpecParser:
    """
    Parses OpenAPI/Swagger specifications to identify attack surfaces.
    Replaces ZAP's spidering logic for API-centric scans.
    """
    
    def __init__(self, spec_path: str):
        self.spec_path = spec_path
        self.endpoints: List[APIEndpoint] = []
        
    def parse(self) -> List[APIEndpoint]:
        """
        Parse the OpenAPI spec and return a list of endpoints.
        """
        if ResolvingParser is None:
            raise ImportError("prance is not installed. Please run 'pip install prance openapi-spec-validator'")

        logging.info(f"Parsing spec: {self.spec_path}")
        try:
            parser = ResolvingParser(self.spec_path)
        except Exception as e:
            logging.error(f"Failed to parse spec: {e}")
            raise

        spec = parser.specification
        paths = spec.get('paths', {})

        unique_keys = set()
        
        for path, path_item in paths.items():
            # generic path parameters
            path_params = path_item.get('parameters', [])
            
            for method_name, operation in path_item.items():
                if method_name.lower() not in ['get', 'post', 'put', 'delete', 'patch']:
                    continue
                
                # Deduplication Key
                key = (method_name.upper(), path)
                if key in unique_keys:
                    continue
                unique_keys.add(key)
                
                # Extract parameters (merge with path-level)
                op_params = operation.get('parameters', [])
                full_params = path_params + op_params
                
                # Extract request body schema if present
                body_schema = None
                example = None
                request_body = operation.get('requestBody', {})
                content = request_body.get('content', {})
                if 'application/json' in content:
                    json_content = content['application/json']
                    body_schema = json_content.get('schema')
                    example = json_content.get('example')
                
                endpoint = APIEndpoint(
                    path=path,
                    method=method_name,
                    params=full_params,
                    body_schema=body_schema,
                    example=example
                )
                self.endpoints.append(endpoint)
                
        return self.endpoints
