# -*- coding: utf-8 -*-
import sys
from typing import Dict, Any, List

# --- Optional color support ---
try:
    import colorama
    colorama.init(autoreset=True)
    COLOR_SUPPORT = True
except Exception:
    COLOR_SUPPORT = False
    class _Dummy:
        class Fore: RED = YELLOW = BLUE = GREEN = ''
        class Style: RESET_ALL = BRIGHT = ''
    colorama = _Dummy()

# --- OpenAPI validator (optional) ---
try:
    from openapi_spec_validator import validate_spec
    from openapi_spec_validator.validation.exceptions import OpenAPIValidationError
except Exception:
    print("Warning: openapi_spec_validator not installed; skipping spec validation.", file=sys.stderr)
    def validate_spec(_):  # no-op
        return True
    class OpenAPIValidationError(Exception):
        pass

# --- Colors ---
class Colors:
    RED = colorama.Fore.RED if COLOR_SUPPORT else ''
    YELLOW = colorama.Fore.YELLOW if COLOR_SUPPORT else ''
    BLUE = colorama.Fore.BLUE if COLOR_SUPPORT else ''
    GREEN = colorama.Fore.GREEN if COLOR_SUPPORT else ''
    RESET = colorama.Style.RESET_ALL if COLOR_SUPPORT else ''
    BOLD = colorama.Style.BRIGHT if COLOR_SUPPORT else ''

# --- Details extractor ---
class OasDetails:
    def __init__(self, spec: Dict[str, Any]):
        self._spec = spec
        self._endpoints = None
        self._global_security = self._spec.get('security')

    @property
    def endpoints(self) -> List[Dict[str, Any]]:
        if self._endpoints is None:
            self._endpoints = self._extract_endpoints()
        return self._endpoints

    def _extract_endpoints(self) -> List[Dict[str, Any]]:
        paths = self._spec.get('paths', {})
        details = []
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            path_level_params = methods.get('parameters', [])
            for method, ep_details in methods.items():
                if not isinstance(ep_details, dict) or method.lower() in ['parameters', '$ref']:
                    continue
                op_params = list(path_level_params) + list(ep_details.get('parameters', []))
                details.append({
                    'path': path, 'method': method.upper(),
                    'parameters': op_params,
                    'requestBody': ep_details.get('requestBody', {}),
                    'responses': ep_details.get('responses', {}),
                    'summary': ep_details.get('summary', ''),
                    'description': ep_details.get('description', ''),
                    'security': ep_details.get('security', self._global_security),
                    'op_security_raw': ep_details.get('security', None),
                    'global_security': self._global_security,
                    'deprecated': bool(ep_details.get('deprecated', False)),
                    'tags': ep_details.get('tags', [])  # tag support for per-tag lint aggregation
                })
        return details

    def get_info(self) -> Dict[str, Any]: return self._spec.get('info', {})
    def get_schemas(self) -> Dict[str, Any]: return self._spec.get('components', {}).get('schemas', {})
    def get_servers(self) -> List[Dict[str, Any]]: return self._spec.get('servers', [])
    def get_security_schemes(self) -> Dict[str, Any]: return self._spec.get('components', {}).get('securitySchemes', {})
    def spec(self) -> Dict[str, Any]: return self._spec
