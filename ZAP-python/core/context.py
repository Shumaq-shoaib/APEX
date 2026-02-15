from typing import Dict, Optional, List
from pydantic import BaseModel

class ScanScope(BaseModel):
    """Defines the scope of the scan."""
    include_regex: List[str] = []
    exclude_regex: List[str] = []

class AuthConfig(BaseModel):
    """Authentication configuration."""
    token: Optional[str] = None
    token_type: str = "Bearer"
    header_name: str = "Authorization"

class ScanContext(BaseModel):
    """
    Holds the state and configuration for a single scan session.
    Equivalent to ZAP's 'Context' and 'Session' concepts.
    """
    target_url: str
    auth: AuthConfig = AuthConfig()
    headers: Dict[str, str] = {}
    scope: ScanScope = ScanScope()
    
    def get_headers(self) -> Dict[str, str]:
        """Return headers with auth token injected."""
        final_headers = self.headers.copy()
        if self.auth.token:
            final_headers[self.auth.header_name] = f"{self.auth.token_type} {self.auth.token}"
        return final_headers
