"""
HTTP utility functions for scanners.
"""
import httpx
import logging
from typing import Dict, Optional, Union

class HttpUtils:
    @staticmethod
    def send_request(method: str, url: str, headers: Dict, 
                    params: Optional[Dict] = None, 
                    json: Optional[Dict] = None,
                    timeout: int = 10,
                    allow_redirects: bool = True) -> httpx.Response:
        """Standardized request sending with error handling."""
        try:
            # Prepare arguments
            kwargs = {
                'headers': headers,
                'timeout': timeout,
                'follow_redirects': allow_redirects
            }
            
            if params:
                kwargs['params'] = params
            if json:
                kwargs['json'] = json
                
            with httpx.Client() as client:
                return client.request(method, url, **kwargs)
            
        except httpx.TimeoutException:
            raise
        except httpx.HTTPError as e:
            logging.error(f"Request failed: {e}")
            raise
    
    @staticmethod
    def is_redirect_response(response: httpx.Response) -> bool:
        """Check if response is a redirect."""
        return response.status_code in [301, 302, 303, 307, 308]
    
    @staticmethod
    def extract_redirect_location(response: httpx.Response) -> Optional[str]:
        """Extract redirect location from response."""
        if HttpUtils.is_redirect_response(response):
            return response.headers.get('Location') or response.headers.get('location')
        return None
