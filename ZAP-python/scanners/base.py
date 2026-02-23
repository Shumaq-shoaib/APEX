from abc import ABC, abstractmethod
from typing import List, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from core.context import ScanContext

class BaseScanner(ABC):
    """
    Abstract base class for all vulnerability scanners.
    """
    
    def __init__(self, context: "ScanContext"):
        """
        Initialize the scanner with a scan context.
        :param context: Shared ScanContext object.
        """
        self.context = context
        self.results = []

    @property
    @abstractmethod
    def scan_id(self) -> str:
        """Unique ID for the scanner (e.g., 'API-001')"""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the check"""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """OWASP API Category (e.g., 'API1:2023')"""
        pass

    @abstractmethod
    def run(self, endpoint: str, method: str, params: Dict) -> List[Dict]:
        """
        Execute the scan against a specific endpoint.
        
        :param endpoint: The URL path (e.g., /api/v1/users)
        :param method: HTTP method (GET, POST, etc.)
        :param params: Dictionary of parameters (query/body)
        :return: List of vulnerability findings (Dicts)
        """
        pass

    def add_finding(self, title: str, description: str, severity: str, evidence: str = "",
                    request_dump: str = "", response_dump: str = ""):
        """Helper to append a finding with optional HTTP evidence dumps."""
        self.results.append({
            "scanner_id": self.scan_id,
            "title": title,
            "description": description,
            "severity": severity,
            "evidence": evidence,
            "category": self.category,
            "request_dump": request_dump,
            "response_dump": response_dump
        })
