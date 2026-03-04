"""
Shared detection utilities for response analysis.
"""
import re
from typing import List, Dict, Optional

class DetectionUtils:
    # Database error patterns
    DBMS_ERRORS = {
        "MySQL": [r"You have an error in your SQL syntax", r"com\.mysql\.jdbc\.exceptions"],
        "PostgreSQL": [r"org\.postgresql\.util\.PSQLException", r"syntax error at or near"],
        "Oracle": [r"ORA-00933", r"ORA-00942"],
        "SQL Server": [r"Unclosed quotation mark", r"Microsoft OLE DB Provider for SQL Server"],
        "SQLite": [r"SQL logic error", r"unrecognized token"],
        "MongoDB": [r"MongoError", r"errmsg.*\$where"],
    }

    # Generic Application Errors (for Param Tampering)
    APP_ERRORS = [
        r"Exception", r"Stack trace", r"syntax error", 
        r"Fatal error", r"Internal Server Error", r"NullPointerException"
    ]
    
    # Command injection patterns (Exec Output)
    CMD_INJECTION_PATTERNS = [
        r"uid=\d+\(.*\)\s+gid=\d+\(.*\)",  # id output
        r"root:.*:0:0:",                   # /etc/passwd output
        r"\[fonts\]",                       # win.ini output
        r"\[extensions\]",                  # win.ini output
        r"Volume Serial Number",            # dir output
        r"Directory of",                    # dir output
        r"(?:\\sGet-Help)(?i)|cmdlet|get-alias" # PowerShell output
    ]
    
    # Path traversal success indicators
    PATH_TRAVERSAL_INDICATORS = [
        r"root:.*:0:0:",
        r"\[boot loader\]",
        r"\[fonts\]",
        r"\[extensions\]",
        r"\[drivers\]",
    ]

    # External Redirect Patterns (Regex Templates - need formatting with UUID)
    # These are used to create specific compiled regexes at runtime
    REDIRECT_PATTERNS_TEMPLATE = {
        'location_header': r"https?://{uuid}\.owasp\.org",
        'refresh_header': r"5;URL=['\"]https?://{uuid}\.owasp\.org",
        'meta_refresh': r"<meta[^>]*refresh[^>]*url=[\"']https?://{uuid}\.owasp\.org",
        'js_location': r"location(?:\.href)?\s*=\s*['\"]https?://{uuid}\.owasp\.org",
        'js_assign': r"location\.(?:replace|reload|assign)\s*\(['\"]https?://{uuid}\.owasp\.org",
        'js_window': r"window\.(?:open|navigate)\s*\(['\"]https?://{uuid}\.owasp\.org"
    }

    # Info Disclosure Patterns (Passive)
    INFO_DISCLOSURE_PATTERNS = {
        "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "Private Key": r"-----BEGIN [A-Z]+ PRIVATE KEY-----",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Generic API Key": r"api_key\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]",
        "IP Address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b" # Careful with FPS
    }

    # SSRF Success Indicators (Cloud Metadata)
    SSRF_SUCCESS_PATTERNS = [
        r"ami-id", 
        r"instance-id", 
        r"local-ipv4",
        r"public-keys",
        r"reservation-id",
        r"placement/availability-zone",
        r"latest/meta-data",
        r"computeMetadata",
        r"SSH-2.0", 
        r"OpenSSH"
    ]

    # SSRF Error Indicators (Blind/Connection issues)
    SSRF_ERROR_SIGNATURES = [
        "Connection refused", 
        "unreachable", 
        "Could not connect",
        "upstream connect error"
    ]

    # IDOR / BOLA Success Indicators
    # Usually we look for 200 OK + specific data reflection or status changes
    # but generic ones can include finding user-specific keys
    IDOR_SENSITIVE_KEYS = [
        r"\"email\":", r"\"phone\":", r"\"address\":", r"\"credit_card\":",
        r"\"password_hash\":", r"\"token\":"
    ]
    
    # New Astra Scanners Detections
    SSTI_RESULT_PATTERNS = [r"49", r"7777777"]
    XSS_REFLECTION_PATTERNS = [r"<script>alert\(1\)</script>", r"<svg onload=", r"<img src=xss onerror=", r"alert\(1\)", r"confirm\(1\)"]
    CRLF_INDICATOR = "CRLF-Test"
    RATE_LIMIT_SIGNALS = ["rate limit", "too many", "captcha", "Maximum login", "exceed", "throttl"]

    @staticmethod
    def check_error_patterns(text: str, patterns: Dict[str, List[str]]) -> Dict[str, bool]:
        """Check text against error patterns."""
        results = {}
        for db, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, text, re.IGNORECASE):
                    results[db] = True
                    break
        return results

    @staticmethod
    def check_content_patterns(text: str, patterns_list: List[str]) -> Optional[str]:
        """Check if any content patterns match."""
        for pattern in patterns_list:
            if re.search(pattern, text, re.IGNORECASE):
                return pattern
        return None

