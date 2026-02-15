from app.models.dynamic import CheckType, Severity

class ReportManager:
    """
    Centralized manager for scoring and remediation advice.
    """
    
    @staticmethod
    def get_cvss_score(check_type: CheckType, severity: Severity) -> float:
        """
        Returns a static CVSS v3.1 Base Score based on the finding type.
        """
        # Mapping based on typical impact
        if check_type == CheckType.BROKEN_AUTH:
            if severity == Severity.CRITICAL: return 9.8
            if severity == Severity.HIGH: return 8.1
            return 7.5

        if check_type == CheckType.BOLA:
            if severity == Severity.HIGH: return 7.1 # AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N
            return 6.5
            
        if check_type == CheckType.DATA_EXPOSURE:
            return 5.3 # AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

        if check_type == CheckType.SQLI:
            if severity == Severity.CRITICAL: return 9.8
            return 8.1

        if check_type == CheckType.XSS:
            return 6.1

        if check_type == CheckType.OTHER:
            # Covers SSRF, XXE, Redirects
            if severity == Severity.HIGH: return 8.5
            return 5.0

        return 0.0

    @staticmethod
    def get_remediation(check_type: CheckType) -> str:
        """
        Returns detailed remediation advice.
        """
        if check_type == CheckType.BROKEN_AUTH:
            return (
                "1. Enforce Authentication: Ensure all API endpoints that access private data require a valid access token.\n"
                "2. Validate Tokens: strict validation of JWT signatures and expiration.\n"
                "3. Use Standard Libraries: Do not roll your own crypto."
            )
        
        if check_type == CheckType.BOLA:
            return (
                "1. Implement Ownership Checks: When accessing an object by ID, verify that the current user owns it.\n"
                "2. Use Random IDs: Use UUIDs instead of sequential integers to make ID guessing harder.\n"
                "3. Audit Logs: Monitor for sequential access attempts."
            )

        if check_type == CheckType.SQLI:
            return (
                "1. Use Parameterized Queries: Always use prepared statements or ORM abstractions.\n"
                "2. Input Validation: Validate all input against a strict allowlist.\n"
                "3. Principle of Least Privilege: Ensure the database user has minimal permissions."
            )

        if check_type == CheckType.DATA_EXPOSURE:
            return "Ensure backend responses strip PII and sensitive fields before sending to client."

        if check_type == CheckType.XSS:
            return "Sanitize all user-controlled input and use Content Security Policy (CSP) headers."

        if check_type == CheckType.OTHER:
            return "Review the endpoint logic for specific injection or configuration risks (SSRF, XXE, etc.)."

        return "Review the endpoint logic for security best practices."
