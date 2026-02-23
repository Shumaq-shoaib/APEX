from app.models.dynamic import CheckType, Severity

class ReportManager:
    """
    Centralized manager for scoring and remediation advice.
    """

    @staticmethod
    def get_cvss_score(check_type: CheckType, severity: Severity) -> float:
        """
        Returns a static CVSS v3.1 Base Score based on the finding type and severity.
        """
        if check_type == CheckType.BROKEN_AUTH:
            if severity == Severity.CRITICAL: return 9.8
            if severity == Severity.HIGH: return 8.1
            return 7.5

        if check_type == CheckType.BOLA:
            if severity == Severity.CRITICAL: return 8.6
            if severity == Severity.HIGH: return 7.1
            return 6.5

        if check_type == CheckType.DATA_EXPOSURE:
            if severity == Severity.HIGH: return 7.5
            return 5.3

        if check_type == CheckType.SQLI:
            if severity == Severity.CRITICAL: return 9.8
            if severity == Severity.HIGH: return 8.6
            return 7.5

        if check_type == CheckType.SSRF:
            if severity == Severity.CRITICAL: return 9.1
            if severity == Severity.HIGH: return 8.6
            return 6.5

        if check_type == CheckType.INJECTION:
            if severity == Severity.CRITICAL: return 9.8
            if severity == Severity.HIGH: return 8.1
            return 7.2

        if check_type == CheckType.XSS:
            if severity == Severity.HIGH: return 7.1
            return 6.1

        if check_type == CheckType.OTHER:
            if severity == Severity.CRITICAL: return 9.1
            if severity == Severity.HIGH: return 8.5
            return 5.0

        if severity == Severity.CRITICAL: return 9.0
        if severity == Severity.HIGH: return 7.5
        if severity == Severity.MEDIUM: return 5.0
        if severity == Severity.LOW: return 3.5
        return 2.0

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

        if check_type == CheckType.SSRF:
            return (
                "1. Allowlist: Restrict outbound requests to a strict allowlist of trusted hosts.\n"
                "2. Deny Internal Networks: Block requests to private IP ranges (127.0.0.1, 10.x, 169.254.x, etc.).\n"
                "3. Disable Redirects: Do not follow HTTP redirects on server-side requests."
            )

        if check_type == CheckType.INJECTION:
            return (
                "1. Input Validation: Validate and sanitize all user-controlled input.\n"
                "2. Avoid Shell Execution: Never pass user input directly to OS commands.\n"
                "3. Use Libraries: Use safe abstractions instead of raw command execution."
            )

        if check_type == CheckType.DATA_EXPOSURE:
            return "Ensure backend responses strip PII and sensitive fields before sending to client."

        if check_type == CheckType.XSS:
            return "Sanitize all user-controlled input and use Content Security Policy (CSP) headers."

        if check_type == CheckType.OTHER:
            return "Review the endpoint logic for specific injection or configuration risks (SSRF, XXE, etc.)."

        return "Review the endpoint logic for security best practices."
