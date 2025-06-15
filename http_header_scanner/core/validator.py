"""
Header validation with context-aware checks
"""

import re
from typing import Dict, Optional, Tuple
from http_header_scanner.models.headers import SECURITY_HEADERS
from http_header_scanner.models.findings import RiskLevel

class HeaderValidator:
    def __init__(self, context: Optional[Dict] = None):
        self.context = context or {}

    def validate(self, header: str, value: str) -> Tuple[RiskLevel, str, float]:
        """
        Validate a heade with context-aware checks

        Returns:
            Tuple (risk_level, issue_description, cvss_score)
        """
        header_def = SECURITY_HEADERS.get(header)
        if not header_def:
            return RiskLevel.INFO, "Non-security header", 0.0

        # Get framework from context
        framework = self.context.get("framework")
        is_api = self.context.get("is_api", False)
        is_sensitive = self.context.get("is_sensitive", False)
        
        # Header-specific validation
        if header == "Strict-Transport-Security":
            return self._validate_hsts(value, framework)
        elif header == "Content-Security-Policy":
            return self._validate_csp(valie, framework)
        elif header == "Set-Cookie":
            return self._validate_cookie(value, framework)

        ## Add other header validations

        # Default to PASS if no specific validation
        return RiskLevel.PASS, "", 0.0

    def _validate_hsts(self, value: str, framework: Optional[str]) -> Tuple[RiskLevel, str, float]:
        """
            Validate Strict-Transport-Security header
        """
        if not value:
            return RiskLevel.CRITICAL, "Header missing", 9.0

        if "max-age" not in value:
            return RiskLevel.HIGH, "Missing max-age directives", 7.0

        max_age_match = re.search(r"max-age=(\d+)", value)
        if not max_age_match:
            return RiskLevel.HIGH, "Invalid max-age value", 7.0

        max_age = int(max_age_match.group(1))
        if max_age < 31536000: # 1 year
            return RiskLevel.MEDIUM, f"max-age too short ({max_age} < 31536000)", 5.0

        if "includeSubDomains" not in value:
            return RiskLevel.MEDIUM, "Missing includeSubDomains", 4.0

        if "preload" not in value and framework != "Next.js":
            return RiskLevel.LOW, "Missing preload directive", 2.0

        return RiskLevel.PASS, "", 0.0

    def _validate_csp(self, value: str, framework: Optional[str]) -> Tuple[RiskLevel, str, float]:
        """
            Validate COntent-Security-Policy header
        """
        if not value:
            return RiskLevel.CRITICAL, "Header missing", 9.0

        # Framework-specific checks
        if framework == "React" and "'unsafe-inline'" in value:
            return RiskLevel.HIGH, "Avoid 'unsafe-inline' in React apps", 7.0

        if framework == "WordPress" and "unsafe-eval" in value:
            return RiskLevel.MEDIUM, "WordPress should avoid 'unsafe-eval'", 5.0

        # Check for unsafe directives
        unsafe_terms = ["'unsafe-inline'", "'unsafe-eval'", "*", "http:"]
        found_unsafe = [term for term in unsafe_terms if term in value]

        if found_unsafe:
            return RiskLevel.MEDIUM, f"Unsafe directives: {', '.join(found_unsafe)}", 5.0

        return RiskLevel.PASS, "", 0.0

    def _validate_cookie(self, value: str, framework: Optional[str]) -> Tuple[RiskLevel, str, float]:
        """
            Validate Set-Cookie header
        """
        flags = [f.strip().lower() for f in value.split(';')]
        issues = []
        score = 0.0

        # Framework-specific checks
        if framework == "Django" and 'samesite=lax' not in flags:
            issues.append("SameSite should be Lax for Django")
            score += 3.0

        # Standard checks
        if 'secure' not in flags:
            issues.append("Missing Secure flag")
            score += 5.0

        if "httponly" not in flags:
            issues.append("Missing HttpOnly flag")
            score += 5.0

        if not any('samesite' in f for f in flags):
            issues.append("Missing SameSite attribute")
            score += 4.0
        else:
            samesite = next((f for f in flags if 'samesite' in f), None)
            if samesite and 'samesite=none' in samesite and 'secure' not in flags:
                issues.append("Secure flag required for SameSite=None")
                score += 6.0

        if issues:
            risk_level = RiskLevel.HIGH if score > 5 else RiskLevel.MEDIUM
            return risk_level, "; ". join(issues), score

        return RiskLevel.PASS, "", 0.0
