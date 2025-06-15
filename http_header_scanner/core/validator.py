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
        self._validators = {
            "strict-transport-security": self._validate_hsts,
            "content-security-policy": self._validate_csp,
            "set-cookie": self._validate_cookie,
            "x-frame-options": self._validate_xfo,
            "x-content-type-options": self._validate_xcto,
            "permissions-policy": self._validate_permissions_policy,
            "referrer-policy": self._validate_referrer_policy,
            "cross-origin-opener-policy": self._validate_coop,
            "cross-origin-embedder-policy": self._validate_coep,
            "cross-origin-resource-policy": self._validate_corp,
            "content-type": self._validate_content_type,
            "cache-control": self._validate_cache_control,
            "clear-site-data": self._validate_clear_site_data,
            "report-to": self._validate_report_to,
            "access-control-allow-origin": self._validate_cors,
            "x-xss-protection": self._validate_xss_protection,
            "server": self._validate_server_header,
            "x-powered-by": self._validate_x_powered_by,
            "expect-ct": self._validate_expect_ct,
            "feature-policy": self._validate_feature_policy
        }

    def validate(self, header: str, value: str) -> Tuple[RiskLevel, str, float]:
        """
        Validate a header with context-aware checks

        Returns:
            Tuple (risk_level, issue_description, cvss_score)
        """
        normalized_header = header.lower()
        header_def = SECURITY_HEADERS.get(normalized_header)
        if not header_def:
            return RiskLevel.INFO, "Non-security header", 0.0

        validator = self._validators.get(normalized_header)
        if validator:
            return validator(value)

        """
        # Get framework from context
        framework = self.context.get("framework")
        is_api = self.context.get("is_api", False)
        is_sensitive = self.context.get("is_sensitive", False)
        
        # Header-specific validation
        if header == "Strict-Transport-Security":
            return self._validate_hsts(value, framework)
        elif header == "Content-Security-Policy":
            return self._validate_csp(value, framework)
        elif header == "Set-Cookie":
            return self._validate_cookie(value, framework)

        ## Add other header validations
        """

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

        max_age_match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
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
            Validate Content-Security-Policy header
        """
        if not value:
            return RiskLevel.CRITICAL, "Header missing", 9.0

        value_lower = value.lower()

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

        # Check for missing default-src
        if "default-src" not in value_lower:
            return RiskLevel.MEDIUM, "Missing default-src directive", 4.0

        return RiskLevel.PASS, "", 0.0

    def _validate_cookie(self, value: str, framework: Optional[str]) -> Tuple[RiskLevel, str, float]:
        """
            Validate Set-Cookie header
        """
        flags = [f.strip().lower() for f in value.split(';')]
        issues = []
        score = 0.0
        framework = self.context.get("framework")
        is_sensitive = self.context.get("is_sensitive", False)

        # Framework-specific checks
        if framework == "Django" and 'samesite=lax' not in flags:
            issues.append("SameSite should be Lax for Django")
            score += 3.0

        # Critical checks
        if 'secure' not in flags:
            issues.append("Missing Secure flag")
            score += 5.0

        if "httponly" not in flags:
            issues.append("Missing HttpOnly flag")
            score += 5.0

        # SameSite validation
        samesite_flags = [f for f in flags if f.startswith("samesite=")]
        if not samesite_flags:
            issues.append("Missing SameSite attribute")
            score += 4.0
        else:
            samesite_value = samesite_flags[0].split('=')[1]
            samesite = next((f for f in flags if 'samesite' in f), None)
            if samesite_value == "none" and 'secure' not in flags:
                issues.append("Secure flag required for SameSite=None")
                score += 6.0
            elif is_sensitive and samesite_value != "strict":
                issues.append("Sensitive cookies should use SameSite=Strict")
                score += 4.0

        # Additional checks for sensitive contexts
        if is_sensitive:
            if "max-age" not in value and "expires" not in value:
                issues.append("Session cookie missing expiration")
                score += 3.0
            if not any(f.startswith("--host-") for f in flags):
                issues.append("Consider __Host- prefix for path isolation")
                score += 2.0

        if issues:
            risk_level = RiskLevel.HIGH if score > 7.0 else RiskLevel.MEDIUM if score >= 4.0 else RiskLevel.LOW
            return risk_level, "; ". join(issues), min(score, 10.0)

        return RiskLevel.PASS, "", 0.0

    # Additional validation method for otehr headers
    def _validate_xfo(self, value: str) -> Tuple[RiskLevel, str, float]:
        value = value.lower()
        if value in ["deny", "sameorigin"]:
            return RiskLevel.PASS, "", 0.0
        return RiskLevel.MEDIUM, f"Invalid value: {value}. Use DENY or SAMEORIGIN", 5.0

    def _validate_xcto(self, value: str) -> Tuple[RiskLevel, str, float]:
        if value.lower() == "nosniff":
            return RiskLevel.PASS, "", 0.0
        return RiskLevel.HIGH, "Missing nosniff directive", 7.0

    def _validate_permissions_policy(self, value: str) -> Tuple[RiskLevel, str, float]:
        sensitive_features = ["geolocation", "camera", "microphone", "payment"]
        missing = [f for f in sensitive_features if f not in value.lower()]
        if missing:
            return RiskLevel.MEDIUM, f"Missing restrictions for: {', '.join(missing)}", 4.0
        return RiskLevel.PASS, "", 0.0

    def _validate_referrer_policy(self, value: str) -> Tuple[RiskLevel, str, float]:
        """Validate Referrer-Policy header"""
        valid_policies = [
            "no-referrer", "no-referrer-when-downgrade", "origin",
            "origin-when-cross-origin", "same-origin", "strict-origin",
            "strict-origin-when-cross-origin", "unsafe-url"
        ]

        if not value:
            return RiskLevel.MEDIUM, "Header missing", 5.0

        if value.lower() in valid_policies:
            return RiskLevel.PASS, "", 0.0

        return RiskLevel.LOW, f"Consider stronger policy than '{value}'", 3.0

    def _validate_coop(self, value: str) -> Tuple[RiskLevel, str, float]:
        """Validate Cross-Origin-Opener-Policy header"""
        valid_values = ["same-origin", "same-origin-allow-popups", "unsafe-none"]
        value_lower = value.lower()

        if value_lower in valid_values:
            if value_lower == "same-origin":
                return RiskLevel.PASS, "", 0.0
            return RiskLevel.LOW, "Consider using 'same-origin' for maximum isolation", 2.0

        return RiskLevel.MEDIUM, f"Invalid COOP value: {value}", 5.0

    def _validate_coep(self, value: str) -> Tuple[RiskLevel, str, float]:
        """Validate Cross-Origin-Embedder-Policy header"""
        if value.lower() == "require-corp":
            return RiskLevel.PASS, "", 0.0
        return RiskLevel.MEDIUM, "Should be set to 'require-corp'", 5.0

    def _validate_corp(self, value: str) -> Tuple[RiskLevel, str, float]:
        """Validate Cross-Origin-Resource-Policy header"""
        valid_values = ["same-origin", "same-site", "cross-origin"]
        if value.lower() in valid_values:
            return RiskLevel.PASS, "", 0.0
        return RiskLevel.LOW, f"Invalid CORP value: {value}", 3.0

    def _validate_content_type(self, value: str) -> Tuple[RiskLevel, str, float]:
        """Validate Content-Type header"""
        value_lower = value.lower()
        issues = []
        score = 0.0

        # Check for charset declaration
        if "charset=" not in value_lower:
            issues.append("Missing charset declaration")
            score += 3.0

        # Check for XSS-prone content types
        risky_types = ["text/html", "application/xhtml+xml"]
        if any(rt in value_lower for rt in risky_types) and "charset=utf-8" not in value_lower:
            issues.append("HTML content without UTF-8 charset")
            score += 4.0

        if issues:
            return RiskLevel.MEDIUM, "; ".join(issues), min(score, 6.0)

        return RiskLevel.PASS, "", 0.0

    def _validate_cache_control(self, value: str) -> Tuple[RiskLevel, str, float]:
        """Validate Cache-Control header"""
        value_lower = value.lower()
        is_sensitive = self.context.get("is_sensitive", False)
        issues = []
        score = 0.0

        if is_sensitive:
            if "no-store" not in value_lower and "no-cache" not in value_lower:
                issues.append("Sensitive content missing no-store/no-cache")
                score += 6.0

        # Check for overly long caching
        max_age_match = re.search(r"max-age\s*=\s*(\d+)", value_lower)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age > 31536000:  # 1 year
                issues.append(f"Excessive max-age ({max_age} seconds)")
                score += 3.0

        if issues:
            return RiskLevel.MEDIUM, "; ".join(issues), min(score, 6.0)

        return RiskLevel.PASS, "", 0.0

    def _validate_clear_site_data(self, value: str) -> Tuple[RiskLevel, str, float]:
        """Validate Clear-Site-Data header"""
        if not value:
            return RiskLevel.LOW, "Header empty", 2.0

        valid_directives = ["cache", "cookies", "storage", "executionContexts"]
        directives = [d.strip('" ') for d in value.split(",")]
        invalid = [d for d in directives if d not in valid_directives]

        if invalid:
            return RiskLevel.LOW, f"Invalid directives: {', '.join(invalid)}", 3.0

        return RiskLevel.PASS, "", 0.0

    def _validate_report_to(self, value: str) -> Tuple[RiskLevel, str, float]:
        """Validate Report-To header"""
        try:
            # Attempt to parse JSON structure
            groups = json.loads(value)
            if not isinstance(groups, list):
                return RiskLevel.MEDIUM, "Invalid JSON structure: should be an array", 4.0

            for group in groups:
                if "group" not in group or "endpoints" not in group:
                    return RiskLevel.MEDIUM, "Missing required fields in report group", 4.0

            return RiskLevel.PASS, "", 0.0
        except json.JSONDecodeError:
            return RiskLevel.MEDIUM, "Invalid JSON format", 5.0

    def _validate_cors(self, value: str) -> Tuple[RiskLevel, str, float]:
        """Validate Access-Control-Allow-Origin header"""
        is_api = self.context.get("is_api", False)
        is_sensitive = self.context.get("is_sensitive", False)

        if value == "*":
            if is_api and not is_sensitive:
                return RiskLevel.LOW, "Wildcard CORS for public API", 2.0
            return RiskLevel.HIGH, "Wildcard CORS allows any site to access resources", 7.0

        return RiskLevel.PASS, "", 0.0

    def _validate_xss_protection(self, value: str) -> Tuple[RiskLevel, str, float]:
        """Validate X-XSS-Protection header"""
        # This header is deprecated and should be disabled
        if "0" in value:
            return RiskLevel.PASS, "", 0.0
        return RiskLevel.LOW, "Deprecated header - should be disabled with '0'", 2.0

    def _validate_server_header(self, value: str) -> Tuple[RiskLevel, str, float]:
        """Validate Server header (information disclosure)"""
        if value:
            return RiskLevel.LOW, "Reveals server information", 3.0
        return RiskLevel.PASS, "", 0.0

    def _validate_x_powered_by(self, value: str) -> Tuple[RiskLevel, str, float]:
        """Validate X-Powered-By header (information disclosure)"""
        if value:
            return RiskLevel.LOW, "Reveals technology stack", 3.0
        return RiskLevel.PASS, "", 0.0

    def _validate_expect_ct(self, value: str) -> Tuple[RiskLevel, str, float]:
        """Validate Expect-CT header (Certificate Transparency)"""
        if not value:
            return RiskLevel.LOW, "Header missing", 2.0

        value_lower = value.lower()
        if "enforce" not in value_lower:
            return RiskLevel.MEDIUM, "Missing enforce directive", 4.0

        max_age_match = re.search(r"max-age\s*=\s*(\d+)", value_lower)
        if not max_age_match:
            return RiskLevel.MEDIUM, "Missing max-age value", 4.0

        return RiskLevel.PASS, "", 0.0

    def _validate_feature_policy(self, value: str) -> Tuple[RiskLevel, str, float]:
        """Validate Feature-Policy header (deprecated, should migrate to Permissions-Policy)"""
        if value:
            return RiskLevel.LOW, "Deprecated header - migrate to Permissions-Policy", 3.0
        return RiskLevel.PASS, "", 0.0
