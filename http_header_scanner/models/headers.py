"""
Security header definitions with metadata for analysis
"""

from enum import Enum
from typinig import Dict, List, TypedDict, Optional

class HeaderRiskLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

class HeaderCategory(str, Enum):
    TRANSPORT_SECURITY = "Transport Security"
    CONTENT_SECURITY = "Content Security"
    CLICKJACKING = "Clickjacking Protection"
    CORS = "CORS and Cross-Origin Policies"
    COOKIES = "Cookies and Session Security"
    INFO_DISCLOSURE = "Information Disclosure"
    CACHING = "Caching Policies"
    CERT_TRANSPARENCY = "Certificate Transparency"
    FEATURE_CONTROL = "Feature Control"
    REPORTING = "Reporting"

class HeaderDefinition(TypedDict):
    description: str
    improvement: str
    cvss_base_score: float
    risk_level: HeaderRiskLevel
    category: HeaderCategory
    references: List[str]
    required: bool
    api_specific: bool
    web_specific: bool

SECURITY_HEADERS: Dict[str, HeaderDefinition] = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections and prevents SSL stripping attacks.",
        "improvement": "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
        "cvss_base_score": 9.0,
        "risk_level": HeaderRiskLevel.CRITICAL,
        "category": HeaderCategory.TRANSPORT_SECURITY,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            "https://owasp.org/www-community/controls/HTTP_Strict_Transport_Security"
        ],
        "required": True,
        "api_specific": True,
        "web_specific": True
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-sniffing of content types.",
        "improvement": "Set 'X-Content-Type-Options: nosniff'.",
        "cvss_base_score": 5.0,
        "risk_level": HeaderRiskLevel.MEDIUM,
        "category": HeaderCategory.CONTENT_SECURITY,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        ],
        "required": True,
        "api_specific": True,
        "web_specific": True
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks by controlling iframe embedding.",
        "improvement": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
        "cvss_base_score": 6.0,
        "risk_level": HeaderRiskLevel.MEDIUM,
        "category": HeaderCategory.CLICKJACKING,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
        ],
        "required": True,
        "api_specific": False,
        "web_specific": True
    },
}

HEADER_CATEGORIES: Dict[HeaderCategory, List[str]] = {
    HeaderCategory.TRANSPORT_SECURITY: [
        "Strict-Transport-Security"
    ],
    HeaderCategory.CONTENT_SECURITY: [
        "X-Content-Type-Options",
        "Content-Security-Policy"
    ],
    HeaderCategory.CLICKJACKING: [
        "X-Frame-Options"
    ],
    # Other categories would be defined here
}

class FrameworkType(str, Enum):
    FRONTEND = "Frontend"
    BACKEND = "Backend"
    CMS = "CMS"
    SSR = "Server-Side Rendered"
    API = "API Framework"

class FrameworkRecommendation(TypedDict):
    header: str
    recommendation: str
    rationale: str

FRAMEWORK_SPECIFIC_RECOMMENDATIONS: Dict[str, List[FrameworkRecommendation]] = {
    "Content-Security-Policy": [
        {
            "header": "Content-Security-Policy",
            "recommendation": "Use nonce-based CSP with strict directives",
            "rationale": "React's JSX syntax can bypass traditional CSP protections"
        },
        {
            "header": "Cross-Origin-Opener-Policy",
            "recommendation": "Set to 'same-origin'",
            "rationale": "Prevents cross-origin window attacks in React apps"
        }
    ],
    # Other framework-specific recommendations
}
