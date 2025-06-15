"""
Security header definitions with metadata for analysis
"""

from enum import Enum
from typing import Dict, List, TypedDict, Optional

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
    MISCELLANEOUS = "Miscellaneous"

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
    "Content-Security-Policy": {
        "description": "Prevents XSS, clickjacking, and other code injection attacks by defining content sources.",
        "improvement": "Implement a strict CSP with nonce/hash for scripts and avoid 'unsafe-inline'.",
        "cvss_base_score": 9.0,
        "risk_level": HeaderRiskLevel.CRITICAL,
        "category": HeaderCategory.CONTENT_SECURITY,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            "https://owasp.org/www-project-secure-headers/#content-security-policy"
        ],
        "required": True,
        "api_specific": True,
        "web_specific": True
    },
    "X-XSS-Protection": {
        "description": "Enables XSS filtering in older browsers.",
        "improvement": "Set 'X-XSS-Protection: 1; mode=block'.",
        "cvss_base_score": 4.0,
        "risk_level": HeaderRiskLevel.LOW,
        "category": HeaderCategory.CONTENT_SECURITY,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
        ],
        "required": False,
        "api_specific": True,
        "web_specific": True
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is included in requests.",
        "improvement": "Set 'Referrer-Policy: no-referrer-when-downgrade' or stricter.",
        "cvss_base_score": 3.0,
        "risk_level": HeaderRiskLevel.LOW,
        "category": HeaderCategory.CONTENT_SECURITY,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
        ],
        "required": False,
        "api_specific": True,
        "web_specific": True
    },
    "Permissions-Policy": {
        "description": "Controls browser features and APIs that can be used in the document.",
        "improvement": "Set 'Permissions-Policy: geolocation=(self), microphone=(), camera=()'.",
        "cvss_base_score": 6.0,
        "risk_level": HeaderRiskLevel.MEDIUM,
        "category": HeaderCategory.FEATURE_CONTROL,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
        ],
        "required": False,
        "api_specific": False,
        "web_specific": True
    },
    "Expect-CT": {
        "description": "Enforces Certificate Transparency compliance.",
        "improvement": "Set 'Expect-CT: max-age=86400, enforce'.",
        "cvss_base_score": 7.0,
        "risk_level": HeaderRiskLevel.HIGH,
        "category": HeaderCategory.CERT_TRANSPARENCY,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT"
        ],
        "required": False,
        "api_specific": True,
        "web_specific": True
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Prevents other sites from embedding your resources.",
        "improvement": "Set 'Cross-Origin-Resource-Policy: same-origin' or 'same-site'.",
        "cvss_base_score": 6.0,
        "risk_level": HeaderRiskLevel.MEDIUM,
        "category": HeaderCategory.CORS,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
        ],
        "required": False,
        "api_specific": True,
        "web_specific": True
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Requires cross-origin documents to be explicitly loaded with CORP or CORS.",
        "improvement": "Set 'Cross-Origin-Embedder-Policy: require-corp'.",
        "cvss_base_score": 6.0,
        "risk_level": HeaderRiskLevel.MEDIUM,
        "category": HeaderCategory.CORS,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
        ],
        "required": False,
        "api_specific": True,
        "web_specific": True
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates the browsing context to prevent cross-origin attacks.",
        "improvement": "Set 'Cross-Origin-Opener-Policy: same-origin'.",
        "cvss_base_score": 7.0,
        "risk_level": HeaderRiskLevel.HIGH,
        "category": HeaderCategory.CORS,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
        ],
        "required": False,
        "api_specific": True,
        "web_specific": True
    },
    "Access-Control-Allow-Origin": {
        "description": "Controls which origins are allowed to access resources.",
        "improvement": "Avoid '*' when credentials are used; specify exact origins.",
        "cvss_base_score": 7.0,
        "risk_level": HeaderRiskLevel.HIGH,
        "category": HeaderCategory.CORS,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin"
        ],
        "required": False,
        "api_specific": True,
        "web_specific": False
    },
    "Set-Cookie": {
        "description": "Configures cookies with security attributes.",
        "improvement": "Always include Secure, HttpOnly, and SameSite attributes.",
        "cvss_base_score": 8.0,
        "risk_level": HeaderRiskLevel.HIGH,
        "category": HeaderCategory.COOKIES,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"
        ],
        "required": True,
        "api_specific": True,
        "web_specific": True
    },
    "Server": {
        "description": "Reveals server software and version.",
        "improvement": "Remove or obfuscate this header.",
        "cvss_base_score": 3.0,
        "risk_level": HeaderRiskLevel.LOW,
        "category": HeaderCategory.INFO_DISCLOSURE,
        "references": [
            "https://owasp.org/www-project-secure-headers/#server"
        ],
        "required": False,
        "api_specific": True,
        "web_specific": True
    },
    "X-Powered-By": {
        "description": "Reveals backend technology stack.",
        "improvement": "Remove or obfuscate this header.",
        "cvss_base_score": 3.0,
        "risk_level": HeaderRiskLevel.LOW,
        "category": HeaderCategory.INFO_DISCLOSURE,
        "references": [
            "https://owasp.org/www-project-secure-headers/#x-powered-by"
        ],
        "required": False,
        "api_specific": True,
        "web_specific": True
    },
    "Cache-Control": {
        "description": "Controls caching behavior of browsers and proxies.",
        "improvement": "Set 'Cache-Control: no-store' for sensitive pages.",
        "cvss_base_score": 5.0,
        "risk_level": HeaderRiskLevel.MEDIUM,
        "category": HeaderCategory.CACHING,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"
        ],
        "required": False,
        "api_specific": True,
        "web_specific": True
    },
    "Clear-Site-Data": {
        "description": "Clears browsing data associated with the requesting website.",
        "improvement": "Set 'Clear-Site-Data: \"cache\", \"cookies\", \"storage\"' for logout pages.",
        "cvss_base_score": 4.0,
        "risk_level": HeaderRiskLevel.LOW,
        "category": HeaderCategory.COOKIES,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data"
        ],
        "required": False,
        "api_specific": False,
        "web_specific": True
    },
    "Content-Security-Policy-Report-Only": {
        "description": "CSP in report-only mode for testing policies.",
        "improvement": "Use during testing, then implement full CSP.",
        "cvss_base_score": 4.0,
        "risk_level": HeaderRiskLevel.LOW,
        "category": HeaderCategory.REPORTING,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only"
        ],
        "required": False,
        "api_specific": True,
        "web_specific": True
    },
    "Report-To": {
        "description": "Specifies endpoints for browser to send reports.",
        "improvement": "Configure reporting endpoints for CSP and other policies.",
        "cvss_base_score": 3.0,
        "risk_level": HeaderRiskLevel.LOW,
        "category": HeaderCategory.REPORTING,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Report-To"
        ],
        "required": False,
        "api_specific": True,
        "web_specific": True
    },
    "Feature-Policy": {
        "description": "Controls browser features and APIs (deprecated in favor of Permissions-Policy).",
        "improvement": "Migrate to Permissions-Policy.",
        "cvss_base_score": 5.0,
        "risk_level": HeaderRiskLevel.LOW,
        "category": HeaderCategory.FEATURE_CONTROL,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy"
        ],
        "required": False,
        "api_specific": False,
        "web_specific": True
    },
    "Content-Type": {
        "description": "Indicates the media type of the resource.",
        "improvement": "Always set with proper charset (e.g., 'text/html; charset=UTF-8').",
        "cvss_base_score": 5.0,
        "risk_level": HeaderRiskLevel.MEDIUM,
        "category": HeaderCategory.CONTENT_SECURITY,
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type"
        ],
        "required": True,
        "api_specific": True,
        "web_specific": True
    },
    "X-Permitted-Cross-Domain-Policies": {
        "description": "Restricts Adobe Flash and Acrobat cross-domain access.",
        "improvement": "Set 'X-Permitted-Cross-Domain-Policies: none'.",
        "cvss_base_score": 3.0,
        "risk_level": HeaderRiskLevel.LOW,
        "category": HeaderCategory.CORS,
        "references": [
            "https://owasp.org/www-project-secure-headers/#x-permitted-cross-domain-policies"
        ],
        "required": False,
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
        "Content-Security-Policy",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Content-Type"
    ],
    HeaderCategory.CLICKJACKING: [
        "X-Frame-Options",
        "Content-Security-Policy" # frame-ancestors directive
    ],
    HeaderCategory.CORS: [
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Opener-Policy",
        "Access-Control-Allow-Origin",
        "X-Permitted-Cross-Domain-Policies"
    ],
    HeaderCategory.COOKIES: [
        "Set-Cookie",
        "Clear-Site-Data"
    ],
    HeaderCategory.INFO_DISCLOSURE: [
        "Server",
        "X-Powered-By"
    ],
    HeaderCategory.CACHING: [
        "Cache-Control"
    ],
    HeaderCategory.CERT_TRANSPARENCY: [
        "Expect-CT"
    ],
    HeaderCategory.FEATURE_CONTROL: [
        "Permissions-Policy",
        "Feature-Policy"
    ],
    HeaderCategory.REPORTING: [
        "Content-Security-Policy-Report-Only",
        "Report-To"
    ],
    HeaderCategory.MISCELLANEOUS: []
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
        },
        {
            "header": "Content-Security-Policy",
            "recommendation": "Allow 'unsafe-inline' for styles only with hash/nonce",
            "rationale": "WordPress plugins often require inline styles"
        },
        {
            "header": "Content-Security-Policy",
            "recommendation": "Implement strict frame-ancestors directive",
            "rationale": "WordPress admin area is vulnerable to clickjacking"
        }
    ],
    "Strict-Transport-Security": [
        {
            "header": "Strict-Transport-Security",
            "recommendation": "Include 'preload' directive",
            "rationale": "Next.js deployments should be preloaded in browsers"
        }
    ],
    "Set-Cookie": [
        {
            "header": "Set-Cookie",
            "recommendation": "Set SameSite=Lax for Django sessions",
            "rationale": "Django's session cookies should be Lax by default"
        },
        {
            "header": "Set-Cookie",
            "recommendation": "Use __Host- prefix for cookies",
            "rationale": "Laravel apps benefit from path and domain restrictions"
        }
    ],
    "Permissions-Policy": [
        {
            "header": "Permissions-Policy",
            "recommendation": "Restrict geolocation, camera, and microphone",
            "rationale": "E-commerce sites shouldn't require sensitive permissions"
        }
    ],
    "Server": [
        {
            "header": "Server",
            "recommendation": "Remove or obfuscate server header",
            "rationale": "All frameworks should minimize information disclosure"
        }
    ]
    # Other framework-specific recommendations
}
