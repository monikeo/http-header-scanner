"""
Advanced framework detection with improved obfuscation resistance
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Pattern, Set, Tuple
from enum import Enum
from http_header_scanner.models.headers import FrameworkType

@dataclass
class FrameworkIndicator:
    header_patterns: Dict[str, Pattern]
    content_patterns: List[Pattern]
    file_path_patterns: List[Pattern]
    javascript_vars: List[str]
    meta_tags: List[Pattern]
    common_paths: List[str]
    version_detection: Dict[str, Pattern]
    obfuscation_techniques: Set[str]
    obfuscation_resistant: bool = False

@dataclass
class Framework:
    name: str
    type: FrameworkType
    indicators: FrameworkIndicator
    common_ports: Set[int]
    security_guidelines: Dict[str, List[str]]
    common_vulnerabilities: List[str]
    version: Optional[str] = None
    confidence: float = 0.0

class FrameworkDetector:
    def __init__(self):
        self.frameworks = self._load_framework_definitions()

    def _load_framework_definitions(self) -> Dict[str, Framework]:
        frameworks = {}

        # WordPress
        frameworks["WordPress"] = Framework(
            name="WordPress",
            type=FrameworkType.CMS,
            indicators=FrameworkIndicator(
                header_patterns={
                    "X-Powered-By": re.compile(r"WordPress", re.I),
                    "Link": re.compile(r"rel=https://api\.w\.org/"),
                    "Set-Cookie": re.compile(r"wordpress(?:_logged_in)?_[a-f0-9]+"),
                },
                content_patterns=[
                    re.compile(r"<meta name=\"generator\" content=\"WordPress"),
                    re.compile(r"wp-content/(themes|plugins)/"),
                    re.compile(r"/wp-admin/"),
                    re.compile(r"/wp-includes/"),
                    re.compile(r"wp-json/"),
                ],
                file_path_patterns=[
                    re.compile(r"wp-config\.php"),
                    re.compile(r"wp-login\.php")
                ],
                javascript_vars=["wpApiSettings", "wpEmojiSettings"],
                meta_tags=[
                    re.compile(r"<meta name=\"generator\" content=\"WordPress")
                ],
                common_paths=["/wp-admin", "/wp-login.php", "/wp-content"],
                version_detection={
                    "meta": re.compile(r"content=\"WordPress (\d+\.\d+(?:\.\d+)?)\""),
                    "readme": re.compile(r"Version (\d+\.\d+(?:\.\d+)?)")
                },
                obfuscation_techniques={
                    "header_removal", 
                    "generic_server_header"
                }
            ),
            common_ports={80, 443},
            security_guidelines={
                "headers": {
                    "Content-Security-Policy": "Implement strict CSP with nonce/hash for scripts",
                    "X-Content-Type-Options": "Always set to 'nosniff'",
                },
                "general": [
                    "Keep WordPress core and plugins updated",
                    "Implement web application firewall",
                    "Disable XML-RPC if not needed"
                ]
            },
            common_vulnerabilities=[
                "XML-RPC abuse",
                "User enumeration",
                "Plugin vulnerabilities",
                "Brute force attacks"
            ]
        )

        # Add more frameworks (React, Django, etc.) following the same pattern
        return frameworks

    def detect(
        self,
        headers: Dict[str, str],
        content: str = "",
        url: str = ""
    ) -> List[Framework]:
        detected = []
        
        for name, framework in self.frameworks.items():
            confidence = 0.0

            # Header-based detection
            for header_name, pattern in framework.indicators.header_patterns.items():
                if header_name in headers and pattern.search(headers[header_name]):
                    confidence += 0.7

            # Content-based detection
            if content:
                for pattern in framework.indicators.content_patterns:
                    if pattern.search(content):
                        confidence += 1.0

            # Version detection
            version = self._detect_version(framework, headers, content)
            if confidence > 0.5:
                framework.version = version
                framework.confidence = min(confidence, 1.0)
                detected.append(framework)
        return detected

    def _detect_version(
            self,
            framework: Framework,
            headers: Dict[str, str],
            content: str
    ) -> Optional[str]:
        # Chect version in meta tags
        if content:
            for pattern in framework.indicators.meta_tags:
                match = pattern.search(content)
                if match and len(match.groups()) > 0:
                    return match.group(1)

        # Check version in headers
        for header, pattern in framework.indicators.version_detection.items():
            if header in headers:
                match = pattern.search(headers[header])
                if match:
                    return match.group(1)

        return None
