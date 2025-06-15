"""
Advanced framework detection with improved obfuscation resistance
"""

import re
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Pattern, Set, Tuple
from enum import Enum
from http_header_scanner.models.headers import FrameworkType

@dataclass
class FrameworkIndicator:
    header_patterns: Dict[str, Pattern]
    content_patterns: List[Pattern]
    javascript_vars: List[str]
    meta_tags: List[Pattern]
    common_paths: List[str]
    version_detection: Dict[str, Pattern]
    html_fingerprints: List[str]
    script_fingerprints: List[str]

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
        self._load_fingerprint_db()

    def _load_fingerprint_db(self):
        with open("http_header_scanner/data/framework_fingerprints.json") as f:
            self.fingerprints = json.load(f)

    def _load_framework_definitions(self) -> Dict[str, Framework]:
        frameworks = {}

        """
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
        """
        # Load from external definition file
        """
        with open("http_header_scanner/data/framework_definitions.json") as f:
            framework_data = json.load(f)

            for name, data in framework_data.items():
                indicators = data["indicators"]
                framework = Framework(
                    name=name,
                    type=FrameworkType[data["type"]],
                    indicators=FrameworkIndicator(
                        header_patterns={k: re.compile(v, re.I) for k, v in indicators["header_patterns"].items()},
                        content_patterns=[re.compile(p, re.I) for p in indicators["content_patterns"]],
                        javascript_vars=indicators["javascript_vars"],
                        meta_tags=[re.compile(p, re.I) for p in indicators["meta_tags"]],
                        common_paths=indicators["common_paths"],
                        version_detection={k: re.compile(v, re.I) for k, v in indicators["version_detection"].items()},
                        html_fingerprints=indicators["html_fingerprints"],
                        script_fingerprints=indicators["script_fingerprints"]
                    ),
                    security_guidelines=data["security_guidelines"],
                    common_vulnerabilities=data["common_vulnerabilities"]
                )
        """
        with open("http_header_scanner/data/framework_definitions.json") as f:
            framework_data = json.load(f)

        for name, data in framework_data.items():
            framework = Framework(
                name=name,
                type=FrameworkType[data["type"]],
                indicators=FrameworkIndicator(
                    header_patterns={k: re.compile(v, re.I) for k, v in data["indicators"]["header_patterns"].items()},
                    content_patterns=[re.compile(p, re.I) for p in data["indicators"]["content_patterns"]],
                    javascript_vars=data["indicators"]["javascript_vars"],
                    meta_tags=[re.compile(p, re.I) for p in data["indicators"]["meta_tags"]],
                    common_paths=data["indicators"]["common_paths"],
                    version_detection={k: re.compile(v, re.I) for k, v in data["indicators"]["version_detection"].items()},
                    html_fingerprints=data["indicators"]["html_fingerprints"],
                    script_fingerprints=data["indicators"]["script_fingerprints"]
                ),
                common_ports=set(data["common_ports"]),
                security_guidelines=data["security_guidelines"],
                common_vulnerabilities=data["common_vulnerabilities"]
    )
            frameworks[name] = framework

        # Add more frameworks (React, Django, etc.) following the same pattern
        return frameworks

    def detect(
        self,
        headers: Dict[str, str],
        content: str = "",
        url: str = ""
    ) -> List[Framework]:
        detected = []
        content_lower = content.lower()
        
        for name, framework in self.frameworks.items():
            confidence = 0.0
            version = None

            # Header-based detection
            for header_name, pattern in framework.indicators.header_patterns.items():
                if header_name in headers and pattern.search(headers[header_name]):
                    confidence += 0.7
                    version = self._extract_version(
                        framework, headers[header_name], "header"
                    ) or version

            # Content-based detection
            if content:
                # HTML fingerprint matching
                for fp in framework.indicators.html_fingerprints:
                    if fp in content_lower:
                        confidence += 0.8

                # Script fingerprint matching
                for fp in framework.indicators.script_fingerprints:
                    if fp in content_lower:
                        confidence += 0.9

                # Meta tag detection
                for pattern in framework.indicators.meta_tags:
                    match = pattern.search(content)
                    if match:
                        confidence += 0.6
                        version = self._extract_version(
                            framework, match.group(), "meta"
                        ) or version

                # JavaScript variable detection
                for var in framework.indicators.javascript_vars:
                    if var in content:
                        confidence += 0.5

            # Version extraction from content
            if not version and content:
                version = self._extract_version(framework, content, "content")

            if confidence > 0.5:
                framework.version = version
                framework.confidence = min(confidence, 1.0)
                detected.append(framework)
        return sorted(detected, key=lambda f: f.confidence, reverse=True)[:3]

    def _extract_version(
        self,
        framework: Framework,
        content: str,
        source: str
    ) -> Optional[str]:
        patterns = framework.indicators.version_detection.get(source, {})
        for pattern in patterns.values():
            match = pattern.search(content)
            if match and match.lastindex:
                return match.group(1)
        return None

"""
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
"""
