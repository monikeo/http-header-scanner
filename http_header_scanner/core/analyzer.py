"""
Comprehensive security header analysis
"""

import re
import ssl
import socket
from datetime import datetime
from typing import Dict, List, Optional
from http_header_scanner.models.findings import (
    RiskLevel,
    HeaderFinding,
    ContentSecurityPolicyAnalysis,
    TLSFinding,
    FrameworkFinding,
    SecurityAnalysisReport
)
from http_header_scanner.models.headers import SECURITY_HEADERS
from .validator import HeaderValidator
from .detector import FrameworkDetector

class SecurityAnalyzer:
    def __init__(self):
        self.detector = FrameworkDetector()
    
    def analyze(
        self,
        url: str,
        final_url: str,
        status_code: int,
        headers: Dict[str, str],
        content: str = ""
    ) -> SecurityAnalysisReport:
        # Determine context
        context = self._get_context(url, headers, content)
        
        # Initialize report
        report: SecurityAnalysisReport = {
            "url": url,
            "final_url": final_url,
            "status_code": status_code,
            "headers": [],
            "csp_analysis": None,
            "tls_analysis": self._analyze_tls(final_url),
            "framework_analysis": None,
            "overall_risk": RiskLevel.PASS,
            "total_score": 0.0,
            "metrics": {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Detect framework
        frameworks = self.detector.detect(headers, content, url)
        if frameworks:
            report["framework_analysis"] = self._create_framework_finding(frameworks[0])
            context["framework"] = frameworks[0].name
        
        # Analyze headers
        validator = HeaderValidator(context)
        for header, value in headers.items():
            finding = self._analyze_header(header, value, validator)
            report["headers"].append(finding)
            report["total_score"] += finding["cvss_score"]
        
        # Special CSP analysis
        if "Content-Security-Policy" in headers:
            report["csp_analysis"] = self._analyze_csp(headers["Content-Security-Policy"])
            report["total_score"] += report["csp_analysis"]["score"]
        
        # Determine overall risk
        report["overall_risk"] = self._determine_overall_risk(report["total_score"])
        
        return report
    
    def _get_context(self, url: str, headers: Dict[str, str], content: str) -> Dict:
        """Determine context for validation"""
        parsed_url = url.lower()
        return {
            "is_api": "api" in parsed_url or "json" in parsed_url or "xml" in parsed_url,
            "is_sensitive": any(
                term in parsed_url 
                for term in ["login", "auth", "account", "admin", "dashboard"]
            ),
            "is_public": not any(
                term in parsed_url 
                for term in ["login", "auth", "account", "admin"]
            )
        }
    
    def _analyze_header(
        self, 
        header: str, 
        value: str, 
        validator: HeaderValidator
    ) -> HeaderFinding:
        """Analyze an individual header"""
        risk_level, issue, cvss_score = validator.validate(header, value)
        
        header_def = SECURITY_HEADERS.get(header, {})
        return {
            "header": header,
            "value": value,
            "status": risk_level,
            "issue": issue,
            "recommendation": header_def.get("improvement", ""),
            "cvss_score": cvss_score,
            "references": header_def.get("references", [])
        }
    
    def _analyze_csp(self, policy: str) -> ContentSecurityPolicyAnalysis:
        """Perform in-depth CSP analysis"""
        analysis: ContentSecurityPolicyAnalysis = {
            "directives": {},
            "missing_directives": [],
            "unsafe_directives": [],
            "wildcards": [],
            "score": 0,
            "risk_level": RiskLevel.LOW,
            "recommendations": []
        }
        
        # Parse CSP directives
        directives = [d.strip() for d in policy.split(';') if d.strip()]
        for directive in directives:
            parts = directive.split()
            if parts:
                directive_name = parts[0].lower()
                analysis["directives"][directive_name] = parts[1:]
        
        # Check for unsafe directives
        unsafe_terms = ["'unsafe-inline'", "'unsafe-eval'", "http:", "*"]
        for directive, values in analysis["directives"].items():
            for term in unsafe_terms:
                if term in values:
                    analysis["unsafe_directives"].append(f"{directive}: {term}")
                    analysis["score"] += 3
        
        # Check for wildcards
        for directive, values in analysis["directives"].items():
            if "*" in values:
                analysis["wildcards"].append(directive)
                analysis["score"] += 2
        
        # Check for missing critical directives
        critical_directives = ["default-src", "script-src", "object-src", "base-uri"]
        for directive in critical_directives:
            if directive not in analysis["directives"]:
                analysis["missing_directives"].append(directive)
                analysis["score"] += 3
        
        # Determine risk level
        if analysis["score"] >= 10:
            analysis["risk_level"] = RiskLevel.CRITICAL
        elif analysis["score"] >= 5:
            analysis["risk_level"] = RiskLevel.HIGH
        elif analysis["score"] > 0:
            analysis["risk_level"] = RiskLevel.MEDIUM
        
        # Generate recommendations
        if analysis["unsafe_directives"]:
            analysis["recommendations"].append(
                "Remove 'unsafe-inline' and 'unsafe-eval' from CSP directives"
            )
        if analysis["wildcards"]:
            analysis["recommendations"].append(
                "Restrict wildcard usage in CSP directives"
            )
        if analysis["missing_directives"]:
            analysis["recommendations"].append(
                f"Add missing critical directives: {', '.join(analysis['missing_directives'])}"
            )
        
        return analysis
    
    def _analyze_tls(self, url: str) -> TLSFinding:
        """Analyze TLS configuration"""
        try:
            hostname = url.split("//")[-1].split("/")[0].split(":")[0]
            context = ssl.create_default_context()
            context.set_ciphers("ALL:@SECLEVEL=1")
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()
            
            return {
                "version": tls_version,
                "grade": self._get_tls_grade(tls_version),
                "supported_protocols": [tls_version],
                "cipher_strength": cipher[0] if cipher else "Unknown",
                "vulnerabilities": self._get_tls_vulnerabilities(tls_version)
            }
        except Exception as e:
            return {
                "version": "Error",
                "grade": "F",
                "supported_protocols": [],
                "cipher_strength": "Unknown",
                "vulnerabilities": [f"Connection failed: {str(e)}"]
            }
    
    def _get_tls_grade(self, version: str) -> str:
        grades = {
            "SSLv2": "F",
            "SSLv3": "F",
            "TLSv1": "D",
            "TLSv1.1": "C",
            "TLSv1.2": "B",
            "TLSv1.3": "A+"
        }
        return grades.get(version, "N/A")
    
    def _get_tls_vulnerabilities(self, version: str) -> List[str]:
        vulnerabilities = []
        if version in ["SSLv2", "SSLv3"]:
            vulnerabilities.append("POODLE vulnerability")
        if version == "TLSv1.0":
            vulnerabilities.append("BEAST vulnerability")
        return vulnerabilities
    
    def _create_framework_finding(self, framework) -> FrameworkFinding:
        return {
            "name": framework.name,
            "type": framework.type.value,
            "version": framework.version,
            "confidence": framework.confidence,
            "vulnerabilities": framework.common_vulnerabilities,
            "recommendations": framework.security_guidelines.get("general", [])
        }
    
    def _determine_overall_risk(self, score: float) -> RiskLevel:
        if score >= 25:
            return RiskLevel.CRITICAL
        elif score >= 15:
            return RiskLevel.HIGH
        elif score >= 8:
            return RiskLevel.MEDIUM
        elif score > 0:
            return RiskLevel.LOW
        return RiskLevel.PASS
