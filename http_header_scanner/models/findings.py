"""
Data models for security findings and reports
"""

from enum import Enum
from typing import Dict, List, Optional, TypedDict
from .headers import HeaderRiskLevel

class RiskLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
    PASS = "Pass"

class HeaderFinding(TypedDict):
    header: str
    value: str
    status: RiskLevel
    issue: Optional[str]
    recommendation: str
    cvss_score: float
    references: List[str]

class ContentSecurityPolicyAnalysis(TypedDict):
    directives: Dict[str, List[str]]
    missing_directives: List[str]
    unsafe_directives: List[str]
    wildcards: List[str]
    score: int
    risk_level: RiskLevel
    recommendation: List[str]

class TLSFinding(TypedDict):
    version: str
    grade: str
    supported_protocols: List[str]
    cipher_strength: str
    vulnerabilities: List[str]

class FrameworkFinding(TypedDict):
    name: str
    type: str
    version: Optional[str]
    confidence: float
    vulnerabilities: List[str]
    recommendation: List[str]

class SecurityAnalysisReport(TypedDict):
    url: str
    final_url: str
    status_core: int
    headers: List[HeaderFinding]
    csp_analysis: Optional[ContentSecurityPolicyAnalysis]
    tls_analysis: TLSFinding
    framework_analysis: Optional[FrameworkFinding]
    overall_risk: RiskLevel
    total_score: float
    metrics: Dict[str, float]
    timestamp: str
