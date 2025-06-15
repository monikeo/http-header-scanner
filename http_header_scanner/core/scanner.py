"""
Core scanning functionality
"""

import requests
from datetime import datetime
from typing import Dict, Optional
from http_header_scanner.models.findings import SecurityAnalysisReport
from .analyzer import SecurityAnalyzer

class HeaderScanner:
    def __init__(self):
        self.analyzer = SecurityAnalyzer()

    def scan(
        self,
        url: str,
        follow_redirects: bool = True,
        timeout: int = 10,
        user_agent: str = "SecurityScanner/1.0"
    ) -> SecurityAnalysisReport:
        """
            Perform a security scan of a URL
        """
        try:
            # First make a HEAD request
            response = requests.head(
                url,
                allow_redirects=follow_redirects,
                timeout=timeout,
                headers={"User-Agent": user_agent}
            )

            # IF HEAD fails, tyr GET
            if response.status_code >= 400:
                response = requests.get(
                    url,
                    allow_redirects=follow_redirects,
                    timeout=timeout,
                    headers={"User-Agent": user_agent}
                )

            # Get content if needed
            content = ""
            if "text/html" in response.headers.get("Content-Type", ""):
                content = response.text[:5000] # Only first 5000 characters

            # Analyze response
            return self.analyzer.analyze(
                url=url,
                final_url=response.url,
                status_code=response.status_code,
                headers=dict(response.headers),
                content=content
            )
        except requests.RequestException as e:
            # Return error report
            return {
                    "url": url,
                    "final_url": url,
                    "status_code": 0,
                    "headers": [],
                    "csp_analysis": None,
                    "tls_analysis": None,
                    "framework_analysis": None,
                    "overall_risk": "Error",
                    "total_score": 0.0,
                    "metrics": {},
                    "timestamp": datetime.utcnow().isoformat(),
                    "error": str(e)

            }
