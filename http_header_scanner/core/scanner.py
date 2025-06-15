"""
Core scanning functionality
"""

import requests
from datetime import datetime
from typing import Dict, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from http_header_scanner.models.findings import SecurityAnalysisReport
from http_header_scanner.models.findings import RiskLevel
from .analyzer import SecurityAnalyzer
from http_header_scanner.utils.network import get_redirect_chain

class HeaderScanner:
    def __init__(self, max_retries=2, backoff_factor=0.5):
        self.analyzer = SecurityAnalyzer()
        self.session = self._create_session(max_retries, backoff_factor)

    def _create_session(self, max_retries, backoff_factor):
        session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def scan(
        self,
        url: str,
        follow_redirects: bool = True,
        timeout: int = 10,
        user_agent: str = "SecurityScanner/2.0"
    ) -> SecurityAnalysisReport:
        """
            Perform a security scan of a URL
        """
        try:
            # Follow redirect chain
            if follow_redirects:
                redirect_chain = get_redirect_chain(url, timeout, user_agent)
                final_url = redirect_chain[-1] if redirect_chain else url
            else:
                final_url = url

            # First make a HEAD request
            try:
                response = self.session.head(
                    final_url,
                    allow_redirects=False,
                    timeout=timeout,
                    headers={"User-Agent": user_agent}
                )
            except requests.RequestException:
                # Fallback to GET if HEAD fails
                response = self.session.get(
                    final_url,
                    allow_redirects=False,
                    timeout=timeout,
                    headers={"User-Agent": user_agent},
                    stream=True  # Don't download large bodies
                )

            # Get content if needed
            content = ""
            content_type = response.headers.get("Content-Type", "").lower()
            if "text/html" in content_type or "application/json" in content_type:
                try:
                    # Read only first 10KB for efficiency
                    content = response.iter_content(chunk_size=10240).__next__().decode('utf-8', 'ignore')
                except (UnicodeDecodeError, StopIteration):
                    pass

            # Analyze response
            return self.analyzer.analyze(
                url=url,
                final_url=final_url,
                status_code=response.status_code,
                headers=dict(response.headers),
                content=content
            )
        except requests.RequestException as e:
            return self._error_report(url, str(e))
        except Exception as e:
            return self._error_report(url, f"Unexpected error: {str(e)}")

    def _error_report(self, url: str, error: str) -> SecurityAnalysisReport:
        return {
            "url": url,
            "final_url": url,
            "status_code": 0,
            "headers": [],
            "csp_analysis": None,
            "tls_analysis": None,
            "framework_analysis": None,
            "overall_risk": RiskLevel.ERROR,
            "total_score": 0.0,
            "metrics": {"error": 1.0},
            "timestamp": datetime.utcnow().isoformat(),
            "error": error
        }
