"""
Network utilities for security scanning
"""

import socket
import ssl
import typing import Dict, List, Tuple

def get_tls_info(hostname: str, port: int = 443) -> Dict:
    """
    Get detailed TLS information for a host
    """
    context = ssl.create_default_context()
    context.set_ciphers("ALL:@SECLEVEL=1")

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            return {
                    "version:": ssock.version(),
                    "cipher": ssock.cipher(),
                    "compression": ssock.compression(),
                    "alpn_protocol": ssock.selected_alpn_protocol(),
                    "certificate": ssock.getpeercert(),
                    "session": ssock.session,
                    "session_reused": ssock.session_reused
            }

def check_http_headers(url: str) -> Dick:
    """
    Check HTTP headers with redirect following
    """
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        return {
                "final_url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers)
        }
    except requests.RequestException:
        try:
            response = requests.get(url, allow_redirects=True, timeout=10)
            return {
                    "final_url": response.url,
                    "status_code": response.status_code,
                    "headers": dict(response.headers)
            }
        except Exception as e:
            return ("error": str(e))
