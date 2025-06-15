"""
Network utilities for security scanning
"""

import requests
import socket
import ssl
from typing import Dict, List, Tuple
from urllib.parse import urlparse

def get_redirect_chain(url: str, timeout: int = 10, user_agent: str = "SecurityScanner/2.0") -> List[str]:
    chain = []
    current_url = url

    for _ in range(10):  # Max 10 redirects
        try:
            response = requests.head(
                current_url,
                allow_redirects=False,
                timeout=timeout,
                headers={"User-Agent": user_agent}
            )

            chain.append(current_url)

            if 300 <= response.status_code < 400:
                location = response.headers.get('Location')
                if location:
                    # Resolve relative URLs
                    if location.startswith('/'):
                        parsed = urlparse(current_url)
                        current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                    else:
                        current_url = location
                else:
                    break
            else:
                break
        except requests.RequestException:
            break

    return chain

def check_tls_configuration(hostname: str, port: int = 443) -> Dict:
    """Comprehensive TLS configuration checker"""
    try:
        context = ssl.create_default_context()
        context.set_ciphers("ALL:@SECLEVEL=1")

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                cert = ssock.getpeercert()

                return {
                    "version": ssock.version(),
                    "cipher": cipher[0] if cipher else "Unknown",
                    "key_size": cipher[2] if cipher else 0,
                    "cert_issuer": dict(x[0] for x in cert['issuer']) if cert else {},
                    "cert_subject": dict(x[0] for x in cert['subject']) if cert else {},
                    "cert_validity": cert['notAfter'] if cert else "",
                    "protocols_supported": self._get_supported_protocols(hostname)
                }
    except Exception as e:
        return {"error": str(e)}

def _get_supported_protocols(hostname: str) -> Dict[str, bool]:
    """Check support for various TLS versions"""
    protocols = {
        "SSLv2": False,
        "SSLv3": False,
        "TLSv1.0": False,
        "TLSv1.1": False,
        "TLSv1.2": False,
        "TLSv1.3": False
    }

    for proto in protocols.keys():
        try:
            context = ssl.SSLContext(protocol=getattr(ssl, f"PROTOCOL_{proto}"))
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname):
                    protocols[proto] = True
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError):
            pass

    return protocols

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

def check_http_headers(url: str) -> Dict:
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
            return {"error": str(e)}
