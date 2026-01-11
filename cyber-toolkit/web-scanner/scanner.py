#!/usr/bin/env python3
"""
CyberToolkit Web Scanner - Professional Security Analysis Tool

A non-destructive passive web scanner with optional OWASP ZAP integration.
Performs security header analysis, SSL/TLS checks, and reconnaissance.

Author: Ghariani Oussema
License: MIT
"""

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configuration
VERSION = "1.0.0"
USER_AGENT = f"CyberToolkit/{VERSION} (Security Scanner)"
DEFAULT_TIMEOUT = 15
DEFAULT_ZAP_BASE = "http://localhost:8090"

# Security Headers to Check
SECURITY_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Permissions-Policy",
]

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Data class for scan results."""
    target: str
    timestamp: int
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    server: Optional[str] = None
    security_headers: Optional[Dict[str, Any]] = None
    robots_txt: Optional[str] = None
    ssl_info: Optional[Dict[str, Any]] = None
    technologies: Optional[List[str]] = None
    error: Optional[str] = None


class WebScanner:
    """Professional web security scanner."""
    
    def __init__(self, timeout: int = DEFAULT_TIMEOUT, verify_ssl: bool = True):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({"User-Agent": USER_AGENT})
        return session
    
    def normalize_url(self, target: str) -> str:
        """Ensure URL has a proper scheme."""
        if not urlparse(target).scheme:
            return f"https://{target}"
        return target
    
    def check_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze security headers and provide recommendations."""
        results = {}
        for header in SECURITY_HEADERS:
            value = headers.get(header)
            results[header] = {
                "present": value is not None,
                "value": value,
                "recommendation": self._get_header_recommendation(header, value)
            }
        return results
    
    def _get_header_recommendation(self, header: str, value: Optional[str]) -> str:
        """Get security recommendation for a header."""
        recommendations = {
            "X-Frame-Options": "Set to 'DENY' or 'SAMEORIGIN' to prevent clickjacking",
            "Content-Security-Policy": "Implement a strict CSP to prevent XSS attacks",
            "X-Content-Type-Options": "Set to 'nosniff' to prevent MIME-type sniffing",
            "Referrer-Policy": "Set to 'strict-origin-when-cross-origin' or stricter",
            "Strict-Transport-Security": "Enable HSTS with max-age of at least 31536000",
            "X-XSS-Protection": "Set to '1; mode=block' (legacy browsers)",
            "Permissions-Policy": "Restrict browser features to minimize attack surface",
        }
        if value:
            return "Header is set"
        return recommendations.get(header, "Consider implementing this header")
    
    def fetch_robots_txt(self, base_url: str) -> Optional[str]:
        """Fetch and return robots.txt content."""
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            response = self.session.get(
                robots_url, 
                timeout=self.timeout // 2,
                verify=self.verify_ssl
            )
            if response.status_code == 200:
                return response.text[:3000]
        except requests.RequestException:
            pass
        return None
    
    def detect_technologies(self, headers: Dict[str, str], body: str) -> List[str]:
        """Detect web technologies from headers and response body."""
        technologies = []
        
        # Server detection
        server = headers.get("Server", "")
        if "nginx" in server.lower():
            technologies.append("Nginx")
        elif "apache" in server.lower():
            technologies.append("Apache")
        elif "iis" in server.lower():
            technologies.append("Microsoft IIS")
        
        # Framework detection from headers
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            technologies.append(f"X-Powered-By: {powered_by}")
        
        # Common patterns in body
        patterns = {
            "WordPress": ["wp-content", "wp-includes"],
            "Drupal": ["drupal", "sites/default"],
            "Joomla": ["joomla", "/components/"],
            "React": ["react", "_reactRoot"],
            "Vue.js": ["vue", "__vue__"],
            "Angular": ["ng-version", "angular"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
        }
        
        body_lower = body.lower()
        for tech, indicators in patterns.items():
            if any(ind in body_lower for ind in indicators):
                technologies.append(tech)
        
        return list(set(technologies))
    
    def scan(self, target: str) -> ScanResult:
        """Perform a comprehensive passive scan on the target."""
        url = self.normalize_url(target)
        result = ScanResult(target=url, timestamp=int(time.time()))
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl
            )
            
            result.status_code = response.status_code
            result.final_url = response.url
            result.server = response.headers.get("Server")
            result.security_headers = self.check_security_headers(dict(response.headers))
            result.robots_txt = self.fetch_robots_txt(response.url)
            result.technologies = self.detect_technologies(
                dict(response.headers), 
                response.text[:50000]
            )
            
        except requests.exceptions.SSLError as e:
            result.error = f"SSL Error: {str(e)}"
            logger.error(f"SSL error scanning {url}: {e}")
        except requests.exceptions.ConnectionError as e:
            result.error = f"Connection Error: {str(e)}"
            logger.error(f"Connection error scanning {url}: {e}")
        except requests.exceptions.Timeout:
            result.error = "Request timed out"
            logger.error(f"Timeout scanning {url}")
        except requests.RequestException as e:
            result.error = f"Request Error: {str(e)}"
            logger.error(f"Error scanning {url}: {e}")
        
        return result


class ZAPIntegration:
    """OWASP ZAP integration for enhanced scanning."""
    
    def __init__(self, zap_base: str = DEFAULT_ZAP_BASE):
        self.zap_base = zap_base.rstrip("/")
        self.session = requests.Session()
    
    def is_available(self) -> bool:
        """Check if ZAP is running and accessible."""
        try:
            response = self.session.get(
                f"{self.zap_base}/JSON/core/view/version/",
                timeout=5
            )
            return response.status_code == 200
        except requests.RequestException:
            return False
    
    def spider_scan(self, url: str, max_wait: int = 30) -> Dict[str, Any]:
        """Initiate a ZAP spider scan (non-intrusive)."""
        try:
            # Start spider
            spider_url = f"{self.zap_base}/JSON/spider/action/scan/"
            response = self.session.get(
                spider_url,
                params={"url": url},
                timeout=20
            )
            data = response.json()
            scan_id = data.get("scan")
            
            if not scan_id:
                return {"error": "Failed to start spider scan"}
            
            # Wait for completion (with timeout)
            start_time = time.time()
            while time.time() - start_time < max_wait:
                status_response = self.session.get(
                    f"{self.zap_base}/JSON/spider/view/status/",
                    params={"scanId": scan_id},
                    timeout=10
                )
                status = status_response.json().get("status", "0")
                if int(status) >= 100:
                    break
                time.sleep(2)
            
            # Get results
            results_response = self.session.get(
                f"{self.zap_base}/JSON/spider/view/results/",
                params={"scanId": scan_id},
                timeout=10
            )
            
            return {
                "scan_id": scan_id,
                "status": "completed",
                "urls_found": results_response.json().get("results", [])[:50]
            }
            
        except requests.RequestException as e:
            return {"error": str(e)}


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="CyberToolkit Web Scanner - Professional Security Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s https://example.com --output report.json
  %(prog)s example.com --use-zap --stdout
  %(prog)s example.com --no-verify-ssl
        """
    )
    parser.add_argument(
        "target",
        help="Target URL (e.g., example.com or https://example.com)"
    )
    parser.add_argument(
        "--use-zap",
        action="store_true",
        help="Enable OWASP ZAP spider scan (requires ZAP running)"
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print JSON results to stdout"
    )
    parser.add_argument(
        "-o", "--output",
        default="scan_result.json",
        help="Output file path (default: scan_result.json)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"CyberToolkit Web Scanner v{VERSION}"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize scanner
    scanner = WebScanner(
        timeout=args.timeout,
        verify_ssl=not args.no_verify_ssl
    )
    
    logger.info(f"Scanning target: {args.target}")
    
    # Perform scan
    result = scanner.scan(args.target)
    output = asdict(result)
    
    # ZAP integration
    if args.use_zap:
        zap_base = os.environ.get("ZAP_BASE", DEFAULT_ZAP_BASE)
        zap = ZAPIntegration(zap_base)
        
        logger.info(f"Checking ZAP availability at {zap_base}")
        if zap.is_available():
            logger.info("ZAP available - starting spider scan")
            output["zap"] = zap.spider_scan(result.target)
        else:
            logger.warning("ZAP not available - skipping ZAP scan")
            output["zap"] = {"error": f"ZAP not reachable at {zap_base}"}
    
    # Output results
    json_output = json.dumps(output, indent=2, default=str)
    
    if args.stdout or args.output == "-":
        print(json_output)
    else:
        output_path = args.output
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_output)
        logger.info(f"Results saved to {output_path}")


if __name__ == "__main__":
    main()
