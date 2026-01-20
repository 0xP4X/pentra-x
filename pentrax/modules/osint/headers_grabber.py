#!/usr/bin/env python3
"""
PENTRA-X HTTP Headers Analyzer
HTTP header analysis and security assessment.
"""

import requests
import time
from typing import Optional, Dict

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter, validate_url
from ...core.logging import get_logger, log_result
from ...core.config import get_config


# Security headers to check
SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HSTS - Forces HTTPS',
    'Content-Security-Policy': 'CSP - Prevents XSS and injection attacks',
    'X-Content-Type-Options': 'Prevents MIME type sniffing',
    'X-Frame-Options': 'Prevents clickjacking',
    'X-XSS-Protection': 'XSS filter (legacy)',
    'Referrer-Policy': 'Controls referrer information',
    'Permissions-Policy': 'Controls browser feature access',
    'Cross-Origin-Embedder-Policy': 'Controls cross-origin embedding',
    'Cross-Origin-Opener-Policy': 'Controls cross-origin window access',
    'Cross-Origin-Resource-Policy': 'Controls cross-origin resource sharing',
}


def headers_grabber(url: Optional[str] = None) -> Optional[Dict]:
    """
    Analyze HTTP headers of a URL.
    
    Args:
        url: Target URL
        
    Returns:
        Dictionary with headers and analysis or None
    """
    logger = get_logger()
    config = get_config()
    
    header("HTTP Headers Analyzer")
    
    # Get URL
    if not url:
        url = safe_input(f"{Colors.OKGREEN}Enter URL: {Colors.ENDC}")
        if not url:
            return None
        url = url.strip()
    
    if not url:
        error("URL required")
        safe_press_enter()
        return None
    
    # Ensure URL has scheme
    if not url.startswith('http'):
        url = 'http://' + url
    
    # Options
    follow_redirects = safe_input(f"{Colors.OKGREEN}Follow redirects? (Y/n): {Colors.ENDC}")
    follow_redirects = follow_redirects.lower() != 'n' if follow_redirects else True
    
    user_agent = config.get('web.user_agent', 'Mozilla/5.0')
    timeout = config.get('web.timeout', 10)
    
    headers_req = {'User-Agent': user_agent}
    
    logger.tool_start("Headers Grabber", url)
    
    try:
        start_time = time.time()
        response = requests.get(url, headers=headers_req, timeout=timeout, allow_redirects=follow_redirects)
        elapsed = time.time() - start_time
        
        # Display results
        print(f"\n{Colors.OKCYAN}Response for {url}:{Colors.ENDC}")
        print("-" * 60)
        
        print(f"\n{Colors.OKGREEN}Status: {response.status_code} | Time: {elapsed:.2f}s{Colors.ENDC}")
        
        # Redirect chain
        if response.history:
            print(f"\n{Colors.WARNING}Redirect Chain:{Colors.ENDC}")
            for i, resp in enumerate(response.history):
                print(f"  {i+1}. [{resp.status_code}] {resp.url}")
            print(f"  -> Final: {response.url}")
        
        # All headers
        print(f"\n{Colors.OKGREEN}Response Headers:{Colors.ENDC}")
        for key, value in response.headers.items():
            print(f"  {key}: {value}")
        
        # Security header analysis
        print(f"\n{Colors.OKCYAN}Security Header Analysis:{Colors.ENDC}")
        missing_headers = []
        present_headers = []
        
        for sec_header, description in SECURITY_HEADERS.items():
            if sec_header in response.headers:
                present_headers.append(sec_header)
                print(f"  {Colors.OKGREEN}✓ {sec_header}{Colors.ENDC}: {response.headers[sec_header][:60]}")
            else:
                missing_headers.append(sec_header)
                print(f"  {Colors.FAIL}✗ {sec_header}{Colors.ENDC}: Missing ({description})")
        
        # Score
        score = len(present_headers) / len(SECURITY_HEADERS) * 100
        
        print(f"\n{Colors.OKCYAN}Security Score: {score:.0f}%{Colors.ENDC}")
        if score >= 70:
            success("Good security header configuration")
        elif score >= 40:
            warning("Moderate security - some headers missing")
        else:
            error("Poor security - many important headers missing")
        
        # Server info
        server = response.headers.get('Server', 'Not disclosed')
        powered_by = response.headers.get('X-Powered-By', 'Not disclosed')
        
        print(f"\n{Colors.OKGREEN}Server Information:{Colors.ENDC}")
        print(f"  Server: {server}")
        print(f"  X-Powered-By: {powered_by}")
        
        if server != 'Not disclosed' or powered_by != 'Not disclosed':
            warning("Server version disclosure may aid attackers")
        
        print("-" * 60)
        
        log_result("headers", f"URL: {url}\nHeaders: {dict(response.headers)}")
        logger.tool_end("Headers Grabber", success=True)
        
        safe_press_enter()
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'security_score': score,
            'missing_headers': missing_headers,
        }
        
    except requests.Timeout:
        error("Request timed out")
        logger.tool_end("Headers Grabber", success=False)
        safe_press_enter()
        return None
    except requests.RequestException as e:
        error(f"Request failed: {e}")
        logger.tool_end("Headers Grabber", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    headers_grabber()
