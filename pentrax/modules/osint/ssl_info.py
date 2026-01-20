#!/usr/bin/env python3
"""
PENTRA-X SSL Certificate Info
SSL/TLS certificate analysis.
"""

import ssl
import socket
import json
from datetime import datetime
from typing import Optional, Dict

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter, validate_domain
from ...core.logging import get_logger, log_result


def ssl_info(domain: Optional[str] = None) -> Optional[Dict]:
    """
    Get SSL certificate information for a domain.
    
    Args:
        domain: Domain to analyze
        
    Returns:
        Certificate information dictionary or None
    """
    logger = get_logger()
    
    header("SSL Certificate Info")
    
    # Get domain
    if not domain:
        domain = safe_input(f"{Colors.OKGREEN}Enter domain: {Colors.ENDC}")
        if not domain:
            return None
        domain = domain.strip()
    
    if not domain:
        error("Domain required")
        safe_press_enter()
        return None
    
    # Remove protocol if present
    if '://' in domain:
        domain = domain.split('://')[1]
    domain = domain.split('/')[0]  # Remove path
    
    logger.tool_start("SSL Info", domain)
    
    try:
        ctx = ssl.create_default_context()
        
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
        
        if not isinstance(cert, dict):
            error("Could not retrieve certificate details")
            logger.tool_end("SSL Info", success=False)
            safe_press_enter()
            return None
        
        # Parse certificate
        subject = {}
        if 'subject' in cert:
            for item in cert['subject']:
                for key, value in item:
                    subject[key] = value
        
        issuer = {}
        if 'issuer' in cert:
            for item in cert['issuer']:
                for key, value in item:
                    issuer[key] = value
        
        # Display results
        print(f"\n{Colors.OKCYAN}SSL Certificate for {domain}:{Colors.ENDC}")
        print("-" * 60)
        
        print(f"\n{Colors.OKGREEN}Subject:{Colors.ENDC}")
        for k, v in subject.items():
            print(f"  {k}: {v}")
        
        print(f"\n{Colors.OKGREEN}Issuer:{Colors.ENDC}")
        for k, v in issuer.items():
            print(f"  {k}: {v}")
        
        # Validity dates
        not_before = cert.get('notBefore', 'Unknown')
        not_after = cert.get('notAfter', 'Unknown')
        
        print(f"\n{Colors.OKGREEN}Validity:{Colors.ENDC}")
        print(f"  Not Before: {not_before}")
        print(f"  Not After:  {not_after}")
        
        # Check expiry
        if not_after and isinstance(not_after, str):
            try:
                exp_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_left = (exp_dt - datetime.utcnow()).days
                
                if days_left < 0:
                    print(f"\n{Colors.FAIL}[!] Certificate is EXPIRED!{Colors.ENDC}")
                elif days_left < 30:
                    print(f"\n{Colors.WARNING}[!] Certificate expires in {days_left} days!{Colors.ENDC}")
                else:
                    print(f"\n{Colors.OKGREEN}[+] Certificate valid for {days_left} days{Colors.ENDC}")
            except Exception:
                pass
        
        # Check self-signed
        if subject and issuer and subject == issuer:
            print(f"\n{Colors.WARNING}[!] Certificate appears to be self-signed!{Colors.ENDC}")
        
        # SANs
        san = cert.get('subjectAltName', [])
        if san:
            print(f"\n{Colors.OKGREEN}Subject Alternative Names:{Colors.ENDC}")
            for san_type, san_value in san[:10]:  # Limit to 10
                print(f"  {san_type}: {san_value}")
        
        print("-" * 60)
        
        success("SSL certificate analysis completed")
        log_result("ssl_info", json.dumps(cert, default=str))
        logger.tool_end("SSL Info", success=True)
        
        safe_press_enter()
        return cert
        
    except ssl.SSLCertVerificationError as e:
        error(f"SSL verification error: {e}")
        warning("The certificate may be invalid, self-signed, or expired")
        logger.tool_end("SSL Info", success=False)
        safe_press_enter()
        return None
    except socket.timeout:
        error("Connection timed out")
        logger.tool_end("SSL Info", success=False)
        safe_press_enter()
        return None
    except Exception as e:
        error(f"Failed to get SSL info: {e}")
        logger.tool_end("SSL Info", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    ssl_info()
