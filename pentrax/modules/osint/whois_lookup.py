#!/usr/bin/env python3
"""
PENTRA-X Whois Lookup
Domain registration and ownership information.
"""

import subprocess
from typing import Optional, Dict

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter, check_tool_installed, validate_domain
from ...core.logging import get_logger, log_result


def whois_lookup(domain: Optional[str] = None) -> Optional[Dict]:
    """
    Perform Whois lookup on a domain.
    
    Args:
        domain: Domain to lookup
        
    Returns:
        Dictionary with parsed whois data or None
    """
    logger = get_logger()
    
    header("Whois Lookup")
    
    # Check tool
    if not check_tool_installed('whois'):
        error("whois is not installed")
        info("Install with: sudo apt install whois")
        safe_press_enter()
        return None
    
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
    
    logger.tool_start("Whois Lookup", domain)
    
    try:
        result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            error(f"Whois lookup failed: {result.stderr}")
            logger.tool_end("Whois Lookup", success=False)
            safe_press_enter()
            return None
        
        output = result.stdout
        
        # Display full output
        print(f"\n{Colors.OKCYAN}Whois Results for {domain}:{Colors.ENDC}")
        print("-" * 60)
        print(output)
        
        # Parse key fields
        key_fields = {}
        highlights = []
        
        for line in output.splitlines():
            line_lower = line.lower()
            if any(key in line_lower for key in [
                'registrar', 'creation date', 'expiry', 'expiration',
                'name server', 'status', 'updated date', 'registrant'
            ]):
                highlights.append(line.strip())
                
                # Parse into dict
                if ':' in line:
                    key, value = line.split(':', 1)
                    key_fields[key.strip()] = value.strip()
        
        # Display highlights
        if highlights:
            print(f"\n{Colors.OKGREEN}Key Information:{Colors.ENDC}")
            for h in highlights[:15]:  # Limit to 15
                print(f"  {h}")
        
        success("Whois lookup completed")
        log_result("whois", output)
        logger.tool_end("Whois Lookup", success=True)
        
        safe_press_enter()
        return key_fields
        
    except subprocess.TimeoutExpired:
        error("Lookup timed out")
        logger.tool_end("Whois Lookup", success=False)
        safe_press_enter()
        return None
    except Exception as e:
        error(f"Lookup failed: {e}")
        logger.tool_end("Whois Lookup", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    whois_lookup()
