#!/usr/bin/env python3
"""
PENTRA-X DNS Lookup
DNS record enumeration for domains.
"""

import subprocess
from typing import Optional, Dict, List

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter, validate_domain
from ...core.logging import get_logger, log_result


RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME', 'PTR', 'SRV']


def dns_lookup(domain: Optional[str] = None) -> Optional[Dict[str, List[str]]]:
    """
    Perform DNS lookup on a domain.
    
    Args:
        domain: Domain to lookup
        
    Returns:
        Dictionary of record type -> values or None
    """
    logger = get_logger()
    
    header("DNS Lookup")
    
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
    
    # Select record types
    print(f"\n{Colors.OKCYAN}Select record types:{Colors.ENDC}")
    print(f"  {Colors.OKCYAN}1.{Colors.ENDC} All common records (A, AAAA, MX, TXT, NS)")
    print(f"  {Colors.OKCYAN}2.{Colors.ENDC} A records only")
    print(f"  {Colors.OKCYAN}3.{Colors.ENDC} MX records only")
    print(f"  {Colors.OKCYAN}4.{Colors.ENDC} TXT records only")
    print(f"  {Colors.OKCYAN}5.{Colors.ENDC} All record types")
    print(f"  {Colors.OKCYAN}0.{Colors.ENDC} Back")
    
    choice = safe_input(f"\n{Colors.OKGREEN}Select option: {Colors.ENDC}")
    if choice is None or choice == '0':
        return None
    
    if choice == '1':
        types_to_check = ['A', 'AAAA', 'MX', 'TXT', 'NS']
    elif choice == '2':
        types_to_check = ['A']
    elif choice == '3':
        types_to_check = ['MX']
    elif choice == '4':
        types_to_check = ['TXT']
    elif choice == '5':
        types_to_check = RECORD_TYPES
    else:
        types_to_check = ['A', 'AAAA', 'MX', 'TXT', 'NS']
    
    logger.tool_start("DNS Lookup", domain)
    
    records: Dict[str, List[str]] = {}
    
    print(f"\n{Colors.OKCYAN}DNS Records for {domain}:{Colors.ENDC}")
    print("-" * 60)
    
    for rtype in types_to_check:
        try:
            result = subprocess.run(
                ['dig', '+short', domain, rtype],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                values = result.stdout.strip().splitlines()
                records[rtype] = values
                
                print(f"\n{Colors.OKGREEN}{rtype} Records:{Colors.ENDC}")
                for v in values:
                    print(f"  {v}")
                    
        except subprocess.TimeoutExpired:
            warning(f"Timeout fetching {rtype} records")
        except Exception as e:
            warning(f"Error fetching {rtype}: {e}")
    
    print("-" * 60)
    
    if records:
        success(f"Found {sum(len(v) for v in records.values())} records across {len(records)} types")
        log_result("dns_lookup", str(records))
        logger.tool_end("DNS Lookup", success=True)
    else:
        warning("No DNS records found")
        logger.tool_end("DNS Lookup", success=True)
    
    safe_press_enter()
    return records


if __name__ == "__main__":
    dns_lookup()
