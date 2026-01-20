#!/usr/bin/env python3
"""
PENTRA-X ARP Scan Module
Discover hosts on the local network using ARP.
"""

import subprocess
from typing import List, Tuple, Optional

from ...core.colors import Colors, success, error, info, warning
from ...core.utils import (
    safe_input,
    safe_subprocess_run_with_output,
    check_tool_installed,
    require_root,
    safe_press_enter,
)
from ...core.spinner import Spinner
from ...core.logging import get_logger, log_result


@require_root
def arp_scan() -> Optional[List[Tuple[str, str]]]:
    """
    Perform ARP scan to discover hosts on the local network.
    
    Returns:
        List of (IP, MAC) tuples or None if failed/cancelled
    """
    logger = get_logger()
    
    print(f"\n{Colors.OKCYAN}=== ARP Network Scan ==={Colors.ENDC}")
    
    # Check if arp-scan is installed
    if not check_tool_installed('arp-scan'):
        warning("arp-scan is not installed.")
        info("Install with: sudo apt install arp-scan")
        safe_press_enter()
        return None
    
    # Get interface
    interface = safe_input(f"{Colors.OKGREEN}Enter interface (default: eth0): {Colors.ENDC}")
    if interface is None:
        return None
    interface = interface.strip() or 'eth0'
    
    logger.tool_start("ARP Scan", interface)
    
    try:
        with Spinner(f"Scanning network on {interface}...", style='dots') as spinner:
            result = subprocess.run(
                ['sudo', 'arp-scan', '--interface', interface, '--localnet'],
                capture_output=True,
                text=True,
                timeout=60
            )
        
        if result.returncode == 0:
            # Parse results
            hosts = []
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                parts = line.split('\t')
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    mac = parts[1].strip()
                    if ip and mac and '.' in ip:
                        hosts.append((ip, mac))
            
            # Display results
            success(f"Found {len(hosts)} hosts:")
            print()
            
            for ip, mac in hosts:
                print(f"  {Colors.OKGREEN}{ip:20}{Colors.ENDC} {mac}")
            
            # Log results
            result_str = '\n'.join([f"{ip}\t{mac}" for ip, mac in hosts])
            log_result("arp_scan", result_str)
            logger.tool_end("ARP Scan", success=True)
            
            safe_press_enter()
            return hosts
        else:
            error(f"ARP scan failed: {result.stderr}")
            logger.tool_end("ARP Scan", success=False)
            safe_press_enter()
            return None
            
    except subprocess.TimeoutExpired:
        error("Scan timed out after 60 seconds")
        logger.tool_end("ARP Scan", success=False)
        safe_press_enter()
        return None
    except Exception as e:
        error(f"Error during scan: {e}")
        logger.tool_end("ARP Scan", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    arp_scan()
