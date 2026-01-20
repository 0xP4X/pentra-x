#!/usr/bin/env python3
"""
PENTRA-X Network Enumeration Module
Comprehensive network discovery and enumeration.
"""

import subprocess
import socket
from typing import Optional, Dict, List

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import (
    safe_input,
    check_tool_installed,
    require_root,
    safe_press_enter,
)
from ...core.spinner import Spinner
from ...core.logging import get_logger, log_result


@require_root
def network_enumeration() -> Optional[Dict]:
    """
    Perform comprehensive network enumeration.
    
    Returns:
        Dictionary with enumeration results or None if failed
    """
    logger = get_logger()
    
    header("Network Enumeration")
    
    print(f"\n{Colors.OKCYAN}Select enumeration type:{Colors.ENDC}")
    print(f"  {Colors.OKCYAN}1.{Colors.ENDC} Interface Information")
    print(f"  {Colors.OKCYAN}2.{Colors.ENDC} Routing Table")
    print(f"  {Colors.OKCYAN}3.{Colors.ENDC} ARP Cache")
    print(f"  {Colors.OKCYAN}4.{Colors.ENDC} DNS Configuration")
    print(f"  {Colors.OKCYAN}5.{Colors.ENDC} Active Connections")
    print(f"  {Colors.OKCYAN}6.{Colors.ENDC} Full Enumeration (All)")
    print(f"  {Colors.OKCYAN}0.{Colors.ENDC} Back")
    
    choice = safe_input(f"\n{Colors.OKGREEN}Select option: {Colors.ENDC}")
    if choice is None or choice == '0':
        return None
    
    logger.tool_start("Network Enumeration", f"Option {choice}")
    
    results = {}
    
    try:
        if choice in ['1', '6']:
            info("Gathering interface information...")
            results['interfaces'] = _get_interfaces()
            
        if choice in ['2', '6']:
            info("Gathering routing table...")
            results['routes'] = _get_routes()
            
        if choice in ['3', '6']:
            info("Gathering ARP cache...")
            results['arp'] = _get_arp_cache()
            
        if choice in ['4', '6']:
            info("Gathering DNS configuration...")
            results['dns'] = _get_dns_config()
            
        if choice in ['5', '6']:
            info("Gathering active connections...")
            results['connections'] = _get_connections()
        
        # Display summary
        print(f"\n{Colors.OKCYAN}=== Enumeration Results ==={Colors.ENDC}")
        _display_results(results)
        
        # Log
        log_result("network_enum", str(results))
        logger.tool_end("Network Enumeration", success=True)
        
        safe_press_enter()
        return results
        
    except Exception as e:
        error(f"Enumeration failed: {e}")
        logger.tool_end("Network Enumeration", success=False)
        safe_press_enter()
        return None


def _get_interfaces() -> List[Dict]:
    """Get network interface information."""
    interfaces = []
    try:
        result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"\n{Colors.OKBLUE}Interface Information:{Colors.ENDC}")
            print(result.stdout)
    except Exception as e:
        warning(f"Could not get interface info: {e}")
    return interfaces


def _get_routes() -> List[Dict]:
    """Get routing table."""
    routes = []
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"\n{Colors.OKBLUE}Routing Table:{Colors.ENDC}")
            print(result.stdout)
    except Exception as e:
        warning(f"Could not get routes: {e}")
    return routes


def _get_arp_cache() -> List[Dict]:
    """Get ARP cache."""
    arp_entries = []
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"\n{Colors.OKBLUE}ARP Cache:{Colors.ENDC}")
            print(result.stdout)
    except Exception as e:
        warning(f"Could not get ARP cache: {e}")
    return arp_entries


def _get_dns_config() -> Dict:
    """Get DNS configuration."""
    dns_config = {}
    try:
        with open('/etc/resolv.conf', 'r') as f:
            content = f.read()
            print(f"\n{Colors.OKBLUE}DNS Configuration:{Colors.ENDC}")
            print(content)
    except Exception as e:
        warning(f"Could not get DNS config: {e}")
    return dns_config


def _get_connections() -> List[Dict]:
    """Get active network connections."""
    connections = []
    try:
        result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"\n{Colors.OKBLUE}Active Connections:{Colors.ENDC}")
            print(result.stdout)
    except Exception as e:
        warning(f"Could not get connections: {e}")
    return connections


def _display_results(results: Dict) -> None:
    """Display enumeration results summary."""
    for category, data in results.items():
        if data:
            success(f"{category}: {len(data) if isinstance(data, list) else 'OK'}")


if __name__ == "__main__":
    network_enumeration()
