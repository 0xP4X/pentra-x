#!/usr/bin/env python3
"""
PENTRA-X Nmap Wrapper Module
Advanced scanning using Nmap with preset configurations.
"""

import subprocess
import re
from typing import Optional, Dict, Any

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import (
    safe_input,
    safe_subprocess_run_with_output,
    check_tool_installed,
    validate_ip,
    validate_domain,
    safe_press_enter,
)
from ...core.logging import get_logger, log_result


# Nmap scan presets
SCAN_PRESETS = {
    '1': ('Quick Scan', '-T4 -F'),
    '2': ('Intense Scan', '-T4 -A -v'),
    '3': ('Quick Scan Plus', '-sV -T4 -O -F --version-light'),
    '4': ('Intense Scan, All TCP', '-p 1-65535 -T4 -A -v'),
    '5': ('Intense Scan, No Ping', '-T4 -A -v -Pn'),
    '6': ('Stealth Scan', '-sS -T2 -f'),
    '7': ('Vulnerability Scan', '--script vuln'),
    '8': ('Full Scan (Slow)', '-sS -sV -sC -A -O -p-'),
    '9': ('Custom Scan', 'custom'),
}


def nmap_scan(target: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Perform advanced Nmap scan with preset options.
    
    Args:
        target: Target IP, hostname, or CIDR range
        
    Returns:
        Scan results as dictionary or None if failed
    """
    logger = get_logger()
    
    header("Nmap Advanced Scanner")
    
    # Check nmap installation
    if not check_tool_installed('nmap'):
        error("Nmap is not installed")
        info("Install with: sudo apt install nmap")
        safe_press_enter()
        return None
    
    # Get target
    if not target:
        target = safe_input(f"{Colors.OKGREEN}Enter target (IP/hostname/CIDR): {Colors.ENDC}")
        if not target:
            return None
        target = target.strip()
    
    if not target:
        error("Target required")
        safe_press_enter()
        return None
    
    # Validate target (allow CIDR notation)
    base_target = target.split('/')[0]  # Handle CIDR
    if not validate_ip(base_target) and not validate_domain(base_target):
        warning(f"'{target}' may not be valid - proceeding anyway")
    
    # Show scan options
    print(f"\n{Colors.OKCYAN}Select scan type:{Colors.ENDC}")
    for key, (name, _) in SCAN_PRESETS.items():
        print(f"  {Colors.OKCYAN}{key}.{Colors.ENDC} {name}")
    print(f"  {Colors.OKCYAN}0.{Colors.ENDC} Back")
    
    choice = safe_input(f"\n{Colors.OKGREEN}Select scan type (1-9, 0 to cancel): {Colors.ENDC}")
    if choice is None or choice == '0':
        return None
    
    choice = choice.strip()
    if choice not in SCAN_PRESETS:
        error("Invalid option")
        safe_press_enter()
        return None
    
    scan_name, scan_args = SCAN_PRESETS[choice]
    
    # Handle custom scan
    if scan_args == 'custom':
        custom_args = safe_input(f"{Colors.OKGREEN}Enter nmap arguments: {Colors.ENDC}")
        if custom_args is None:
            return None
        scan_args = custom_args.strip()
    
    # Build command
    cmd = ['nmap'] + scan_args.split() + [target]
    
    info(f"Running: {' '.join(cmd)}")
    logger.tool_start(f"Nmap {scan_name}", target)
    
    try:
        print(f"\n{Colors.OKCYAN}Scan Output:{Colors.ENDC}")
        print("-" * 60)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600  # 1 hour max
        )
        
        # Display output
        if result.stdout:
            print(result.stdout)
        
        if result.stderr:
            print(f"{Colors.WARNING}{result.stderr}{Colors.ENDC}")
        
        print("-" * 60)
        
        if result.returncode == 0:
            success(f"Scan completed successfully")
            
            # Log full output
            log_result("nmap_scan", f"Target: {target}\nCommand: {' '.join(cmd)}\n\n{result.stdout}")
            logger.tool_end(f"Nmap {scan_name}", success=True)
            
            # Parse basic results
            results = {
                'target': target,
                'scan_type': scan_name,
                'raw_output': result.stdout,
                'hosts': _parse_nmap_hosts(result.stdout),
            }
            
            safe_press_enter()
            return results
        else:
            error(f"Nmap exited with code {result.returncode}")
            logger.tool_end(f"Nmap {scan_name}", success=False)
            safe_press_enter()
            return None
            
    except subprocess.TimeoutExpired:
        error("Scan timed out after 1 hour")
        logger.tool_end(f"Nmap {scan_name}", success=False)
        safe_press_enter()
        return None
    except KeyboardInterrupt:
        warning("Scan interrupted by user")
        logger.tool_end(f"Nmap {scan_name}", success=False)
        safe_press_enter()
        return None
    except Exception as e:
        error(f"Scan failed: {e}")
        logger.tool_end(f"Nmap {scan_name}", success=False)
        safe_press_enter()
        return None


def _parse_nmap_hosts(output: str) -> list:
    """Parse host information from nmap output."""
    hosts = []
    
    # Simple regex to extract hosts
    host_pattern = r'Nmap scan report for ([^\s]+)'
    port_pattern = r'(\d+)/tcp\s+(\w+)\s+(\S+)'
    
    current_host = None
    current_ports = []
    
    for line in output.split('\n'):
        host_match = re.search(host_pattern, line)
        if host_match:
            if current_host:
                hosts.append({'host': current_host, 'ports': current_ports})
            current_host = host_match.group(1)
            current_ports = []
            continue
        
        port_match = re.search(port_pattern, line)
        if port_match and current_host:
            current_ports.append({
                'port': int(port_match.group(1)),
                'state': port_match.group(2),
                'service': port_match.group(3),
            })
    
    # Add last host
    if current_host:
        hosts.append({'host': current_host, 'ports': current_ports})
    
    return hosts


if __name__ == "__main__":
    nmap_scan()
