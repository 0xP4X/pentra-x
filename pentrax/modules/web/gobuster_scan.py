#!/usr/bin/env python3
"""
PENTRA-X Gobuster Wrapper
Directory and file discovery using Gobuster.
"""

import subprocess
from typing import Optional, List

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import (
    safe_input,
    check_tool_installed,
    validate_url,
    safe_press_enter,
)
from ...core.logging import get_logger, log_result
from ...core.config import get_config


def gobuster_scan(url: Optional[str] = None) -> Optional[List[str]]:
    """
    Perform directory discovery using Gobuster.
    
    Args:
        url: Target URL
        
    Returns:
        List of discovered paths or None
    """
    logger = get_logger()
    config = get_config()
    
    header("Gobuster Directory Scanner")
    
    # Check installation
    if not check_tool_installed('gobuster'):
        error("Gobuster is not installed")
        info("Install with: sudo apt install gobuster")
        safe_press_enter()
        return None
    
    # Get URL
    if not url:
        url = safe_input(f"{Colors.OKGREEN}Enter target URL: {Colors.ENDC}")
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
    
    # Get wordlist
    default_wordlist = config.get('wordlists.directories', '/usr/share/wordlists/dirb/common.txt')
    wordlist = safe_input(f"{Colors.OKGREEN}Wordlist path (default: {default_wordlist}): {Colors.ENDC}")
    wordlist = wordlist.strip() if wordlist else default_wordlist
    
    # Select mode
    print(f"\n{Colors.OKCYAN}Select scan mode:{Colors.ENDC}")
    print(f"  {Colors.OKCYAN}1.{Colors.ENDC} Directory enumeration (dir)")
    print(f"  {Colors.OKCYAN}2.{Colors.ENDC} Virtual host discovery (vhost)")
    print(f"  {Colors.OKCYAN}3.{Colors.ENDC} DNS subdomain (dns)")
    print(f"  {Colors.OKCYAN}0.{Colors.ENDC} Back")
    
    mode_choice = safe_input(f"\n{Colors.OKGREEN}Select mode: {Colors.ENDC}")
    if mode_choice is None or mode_choice == '0':
        return None
    
    # Build command
    cmd = ['gobuster']
    
    if mode_choice == '1':
        cmd.extend(['dir', '-u', url, '-w', wordlist])
        
        # Additional options
        threads = safe_input(f"{Colors.OKGREEN}Threads (default 10): {Colors.ENDC}") or '10'
        cmd.extend(['-t', threads.strip()])
        
        extensions = safe_input(f"{Colors.OKGREEN}File extensions (e.g., php,html,txt): {Colors.ENDC}")
        if extensions:
            cmd.extend(['-x', extensions.strip()])
            
    elif mode_choice == '2':
        cmd.extend(['vhost', '-u', url, '-w', wordlist])
    elif mode_choice == '3':
        domain = safe_input(f"{Colors.OKGREEN}Enter domain for DNS enumeration: {Colors.ENDC}")
        if domain:
            cmd.extend(['dns', '-d', domain.strip(), '-w', wordlist])
        else:
            error("Domain required for DNS mode")
            safe_press_enter()
            return None
    else:
        cmd.extend(['dir', '-u', url, '-w', wordlist])
    
    info(f"Running: {' '.join(cmd)}")
    logger.tool_start("Gobuster", url)
    
    try:
        print(f"\n{Colors.OKCYAN}Gobuster Output:{Colors.ENDC}")
        print("-" * 60)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        
        if result.stdout:
            print(result.stdout)
        if result.stderr and 'Error' in result.stderr:
            print(f"{Colors.FAIL}{result.stderr}{Colors.ENDC}")
        
        print("-" * 60)
        
        # Parse results
        found_paths = []
        for line in result.stdout.splitlines():
            if 'Status:' in line or 'Found:' in line:
                found_paths.append(line)
        
        if found_paths:
            success(f"Found {len(found_paths)} paths/files")
        else:
            warning("No paths discovered")
        
        log_result("gobuster", result.stdout)
        logger.tool_end("Gobuster", success=True)
        
        safe_press_enter()
        return found_paths
        
    except subprocess.TimeoutExpired:
        error("Scan timed out after 30 minutes")
        logger.tool_end("Gobuster", success=False)
        safe_press_enter()
        return None
    except Exception as e:
        error(f"Scan failed: {e}")
        logger.tool_end("Gobuster", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    gobuster_scan()
