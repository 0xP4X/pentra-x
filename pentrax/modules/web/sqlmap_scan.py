#!/usr/bin/env python3
"""
PENTRA-X SQLMap Wrapper
SQL Injection testing using SQLMap.
"""

import subprocess
from typing import Optional, Dict, List

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import (
    safe_input,
    safe_subprocess_run_with_output,
    check_tool_installed,
    validate_url,
    safe_press_enter,
)
from ...core.logging import get_logger, log_result


def sqlmap_scan(url: Optional[str] = None) -> Optional[List[str]]:
    """
    Perform SQL injection testing using SQLMap.
    
    Args:
        url: Target URL with parameter (e.g., http://example.com/page?id=1)
        
    Returns:
        List of found vulnerabilities or None
    """
    logger = get_logger()
    
    header("SQLMap Injection Scanner")
    
    # Check SQLMap installation
    if not check_tool_installed('sqlmap'):
        error("SQLMap is not installed")
        info("Install with: sudo apt install sqlmap")
        safe_press_enter()
        return None
    
    # Get target URL
    if not url:
        url = safe_input(f"{Colors.OKGREEN}Enter target URL (with parameter, e.g., http://site.com/page?id=1): {Colors.ENDC}")
        if not url:
            return None
        url = url.strip()
    
    if not url:
        error("Target URL required")
        safe_press_enter()
        return None
    
    # SQLMap options
    print(f"\n{Colors.OKCYAN}Select scan type:{Colors.ENDC}")
    print(f"  {Colors.OKCYAN}1.{Colors.ENDC} Quick scan (--batch)")
    print(f"  {Colors.OKCYAN}2.{Colors.ENDC} Full scan (--batch --crawl=2 --level=5 --risk=3)")
    print(f"  {Colors.OKCYAN}3.{Colors.ENDC} Database enumeration (--batch --dbs)")
    print(f"  {Colors.OKCYAN}4.{Colors.ENDC} Table enumeration (--batch --tables -D <db>)")
    print(f"  {Colors.OKCYAN}5.{Colors.ENDC} Custom options")
    print(f"  {Colors.OKCYAN}0.{Colors.ENDC} Back")
    
    choice = safe_input(f"\n{Colors.OKGREEN}Select option: {Colors.ENDC}")
    if choice is None or choice == '0':
        return None
    
    # Build command
    cmd = ['sqlmap', '-u', url]
    
    if choice == '1':
        cmd.extend(['--batch', '--crawl=1'])
    elif choice == '2':
        cmd.extend(['--batch', '--crawl=2', '--level=5', '--risk=3'])
    elif choice == '3':
        cmd.extend(['--batch', '--dbs'])
    elif choice == '4':
        db_name = safe_input(f"{Colors.OKGREEN}Enter database name: {Colors.ENDC}")
        if db_name:
            cmd.extend(['--batch', '--tables', '-D', db_name.strip()])
        else:
            cmd.extend(['--batch', '--tables'])
    elif choice == '5':
        custom_opts = safe_input(f"{Colors.OKGREEN}Enter SQLMap options: {Colors.ENDC}")
        if custom_opts:
            cmd.extend(custom_opts.strip().split())
    else:
        cmd.extend(['--batch'])
    
    info(f"Running: {' '.join(cmd)}")
    logger.tool_start("SQLMap", url)
    
    try:
        print(f"\n{Colors.OKCYAN}SQLMap Output:{Colors.ENDC}")
        print("-" * 60)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        
        if result.stdout:
            print(result.stdout)
        
        # Parse vulnerabilities
        vulnerabilities = []
        for line in result.stdout.splitlines():
            if "is vulnerable" in line.lower() or "parameter" in line.lower():
                vulnerabilities.append(line)
                print(f"{Colors.OKGREEN}[VULN] {line}{Colors.ENDC}")
        
        print("-" * 60)
        
        if vulnerabilities:
            success(f"Found {len(vulnerabilities)} potential vulnerabilities")
        else:
            warning("No SQLi vulnerabilities found")
        
        log_result("sqlmap", result.stdout)
        logger.tool_end("SQLMap", success=True)
        
        safe_press_enter()
        return vulnerabilities
        
    except subprocess.TimeoutExpired:
        error("Scan timed out after 30 minutes")
        logger.tool_end("SQLMap", success=False)
        safe_press_enter()
        return None
    except Exception as e:
        error(f"Scan failed: {e}")
        logger.tool_end("SQLMap", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    sqlmap_scan()
