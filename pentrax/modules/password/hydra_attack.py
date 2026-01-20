#!/usr/bin/env python3
"""
PENTRA-X Hydra Wrapper
Brute force login attacks using Hydra.
"""

import subprocess
from typing import Optional

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter, check_tool_installed
from ...core.logging import get_logger, log_result
from ...core.config import get_config


def hydra_attack(target: Optional[str] = None) -> bool:
    """
    Perform brute force login attack using Hydra.
    
    Args:
        target: Target IP or hostname
        
    Returns:
        True if credentials found, False otherwise
    """
    logger = get_logger()
    config = get_config()
    
    header("Hydra Login Bruteforce")
    
    # Check installation
    if not check_tool_installed('hydra'):
        error("Hydra is not installed")
        info("Install with: sudo apt install hydra")
        safe_press_enter()
        return False
    
    # Get target
    if not target:
        target = safe_input(f"{Colors.OKGREEN}Enter target IP/hostname: {Colors.ENDC}")
        if not target:
            return False
        target = target.strip()
    
    if not target:
        error("Target required")
        safe_press_enter()
        return False
    
    # Select service
    print(f"\n{Colors.OKCYAN}Select service to attack:{Colors.ENDC}")
    print(f"  {Colors.OKCYAN}1.{Colors.ENDC} SSH")
    print(f"  {Colors.OKCYAN}2.{Colors.ENDC} FTP")
    print(f"  {Colors.OKCYAN}3.{Colors.ENDC} HTTP Basic Auth")
    print(f"  {Colors.OKCYAN}4.{Colors.ENDC} HTTP Form POST")
    print(f"  {Colors.OKCYAN}5.{Colors.ENDC} MySQL")
    print(f"  {Colors.OKCYAN}6.{Colors.ENDC} SMB")
    print(f"  {Colors.OKCYAN}7.{Colors.ENDC} RDP")
    print(f"  {Colors.OKCYAN}8.{Colors.ENDC} Custom")
    print(f"  {Colors.OKCYAN}0.{Colors.ENDC} Back")
    
    choice = safe_input(f"\n{Colors.OKGREEN}Select service: {Colors.ENDC}")
    if choice is None or choice == '0':
        return False
    
    service = None
    port = None
    
    if choice == '1':
        service = 'ssh'
        port = 22
    elif choice == '2':
        service = 'ftp'
        port = 21
    elif choice == '3':
        service = 'http-get'
        port = 80
    elif choice == '4':
        service = 'http-post-form'
        port = 80
    elif choice == '5':
        service = 'mysql'
        port = 3306
    elif choice == '6':
        service = 'smb'
        port = 445
    elif choice == '7':
        service = 'rdp'
        port = 3389
    elif choice == '8':
        service = safe_input(f"{Colors.OKGREEN}Enter service name: {Colors.ENDC}")
        port_input = safe_input(f"{Colors.OKGREEN}Enter port: {Colors.ENDC}")
        try:
            port = int(port_input) if port_input else 22
        except ValueError:
            port = 22
    else:
        error("Invalid selection")
        safe_press_enter()
        return False
    
    # Custom port
    port_input = safe_input(f"{Colors.OKGREEN}Port (default {port}): {Colors.ENDC}")
    if port_input:
        try:
            port = int(port_input.strip())
        except ValueError:
            pass
    
    # Username options
    print(f"\n{Colors.OKCYAN}Username options:{Colors.ENDC}")
    print(f"  {Colors.OKCYAN}1.{Colors.ENDC} Single username")
    print(f"  {Colors.OKCYAN}2.{Colors.ENDC} Username wordlist")
    
    user_choice = safe_input(f"\n{Colors.OKGREEN}Select option: {Colors.ENDC}") or '1'
    
    if user_choice == '1':
        username = safe_input(f"{Colors.OKGREEN}Username: {Colors.ENDC}")
        if not username:
            error("Username required")
            safe_press_enter()
            return False
        user_opt = ['-l', username.strip()]
    else:
        userlist = safe_input(f"{Colors.OKGREEN}Username wordlist path: {Colors.ENDC}")
        if not userlist:
            error("Wordlist path required")
            safe_press_enter()
            return False
        user_opt = ['-L', userlist.strip()]
    
    # Password wordlist
    default_wordlist = config.get('wordlists.passwords', '/usr/share/wordlists/rockyou.txt')
    passlist = safe_input(f"{Colors.OKGREEN}Password wordlist (default: {default_wordlist}): {Colors.ENDC}")
    passlist = passlist.strip() if passlist else default_wordlist
    
    # Build command
    cmd = ['hydra'] + user_opt + ['-P', passlist, '-s', str(port), target, service, '-V']
    
    # Additional options for HTTP form
    if service == 'http-post-form':
        form_path = safe_input(f"{Colors.OKGREEN}Form path (e.g., /login): {Colors.ENDC}") or '/login'
        form_data = safe_input(f"{Colors.OKGREEN}Form data (e.g., user=^USER^&pass=^PASS^): {Colors.ENDC}")
        fail_string = safe_input(f"{Colors.OKGREEN}Failure string (e.g., 'Invalid'): {Colors.ENDC}") or 'Invalid'
        
        http_form = f"{form_path}:{form_data}:{fail_string}"
        cmd = ['hydra'] + user_opt + ['-P', passlist, target, 'http-post-form', http_form, '-V']
    
    info(f"Running Hydra attack on {target}:{port} ({service})")
    warning("This may take a long time depending on wordlist size")
    
    logger.tool_start("Hydra Attack", f"{target}:{port}/{service}")
    
    try:
        print(f"\n{Colors.OKCYAN}Hydra Output:{Colors.ENDC}")
        print("-" * 60)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
        
        print("-" * 60)
        
        # Check for success
        if 'host:' in result.stdout.lower() and 'login:' in result.stdout.lower():
            success("Credentials found!")
            log_result("hydra", result.stdout)
            logger.tool_end("Hydra Attack", success=True)
            safe_press_enter()
            return True
        else:
            warning("No credentials found")
            logger.tool_end("Hydra Attack", success=True)
            safe_press_enter()
            return False
            
    except subprocess.TimeoutExpired:
        error("Attack timed out after 1 hour")
        logger.tool_end("Hydra Attack", success=False)
        safe_press_enter()
        return False
    except Exception as e:
        error(f"Attack failed: {e}")
        logger.tool_end("Hydra Attack", success=False)
        safe_press_enter()
        return False


if __name__ == "__main__":
    hydra_attack()
