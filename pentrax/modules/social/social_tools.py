#!/usr/bin/env python3
"""
PENTRA-X SET Toolkit Wrapper
Social Engineering Toolkit integration.
"""

import subprocess
from typing import Optional

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter, check_tool_installed, require_root
from ...core.logging import get_logger


@require_root
def setoolkit() -> None:
    """Launch the Social Engineering Toolkit."""
    logger = get_logger()
    
    header("Social Engineering Toolkit (SET)")
    
    warning("SET is for AUTHORIZED TESTING ONLY!")
    
    if not check_tool_installed('setoolkit'):
        error("SET is not installed")
        info("Install with: sudo apt install set")
        safe_press_enter()
        return
    
    print(f"\n{Colors.OKCYAN}SET Attack Vectors:{Colors.ENDC}")
    print(f"  1) Social-Engineering Attacks")
    print(f"  2) Penetration Testing (Fast-Track)")
    print(f"  3) Third Party Modules")
    print(f"  4) Update SET")
    print(f"  5) Exit")
    
    logger.tool_start("SET", "Launching")
    
    try:
        subprocess.run(['sudo', 'setoolkit'])
        logger.tool_end("SET", success=True)
    except KeyboardInterrupt:
        info("SET closed")
        logger.tool_end("SET", success=True)
    except Exception as e:
        error(f"SET failed: {e}")
        logger.tool_end("SET", success=False)
    
    safe_press_enter()


def email_spoof() -> Optional[bool]:
    """
    Create a spoofed email (for testing mail filters).
    """
    import re
    import shutil
    
    logger = get_logger()
    
    header("Email Spoofer")
    
    warning("FOR AUTHORIZED TESTING ONLY!")
    warning("Many email servers reject spoofed emails.")
    
    # Get email details
    def valid_email(addr):
        return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", addr)
    
    sender = safe_input(f"{Colors.OKGREEN}From (spoofed address): {Colors.ENDC}")
    if not sender:
        return None
    
    recipient = safe_input(f"{Colors.OKGREEN}To (target address): {Colors.ENDC}")
    if not recipient:
        return None
    
    if not valid_email(sender) or not valid_email(recipient):
        error("Invalid email address format")
        safe_press_enter()
        return False
    
    subject = safe_input(f"{Colors.OKGREEN}Subject: {Colors.ENDC}") or "Test Email"
    body = safe_input(f"{Colors.OKGREEN}Body: {Colors.ENDC}") or "This is a test email."
    
    message = f"Subject: {subject}\nFrom: {sender}\nTo: {recipient}\n\n{body}"
    
    print(f"\n{Colors.OKCYAN}Email Preview:{Colors.ENDC}")
    print("-" * 40)
    print(message)
    print("-" * 40)
    
    # Check sendmail
    if not shutil.which("sendmail"):
        warning("sendmail not found - showing raw email only")
        info("Install with: sudo apt install sendmail")
        info("Or use: swaks (Swiss Army Knife for SMTP)")
        safe_press_enter()
        return False
    
    confirm = safe_input(f"{Colors.WARNING}Send this email? (y/N): {Colors.ENDC}")
    if confirm and confirm.lower() == 'y':
        logger.tool_start("Email Spoof", f"{sender} -> {recipient}")
        
        try:
            result = subprocess.run(
                ['sendmail', recipient],
                input=message.encode(),
                capture_output=True
            )
            
            if result.returncode == 0:
                success("Email sent (check spam folder)")
                logger.tool_end("Email Spoof", success=True)
                safe_press_enter()
                return True
            else:
                error(f"sendmail failed: {result.stderr.decode()}")
                logger.tool_end("Email Spoof", success=False)
        except Exception as e:
            error(f"Failed: {e}")
            logger.tool_end("Email Spoof", success=False)
    else:
        info("Email not sent")
    
    safe_press_enter()
    return False


def site_cloner() -> Optional[str]:
    """
    Clone a website for phishing analysis.
    """
    import os
    
    logger = get_logger()
    
    header("Website Cloner")
    
    warning("FOR AUTHORIZED TESTING ONLY!")
    
    # Check wget
    if not check_tool_installed('wget'):
        error("wget not installed")
        info("Install with: sudo apt install wget")
        safe_press_enter()
        return None
    
    url = safe_input(f"{Colors.OKGREEN}Enter URL to clone: {Colors.ENDC}")
    if not url:
        return None
    
    if not url.startswith('http'):
        url = 'https://' + url
    
    output_dir = safe_input(f"{Colors.OKGREEN}Output directory (default: cloned_site): {Colors.ENDC}")
    output_dir = output_dir.strip() if output_dir else 'cloned_site'
    
    logger.tool_start("Site Cloner", url)
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        info(f"Cloning {url}...")
        
        cmd = [
            'wget',
            '--mirror',
            '--convert-links',
            '--adjust-extension',
            '--page-requisites',
            '--no-parent',
            '-P', output_dir,
            url
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0 or os.listdir(output_dir):
            success(f"Site cloned to {output_dir}/")
            info("You can serve it with: python3 -m http.server 80")
            logger.tool_end("Site Cloner", success=True)
            safe_press_enter()
            return output_dir
        else:
            error("Cloning failed")
            if result.stderr:
                print(result.stderr[:500])
            logger.tool_end("Site Cloner", success=False)
            
    except subprocess.TimeoutExpired:
        warning("Cloning timed out - partial content may exist")
        logger.tool_end("Site Cloner", success=False)
    except Exception as e:
        error(f"Cloning failed: {e}")
        logger.tool_end("Site Cloner", success=False)
    
    safe_press_enter()
    return None


if __name__ == "__main__":
    print("1) SET Toolkit")
    print("2) Email Spoofer")
    print("3) Site Cloner")
    choice = input("Select: ")
    if choice == '1':
        setoolkit()
    elif choice == '2':
        email_spoof()
    elif choice == '3':
        site_cloner()
