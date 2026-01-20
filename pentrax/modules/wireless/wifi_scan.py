#!/usr/bin/env python3
"""
PENTRA-X WiFi Scanner
Scan for wireless networks and analyze security.
"""

import subprocess
import re
from typing import Optional, List, Dict

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter, check_tool_installed, require_root
from ...core.logging import get_logger, log_result
from ...core.config import get_config


@require_root
def wifi_scan(interface: Optional[str] = None) -> Optional[List[Dict]]:
    """
    Scan for wireless networks.
    
    Args:
        interface: Wireless interface to use
        
    Returns:
        List of found networks or None
    """
    logger = get_logger()
    config = get_config()
    
    header("WiFi Network Scanner")
    
    # Check iwlist
    if not check_tool_installed('iwlist'):
        error("iwlist not available")
        info("Install wireless-tools: sudo apt install wireless-tools")
        safe_press_enter()
        return None
    
    # Get interface
    if not interface:
        default_iface = config.get('wireless.default_interface', 'wlan0')
        interface = safe_input(f"{Colors.OKGREEN}Enter wireless interface (default: {default_iface}): {Colors.ENDC}")
        interface = interface.strip() if interface else default_iface
    
    logger.tool_start("WiFi Scan", interface)
    
    try:
        info(f"Scanning on {interface}...")
        
        result = subprocess.run(
            ['iwlist', interface, 'scan'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            error(f"Scan failed: {result.stderr}")
            logger.tool_end("WiFi Scan", success=False)
            safe_press_enter()
            return None
        
        # Parse output
        networks = []
        current_network = {}
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            
            if 'Cell' in line and 'Address:' in line:
                if current_network:
                    networks.append(current_network)
                mac = line.split('Address:')[1].strip()
                current_network = {'bssid': mac}
                
            elif 'ESSID:' in line:
                ssid = line.split('ESSID:')[1].strip().strip('"')
                current_network['ssid'] = ssid if ssid else '<hidden>'
                
            elif 'Channel:' in line:
                channel = re.search(r'Channel:(\d+)', line)
                if channel:
                    current_network['channel'] = int(channel.group(1))
                    
            elif 'Encryption key:' in line:
                current_network['encrypted'] = 'on' in line.lower()
                
            elif 'IE:' in line:
                if 'WPA2' in line:
                    current_network['security'] = 'WPA2'
                elif 'WPA' in line:
                    current_network['security'] = current_network.get('security', 'WPA')
                    
            elif 'Signal level=' in line:
                signal = re.search(r'Signal level=(-?\d+)', line)
                if signal:
                    current_network['signal'] = int(signal.group(1))
        
        if current_network:
            networks.append(current_network)
        
        # Set default security
        for net in networks:
            if 'security' not in net:
                net['security'] = 'WEP/Open' if net.get('encrypted') else 'Open'
        
        # Display results
        print(f"\n{Colors.OKCYAN}Found {len(networks)} networks:{Colors.ENDC}")
        print("-" * 70)
        print(f"{'SSID':<25} {'BSSID':<18} {'CH':<4} {'SIG':<6} {'SECURITY'}")
        print("-" * 70)
        
        for net in sorted(networks, key=lambda x: x.get('signal', -100), reverse=True):
            ssid = net.get('ssid', '<unknown>')[:24]
            bssid = net.get('bssid', 'N/A')
            channel = str(net.get('channel', 'N/A'))
            signal = f"{net.get('signal', 'N/A')} dBm"
            security = net.get('security', 'Unknown')
            
            # Color by security
            if security == 'Open':
                sec_color = Colors.FAIL
            elif security == 'WEP/Open':
                sec_color = Colors.WARNING
            else:
                sec_color = Colors.OKGREEN
            
            print(f"{ssid:<25} {bssid:<18} {channel:<4} {signal:<6} {sec_color}{security}{Colors.ENDC}")
        
        print("-" * 70)
        
        success(f"Scan complete. Found {len(networks)} networks.")
        log_result("wifi_scan", str(networks))
        logger.tool_end("WiFi Scan", success=True)
        
        safe_press_enter()
        return networks
        
    except subprocess.TimeoutExpired:
        error("Scan timed out")
        logger.tool_end("WiFi Scan", success=False)
        safe_press_enter()
        return None
    except Exception as e:
        error(f"Scan failed: {e}")
        logger.tool_end("WiFi Scan", success=False)
        safe_press_enter()
        return None


@require_root
def enable_monitor_mode(interface: Optional[str] = None) -> Optional[str]:
    """
    Enable monitor mode on wireless interface.
    
    Args:
        interface: Wireless interface
        
    Returns:
        Monitor interface name or None
    """
    header("Enable Monitor Mode")
    
    # Check airmon-ng
    if not check_tool_installed('airmon-ng'):
        error("airmon-ng not installed")
        info("Install aircrack-ng: sudo apt install aircrack-ng")
        safe_press_enter()
        return None
    
    config = get_config()
    
    if not interface:
        default_iface = config.get('wireless.default_interface', 'wlan0')
        interface = safe_input(f"{Colors.OKGREEN}Enter interface (default: {default_iface}): {Colors.ENDC}")
        interface = interface.strip() if interface else default_iface
    
    try:
        # Kill interfering processes
        info("Killing interfering processes...")
        subprocess.run(['airmon-ng', 'check', 'kill'], capture_output=True)
        
        # Enable monitor mode
        info(f"Enabling monitor mode on {interface}...")
        result = subprocess.run(['airmon-ng', 'start', interface], capture_output=True, text=True)
        
        print(result.stdout)
        
        # Determine monitor interface name
        mon_interface = f"{interface}mon"
        
        # Verify it exists
        check = subprocess.run(['iwconfig', mon_interface], capture_output=True)
        if check.returncode == 0:
            success(f"Monitor mode enabled: {mon_interface}")
            safe_press_enter()
            return mon_interface
        else:
            # Try without 'mon' suffix
            check = subprocess.run(['iwconfig', interface], capture_output=True)
            if check.returncode == 0 and 'Monitor' in subprocess.run(['iwconfig', interface], capture_output=True, text=True).stdout:
                success(f"Monitor mode enabled: {interface}")
                safe_press_enter()
                return interface
        
        warning("Could not verify monitor interface")
        safe_press_enter()
        return mon_interface
        
    except Exception as e:
        error(f"Failed: {e}")
        safe_press_enter()
        return None


if __name__ == "__main__":
    wifi_scan()
