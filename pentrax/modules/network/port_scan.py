#!/usr/bin/env python3
"""
PENTRA-X Port Scanner Module
Fast TCP port scanning using sockets.
"""

import socket
import threading
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from ...core.colors import Colors, success, error, info, warning
from ...core.utils import (
    safe_input,
    validate_ip,
    validate_domain,
    get_common_service,
    safe_press_enter,
)
from ...core.spinner import ProgressBar
from ...core.logging import get_logger, log_result
from ...core.config import get_config


def port_scan(target: Optional[str] = None) -> Optional[Dict[int, str]]:
    """
    Perform TCP port scan on target.
    
    Args:
        target: Target IP or hostname (prompts if not provided)
        
    Returns:
        Dictionary of {port: service_name} for open ports, or None if failed
    """
    logger = get_logger()
    config = get_config()
    
    print(f"\n{Colors.OKCYAN}=== Port Scanner ==={Colors.ENDC}")
    
    # Get target
    if not target:
        target = safe_input(f"{Colors.OKGREEN}Enter target IP/hostname: {Colors.ENDC}")
        if not target:
            return None
        target = target.strip()
    
    if not target:
        error("Target required")
        safe_press_enter()
        return None
    
    # Validate target
    if not validate_ip(target) and not validate_domain(target):
        warning(f"'{target}' may not be a valid IP or domain - proceeding anyway")
    
    # Get port range
    port_input = safe_input(f"{Colors.OKGREEN}Enter ports (e.g., 1-1000, 80,443,8080, or 'common'): {Colors.ENDC}")
    if port_input is None:
        return None
    port_input = port_input.strip() or 'common'
    
    # Parse ports
    ports_to_scan = []
    
    if port_input.lower() == 'common':
        # Common ports from config
        common_ports = config.get('network.default_ports', '21,22,80,443,8080')
        ports_to_scan = [int(p.strip()) for p in common_ports.split(',')]
    elif '-' in port_input:
        # Port range
        try:
            start, end = map(int, port_input.split('-'))
            ports_to_scan = list(range(start, end + 1))
        except ValueError:
            error("Invalid port range format")
            safe_press_enter()
            return None
    else:
        # Comma-separated ports
        try:
            ports_to_scan = [int(p.strip()) for p in port_input.split(',')]
        except ValueError:
            error("Invalid port format")
            safe_press_enter()
            return None
    
    # Get timeout and threads from config
    timeout = config.get('network.timeout', 1)
    max_threads = config.get('network.max_threads', 50)
    
    info(f"Scanning {len(ports_to_scan)} ports on {target}...")
    logger.tool_start("Port Scan", f"{target} ({len(ports_to_scan)} ports)")
    
    open_ports: Dict[int, str] = {}
    lock = threading.Lock()
    
    def scan_port(port: int) -> Optional[int]:
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                return port
        except Exception:
            pass
        return None
    
    # Scan with progress bar
    progress = ProgressBar(len(ports_to_scan), "Scanning ports", width=40)
    
    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports_to_scan}
            
            for future in as_completed(futures):
                progress.update()
                port = future.result()
                if port is not None:
                    service = get_common_service(port)
                    with lock:
                        open_ports[port] = service
        
        progress.finish()
        
        # Display results
        if open_ports:
            success(f"Found {len(open_ports)} open ports:")
            print()
            
            for port in sorted(open_ports.keys()):
                service = open_ports[port]
                print(f"  {Colors.OKGREEN}{port:6}{Colors.ENDC} {service}")
            
            # Log results
            result_str = '\n'.join([f"{port}\t{svc}" for port, svc in sorted(open_ports.items())])
            log_result("port_scan", f"Target: {target}\n{result_str}")
            logger.tool_end("Port Scan", success=True)
        else:
            warning("No open ports found")
            logger.tool_end("Port Scan", success=True)
        
        safe_press_enter()
        return open_ports
        
    except KeyboardInterrupt:
        warning("Scan interrupted")
        logger.tool_end("Port Scan", success=False)
        safe_press_enter()
        return open_ports
    except Exception as e:
        error(f"Scan error: {e}")
        logger.tool_end("Port Scan", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    port_scan()
