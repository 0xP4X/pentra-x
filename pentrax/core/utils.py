#!/usr/bin/env python3
"""
PENTRA-X Utility Functions
Shared helper functions for subprocess handling, input, and system operations.
"""

import os
import sys
import subprocess
import signal
import shutil
import re
from typing import Optional, List, Any, Callable
from pathlib import Path

from .colors import Colors


# Global list to track running processes for cleanup
running_processes: List[subprocess.Popen] = []
active_spinners: List[Any] = []


def safe_subprocess_run(cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
    """
    Run subprocess command with proper cleanup tracking.
    
    Args:
        cmd: Command and arguments as list
        **kwargs: Additional arguments for subprocess.run
        
    Returns:
        CompletedProcess instance
    """
    try:
        proc = subprocess.Popen(cmd, **kwargs)
        running_processes.append(proc)
        proc.wait()
        return subprocess.CompletedProcess(cmd, proc.returncode, proc.stdout, proc.stderr)
    finally:
        if proc in running_processes:
            running_processes.remove(proc)


def safe_subprocess_run_with_output(cmd: List[str], **kwargs) -> Optional[subprocess.CompletedProcess]:
    """
    Run subprocess command with real-time output and CTRL+C handling.
    
    Args:
        cmd: Command and arguments as list
        **kwargs: Additional arguments for subprocess.Popen
        
    Returns:
        CompletedProcess instance or None if interrupted
    """
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            **kwargs
        )
        running_processes.append(proc)
        
        # Stream output in real-time
        if proc.stdout:
            for line in proc.stdout:
                print(line, end='')
        
        proc.wait()
        return subprocess.CompletedProcess(cmd, proc.returncode)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Process interrupted by user{Colors.ENDC}")
        if proc:
            proc.terminate()
            proc.wait(timeout=5)
        return None
    finally:
        if 'proc' in locals() and proc in running_processes:
            running_processes.remove(proc)


def safe_input(prompt: str = "") -> Optional[str]:
    """
    Get user input with CTRL+C handling.
    
    Args:
        prompt: Input prompt string
        
    Returns:
        User input string or None if interrupted
    """
    try:
        return input(prompt)
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def safe_press_enter(prompt: str = "\n[Press Enter to return to the menu]") -> bool:
    """
    Safe 'Press Enter' prompt with CTRL+C handling.
    
    Args:
        prompt: Prompt text
        
    Returns:
        True if Enter pressed, False if interrupted
    """
    try:
        input(prompt)
        return True
    except (KeyboardInterrupt, EOFError):
        print()
        return False


def run_with_interrupt_handling(func: Callable, *args, **kwargs) -> Any:
    """
    Run a function with proper CTRL+C handling.
    
    Args:
        func: Function to run
        *args: Positional arguments
        **kwargs: Keyword arguments
        
    Returns:
        Function result or None if interrupted
    """
    try:
        return func(*args, **kwargs)
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Operation cancelled{Colors.ENDC}")
        return None


def check_root() -> bool:
    """Check if running as root/sudo."""
    return os.geteuid() == 0


def require_root(func: Callable) -> Callable:
    """Decorator that requires root privileges."""
    def wrapper(*args, **kwargs):
        if not check_root():
            print(f"{Colors.FAIL}[-] This operation requires root privileges.{Colors.ENDC}")
            print(f"{Colors.OKBLUE}[*] Please run: sudo pentrax{Colors.ENDC}")
            return None
        return func(*args, **kwargs)
    return wrapper


def check_tool_installed(tool_name: str) -> bool:
    """Check if a tool is installed and available in PATH."""
    return shutil.which(tool_name) is not None


def ensure_tool_installed(tool_name: str, install_cmd: Optional[str] = None) -> bool:
    """
    Ensure a tool is installed, optionally installing it if missing.
    
    Args:
        tool_name: Name of the tool to check
        install_cmd: Optional install command if tool is missing
        
    Returns:
        True if tool is available, False otherwise
    """
    if check_tool_installed(tool_name):
        return True
    
    print(f"{Colors.WARNING}[!] {tool_name} is not installed.{Colors.ENDC}")
    
    if install_cmd:
        print(f"{Colors.OKBLUE}[*] Install with: {install_cmd}{Colors.ENDC}")
        
        response = safe_input(f"Install {tool_name} now? (y/n): ")
        if response and response.lower() == 'y':
            try:
                subprocess.run(install_cmd, shell=True, check=True)
                return check_tool_installed(tool_name)
            except subprocess.CalledProcessError:
                print(f"{Colors.FAIL}[-] Installation failed.{Colors.ENDC}")
    
    return False


def validate_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    
    octets = ip.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets)


def validate_domain(domain: str) -> bool:
    """Validate domain name format."""
    # Simple domain validation
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def validate_url(url: str) -> bool:
    """Validate URL format."""
    pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return bool(re.match(pattern, url, re.IGNORECASE))


def validate_port(port: Any) -> bool:
    """Validate port number."""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def get_common_service(port: int) -> str:
    """Get common service name for a port number."""
    services = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPCBind', 119: 'NNTP',
        135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 194: 'IRC',
        389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog',
        587: 'Submission', 631: 'CUPS', 993: 'IMAPS', 995: 'POP3S',
        1080: 'SOCKS', 1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
        6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
    }
    return services.get(port, 'Unknown')


def humanize_size(size_bytes: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def cleanup_resources() -> None:
    """Clean up all resources before exit."""
    print(f"{Colors.OKCYAN}[*] Cleaning up resources...{Colors.ENDC}")
    
    # Stop all active spinners
    for spinner in active_spinners[:]:
        try:
            spinner.stop()
        except Exception:
            pass
    
    # Terminate all running processes
    for process in running_processes[:]:
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        except Exception:
            pass


def color_menu_numbers(menu_text: str) -> str:
    """Color menu numbers in cyan for better visibility."""
    def repl(match):
        return f"{Colors.OKCYAN}{match.group(0)}{Colors.ENDC}"
    return re.sub(r'^\d+\.', repl, menu_text, flags=re.MULTILINE)


def typewriter(text: str, delay: float = 0.01) -> None:
    """Print text with typewriter effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()


def animated_print(text: str, delay: float = 0.03) -> None:
    """Print text with animation effect."""
    for line in text.split('\n'):
        print(line)
