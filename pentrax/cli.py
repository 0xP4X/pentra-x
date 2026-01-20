#!/usr/bin/env python3
"""
PENTRA-X Command Line Interface
Main menu and navigation system.
"""

import sys
import os
import curses
from typing import Optional, Callable, List, Tuple

from .core.colors import Colors, cprint, success, info, warning, error
from .core.utils import safe_input, safe_press_enter
from .core.config import get_config

# Import network modules
from .modules.network.arp_scan import arp_scan
from .modules.network.port_scan import port_scan
from .modules.network.nmap_scan import nmap_scan
from .modules.network.network_enum import network_enumeration

# Import web modules
from .modules.web.sqlmap_scan import sqlmap_scan
from .modules.web.xss_test import xss_test
from .modules.web.lfi_rfi_test import lfi_rfi_test
from .modules.web.gobuster_scan import gobuster_scan
from .modules.web.dir_bruteforce import dir_bruteforce

# Import OSINT modules
from .modules.osint.whois_lookup import whois_lookup
from .modules.osint.dns_lookup import dns_lookup
from .modules.osint.ssl_info import ssl_info
from .modules.osint.subdomain_finder import subdomain_finder
from .modules.osint.headers_grabber import headers_grabber
from .modules.osint.cve_search import cve_search

# Import crypto modules
from .modules.crypto.file_crypto import encrypt_file, decrypt_file
from .modules.crypto.hash_utils import hash_file, generate_key
from .modules.crypto.secure_delete import secure_delete

# Import password modules
from .modules.password.hash_cracker import crack_hash
from .modules.password.hydra_attack import hydra_attack

# Import postex modules
from .modules.postex.reverse_shell import generate_reverse_shell, start_listener
from .modules.postex.msfvenom_gen import msfvenom_generate

# Import wireless modules
from .modules.wireless.wifi_scan import wifi_scan, enable_monitor_mode

# Import social modules
from .modules.social.phishing_gen import phishing_page_generator

# Import mitm modules
from .modules.mitm.arp_spoof import arp_spoof, dns_spoof


BANNER = f"""
{Colors.OKCYAN}
██████╗ ███████╗███╗   ██╗████████╗██████╗  █████╗ ██╗  ██╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗╚██╗██╔╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║ ╚███╔╝ 
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔═══╝ ██╔══██║ ██╔██╗ 
██║     ███████╗██║ ╚████║   ██║   ██║     ██║  ██║██╔╝ ██╗
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝

      FULL PENTEST TOOLKIT (V2.0.0)
{Colors.ENDC}
"""

DISCLAIMER = f"""
{Colors.WARNING}
╔══════════════════════════════════════════════════════════════╗
║                        ⚠️  DISCLAIMER ⚠️                        ║
╠══════════════════════════════════════════════════════════════╣
║  This toolkit is for EDUCATIONAL and AUTHORIZED testing only ║
║  Unauthorized use against systems you do not own or have     ║
║  explicit written permission to test is ILLEGAL.             ║
╚══════════════════════════════════════════════════════════════╝
{Colors.ENDC}
"""


# Menu structure: (name, function)
CATEGORIZED_MENUS = {
    "Network Reconnaissance": [
        ("ARP Scan", arp_scan),
        ("Port Scan", port_scan),
        ("Nmap Advanced Scan", nmap_scan),
        ("Network Enumeration", network_enumeration),
    ],
    "Web Testing & Exploitation": [
        ("Gobuster Directory Scan", gobuster_scan),
        ("SQLMap Injection Scan", sqlmap_scan),
        ("XSS Testing", xss_test),
        ("LFI/RFI Testing", lfi_rfi_test),
        ("Directory Bruteforce", dir_bruteforce),
    ],
    "Wireless Attacks": [
        ("WiFi Network Scan", wifi_scan),
        ("Enable Monitor Mode", enable_monitor_mode),
    ],
    "Social Engineering": [
        ("Phishing Page Generator", phishing_page_generator),
    ],
    "Password Attacks": [
        ("Hydra Login Bruteforce", hydra_attack),
        ("Hash Cracker", crack_hash),
    ],
    "MITM & Network Attacks": [
        ("ARP Spoofing", arp_spoof),
        ("DNS Spoofing", dns_spoof),
    ],
    "File Encryption & Security": [
        ("Encrypt File", encrypt_file),
        ("Decrypt File", decrypt_file),
        ("Secure File Deletion", secure_delete),
        ("File Hash Calculator", hash_file),
        ("Generate Encryption Key", generate_key),
    ],
    "Information Gathering": [
        ("Whois Lookup", whois_lookup),
        ("DNS Lookup", dns_lookup),
        ("SSL Certificate Info", ssl_info),
        ("Subdomain Finder", subdomain_finder),
        ("HTTP Headers", headers_grabber),
        ("CVE Search", cve_search),
    ],
    "Post Exploitation": [
        ("Generate Reverse Shell", generate_reverse_shell),
        ("Start Listener (Netcat)", start_listener),
        ("Generate msfvenom Payload", msfvenom_generate),
    ],
}

MAIN_CATEGORIES = list(CATEGORIZED_MENUS.keys()) + ["Help & Documentation"]


def show_banner() -> None:
    """Display the PENTRA-X banner."""
    config = get_config()
    
    if config.get('display.clear_screen', True):
        os.system('clear')
    
    print(BANNER)
    print(DISCLAIMER)


def show_main_menu() -> None:
    """Display the main categorized menu."""
    print(f"\n{Colors.OKCYAN}=== PENTRA-X MAIN MENU ==={Colors.ENDC}")
    print(f"{Colors.WARNING}Choose a category:{Colors.ENDC}\n")
    
    for i, category in enumerate(MAIN_CATEGORIES, 1):
        print(f"{Colors.OKCYAN}{i}.{Colors.ENDC} {category}")
    
    print(f"{Colors.OKCYAN}0.{Colors.ENDC} Exit")
    
    choice = safe_input(f"\n{Colors.OKGREEN}Select Category > {Colors.ENDC}")
    if choice is None:
        return
    
    choice = choice.strip()
    
    if choice == "0":
        print("Exiting...")
        exit(0)
    
    try:
        choice_num = int(choice)
        if 1 <= choice_num <= len(MAIN_CATEGORIES):
            selected_category = MAIN_CATEGORIES[choice_num - 1]
            if selected_category == "Help & Documentation":
                show_help_menu()
            else:
                show_category_menu(selected_category)
        else:
            error("Invalid option.")
    except ValueError:
        error("Invalid input.")


def show_category_menu(category: str) -> None:
    """Display menu for a specific category with arrow key navigation."""
    tools = CATEGORIZED_MENUS.get(category, [])
    
    if not tools:
        warning(f"No tools available in {category}")
        safe_press_enter()
        return
    
    def menu(stdscr):
        curses.curs_set(0)
        curses.start_color()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)   # Selected
        curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Header
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)     # Warning
        curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_BLACK)   # Regular
        
        current_row = 0
        
        while True:
            stdscr.clear()
            stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
            stdscr.addstr(0, 0, f"=== {category} ===")
            stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
            
            for i, (tool_name, tool_func) in enumerate(tools):
                if i == current_row:
                    stdscr.attron(curses.color_pair(1))
                    stdscr.addstr(i + 2, 2, f"> {tool_name}")
                    stdscr.attroff(curses.color_pair(1))
                else:
                    stdscr.attron(curses.color_pair(4))
                    stdscr.addstr(i + 2, 4, tool_name)
                    stdscr.attroff(curses.color_pair(4))
            
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(len(tools) + 3, 2, "0. Back to Main Menu")
            stdscr.attroff(curses.color_pair(4))
            
            stdscr.refresh()
            key = stdscr.getch()
            
            if key == curses.KEY_UP and current_row > 0:
                current_row -= 1
            elif key == curses.KEY_DOWN and current_row < len(tools) - 1:
                current_row += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                tool_name, tool_func = tools[current_row]
                if tool_func:
                    curses.endwin()
                    tool_func()
                    return
                else:
                    stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
                    stdscr.addstr(len(tools) + 5, 2, f"[-] {tool_name} - Coming soon!")
                    stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
                    stdscr.refresh()
                    stdscr.getch()
            elif key == ord('0'):
                break
    
    curses.wrapper(menu)


def show_help_menu() -> None:
    """Display help menu."""
    print(f"\n{Colors.OKCYAN}=== HELP & DOCUMENTATION ==={Colors.ENDC}")
    print(f"""
{Colors.OKBLUE}PENTRA-X v2.0.0{Colors.ENDC}
A comprehensive penetration testing toolkit.

{Colors.OKCYAN}Categories:{Colors.ENDC}
  1. Network Reconnaissance - ARP scans, port scans, Nmap
  2. Web Testing - SQL injection, XSS, LFI/RFI, SSRF
  3. Wireless Attacks - WiFi scanning, handshake capture
  4. Social Engineering - Phishing frameworks
  5. Password Attacks - Brute force, hash cracking
  6. MITM Attacks - ARP/DNS spoofing
  7. File Security - Encryption, secure deletion
  8. Information Gathering - OSINT, DNS, Whois
  9. Post Exploitation - Shells, payloads, persistence

{Colors.OKCYAN}Navigation:{Colors.ENDC}
  • Use arrow keys ↑↓ to navigate menus
  • Press Enter to select
  • Press 0 to go back
  • Press Ctrl+C to exit gracefully

{Colors.WARNING}Legal Notice:{Colors.ENDC}
  Only use on systems you own or have explicit permission to test.
""")
    safe_press_enter()


def main_menu() -> None:
    """Main menu loop."""
    while True:
        show_main_menu()


if __name__ == "__main__":
    main_menu()
