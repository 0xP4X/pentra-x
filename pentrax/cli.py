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
from .modules.osint.report_gen import generate_report

# Import crypto modules
from .modules.crypto.file_crypto import encrypt_file, decrypt_file
from .modules.crypto.hash_utils import hash_file, generate_key
from .modules.crypto.secure_delete import secure_delete
from .modules.crypto.zip_crack import crack_zip

# Import password modules
from .modules.password.hash_cracker import crack_hash
from .modules.password.hydra_attack import hydra_attack

# Import postex modules
from .modules.postex.reverse_shell import generate_reverse_shell, start_listener
from .modules.postex.msfvenom_gen import msfvenom_generate

# Import wireless modules
from .modules.wireless.wifi_scan import wifi_scan, enable_monitor_mode
from .modules.wireless.handshake import capture_handshake, crack_handshake

# Import social modules
from .modules.social.phishing_gen import phishing_page_generator
from .modules.social.social_tools import setoolkit, email_spoof, site_cloner

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
        ("Capture WPA Handshake", capture_handshake),
        ("Crack WPA Handshake", crack_handshake),
    ],
    "Social Engineering": [
        ("Phishing Page Generator", phishing_page_generator),
        ("SET Toolkit", setoolkit),
        ("Email Spoofer", email_spoof),
        ("Website Cloner", site_cloner),
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
        ("Crack ZIP Password", crack_zip),
    ],
    "Information Gathering": [
        ("Whois Lookup", whois_lookup),
        ("DNS Lookup", dns_lookup),
        ("SSL Certificate Info", ssl_info),
        ("Subdomain Finder", subdomain_finder),
        ("HTTP Headers", headers_grabber),
        ("CVE Search", cve_search),
        ("Generate Report", generate_report),
    ],
    "Post Exploitation": [
        ("Generate Reverse Shell", generate_reverse_shell),
        ("Start Listener (Netcat)", start_listener),
        ("Generate msfvenom Payload", msfvenom_generate),
    ],
}

MAIN_CATEGORIES = list(CATEGORIZED_MENUS.keys()) + ["Help & Documentation"]


def show_banner() -> None:
    """Display the PENTRA-X banner with animation."""
    import time
    config = get_config()
    
    if config.get('display.clear_screen', True):
        # Use cross-platform clear command
        os.system('cls' if os.name == 'nt' else 'clear')
    
    # Animate Banner
    for line in BANNER.split('\n'):
        if line.strip():
            print(f"{Colors.OKCYAN}{line}{Colors.ENDC}")
            time.sleep(0.05)
    
    print(f"\n      {Colors.BOLD}{Colors.OKBLUE}FULL PENTEST TOOLKIT (V2.0.0){Colors.ENDC}\n")
    
    # Animate Disclaimer
    for line in DISCLAIMER.split('\n'):
        if line.strip():
            print(line)
            time.sleep(0.02)
    
    time.sleep(0.5)


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
    """Display an advanced and official help & documentation menu."""
    from .core.config import get_config
    config = get_config()
    
    print(f"\n{Colors.OKCYAN}╔{'═' * 70}╗{Colors.ENDC}")
    print(f"{Colors.OKCYAN}║{' PENTRA-X ADVANCED DOCUMENTATION ':^70}║{Colors.ENDC}")
    print(f"{Colors.OKCYAN}╚{'═' * 70}╝{Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}{Colors.OKBLUE}1. OVERVIEW{Colors.ENDC}")
    print(f"   PENTRA-X is a modular, high-performance penetration testing framework")
    print(f"   designed for security professionals and authorized auditors.")
    print(f"   Version: {Colors.OKGREEN}v2.0.0{Colors.ENDC} | Author: {Colors.OKGREEN}Prince Ofori{Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}{Colors.OKBLUE}2. OPERATIONAL MODULES{Colors.ENDC}")
    print(f"   {Colors.OKCYAN}• Network Recon  :{Colors.ENDC} Stealth scans, service discovery, and nmap automation.")
    print(f"   {Colors.OKCYAN}• Web Auditing   :{Colors.ENDC} SQLi, XSS, Path Traversal, and directory enumeration.")
    print(f"   {Colors.OKCYAN}• Wireless       :{Colors.ENDC} Monitor mode injection and handshake cryptanalysis.")
    print(f"   {Colors.OKCYAN}• Social Eng     :{Colors.ENDC} Dynamic phishing generation and site replication.")
    print(f"   {Colors.OKCYAN}• OSINT & Intel  :{Colors.ENDC} DNS/Whois lookups, SSL analysis, and CVE tracking.")
    print(f"   {Colors.OKCYAN}• Post-Exploit   :{Colors.ENDC} Multi-lang reverse shells and msfvenom integration.")
    
    print(f"\n{Colors.BOLD}{Colors.OKBLUE}3. NAVIGATION & INTERFACE{Colors.ENDC}")
    print(f"   {Colors.OKCYAN}↑/↓{Colors.ENDC}        Move selection in menus")
    print(f"   {Colors.OKCYAN}Enter{Colors.ENDC}      Execute selected module or submenu")
    print(f"   {Colors.OKCYAN}0{Colors.ENDC}          Return to previous menu / Exit main menu")
    print(f"   {Colors.OKCYAN}Ctrl+C{Colors.ENDC}     Graceful interrupt of active scans and processes")
    
    print(f"\n{Colors.BOLD}{Colors.OKBLUE}4. DATA MANAGEMENT{Colors.ENDC}")
    print(f"   {Colors.OKCYAN}Logs     :{Colors.ENDC} {config.get('general.logs_dir')}")
    print(f"   {Colors.OKCYAN}Results  :{Colors.ENDC} {config.get('general.results_dir')}")
    print(f"   {Colors.OKCYAN}Reports  :{Colors.ENDC} Detailed HTML/JSON/TXT reports are generated in the results dir.")
    
    print(f"\n{Colors.BOLD}{Colors.OKBLUE}5. CONFIGURATION{Colors.ENDC}")
    print(f"   Global settings are stored in {Colors.OKCYAN}/etc/pentrax/config.yaml{Colors.ENDC}")
    print(f"   User overrides are possible via {Colors.OKCYAN}~/.pentrax/config.yaml{Colors.ENDC}")
    
    print(f"\n{Colors.WARNING}⚠️  OFFICIAL LEGAL NOTICE{Colors.ENDC}")
    print(f"   This software is for AUTHORIZED professional use only. Performance")
    print(f"   of unauthorized security testing is a violation of international")
    print(f"   cyber-laws. The author assumes no liability for malicious use.")
    
    print(f"\n{Colors.OKCYAN}{'═' * 72}{Colors.ENDC}")
    safe_press_enter()


def main_menu() -> None:
    """Main menu loop."""
    while True:
        show_main_menu()


if __name__ == "__main__":
    main_menu()
