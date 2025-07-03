# pentraX - Full Pentesting Toolkit (Linux)

## Overview
pentraX is an all-in-one Linux pentesting toolkit for network, web, social engineering, OSINT, and WiFi security assessments. It features a menu-driven interface and automates installation of dependencies and wordlists.

## Features
- ARP scan, port scan, whois, HTTP headers, hash cracking, DNS/SSL info, subdomain finder, directory brute-force, CVE search
- Nmap, Hydra, SQLMap, SET, fake email spoof, phishing page generator
- OSINT wordlist generator
- WiFi analysis and hacking: scan, handshake capture, WPA cracking, deauth, Wifite automation

## Installation
1. Clone the repo or copy `pentrax.py` to your Linux machine.
2. Run: `python3 pentrax.py`
3. The toolkit will auto-install all required tools and wordlists (requires sudo).

## Usage
- Run as root or with sudo for full functionality.
- Follow the menu prompts. Use option `99` for advanced WiFi/OSINT tools.
- Logs and results are saved as `results_*.txt` in the current directory.

## Menu Structure
- 1-10: Core network/web tools
- 99: More tools (11-22: advanced, social engineering, WiFi, OSINT)

## Legal Notice
**Use this toolkit only in authorized environments (CTF, lab, or with explicit written permission). Unauthorized use is illegal.**

## Dependencies
- Auto-installed: nmap, hydra, sqlmap, gobuster, arp-scan, whois, setoolkit, sendmail, dig, aircrack-ng, wifite, reaver, hcxdumptool, hcxtools
- Wordlists: rockyou.txt, dirb/common.txt, subdomains-top1million-5000.txt (auto-downloaded)

## Author
- astra-incognito ([GitHub Profile](https://github.com/astra-incognito/)) 