# Add the ASCII logo/banner at the top
LOGO = '''
██████╗ ███████╗███╗   ██╗████████╗██████╗  █████╗ ██╗  ██╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗╚██╗██╔╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║ ╚███╔╝ 
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔═══╝ ██╔══██║ ██╔██╗ 
██║     ███████╗██║ ╚████║   ██║   ██║     ██║  ██║██╔╝ ██╗
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝
FULL PENTEST TOOLKIT (WSL EDITION)
'''

# Insert the logo at the top
README = f"""
<pre>
{LOGO}
</pre>

# 🛡️ pentraX - Full Pentesting Toolkit (Linux)

---

> **⚠️ DISCLAIMER:**
> 
> This toolkit is for **educational and authorized penetration testing use only**.
> Unauthorized use against systems you do not own or have explicit written permission to test is **illegal and unethical**.
> By using this toolkit, you agree to comply with all applicable laws and regulations.
> The author assumes no liability for misuse or damage caused by this software.

---

## 🚀 Features
- 🔍 ARP scan, port scan, whois, HTTP headers, hash cracking, DNS/SSL info, subdomain finder, directory brute-force, CVE search
- 🕵️‍♂️ Nmap, Hydra, SQLMap, SET, fake email spoof, phishing page generator
- 🧠 OSINT wordlist generator
- 📡 WiFi analysis and hacking: scan, handshake capture, WPA cracking, deauth, Wifite automation
- 🦹‍♂️ Advanced MITM (wired & WiFi), Evil Twin, phishing portals, credential/session harvesting
- 🐍 Reverse shell, msfvenom payloads, persistence, and more!

## ⚡ Installation
1. Clone the repo or copy `pentrax.py` to your Linux machine.
2. Run: `python3 pentrax.py`
3. The toolkit will auto-install all required tools and wordlists (requires sudo).

## 🕹️ Usage
- Run as root or with sudo for full functionality.
- Follow the animated menu prompts. Use `99` for next page, `0` for back/exit.
- Logs and results are saved as `results_*.txt` in the current directory.

## 🗂️ Menu Structure
- 1-10: Core network/web tools
- 11-20: More tools (WiFi, OSINT, social engineering)
- 21+: Advanced, reverse shell, MITM, WiFi MITM, etc.
- Use `99` for next page, `0` for back/exit

## 📦 Dependencies
- Auto-installed: nmap, hydra, sqlmap, gobuster, arp-scan, whois, setoolkit, sendmail, dig, aircrack-ng, wifite, reaver, hcxdumptool, hcxtools, mitmproxy, dsniff, wifiphisher
- Wordlists: rockyou.txt, dirb/common.txt, subdomains-top1million-5000.txt (auto-downloaded)

## 👨‍💻 Author
- astra-incognito ([GitHub Profile](https://github.com/astra-incognito/))

---

> **Have fun, hack ethically, and enjoy the animations!**
"""

# Overwrite the README.md file with the new content
with open("README.md", "w") as f:
    f.write(README) 