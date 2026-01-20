```
██████╗ ███████╗███╗   ██╗████████╗██████╗  █████╗ ██╗  ██╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗╚██╗██╔╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║ ╚███╔╝ 
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔═══╝ ██╔══██║ ██╔██╗ 
██║     ███████╗██║ ╚████║   ██║   ██║     ██║  ██║██╔╝ ██╗
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝

      FULL PENTEST TOOLKIT (V2.0.0)
```

<p align="center">
  <b>PENTRA-X: Full Pentest Toolkit (v2.0.0)</b><br>
  <i>Created by 0xP4X</i><br>
  <a href="https://github.com/0xP4X/">GitHub</a>
</p>

# 🛡️ PENTRA-X - Advanced Pentesting Toolkit

> **⚠️ DISCLAIMER:**
> 
> This toolkit is for **educational and authorized penetration testing use only**.
> Unauthorized use against systems you do not own or have explicit written permission to test is **illegal and unethical**.
> By using this toolkit, you agree to comply with all applicable laws and regulations.

---

## 🚀 What's New in v2.0.0

- ✅ **Modular Architecture** - Clean package structure for easy extension
- ✅ **37 Working Tools** - All tools fully implemented (no placeholders)
- ✅ **YAML Configuration** - Customizable settings via `config.yaml`
- ✅ **Structured Logging** - File and console logging with colors
- ✅ **Progress Indicators** - Spinners and progress bars for all operations
- ✅ **Report Generation** - Professional HTML/TXT/JSON pentest reports

---

## 🏃‍♂️ Quick Start

### Requirements
- Linux system (Kali, Parrot, Ubuntu, etc.)
- Python 3.7+
- Root/sudo privileges for full functionality

### Installation
```bash
git clone https://github.com/0xP4X/pentra-x.git
cd pentra-x

# Option 1: Install as package (recommended)
pip install -e .
pentrax

# Option 2: Run directly
python3 -m pentrax

# Option 3: System-wide install
sudo ./install.sh
```

---

## 📋 Tools (37 Total)

### 1. Network Reconnaissance (4)
| Tool | Description |
|------|-------------|
| ARP Scan | Discover hosts on local network |
| Port Scan | Multi-threaded TCP port scanner |
| Nmap Advanced | 8 preset scan types with parsing |
| Network Enum | Interfaces, routes, ARP, DNS, connections |

### 2. Web Testing & Exploitation (5)
| Tool | Description |
|------|-------------|
| SQLMap | SQL injection scanner |
| XSS Testing | 15 XSS payload variants |
| LFI/RFI Testing | Path traversal + PHP filters |
| Gobuster | Directory/vhost/DNS brute force |
| Dir Bruteforce | Multi-threaded directory finder |

### 3. Wireless Attacks (4)
| Tool | Description |
|------|-------------|
| WiFi Scan | Network discovery with security analysis |
| Monitor Mode | Enable/disable monitor interface |
| Handshake Capture | WPA/WPA2 4-way handshake capture |
| Handshake Crack | Aircrack-ng wordlist attack |

### 4. Social Engineering (4)
| Tool | Description |
|------|-------------|
| Phishing Generator | Custom login pages + PHP capture |
| SET Toolkit | Launch Social Engineering Toolkit |
| Email Spoofer | Spoofed email sender |
| Website Cloner | Mirror sites with wget |

### 5. Password Attacks (2)
| Tool | Description |
|------|-------------|
| Hydra | Multi-protocol brute force |
| Hash Cracker | MD5/SHA1/SHA256/SHA512 cracker |

### 6. MITM & Network Attacks (2)
| Tool | Description |
|------|-------------|
| ARP Spoofing | Traffic interception |
| DNS Spoofing | Redirect DNS queries |

### 7. File Encryption & Security (6)
| Tool | Description |
|------|-------------|
| Encrypt File | AES-256 encryption |
| Decrypt File | AES-256 decryption |
| Secure Delete | Multi-pass file wiping |
| Hash Calculator | MD5/SHA1/SHA256/SHA512 |
| Key Generator | Random encryption keys |
| ZIP Cracker | Password-protected ZIP attack |

### 8. Information Gathering (7)
| Tool | Description |
|------|-------------|
| Whois Lookup | Domain registration info |
| DNS Lookup | A/AAAA/MX/TXT/NS records |
| SSL Info | Certificate analysis + expiry check |
| Subdomain Finder | Multi-threaded DNS enumeration |
| HTTP Headers | Security header analysis |
| CVE Search | Vulnerability database lookup |
| Report Generator | HTML/TXT/JSON pentest reports |

### 9. Post Exploitation (3)
| Tool | Description |
|------|-------------|
| Reverse Shell | 9 language templates |
| Netcat Listener | Quick listener setup |
| MSFvenom | Payload generation |

---

## 📁 Package Structure

```
pentra-x/
├── pentrax/
│   ├── __init__.py       # Linux check + exports
│   ├── __main__.py       # Entry point
│   ├── cli.py            # Curses menu system
│   ├── core/             # Shared utilities
│   │   ├── colors.py, config.py, logging.py
│   │   ├── spinner.py, utils.py
│   └── modules/          # Tool categories
│       ├── network/, web/, wireless/
│       ├── social/, password/, mitm/
│       ├── crypto/, osint/, postex/
├── config.yaml           # Configuration
├── requirements.txt      # Dependencies
└── setup.py              # pip install
```

---

## ⚙️ Configuration

Edit `config.yaml` to customize:
```yaml
general:
  results_dir: ~/.pentrax/results
  
network:
  default_timeout: 3
  max_threads: 100

wordlists:
  passwords: /usr/share/wordlists/rockyou.txt
  subdomains: /usr/share/wordlists/subdomains.txt
```

---

## 💡 Usage Tips

- Use **root privileges** for full functionality
- Run on **Kali Linux** or similar for best results
- Navigate menus with **arrow keys** ↑↓
- Press **Ctrl+C** to exit gracefully
- Generated reports saved to `~/.pentrax/results/`

---

## ⚠️ Legal Considerations

- Only test systems you **own** or have **written permission** to test
- Maintain proper **documentation** of testing activities
- Follow **responsible disclosure** for vulnerabilities found
- Unauthorized testing is **illegal** in most jurisdictions

---

## 📜 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

Contributions welcome! Submit a Pull Request.

---

<p align="center">
  <b>Created with ❤️ by 0xP4X</b><br>
  <a href="https://github.com/0xP4X/">https://github.com/0xP4X/</a>
</p>