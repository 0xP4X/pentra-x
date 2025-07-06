
```

██████╗ ███████╗███╗   ██╗████████╗██████╗  █████╗ ██╗  ██╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗╚██╗██╔╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║ ╚███╔╝ 
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔═══╝ ██╔══██║ ██╔██╗ 
██║     ███████╗██║ ╚████║   ██║   ██║     ██║  ██║██╔╝ ██╗
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝

      FULL PENTEST TOOLKIT (V1.2.1)
```

<p align="center">
  <b>PENTRA-X: Full Pentest Toolkit (v1.2.1)</b><br>
  <i>Created by astra-incognito</i><br>
  <a href="https://github.com/astra-incognito/">GitHub</a>
</p>

# 🛡️ PENTRA-X - Advanced Pentesting Toolkit

> **⚠️ DISCLAIMER:**
> 
> This toolkit is for **educational and authorized penetration testing use only**.
> Unauthorized use against systems you do not own or have explicit written permission to test is **illegal and unethical**.
> By using this toolkit, you agree to comply with all applicable laws and regulations.
> The author assumes no liability for misuse or damage caused by this software.

---

## 🚀 **NEW IN V1.2.1**

### ✨ **Enhanced User Experience**
- **🎯 Arrow Key Navigation** - Navigate menus with arrow keys (Linux only)
- **🎨 Colorized Interface** - Beautiful colored menus and output
- **⚡ Graceful CTRL+C Handling** - Professional exit with cleanup
- **🔄 Real-time Progress Indicators** - Spinners for long operations
- **📱 Responsive Design** - Clean, modern interface

### 🛠️ **Advanced Features**
- **🔍 Network Enumeration** - Complete network discovery and mapping
- **🎯 Advanced XSS Testing** - Comprehensive XSS payload testing
- **📊 OSINT Wordlist Generator** - Customizable password generation
- **🔧 Tool Management System** - Auto-install, update, and manage tools
- **📋 Categorized Menu System** - Organized tool categories

### 🛡️ **Security & Stability**
- **🛡️ Process Management** - Automatic cleanup of running processes
- **🧹 Resource Cleanup** - Temporary file cleanup on exit
- **⚡ Interrupt Handling** - Safe cancellation of operations
- **🔒 Error Recovery** - Robust error handling throughout

---

## 🏃‍♂️ **Quick Start**

### **Requirements**
- Linux system (Kali, Parrot, Ubuntu, etc.)
- Python 3.7+
- Root/sudo privileges for full functionality

### **Installation & Usage**
```bash
# Clone or download the toolkit
git clone https://github.com/astra-incognito/pentra-x.git
cd pentra-x

# Run the toolkit
python3 pentrax.py
```

The toolkit will automatically:
- ✅ Check and install dependencies
- ✅ Set up required tools and wordlists
- ✅ Configure the environment
- ✅ Launch the interactive menu

---

## 🎯 **Core Features**

### **🔍 Network Reconnaissance**
- **ARP Scanning** - Find live hosts on local network
- **Port Scanning** - Comprehensive port enumeration
- **Network Enumeration** - Complete network discovery and mapping
- **Nmap Integration** - Advanced scanning with custom profiles
- **Service Detection** - Identify running services and versions

### **🌐 Web Testing & Exploitation**
- **Directory Bruteforce** - Find hidden directories and files
- **Advanced XSS Testing** - Multiple payload types and techniques
- **SQL Injection Testing** - Automated SQLMap integration
- **Header Analysis** - HTTP response header inspection
- **SSL Certificate Analysis** - Certificate validation and info

### **📡 Wireless Attacks**
- **WiFi Scanning** - Discover wireless networks
- **Handshake Capture** - Capture WPA handshakes
- **WPA Cracking** - Crack captured handshakes
- **Deauth Attacks** - Force client reconnection
- **Evil Twin** - Clone target networks
- **Wifiphisher Integration** - Advanced WiFi phishing

### **🕵️‍♂️ OSINT & Information Gathering**
- **Whois Lookup** - Domain registration information
- **DNS Enumeration** - DNS record analysis
- **Subdomain Discovery** - Find subdomains of target domains
- **Social Media OSINT** - Username enumeration across platforms
- **Custom Wordlist Generation** - OSINT-based password lists

### **🦹‍♂️ Social Engineering**
- **Phishing Page Generator** - Custom phishing templates
- **Email Spoofing** - Fake email creation
- **Advanced Site Cloning** - Clone target websites
- **Phishing Server Setup** - Apache, Flask, Nginx, Express servers
- **Template Management** - Banking, social media, corporate templates

### **🔧 Advanced Tools**
- **Hash Cracking** - SHA256, SHA1, MD5 hash cracking
- **CVE Search** - Vulnerability database lookup
- **Reverse Shell Generation** - Multiple payload types
- **Persistence Scripts** - Post-exploitation persistence
- **MITM Attacks** - Man-in-the-middle techniques

---

## 🎮 **Menu Navigation**

### **Arrow Key Navigation (Linux)**
- **↑/↓** - Navigate menu options
- **Enter** - Select option
- **0** - Go back/exit
- **Ctrl+C** - Graceful exit with cleanup

### **Menu Categories**
1. **Network Reconnaissance** - Scanning and enumeration tools
2. **Web Testing & Exploitation** - Web application testing
3. **Wireless Attacks** - WiFi hacking and analysis
4. **Social Engineering** - Phishing and social engineering
5. **Information Gathering** - OSINT and reconnaissance
6. **Advanced Attacks** - Advanced exploitation techniques
7. **Tool Management** - Install, update, and manage tools

---

## 🛠️ **Tool Management System**

### **Auto-Installation**
The toolkit automatically installs and configures:
- **Core Tools**: nmap, hydra, sqlmap, gobuster, aircrack-ng
- **Wordlists**: rockyou.txt, dirb/common.txt, subdomains lists
- **Python Dependencies**: requests, beautifulsoup4, selenium, scapy
- **GitHub Tools**: BlackEye, SocialFish, HiddenEye, Wifiphisher

### **Tool Updates**
- **Automatic Updates** - Keep all tools current
- **Status Checking** - Verify tool functionality
- **Custom Wrappers** - Create custom tool integrations

---

## 🛡️ **Advanced Security Features**

### **Graceful CTRL+C Handling**
- **Process Cleanup** - Terminates all running processes
- **Resource Management** - Cleans up temporary files
- **Professional Exit** - Beautiful exit summary
- **No Orphaned Processes** - Complete cleanup on exit

### **Error Recovery**
- **Robust Error Handling** - Graceful error recovery
- **Safe Input Handling** - CTRL+C safe user input
- **Process Monitoring** - Track and manage subprocesses
- **Resource Tracking** - Monitor spinners and processes

---

## 📊 **Usage Examples**

### **Network Enumeration**
```bash
# Run the toolkit
python3 pentrax.py

# Select "Network Reconnaissance"
# Choose "Network Enumeration"
# Enter target network (e.g., 192.168.1.0/24)
```

### **Web Application Testing**
```bash
# Select "Web Testing & Exploitation"
# Choose "Advanced XSS Testing"
# Enter target URL
# Select payload types
```

### **WiFi Analysis**
```bash
# Select "Wireless Attacks"
# Choose "WiFi Scan"
# Select interface
# View discovered networks
```

---

## 🔧 **Configuration**

### **Custom Wordlists**
```bash
# The toolkit automatically downloads and manages wordlists
# Custom wordlists can be added to /usr/share/wordlists/
```

### **Tool Integration**
```bash
# Custom tools can be integrated via the Tool Management menu
# Select "Create Custom Tool Wrapper" to add new tools
```

---

## 📦 **Dependencies**

### **Auto-Installed System Tools**
- nmap, hydra, sqlmap, gobuster, arp-scan
- aircrack-ng, wifite, reaver, hcxdumptool
- whois, dig, setoolkit, bettercap
- dirb, nikto, whatweb, theharvester

### **Python Dependencies**
- requests, beautifulsoup4, selenium, scapy
- cryptography, paramiko, netaddr, dnspython
- python-nmap, python-whois, shodan

### **GitHub Tools**
- BlackEye, SocialFish, HiddenEye
- Wifiphisher, Sherlock, Photon
- Subfinder, Amass, Nuclei, HTTPX

---

## 🐛 **Troubleshooting**

### **Common Issues**
1. **Permission Denied** - Run with sudo for full functionality
2. **Tool Not Found** - Use Tool Management to install missing tools
3. **Wordlist Missing** - Toolkit auto-downloads required wordlists
4. **Interface Issues** - Ensure you're on Linux for arrow key navigation

### **Platform Support**
- **✅ Linux** - Full functionality with arrow key navigation
- **⚠️ Windows** - Limited functionality (no wireless attacks, arrow keys)
- **✅ WSL** - Full functionality on Windows Subsystem for Linux

---

## 📝 **Logging & Output**

### **Results Storage**
- **Scan Results** - Saved as `pentrax_scan_*.xml`
- **Wordlists** - Generated as `pentrax_wordlist_*.txt`
- **Logs** - Stored as `pentrax_output_*.log`
- **Temporary Files** - Auto-cleaned on exit

### **Output Formats**
- **XML** - Nmap scan results
- **TXT** - Text-based reports
- **CSV** - Structured data export
- **JSON** - API responses and data

---

## 👨‍💻 **Development**

### **Contributing**
1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Submit a pull request

### **Code Structure**
- **Modular Design** - Easy to extend and modify
- **Clean Architecture** - Well-organized functions
- **Error Handling** - Comprehensive error management
- **Documentation** - Inline code documentation

---

## 📄 **License & Legal**

### **Educational Use Only**
This toolkit is designed for:
- ✅ Educational purposes
- ✅ Authorized penetration testing
- ✅ Security research
- ✅ Ethical hacking practice

### **Prohibited Uses**
- ❌ Unauthorized system access
- ❌ Illegal activities
- ❌ Malicious attacks
- ❌ Unethical behavior

---

## 🌟 **Credits & Acknowledgments**

### **Author**
- **astra-incognito** - Main developer
- **GitHub**: https://github.com/astra-incognito/

### **Contributors**
- Open source community
- Security researchers
- Penetration testers

### **Tools & Libraries**
- Nmap, Hydra, SQLMap, Aircrack-ng
- Python community libraries
- Open source security tools

---

## 📞 **Support & Community**

### **Getting Help**
- **GitHub Issues** - Report bugs and request features
- **Documentation** - Comprehensive inline documentation
- **Community** - Join security communities

### **Stay Updated**
- **GitHub** - Latest releases and updates
- **Security News** - Follow security trends
- **Tool Updates** - Keep tools current

---

> **🎯 Remember: Use responsibly, hack ethically, be a force for good!**

---

🌐 **Website:** [https://pentrax.onrender.com](https://pentrax.onrender.com)
📧 **Contact:** [GitHub Profile](https://github.com/astra-incognito/)

---

# 📱 **iPhone-Style Stealth Calculator (Red Team Demo)**

**WARNING: This project is for educational, red team, and authorized penetration testing use only. Unauthorized use is illegal and unethical.**

## 🎯 **Features**
- **Beautiful iPhone-style calculator UI** (Tkinter, Windows-ready)
- **Stealth reverse shell**: Triggers when the user presses `+`
- **Remote kill switch**: Attacker can type `KILL` to self-destruct
- **Self-destruction**: Deletes executable and logs on kill
- **One-time trigger**: Reverse shell only launches once per run
- **Logging**: Each trigger is logged to hidden `.calc_log` file

## 🚀 **Usage (Red Team / Pentest Demo)**

### **1. Configure the Reverse Shell**
Edit `calculator.py` and set:
```python
ATTACKER_IP = "YOUR_KALI_IP"  # <-- Set your Kali IP here
ATTACKER_PORT = 4444           # <-- Set your desired port here
```