```
██████╗ ███████╗███╗   ██╗████████╗██████╗  █████╗ ██╗  ██╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗╚██╗██╔╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║ ╚███╔╝ 
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔═══╝ ██╔══██║ ██╔██╗ 
██║     ███████╗██║ ╚████║   ██║   ██║     ██║  ██║██╔╝ ██╗
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝
FULL PENTEST TOOLKIT (v1.0)

# 🛡️ pentraX - Full Pentesting Toolkit (Linux)

---

> **⚠️ DISCLAIMER:**
> 
> This toolkit is for **educational and authorized penetration testing use only**.
> Unauthorized use against systems you do not own or have explicit written permission to test is **illegal and unethical**.
> By using this toolkit, you agree to comply with all applicable laws and regulations.
> The author assumes no liability for misuse or damage caused by this software.

---

## 🏃‍♂️ How to Run (Python & C++ Versions)

### ▶️ Python Version
1. Ensure you have Python 3 installed.
2. Run:
   ```sh
   python3 pentrax.py
   ```
3. The toolkit will auto-install all required tools and wordlists (requires sudo/root).

### ▶️ C++ Version
1. Ensure you have a C++ compiler (g++), OpenSSL development libraries, and required system tools installed.
   - On Ubuntu/Kali/WSL:
     ```sh
     sudo apt update
     sudo apt install g++ libssl-dev
     ```
2. Compile the C++ toolkit:
   ```sh
   g++ -o pentrax pentrax.cpp -lssl -lcrypto
   ```
3. Run the compiled binary:
   ```sh
   ./pentrax
   ```
4. Run as root or with sudo for full functionality (for features requiring elevated privileges).

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

> **Have fun, hack ethically, be a legion!**

---

🌐 **Website:** [https://pentrax.onrender.com](https://pentrax.onrender.com) 

# iPhone-Style Stealth Calculator (Red Team Demo)

**WARNING: This project is for educational, red team, and authorized penetration testing use only. Unauthorized use is illegal and unethical.**

---

## Features
- **Beautiful iPhone-style calculator UI** (Tkinter, Windows-ready)
- **Stealth reverse shell**: Triggers when the user presses `+`, connects back to the attacker's machine
- **Remote kill switch**: Attacker can type `KILL` in the shell to self-destruct the calculator and erase logs
- **Self-destruction**: Deletes its own executable/script and `.calc_log` file on kill
- **One-time trigger**: Reverse shell only launches once per run
- **Logging**: Each trigger is logged to a hidden `.calc_log` file

---

## Usage (Red Team / Pentest Demo)

1. **Configure the Reverse Shell**
   - Edit `calculator.py` and set:
     ```python
     ATTACKER_IP = "YOUR_KALI_IP"  # <-- Set your Kali IP here
     ATTACKER_PORT = 4444           # <-- Set your desired port here
     ```

2. **Build the Executable (Optional)**
   - Use [PyInstaller](https://www.pyinstaller.org/) to create a Windows `.exe`:
     ```bash
     pyinstaller --onefile --noconsole calculator.py
     ```

3. **Start Listener on Kali**
   - On your Kali machine:
     ```bash
     nc -lvnp 4444
     ```

4. **Deploy the Calculator**
   - Run the calculator on the target Windows PC.
   - When the user presses `+`, you get a shell on your Kali terminal.

5. **Remote Kill Switch**
   - In your shell, type:
     ```
     KILL
     ```
   - The calculator will self-destruct and exit.

---

## How the Attacker Gets Connected

Once the calculator is running on the victim's device, the attacker must:

1. **Start a Listener on Kali**
   - Open a terminal and run:
     ```bash
     nc -lvnp 4444
     ```
     (Replace `4444` with the port you set in `ATTACKER_PORT`.)

2. **Wait for the Trigger**
   - The victim uses the calculator as normal.
   - When the user presses the `+` button, the reverse shell is triggered and connects back to your Kali machine.

3. **Get the Shell**
   - As soon as the user presses `+`, you will see a connection in your Netcat terminal.
   - You now have a command shell on the victim’s machine. Type commands and see the output.

4. **(Optional) Use the Kill Switch**
   - To self-destruct the calculator remotely, type:
     ```
     KILL
     ```
     in your shell and press Enter. The calculator will delete itself and its logs, then exit.

### Summary Table

| Step                | Action on Attacker (Kali) Side         | Action on Victim Side         |
|---------------------|----------------------------------------|-------------------------------|
| 1. Start Listener   | `nc -lvnp 4444`                        |                               |
| 2. Deploy Calculator|                                        | User runs calculator.exe      |
| 3. Trigger Shell    |                                        | User presses `+`              |
| 4. Get Shell        | Shell appears in Netcat terminal       |                               |
| 5. Remote Kill      | Type `KILL` in shell, press Enter      | Calculator self-destructs     |

---

## Ethical & Legal Notice
- **This project is for educational and authorized security testing only.**
- Do not use, distribute, or demonstrate this tool without explicit permission.
- The authors are not responsible for misuse or damages.

---

## Credits
- UI inspired by iPhone Calculator
- Reverse shell and kill switch for red team/pentest demo scenarios 