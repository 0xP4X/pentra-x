#!/usr/bin/env python3
"""
PENTRA-X File Hash Calculator
Calculate various hash digests of files.
"""

import os
import hashlib
from pathlib import Path
from typing import Optional, Dict

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter, humanize_size
from ...core.spinner import Spinner
from ...core.logging import get_logger, log_result


def hash_file(filepath: Optional[str] = None) -> Optional[Dict[str, str]]:
    """
    Calculate multiple hash digests of a file.
    
    Args:
        filepath: Path to file
        
    Returns:
        Dictionary of hash type -> hash value or None
    """
    logger = get_logger()
    
    header("File Hash Calculator")
    
    # Get file path
    if not filepath:
        filepath = safe_input(f"{Colors.OKGREEN}Enter file path: {Colors.ENDC}")
        if not filepath:
            return None
        filepath = filepath.strip()
    
    if not filepath or not os.path.exists(filepath):
        error(f"File not found: {filepath}")
        safe_press_enter()
        return None
    
    file_size = os.path.getsize(filepath)
    filename = Path(filepath).name
    
    info(f"Calculating hashes for {filename} ({humanize_size(file_size)})")
    
    logger.tool_start("File Hash", filepath)
    
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256(),
        'sha512': hashlib.sha512(),
    }
    
    try:
        with Spinner("Calculating hashes...", style='dots') as spinner:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    for h in hashes.values():
                        h.update(chunk)
        
        # Get results
        results = {name: h.hexdigest() for name, h in hashes.items()}
        
        # Display
        print(f"\n{Colors.OKCYAN}File: {filename}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Size: {humanize_size(file_size)}{Colors.ENDC}")
        print("-" * 60)
        
        for name, value in results.items():
            print(f"\n{Colors.OKGREEN}{name.upper()}:{Colors.ENDC}")
            print(f"  {value}")
        
        print("-" * 60)
        
        success("Hash calculation completed")
        log_result("file_hash", f"{filepath}\n{results}")
        logger.tool_end("File Hash", success=True)
        
        safe_press_enter()
        return results
        
    except Exception as e:
        error(f"Hash calculation failed: {e}")
        logger.tool_end("File Hash", success=False)
        safe_press_enter()
        return None


def generate_key(length: int = 32) -> Optional[str]:
    """
    Generate a random encryption key.
    
    Args:
        length: Key length in bytes
        
    Returns:
        Hex-encoded key or None
    """
    header("Generate Encryption Key")
    
    # Get length
    length_input = safe_input(f"{Colors.OKGREEN}Key length in bytes (default 32): {Colors.ENDC}")
    if length_input:
        try:
            length = int(length_input.strip())
            if length < 16:
                warning("Minimum key length is 16 bytes")
                length = 16
            elif length > 64:
                warning("Maximum key length is 64 bytes")
                length = 64
        except ValueError:
            length = 32
    
    try:
        key_bytes = os.urandom(length)
        key_hex = key_bytes.hex()
        
        print(f"\n{Colors.OKCYAN}Generated {length}-byte key:{Colors.ENDC}")
        print("-" * 60)
        print(f"\n{Colors.OKGREEN}Hex:{Colors.ENDC}")
        print(f"  {key_hex}")
        
        import base64
        key_b64 = base64.b64encode(key_bytes).decode()
        print(f"\n{Colors.OKGREEN}Base64:{Colors.ENDC}")
        print(f"  {key_b64}")
        
        print("-" * 60)
        
        # Save option
        save = safe_input(f"{Colors.OKGREEN}Save to file? (y/N): {Colors.ENDC}")
        if save and save.lower() == 'y':
            filename = f"key_{length}bytes.txt"
            with open(filename, 'w') as f:
                f.write(f"Hex: {key_hex}\n")
                f.write(f"Base64: {key_b64}\n")
            success(f"Key saved to {filename}")
        
        success("Key generated successfully")
        safe_press_enter()
        return key_hex
        
    except Exception as e:
        error(f"Key generation failed: {e}")
        safe_press_enter()
        return None


if __name__ == "__main__":
    hash_file()
