#!/usr/bin/env python3
"""
PENTRA-X File Encryption
AES-256 file encryption and decryption.
"""

import os
import hashlib
from pathlib import Path
from typing import Optional

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter, humanize_size
from ...core.spinner import Spinner
from ...core.logging import get_logger, log_result

# Try to import crypto library
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# PKCS7 padding
def pad(data: bytes, block_size: int = 16) -> bytes:
    """Add PKCS7 padding."""
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)


def unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding."""
    if not data:
        return data
    padding_len = data[-1]
    if padding_len > len(data) or padding_len > 16:
        raise ValueError("Invalid padding")
    return data[:-padding_len]


def encrypt_file(filepath: Optional[str] = None, password: Optional[str] = None) -> bool:
    """
    Encrypt a file using AES-256.
    
    Args:
        filepath: Path to file to encrypt
        password: Encryption password
        
    Returns:
        True if successful, False otherwise
    """
    logger = get_logger()
    
    header("File Encryption (AES-256)")
    
    if not CRYPTO_AVAILABLE:
        error("PyCryptodome not installed")
        info("Install with: pip install pycryptodome")
        safe_press_enter()
        return False
    
    # Get file path
    if not filepath:
        filepath = safe_input(f"{Colors.OKGREEN}Enter file path to encrypt: {Colors.ENDC}")
        if not filepath:
            return False
        filepath = filepath.strip()
    
    if not filepath or not os.path.exists(filepath):
        error(f"File not found: {filepath}")
        safe_press_enter()
        return False
    
    if filepath.endswith('.enc'):
        warning("File already appears to be encrypted")
    
    # Get password
    if not password:
        password = safe_input(f"{Colors.OKGREEN}Enter encryption password: {Colors.ENDC}")
        if not password:
            error("Password required")
            safe_press_enter()
            return False
        
        confirm = safe_input(f"{Colors.OKGREEN}Confirm password: {Colors.ENDC}")
        if password != confirm:
            error("Passwords do not match")
            safe_press_enter()
            return False
    
    logger.tool_start("File Encryption", filepath)
    
    try:
        # Generate key from password
        salt = get_random_bytes(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
        
        # Read file
        file_size = os.path.getsize(filepath)
        info(f"Encrypting {Path(filepath).name} ({humanize_size(file_size)})")
        
        with Spinner("Encrypting file...", style='dots') as spinner:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # Encrypt
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(pad(data))
            
            # Write encrypted file
            output_path = filepath + '.enc'
            with open(output_path, 'wb') as f:
                f.write(salt)  # 16 bytes
                f.write(iv)    # 16 bytes
                f.write(encrypted)
        
        success(f"Encrypted file saved: {output_path}")
        
        # Optionally delete original
        delete_original = safe_input(f"{Colors.WARNING}Delete original file? (y/N): {Colors.ENDC}")
        if delete_original and delete_original.lower() == 'y':
            os.remove(filepath)
            info("Original file deleted")
        
        log_result("encryption", f"Encrypted: {filepath} -> {output_path}")
        logger.tool_end("File Encryption", success=True)
        
        safe_press_enter()
        return True
        
    except Exception as e:
        error(f"Encryption failed: {e}")
        logger.tool_end("File Encryption", success=False)
        safe_press_enter()
        return False


def decrypt_file(filepath: Optional[str] = None, password: Optional[str] = None) -> bool:
    """
    Decrypt a file encrypted with AES-256.
    
    Args:
        filepath: Path to encrypted file
        password: Decryption password
        
    Returns:
        True if successful, False otherwise
    """
    logger = get_logger()
    
    header("File Decryption (AES-256)")
    
    if not CRYPTO_AVAILABLE:
        error("PyCryptodome not installed")
        info("Install with: pip install pycryptodome")
        safe_press_enter()
        return False
    
    # Get file path
    if not filepath:
        filepath = safe_input(f"{Colors.OKGREEN}Enter encrypted file path (.enc): {Colors.ENDC}")
        if not filepath:
            return False
        filepath = filepath.strip()
    
    if not filepath or not os.path.exists(filepath):
        error(f"File not found: {filepath}")
        safe_press_enter()
        return False
    
    # Get password
    if not password:
        password = safe_input(f"{Colors.OKGREEN}Enter decryption password: {Colors.ENDC}")
        if not password:
            error("Password required")
            safe_press_enter()
            return False
    
    logger.tool_start("File Decryption", filepath)
    
    try:
        with Spinner("Decrypting file...", style='dots') as spinner:
            with open(filepath, 'rb') as f:
                salt = f.read(16)
                iv = f.read(16)
                encrypted = f.read()
            
            # Derive key
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
            
            # Decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted))
            
            # Write decrypted file
            if filepath.endswith('.enc'):
                output_path = filepath[:-4]
            else:
                output_path = filepath + '.dec'
            
            with open(output_path, 'wb') as f:
                f.write(decrypted)
        
        success(f"Decrypted file saved: {output_path}")
        
        log_result("decryption", f"Decrypted: {filepath} -> {output_path}")
        logger.tool_end("File Decryption", success=True)
        
        safe_press_enter()
        return True
        
    except ValueError as e:
        error("Decryption failed - wrong password or corrupted file")
        logger.tool_end("File Decryption", success=False)
        safe_press_enter()
        return False
    except Exception as e:
        error(f"Decryption failed: {e}")
        logger.tool_end("File Decryption", success=False)
        safe_press_enter()
        return False


if __name__ == "__main__":
    print("1. Encrypt file")
    print("2. Decrypt file")
    choice = input("Select: ")
    if choice == '1':
        encrypt_file()
    elif choice == '2':
        decrypt_file()
