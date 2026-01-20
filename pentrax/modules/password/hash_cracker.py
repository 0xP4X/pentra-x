#!/usr/bin/env python3
"""
PENTRA-X Hash Cracker
Crack password hashes using wordlist attacks.
"""

import os
import hashlib
from typing import Optional

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter
from ...core.spinner import ProgressBar
from ...core.logging import get_logger, log_result
from ...core.config import get_config


def crack_hash(target_hash: Optional[str] = None) -> Optional[str]:
    """
    Crack a password hash using wordlist attack.
    
    Args:
        target_hash: Hash to crack
        
    Returns:
        Cracked password or None
    """
    logger = get_logger()
    config = get_config()
    
    header("Hash Cracker")
    
    # Get hash
    if not target_hash:
        target_hash = safe_input(f"{Colors.OKGREEN}Enter hash to crack: {Colors.ENDC}")
        if not target_hash:
            return None
        target_hash = target_hash.strip().lower()
    
    if not target_hash:
        error("Hash required")
        safe_press_enter()
        return None
    
    # Detect hash type by length
    hash_len = len(target_hash)
    
    print(f"\n{Colors.OKCYAN}Select hash type:{Colors.ENDC}")
    print(f"  {Colors.OKCYAN}1.{Colors.ENDC} MD5 (32 chars)")
    print(f"  {Colors.OKCYAN}2.{Colors.ENDC} SHA1 (40 chars)")
    print(f"  {Colors.OKCYAN}3.{Colors.ENDC} SHA256 (64 chars)")
    print(f"  {Colors.OKCYAN}4.{Colors.ENDC} SHA512 (128 chars)")
    print(f"  {Colors.OKCYAN}5.{Colors.ENDC} Auto-detect")
    
    choice = safe_input(f"\n{Colors.OKGREEN}Select hash type (default auto): {Colors.ENDC}") or '5'
    
    hash_func = None
    hash_name = ""
    
    if choice == '1':
        hash_func = hashlib.md5
        hash_name = "MD5"
    elif choice == '2':
        hash_func = hashlib.sha1
        hash_name = "SHA1"
    elif choice == '3':
        hash_func = hashlib.sha256
        hash_name = "SHA256"
    elif choice == '4':
        hash_func = hashlib.sha512
        hash_name = "SHA512"
    else:
        # Auto-detect
        if hash_len == 32:
            hash_func = hashlib.md5
            hash_name = "MD5 (auto-detected)"
        elif hash_len == 40:
            hash_func = hashlib.sha1
            hash_name = "SHA1 (auto-detected)"
        elif hash_len == 64:
            hash_func = hashlib.sha256
            hash_name = "SHA256 (auto-detected)"
        elif hash_len == 128:
            hash_func = hashlib.sha512
            hash_name = "SHA512 (auto-detected)"
        else:
            error(f"Unknown hash length: {hash_len}")
            info("Supported: MD5 (32), SHA1 (40), SHA256 (64), SHA512 (128)")
            safe_press_enter()
            return None
    
    info(f"Hash type: {hash_name}")
    
    # Get wordlist
    default_wordlist = config.get('wordlists.passwords', '/usr/share/wordlists/rockyou.txt')
    wordlist_path = safe_input(f"{Colors.OKGREEN}Wordlist path (default: {default_wordlist}): {Colors.ENDC}")
    wordlist_path = wordlist_path.strip() if wordlist_path else default_wordlist
    
    if not os.path.exists(wordlist_path):
        error(f"Wordlist not found: {wordlist_path}")
        safe_press_enter()
        return None
    
    # Count lines for progress
    info("Counting words in wordlist...")
    with open(wordlist_path, 'rb') as f:
        word_count = sum(1 for _ in f)
    
    info(f"Wordlist contains {word_count:,} words")
    
    logger.tool_start("Hash Cracker", f"{hash_name}: {target_hash[:16]}...")
    
    progress = ProgressBar(word_count, f"Cracking {hash_name}")
    
    try:
        with open(wordlist_path, 'rb') as f:
            for i, word in enumerate(f, 1):
                if i % 10000 == 0:
                    progress.set_progress(i)
                
                word = word.strip()
                
                try:
                    test_hash = hash_func(word).hexdigest()
                    
                    if test_hash == target_hash:
                        progress.finish()
                        
                        password = word.decode('utf-8', errors='replace')
                        success(f"Hash cracked!")
                        
                        print(f"\n{Colors.OKGREEN}Password: {password}{Colors.ENDC}")
                        print(f"Attempts: {i:,}")
                        
                        log_result("hash_crack", f"{target_hash} = {password}")
                        logger.tool_end("Hash Cracker", success=True)
                        
                        safe_press_enter()
                        return password
                        
                except Exception:
                    continue
        
        progress.finish(success=False)
        
        warning("Hash not found in wordlist")
        info("Try a larger wordlist or different hash type")
        
        logger.tool_end("Hash Cracker", success=True)
        safe_press_enter()
        return None
        
    except KeyboardInterrupt:
        warning("Cracking interrupted")
        logger.tool_end("Hash Cracker", success=False)
        safe_press_enter()
        return None
    except Exception as e:
        error(f"Cracking failed: {e}")
        logger.tool_end("Hash Cracker", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    crack_hash()
