#!/usr/bin/env python3
"""
PENTRA-X ZIP Password Cracker
Crack password-protected ZIP files.
"""

import zipfile
import os
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter
from ...core.spinner import ProgressBar
from ...core.logging import get_logger, log_result
from ...core.config import get_config


def crack_zip(zip_path: Optional[str] = None) -> Optional[str]:
    """
    Crack a password-protected ZIP file.
    
    Args:
        zip_path: Path to ZIP file
        
    Returns:
        Password if found, None otherwise
    """
    logger = get_logger()
    config = get_config()
    
    header("ZIP Password Cracker")
    
    # Get ZIP file
    if not zip_path:
        zip_path = safe_input(f"{Colors.OKGREEN}Enter ZIP file path: {Colors.ENDC}")
        if not zip_path:
            return None
        zip_path = zip_path.strip()
    
    if not os.path.exists(zip_path):
        error(f"File not found: {zip_path}")
        safe_press_enter()
        return None
    
    # Check if it's a valid ZIP
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Check if encrypted
            for info_item in zf.infolist():
                if info_item.flag_bits & 0x1:
                    break
            else:
                warning("This ZIP file is not password protected")
                safe_press_enter()
                return None
    except zipfile.BadZipFile:
        error("Invalid or corrupted ZIP file")
        safe_press_enter()
        return None
    
    info("ZIP file is password protected")
    
    # Get wordlist
    default_wordlist = config.get('wordlists.passwords', '/usr/share/wordlists/rockyou.txt')
    wordlist = safe_input(f"{Colors.OKGREEN}Wordlist (default: {default_wordlist}): {Colors.ENDC}")
    wordlist = wordlist.strip() if wordlist else default_wordlist
    
    if not os.path.exists(wordlist):
        error(f"Wordlist not found: {wordlist}")
        safe_press_enter()
        return None
    
    # Count words
    info("Counting words in wordlist...")
    with open(wordlist, 'rb') as f:
        word_count = sum(1 for _ in f)
    
    info(f"Testing {word_count:,} passwords...")
    
    logger.tool_start("ZIP Crack", zip_path)
    
    progress = ProgressBar(word_count, "Cracking ZIP")
    found_password = None
    
    def try_password(password: bytes) -> Optional[str]:
        """Try a single password."""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(pwd=password)
            return password.decode('utf-8', errors='replace')
        except (RuntimeError, zipfile.BadZipFile):
            return None
        except Exception:
            return None
    
    try:
        with open(wordlist, 'rb') as f:
            for i, line in enumerate(f, 1):
                if i % 1000 == 0:
                    progress.set_progress(i)
                
                password = line.strip()
                
                try:
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        # Try to read first file with password
                        first_file = zf.namelist()[0]
                        zf.read(first_file, pwd=password)
                    
                    # Success!
                    found_password = password.decode('utf-8', errors='replace')
                    break
                    
                except (RuntimeError, zipfile.BadZipFile):
                    continue
                except Exception:
                    continue
        
        progress.finish(success=found_password is not None)
        
        if found_password:
            success(f"Password found: {found_password}")
            
            # Offer to extract
            extract = safe_input(f"{Colors.OKGREEN}Extract contents? (Y/n): {Colors.ENDC}")
            if extract.lower() != 'n':
                output_dir = Path(zip_path).stem + "_extracted"
                os.makedirs(output_dir, exist_ok=True)
                
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.extractall(path=output_dir, pwd=found_password.encode())
                
                success(f"Extracted to: {output_dir}/")
            
            log_result("zip_crack", f"File: {zip_path}, Password: {found_password}")
            logger.tool_end("ZIP Crack", success=True)
        else:
            warning("Password not found in wordlist")
            logger.tool_end("ZIP Crack", success=True)
        
        safe_press_enter()
        return found_password
        
    except KeyboardInterrupt:
        warning("Cracking interrupted")
        logger.tool_end("ZIP Crack", success=False)
        safe_press_enter()
        return None
    except Exception as e:
        error(f"Cracking failed: {e}")
        logger.tool_end("ZIP Crack", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    crack_zip()
