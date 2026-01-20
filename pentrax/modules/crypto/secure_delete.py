#!/usr/bin/env python3
"""
PENTRA-X Secure File Deletion
Securely delete files to prevent recovery.
"""

import os
import random
from pathlib import Path
from typing import Optional

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter, humanize_size
from ...core.spinner import ProgressBar
from ...core.logging import get_logger, log_result


def secure_delete(filepath: Optional[str] = None, passes: int = 3) -> bool:
    """
    Securely delete a file by overwriting with random data.
    
    Args:
        filepath: Path to file to delete
        passes: Number of overwrite passes
        
    Returns:
        True if successful, False otherwise
    """
    logger = get_logger()
    
    header("Secure File Deletion")
    
    # Get file path
    if not filepath:
        filepath = safe_input(f"{Colors.OKGREEN}Enter file path to securely delete: {Colors.ENDC}")
        if not filepath:
            return False
        filepath = filepath.strip()
    
    if not filepath or not os.path.exists(filepath):
        error(f"File not found: {filepath}")
        safe_press_enter()
        return False
    
    file_size = os.path.getsize(filepath)
    filename = Path(filepath).name
    
    # Confirm deletion
    print(f"\n{Colors.WARNING}WARNING: This will permanently destroy the file!{Colors.ENDC}")
    print(f"  File: {filename}")
    print(f"  Size: {humanize_size(file_size)}")
    
    confirm = safe_input(f"\n{Colors.FAIL}Type 'DELETE' to confirm: {Colors.ENDC}")
    if confirm != 'DELETE':
        info("Deletion cancelled")
        safe_press_enter()
        return False
    
    # Get number of passes
    passes_input = safe_input(f"{Colors.OKGREEN}Number of overwrite passes (default 3): {Colors.ENDC}")
    if passes_input:
        try:
            passes = int(passes_input.strip())
            passes = max(1, min(passes, 35))  # Limit to 1-35 passes
        except ValueError:
            passes = 3
    
    logger.tool_start("Secure Delete", filepath)
    
    try:
        progress = ProgressBar(passes, f"Wiping {filename}")
        
        with open(filepath, 'r+b') as f:
            for i in range(passes):
                progress.update()
                
                f.seek(0)
                
                # Different patterns for each pass
                if i % 3 == 0:
                    # Random data
                    f.write(os.urandom(file_size))
                elif i % 3 == 1:
                    # All zeros
                    f.write(b'\x00' * file_size)
                else:
                    # All ones
                    f.write(b'\xFF' * file_size)
                
                f.flush()
                os.fsync(f.fileno())
        
        progress.finish()
        
        # Rename file with random name before deletion
        random_name = f".{random.randint(100000, 999999)}.tmp"
        random_path = str(Path(filepath).parent / random_name)
        os.rename(filepath, random_path)
        
        # Delete the file
        os.remove(random_path)
        
        success(f"File '{filename}' securely deleted ({passes} passes)")
        
        log_result("secure_delete", f"Deleted: {filepath} ({passes} passes)")
        logger.tool_end("Secure Delete", success=True)
        
        safe_press_enter()
        return True
        
    except PermissionError:
        error("Permission denied - cannot modify/delete file")
        logger.tool_end("Secure Delete", success=False)
        safe_press_enter()
        return False
    except Exception as e:
        error(f"Secure deletion failed: {e}")
        logger.tool_end("Secure Delete", success=False)
        safe_press_enter()
        return False


if __name__ == "__main__":
    secure_delete()
