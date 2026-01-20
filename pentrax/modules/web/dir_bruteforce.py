#!/usr/bin/env python3
"""
PENTRA-X Directory Bruteforce
Simple directory and file discovery using requests.
"""

import requests
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter
from ...core.spinner import ProgressBar
from ...core.logging import get_logger, log_result
from ...core.config import get_config


def dir_bruteforce(url: Optional[str] = None) -> Optional[List[str]]:
    """
    Bruteforce directories and files on a target URL.
    
    Args:
        url: Base URL to scan
        
    Returns:
        List of discovered paths or None
    """
    logger = get_logger()
    config = get_config()
    
    header("Directory Bruteforce")
    
    # Get URL
    if not url:
        url = safe_input(f"{Colors.OKGREEN}Enter base URL: {Colors.ENDC}")
        if not url:
            return None
        url = url.strip()
    
    if not url:
        error("URL required")
        safe_press_enter()
        return None
    
    # Ensure URL format
    if not url.startswith('http'):
        url = 'http://' + url
    url = url.rstrip('/')
    
    # Get wordlist
    default_wordlist = config.get('wordlists.directories', '/usr/share/wordlists/dirb/common.txt')
    wordlist_path = safe_input(f"{Colors.OKGREEN}Wordlist path (default: {default_wordlist}): {Colors.ENDC}")
    wordlist_path = wordlist_path.strip() if wordlist_path else default_wordlist
    
    # Load wordlist
    try:
        with open(wordlist_path, 'r') as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        error(f"Wordlist not found: {wordlist_path}")
        safe_press_enter()
        return None
    
    info(f"Loaded {len(paths)} paths from wordlist")
    
    # Config
    user_agent = config.get('web.user_agent', 'Mozilla/5.0')
    timeout = config.get('web.timeout', 5)
    max_threads = config.get('network.max_threads', 20)
    
    headers = {'User-Agent': user_agent}
    
    logger.tool_start("Dir Bruteforce", url)
    
    found_paths = []
    progress = ProgressBar(len(paths), "Scanning directories")
    
    def check_path(path: str) -> Optional[tuple]:
        """Check if path exists."""
        try:
            test_url = f"{url}/{path}"
            response = requests.get(test_url, headers=headers, timeout=timeout, allow_redirects=False)
            
            if response.status_code == 200:
                return (path, response.status_code, len(response.content))
            elif response.status_code in [301, 302, 307, 308]:
                return (path, response.status_code, 'redirect')
            elif response.status_code == 403:
                return (path, response.status_code, 'forbidden')
        except:
            pass
        return None
    
    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(check_path, path): path for path in paths}
            
            for future in as_completed(futures):
                progress.update()
                result = future.result()
                
                if result:
                    path, status, info_text = result
                    found_paths.append(f"{url}/{path}")
                    
                    if status == 200:
                        print(f"\n{Colors.OKGREEN}[200] {url}/{path}{Colors.ENDC}")
                    elif status in [301, 302, 307, 308]:
                        print(f"\n{Colors.WARNING}[{status}] {url}/{path} (redirect){Colors.ENDC}")
                    elif status == 403:
                        print(f"\n{Colors.OKCYAN}[403] {url}/{path} (forbidden){Colors.ENDC}")
        
        progress.finish()
        
        # Results
        if found_paths:
            success(f"Found {len(found_paths)} paths!")
            log_result("dir_bruteforce", '\n'.join(found_paths))
        else:
            warning("No paths found")
        
        logger.tool_end("Dir Bruteforce", success=True)
        safe_press_enter()
        return found_paths
        
    except KeyboardInterrupt:
        warning("Scan interrupted")
        logger.tool_end("Dir Bruteforce", success=False)
        safe_press_enter()
        return found_paths
    except Exception as e:
        error(f"Scan failed: {e}")
        logger.tool_end("Dir Bruteforce", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    dir_bruteforce()
