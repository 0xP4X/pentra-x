#!/usr/bin/env python3
"""
PENTRA-X Subdomain Finder
Subdomain enumeration using wordlist and DNS resolution.
"""

import socket
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter
from ...core.spinner import ProgressBar
from ...core.logging import get_logger, log_result
from ...core.config import get_config


def subdomain_finder(domain: Optional[str] = None) -> Optional[List[str]]:
    """
    Find subdomains for a domain using DNS resolution.
    
    Args:
        domain: Target domain
        
    Returns:
        List of found subdomains or None
    """
    logger = get_logger()
    config = get_config()
    
    header("Subdomain Finder")
    
    # Get domain
    if not domain:
        domain = safe_input(f"{Colors.OKGREEN}Enter domain (e.g., example.com): {Colors.ENDC}")
        if not domain:
            return None
        domain = domain.strip()
    
    if not domain:
        error("Domain required")
        safe_press_enter()
        return None
    
    # Get wordlist
    default_wordlist = config.get('wordlists.subdomains', '/usr/share/wordlists/subdomains-top1million-5000.txt')
    wordlist_path = safe_input(f"{Colors.OKGREEN}Wordlist path (default: {default_wordlist}): {Colors.ENDC}")
    wordlist_path = wordlist_path.strip() if wordlist_path else default_wordlist
    
    # Alternative wordlists if default doesn't exist
    alternative_wordlists = [
        '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
        '/usr/share/wordlists/amass/subdomains.lst',
        '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
    ]
    
    # Load wordlist
    subdomains_to_check = []
    try:
        with open(wordlist_path, 'r') as f:
            subdomains_to_check = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        warning(f"Wordlist not found: {wordlist_path}")
        
        # Try alternatives
        for alt in alternative_wordlists:
            try:
                with open(alt, 'r') as f:
                    subdomains_to_check = [line.strip() for line in f if line.strip()]
                info(f"Using alternative wordlist: {alt}")
                break
            except FileNotFoundError:
                continue
        
        if not subdomains_to_check:
            # Use built-in common subdomains
            subdomains_to_check = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
                'ns', 'webdisk', 'blog', 'test', 'portal', 'app', 'admin', 'api', 'dev',
                'staging', 'prod', 'git', 'gitlab', 'github', 'svn', 'cdn', 'cloud',
                'cpanel', 'whm', 'webhost', 'secure', 'shop', 'support', 'help', 'docs',
                'www2', 'www1', 'old', 'new', 'beta', 'alpha', 'demo', 'mobile', 'm',
                'forum', 'forums', 'wiki', 'store', 'vpn', 'remote', 'owa', 'outlook',
                'exchange', 'autodiscover', 'sip', 'lyncdiscover', 'mysql', 'sql', 'db',
                'database', 'backup', 'mx', 'mx1', 'mx2', 'email', 'imap', 'pop3',
            ]
            warning("Using built-in subdomain list (60 common subdomains)")
    
    info(f"Checking {len(subdomains_to_check)} subdomains for {domain}")
    
    max_threads = config.get('network.max_threads', 30)
    
    logger.tool_start("Subdomain Finder", domain)
    
    found_subdomains = []
    progress = ProgressBar(len(subdomains_to_check), "Scanning subdomains")
    
    def check_subdomain(subdomain: str) -> Optional[str]:
        """Check if subdomain resolves."""
        full_domain = f"{subdomain}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            return full_domain
        except socket.gaierror:
            return None
    
    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains_to_check}
            
            for future in as_completed(futures):
                progress.update()
                result = future.result()
                
                if result:
                    found_subdomains.append(result)
                    print(f"\n{Colors.OKGREEN}[FOUND] {result}{Colors.ENDC}")
        
        progress.finish()
        
        # Results
        if found_subdomains:
            success(f"Found {len(found_subdomains)} subdomains!")
            
            print(f"\n{Colors.OKCYAN}All Found Subdomains:{Colors.ENDC}")
            for sub in sorted(found_subdomains):
                try:
                    ip = socket.gethostbyname(sub)
                    print(f"  {sub} -> {ip}")
                except:
                    print(f"  {sub}")
            
            log_result("subdomain_finder", '\n'.join(found_subdomains))
        else:
            warning("No subdomains found")
        
        logger.tool_end("Subdomain Finder", success=True)
        safe_press_enter()
        return found_subdomains
        
    except KeyboardInterrupt:
        warning("Scan interrupted")
        logger.tool_end("Subdomain Finder", success=False)
        safe_press_enter()
        return found_subdomains
    except Exception as e:
        error(f"Scan failed: {e}")
        logger.tool_end("Subdomain Finder", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    subdomain_finder()
