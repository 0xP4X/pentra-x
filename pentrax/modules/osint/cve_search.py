#!/usr/bin/env python3
"""
PENTRA-X CVE Search
Search for CVE vulnerabilities.
"""

import requests
import json
from typing import Optional, List, Dict

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter
from ...core.logging import get_logger, log_result


def cve_search(keyword: Optional[str] = None) -> Optional[List[Dict]]:
    """
    Search for CVE vulnerabilities by keyword.
    
    Args:
        keyword: Search keyword (product, vendor, CVE ID)
        
    Returns:
        List of CVE results or None
    """
    logger = get_logger()
    
    header("CVE Vulnerability Search")
    
    # Get keyword
    if not keyword:
        keyword = safe_input(f"{Colors.OKGREEN}Enter search keyword (product, vendor, or CVE ID): {Colors.ENDC}")
        if not keyword:
            return None
        keyword = keyword.strip()
    
    if not keyword:
        error("Search keyword required")
        safe_press_enter()
        return None
    
    # Options
    print(f"\n{Colors.OKCYAN}Search options:{Colors.ENDC}")
    print(f"  {Colors.OKCYAN}1.{Colors.ENDC} Search by keyword")
    print(f"  {Colors.OKCYAN}2.{Colors.ENDC} Get specific CVE (e.g., CVE-2021-44228)")
    print(f"  {Colors.OKCYAN}3.{Colors.ENDC} Search recent CVEs (last 30)")
    
    choice = safe_input(f"\n{Colors.OKGREEN}Select option (default 1): {Colors.ENDC}") or '1'
    
    logger.tool_start("CVE Search", keyword)
    
    try:
        results = []
        
        if choice == '2' and keyword.upper().startswith('CVE-'):
            # Get specific CVE
            url = f"https://cve.circl.lu/api/cve/{keyword.upper()}"
            info(f"Fetching {keyword.upper()}...")
            
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if data:
                    results = [data]
        elif choice == '3':
            # Recent CVEs
            url = "https://cve.circl.lu/api/last"
            info("Fetching recent CVEs...")
            
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                results = response.json()[:30]
        else:
            # Keyword search
            url = f"https://cve.circl.lu/api/search/{keyword}"
            info(f"Searching for '{keyword}'...")
            
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                results = data.get('data', data) if isinstance(data, dict) else data
        
        if not results:
            warning("No CVEs found")
            logger.tool_end("CVE Search", success=True)
            safe_press_enter()
            return None
        
        # Display results
        print(f"\n{Colors.OKCYAN}Found {len(results)} CVE(s):{Colors.ENDC}")
        print("-" * 60)
        
        for i, cve in enumerate(results[:10], 1):  # Show first 10
            cve_id = cve.get('id', cve.get('cve', {}).get('id', 'Unknown'))
            
            # Handle different API response formats
            if 'summary' in cve:
                summary = cve.get('summary', 'No description')[:200]
            elif 'cve' in cve:
                descriptions = cve.get('cve', {}).get('descriptions', [])
                summary = descriptions[0].get('value', 'No description')[:200] if descriptions else 'No description'
            else:
                summary = 'No description available'
            
            cvss = cve.get('cvss', cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A'))
            published = cve.get('Published', cve.get('published', 'Unknown'))
            
            # Color code by severity
            if isinstance(cvss, (int, float)):
                if cvss >= 9.0:
                    severity_color = Colors.FAIL
                    severity = "CRITICAL"
                elif cvss >= 7.0:
                    severity_color = Colors.WARNING
                    severity = "HIGH"
                elif cvss >= 4.0:
                    severity_color = Colors.OKCYAN
                    severity = "MEDIUM"
                else:
                    severity_color = Colors.OKGREEN
                    severity = "LOW"
            else:
                severity_color = Colors.ENDC
                severity = "UNKNOWN"
            
            print(f"\n{Colors.OKGREEN}{i}. {cve_id}{Colors.ENDC}")
            print(f"   {severity_color}CVSS: {cvss} ({severity}){Colors.ENDC}")
            print(f"   Published: {published}")
            print(f"   {summary}...")
            
            # Show references
            refs = cve.get('references', [])
            if refs and isinstance(refs, list):
                ref_urls = refs[:2]
                if ref_urls:
                    print(f"   References: {ref_urls[0] if isinstance(ref_urls[0], str) else ref_urls[0].get('url', 'N/A')}")
        
        if len(results) > 10:
            info(f"Showing 10 of {len(results)} results")
        
        print("-" * 60)
        
        success("CVE search completed")
        log_result("cve_search", json.dumps(results[:10], default=str))
        logger.tool_end("CVE Search", success=True)
        
        safe_press_enter()
        return results
        
    except requests.Timeout:
        error("Request timed out")
        logger.tool_end("CVE Search", success=False)
        safe_press_enter()
        return None
    except Exception as e:
        error(f"Search failed: {e}")
        logger.tool_end("CVE Search", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    cve_search()
