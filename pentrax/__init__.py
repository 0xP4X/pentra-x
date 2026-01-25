#!/usr/bin/env python3
"""
PENTRA-X - Advanced Pentesting Toolkit
Created by Prince Ofori

A comprehensive penetration testing toolkit featuring:
- Network reconnaissance and scanning
- Web application testing
- Wireless security assessment
- Social engineering tools
- Password attacks and cracking
- MITM attacks
- File encryption and security
- OSINT gathering
- Post-exploitation tools
"""

import sys

# Platform check - Linux only
if not sys.platform.startswith('linux'):
    print("\n[!] PENTRA-X is only supported on Linux.")
    print("Please use a Linux system (Kali, Parrot, Ubuntu, etc.) for full functionality.\n")
    sys.exit(1)

from .core import __version__
from .core.colors import Colors, cprint, success, info, warning, error, header, banner
from .core.spinner import Spinner, ProgressBar
from .core.utils import (
    safe_subprocess_run,
    safe_subprocess_run_with_output,
    safe_input,
    safe_press_enter,
    check_root,
    require_root,
    check_tool_installed,
    validate_ip,
    validate_domain,
    validate_url,
    cleanup_resources,
)
from .core.logging import get_logger, log_result
from .core.config import get_config, Config

__all__ = [
    # Version
    '__version__',
    
    # Colors
    'Colors', 'cprint', 'success', 'info', 'warning', 'error', 'header', 'banner',
    
    # Progress
    'Spinner', 'ProgressBar',
    
    # Utils
    'safe_subprocess_run', 'safe_subprocess_run_with_output',
    'safe_input', 'safe_press_enter',
    'check_root', 'require_root', 'check_tool_installed',
    'validate_ip', 'validate_domain', 'validate_url',
    'cleanup_resources',
    
    # Logging
    'get_logger', 'log_result',
    
    # Config
    'get_config', 'Config',
]
