#!/usr/bin/env python3
"""
PENTRA-X Main Entry Point
Run with: python -m pentrax
"""

import sys
import signal

from . import Colors, cleanup_resources
from .cli import main_menu, show_banner
from .core.config import get_config
from .core.logging import get_logger


def signal_handler(sig, frame):
    """Handle CTRL+C gracefully."""
    print(f"\n\n{Colors.WARNING}[!] Interrupted by user (Ctrl+C){Colors.ENDC}")
    print(f"{Colors.OKCYAN}[*] Cleaning up and exiting gracefully...{Colors.ENDC}")
    
    cleanup_resources()
    
    print(f"\n{Colors.OKGREEN}╔══════════════════════════════════════════════════════════════╗{Colors.ENDC}")
    print(f"{Colors.OKGREEN}║                    PENTRA-X EXIT SUMMARY                     ║{Colors.ENDC}")
    print(f"{Colors.OKGREEN}╠══════════════════════════════════════════════════════════════╣{Colors.ENDC}")
    print(f"{Colors.OKCYAN}║  ✓ Graceful shutdown completed                               ║{Colors.ENDC}")
    print(f"{Colors.OKCYAN}║  ✓ All processes terminated safely                           ║{Colors.ENDC}")
    print(f"{Colors.OKCYAN}║  ✓ Temporary files cleaned up                                ║{Colors.ENDC}")
    print(f"{Colors.OKGREEN}╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}")
    print(f"\n{Colors.OKBLUE}Thank you for using PENTRA-X!{Colors.ENDC}")
    print(f"{Colors.WARNING}Remember: Use responsibly and ethically.{Colors.ENDC}\n")
    sys.exit(0)


def main():
    """Main entry point."""
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Initialize logger and config
    logger = get_logger()
    config = get_config()
    
    try:
        # Show banner if enabled
        if config.get('display.show_banner', True):
            show_banner()
        
        # Check dependencies (optionally)
        # check_dependencies()
        
        # Start main menu
        logger.info("PENTRA-X starting")
        main_menu()
        
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Unexpected error: {e}{Colors.ENDC}")
        logger.critical(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
