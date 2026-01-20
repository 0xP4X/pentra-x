#!/usr/bin/env python3
"""
PENTRA-X Color Utilities
Terminal color codes and styled printing functions.
"""


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Extended colors
    DARK_GREY = '\033[90m'
    LIGHT_RED = '\033[91m'
    LIGHT_GREEN = '\033[92m'
    LIGHT_YELLOW = '\033[93m'
    LIGHT_BLUE = '\033[94m'
    LIGHT_MAGENTA = '\033[95m'
    LIGHT_CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'


def cprint(text: str, color: str) -> None:
    """Print text with the specified color."""
    print(f"{color}{text}{Colors.ENDC}")


def success(text: str) -> None:
    """Print success message in green."""
    print(f"{Colors.OKGREEN}[+] {text}{Colors.ENDC}")


def info(text: str) -> None:
    """Print info message in blue."""
    print(f"{Colors.OKBLUE}[*] {text}{Colors.ENDC}")


def warning(text: str) -> None:
    """Print warning message in yellow."""
    print(f"{Colors.WARNING}[!] {text}{Colors.ENDC}")


def error(text: str) -> None:
    """Print error message in red."""
    print(f"{Colors.FAIL}[-] {text}{Colors.ENDC}")


def header(text: str) -> None:
    """Print header text in cyan with formatting."""
    print(f"\n{Colors.OKCYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}  {text}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}{'=' * 60}{Colors.ENDC}")


def banner(text: str) -> None:
    """Print styled banner."""
    lines = text.strip().split('\n')
    width = max(len(line) for line in lines) + 4
    
    print(f"{Colors.OKCYAN}╔{'═' * width}╗{Colors.ENDC}")
    for line in lines:
        padding = width - len(line) - 2
        print(f"{Colors.OKCYAN}║ {line}{' ' * padding} ║{Colors.ENDC}")
    print(f"{Colors.OKCYAN}╚{'═' * width}╝{Colors.ENDC}")
