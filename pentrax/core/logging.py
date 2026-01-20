#!/usr/bin/env python3
"""
PENTRA-X Logging Framework
Structured logging with file and console output.
"""

import os
import logging
import sys
from datetime import datetime
from typing import Optional
from pathlib import Path

from .colors import Colors


class PentraxLogger:
    """Custom logger for PENTRA-X with colored console output and file logging."""
    
    LOG_DIR = Path.home() / ".pentrax" / "logs"
    
    def __init__(self, name: str = "pentrax", log_level: int = logging.INFO):
        """
        Initialize the logger.
        
        Args:
            name: Logger name
            log_level: Minimum log level to capture
        """
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        
        # Remove existing handlers
        self.logger.handlers = []
        
        # Create log directory
        self.LOG_DIR.mkdir(parents=True, exist_ok=True)
        
        # File handler - logs everything
        log_file = self.LOG_DIR / f"pentrax_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Console handler - colored output
        console_handler = ColoredConsoleHandler()
        console_handler.setLevel(log_level)
        self.logger.addHandler(console_handler)
    
    def debug(self, message: str) -> None:
        """Log debug message."""
        self.logger.debug(message)
    
    def info(self, message: str) -> None:
        """Log info message."""
        self.logger.info(message)
    
    def warning(self, message: str) -> None:
        """Log warning message."""
        self.logger.warning(message)
    
    def error(self, message: str) -> None:
        """Log error message."""
        self.logger.error(message)
    
    def critical(self, message: str) -> None:
        """Log critical message."""
        self.logger.critical(message)
    
    def scan_result(self, scan_type: str, target: str, result: str) -> None:
        """Log a scan result with structured format."""
        self.logger.info(f"SCAN [{scan_type}] Target: {target} | Result: {result}")
    
    def tool_start(self, tool_name: str, target: Optional[str] = None) -> None:
        """Log tool execution start."""
        if target:
            self.logger.info(f"TOOL START: {tool_name} -> {target}")
        else:
            self.logger.info(f"TOOL START: {tool_name}")
    
    def tool_end(self, tool_name: str, success: bool = True) -> None:
        """Log tool execution end."""
        status = "SUCCESS" if success else "FAILED"
        self.logger.info(f"TOOL END: {tool_name} -> {status}")


class ColoredConsoleHandler(logging.StreamHandler):
    """Custom console handler with colored output."""
    
    COLORS = {
        logging.DEBUG: Colors.DARK_GREY,
        logging.INFO: Colors.OKBLUE,
        logging.WARNING: Colors.WARNING,
        logging.ERROR: Colors.FAIL,
        logging.CRITICAL: Colors.FAIL + Colors.BOLD,
    }
    
    PREFIXES = {
        logging.DEBUG: '[D]',
        logging.INFO: '[*]',
        logging.WARNING: '[!]',
        logging.ERROR: '[-]',
        logging.CRITICAL: '[!!]',
    }
    
    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record with colors."""
        try:
            color = self.COLORS.get(record.levelno, Colors.ENDC)
            prefix = self.PREFIXES.get(record.levelno, '[?]')
            
            message = self.format(record)
            formatted = f"{color}{prefix} {message}{Colors.ENDC}"
            
            print(formatted, file=sys.stderr if record.levelno >= logging.ERROR else sys.stdout)
        except Exception:
            self.handleError(record)


# Global logger instance
_logger: Optional[PentraxLogger] = None


def get_logger(name: str = "pentrax") -> PentraxLogger:
    """Get or create the global logger instance."""
    global _logger
    if _logger is None:
        _logger = PentraxLogger(name)
    return _logger


def log_result(scan_type: str, data: str) -> None:
    """Legacy function for backward compatibility. Logs result to file."""
    logger = get_logger()
    logger.scan_result(scan_type, "N/A", data)
    
    # Also write to results file for backward compatibility
    results_dir = Path.home() / ".pentrax" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    
    results_file = results_dir / f"{scan_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(results_file, 'w', encoding='utf-8') as f:
        f.write(f"Scan Type: {scan_type}\n")
        f.write(f"Timestamp: {datetime.now().isoformat()}\n")
        f.write(f"{'=' * 50}\n")
        f.write(data)
